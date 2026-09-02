use std::{
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::Parser;
use regex::Regex;
use sql_fingerprint::{FingerprintOptions, Fingerprinter};
use std::sync::LazyLock;

static HASH_LINE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^#.+$").expect("hash line regex must be valid"));

/// Convert SQL queries into fingerprints.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// Fingerprint a single query instead of reading files or standard input.
    #[arg(long, conflicts_with = "files")]
    query: Option<String>,

    /// SQL files to read; use - or omit files to read standard input.
    files: Vec<PathBuf>,

    /// Preserve numbers embedded in identifiers such as catch22.
    #[arg(long)]
    match_embedded_numbers: bool,

    /// Replace lowercase MD5 checksums with a single placeholder.
    #[arg(long)]
    match_md5_checksums: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        // Downstream consumers such as `head` may close the pipe after receiving enough output.
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> io::Result<()> {
    let args = Args::parse();
    let options = FingerprintOptions::default()
        .with_match_embedded_numbers(args.match_embedded_numbers)
        .with_match_md5_checksums(args.match_md5_checksums);
    let fingerprinter = Fingerprinter::new(options);
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());

    if let Some(query) = args.query.as_deref() {
        let out = fingerprinter.fingerprint(query);
        writeln!(writer, "{out}")?;
    } else if !args.files.is_empty() {
        for path in &args.files {
            if path == Path::new("-") {
                let stdin = io::stdin();
                let reader = stdin.lock();
                process_reader(reader, &mut writer, &fingerprinter)?;
                continue;
            }
            let file = File::open(path).map_err(|source| {
                io::Error::new(
                    source.kind(),
                    format!("failed to open {}: {source}", path.display()),
                )
            })?;
            let reader = BufReader::new(file);
            process_reader(reader, &mut writer, &fingerprinter)?;
        }
    } else {
        let stdin = io::stdin();
        let reader = stdin.lock();
        process_reader(reader, &mut writer, &fingerprinter)?;
    }
    writer.flush()
}

fn process_reader<R: BufRead, W: Write>(
    mut reader: R,
    writer: &mut W,
    fingerprinter: &Fingerprinter,
) -> io::Result<()> {
    let mut record = String::new();

    loop {
        let bytes_read = reader.read_line(&mut record)?;
        if bytes_read == 0 {
            if !record.is_empty() {
                process_record(&record, writer, fingerprinter)?;
            }
            break;
        }

        if record.ends_with(";\n") {
            record.truncate(record.len() - 2);
            process_record(&record, writer, fingerprinter)?;
            record.clear();
        }
    }

    Ok(())
}

fn process_record<W: Write>(
    record: &str,
    writer: &mut W,
    fingerprinter: &Fingerprinter,
) -> io::Result<()> {
    let query = HASH_LINE_RE.replace_all(record, "");
    let query = query.trim_start_matches(|character: char| character.is_ascii_whitespace());

    let Some(first_character) = query.chars().next() else {
        return Ok(());
    };

    if !first_character.is_ascii_alphanumeric() && first_character != '_' {
        return Ok(());
    }
    let fingerprint = fingerprinter.fingerprint(query);
    writeln!(writer, "{fingerprint}")?;
    Ok(())
}
