use std::{
    fs::File,
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use clap::Parser;
use sql_fingerprint::{FingerprintOptions, Fingerprinter};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, conflicts_with = "files")]
    query: Option<String>,
    files: Vec<PathBuf>,
    #[arg(long)]
    match_embedded_numbers: bool,
    #[arg(long)]
    match_md5_checksums: bool,
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    let options = FingerprintOptions::default()
        .with_match_embedded_numbers(args.match_embedded_numbers)
        .with_match_md5_checksums(args.match_md5_checksums);
    let fingerprinter = Fingerprinter::new(options);
    let stdout = io::stdout();
    let mut writer = stdout.lock();

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
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            process_reader(reader, &mut writer, &fingerprinter)?;
        }
    } else {
        let stdin = io::stdin();
        let reader = stdin.lock();
        process_reader(reader, &mut writer, &fingerprinter)?;
    };
    Ok(())
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
                let fingerprint = fingerprinter.fingerprint(&record);
                writeln!(writer, "{fingerprint}")?;
            }
            break;
        }

        if record.ends_with(";\n") {
            record.truncate(record.len() - 2);
            let fingerprint = fingerprinter.fingerprint(&record);
            writeln!(writer, "{fingerprint}")?;

            record.clear();
        }
    }

    Ok(())
}
