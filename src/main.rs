use clap::Parser;
use sql_fingerprint::{FingerprintOptions, Fingerprinter};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    query: String,
    #[arg(long)]
    match_embedded_numbers: bool,
    #[arg(long)]
    match_md5_checksums: bool,
}

fn main() {
    let args = Args::parse();
    let options = FingerprintOptions::default()
        .with_match_embedded_numbers(args.match_embedded_numbers)
        .with_match_md5_checksums(args.match_md5_checksums);

    let fingerprinter = Fingerprinter::new(options);

    let out = fingerprinter.fingerprint(&args.query);
    println!("{out}")
}
