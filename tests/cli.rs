use std::process::{Command, Output};

fn run_cli(args: &[&str]) -> Output {
    // Cargo provides the path to the package binary for integration tests.
    let binary = std::env::var("CARGO_BIN_EXE_sql-fingerprint")
        .expect("Cargo should provide the sql-fingerprint binary");
    Command::new(binary)
        .args(args)
        .output()
        .expect("CLI process should start")
}

#[test]
fn query_argument_prints_fingerprint() {
    let output = run_cli(&["--query", "SELECT * FROM users WHERE id = 42"]);

    assert!(
        output.status.success(),
        "CLI should exit successfully: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be valid UTF-8"),
        "select * from users where id = ?\n"
    );
    assert!(
        output.stderr.is_empty(),
        "stderr should be empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn match_embedded_numbers_option_preserves_numbers_in_identifiers() {
    let output = run_cli(&[
        "--query",
        "SELECT catch22, rt_5min",
        "--match-embedded-numbers",
    ]);

    assert!(
        output.status.success(),
        "CLI should exit successfully: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be valid UTF-8"),
        "select catch22, rt_5min\n"
    );
}

#[test]
fn match_md5_checksums_option_replaces_checksum_as_one_value() {
    let output = run_cli(&[
        "--query",
        "SELECT file_fbc5e685a5d3d45aa1d0347fdb7c4d35 FROM artifacts",
        "--match-md5-checksums",
    ]);

    assert!(
        output.status.success(),
        "CLI should exit successfully: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be valid UTF-8"),
        "select file_? from artifacts\n"
    );
}
