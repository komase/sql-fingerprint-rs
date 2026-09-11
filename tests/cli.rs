use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TempInput {
    path: PathBuf,
}

impl TempInput {
    fn new(contents: &str) -> Self {
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sql-fingerprint-cli-{}-{sequence}.sql",
            std::process::id()
        ));
        fs::write(&path, contents).expect("temporary SQL file should be writable");

        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempInput {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn run_cli(args: &[&str]) -> Output {
    // Cargo provides the path to the package binary for integration tests.
    let binary = env!("CARGO_BIN_EXE_sql-fingerprint");
    Command::new(binary)
        .args(args)
        .output()
        .expect("CLI process should start")
}

fn run_cli_with_stdin(args: &[&str], input: &str) -> Output {
    let binary = env!("CARGO_BIN_EXE_sql-fingerprint");
    let mut child = Command::new(binary)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("CLI process should start");

    {
        let mut stdin = child.stdin.take().expect("stdin pipe should be available");
        stdin
            .write_all(input.as_bytes())
            .expect("SQL input should be writable");
    }

    child.wait_with_output().expect("CLI process should finish")
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

#[test]
fn file_argument_prints_each_fingerprint() {
    // File input uses Percona's exact ";\n" record separator and removes it.
    let input = TempInput::new(
        "SELECT * FROM users WHERE id = 42;\nUPDATE users SET active = true WHERE id = 7;\n",
    );
    let input_path = input
        .path()
        .to_str()
        .expect("temporary SQL file path should be valid UTF-8");
    let output = run_cli(&[input_path]);

    assert!(
        output.status.success(),
        "CLI should exit successfully: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be valid UTF-8"),
        "select * from users where id = ?\nupdate users set active = ? where id = ?\n"
    );
    assert!(
        output.stderr.is_empty(),
        "stderr should be empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn standard_input_prints_each_fingerprint() {
    // Closing the stdin pipe after writing signals EOF to the CLI.
    let output = run_cli_with_stdin(
        &[],
        "SELECT * FROM users WHERE id = 42;\nDELETE FROM users WHERE id = 7;\n",
    );

    assert!(
        output.status.success(),
        "CLI should exit successfully: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be valid UTF-8"),
        "select * from users where id = ?\ndelete from users where id = ?\n"
    );
    assert!(
        output.stderr.is_empty(),
        "stderr should be empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn dash_file_argument_reads_standard_input() {
    // A dash in the file list selects stdin at that exact input position.
    let output = run_cli_with_stdin(&["-"], "SELECT * FROM users WHERE id = 42;\n");

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
fn multiple_files_are_processed_in_argument_order() {
    // Each file contains one complete record so output order identifies input order.
    let first = TempInput::new("SELECT * FROM first_table WHERE id = 1;\n");
    let second = TempInput::new("SELECT * FROM second_table WHERE id = 2;\n");
    let first_path = first
        .path()
        .to_str()
        .expect("first temporary SQL file path should be valid UTF-8");
    let second_path = second
        .path()
        .to_str()
        .expect("second temporary SQL file path should be valid UTF-8");
    let output = run_cli(&[first_path, second_path]);

    assert!(
        output.status.success(),
        "CLI should exit successfully: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be valid UTF-8"),
        "select * from first_table where id = ?\nselect * from second_table where id = ?\n"
    );
    assert!(
        output.stderr.is_empty(),
        "stderr should be empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn query_and_file_arguments_are_rejected() {
    // Direct query input and stream input have different preprocessing rules.
    let input = TempInput::new("SELECT * FROM files;\n");
    let input_path = input
        .path()
        .to_str()
        .expect("temporary SQL file path should be valid UTF-8");
    let output = run_cli(&["--query", "SELECT * FROM direct_query", input_path]);
    let stderr = String::from_utf8(output.stderr).expect("stderr should be valid UTF-8");

    assert!(!output.status.success(), "CLI should reject mixed inputs");
    assert!(output.stdout.is_empty(), "stdout should be empty");
    assert!(
        stderr.contains("cannot be used with") && stderr.contains("--query"),
        "stderr should describe the argument conflict: {stderr}"
    );
}

#[test]
fn stream_input_removes_content_bearing_hash_lines_before_fingerprinting() {
    // CLI preprocessing removes metadata lines even when they contain quotes.
    let output = run_cli_with_stdin(
        &[],
        "# Time: 'quoted metadata'\nSELECT * FROM users WHERE id = 42;\n",
    );

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
fn stream_input_skips_records_without_an_ascii_word_prefix() {
    // Filtering happens after leading whitespace is removed from each record.
    let output = run_cli_with_stdin(
        &[],
        " \t/* metadata */ SELECT * FROM skipped_comment;\n ÄSELECT * FROM skipped_unicode;\n \tSELECT * FROM kept WHERE id = 1;\n",
    );

    assert!(
        output.status.success(),
        "CLI should exit successfully: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be valid UTF-8"),
        "select * from kept where id = ?\n"
    );
    assert!(
        output.stderr.is_empty(),
        "stderr should be empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn query_argument_bypasses_stream_preprocessing() {
    // Direct queries preserve input that stream preprocessing would discard.
    let output = run_cli(&[
        "--query",
        "# Time: 'quoted metadata'\nSELECT * FROM users WHERE id = 42",
    ]);

    assert!(
        output.status.success(),
        "CLI should exit successfully: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be valid UTF-8"),
        "# time: ? select * from users where id = ?\n"
    );
    assert!(
        output.stderr.is_empty(),
        "stderr should be empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn missing_file_reports_its_path() {
    let input = TempInput::new("");
    let missing_path = input.path().to_path_buf();
    drop(input);
    let missing_path = missing_path
        .to_str()
        .expect("temporary SQL file path should be valid UTF-8");
    let output = run_cli(&[missing_path]);
    let stderr = String::from_utf8(output.stderr).expect("stderr should be valid UTF-8");

    assert!(!output.status.success(), "CLI should report file errors");
    assert!(output.stdout.is_empty(), "stdout should be empty");
    assert!(
        stderr.contains(missing_path),
        "stderr should identify the missing file: {stderr}"
    );
}

#[test]
fn final_record_without_separator_is_processed_at_eof() {
    // Percona processes a final partial record even without the ";\n" separator.
    let output = run_cli_with_stdin(&[], "SELECT * FROM users WHERE id = 42");

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
fn empty_stream_records_are_skipped() {
    let output = run_cli_with_stdin(&[], ";\n \t;\nSELECT 1;\n");

    assert!(
        output.status.success(),
        "CLI should exit successfully: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be valid UTF-8"),
        "select ?\n"
    );
    assert!(
        output.stderr.is_empty(),
        "stderr should be empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn help_option_describes_cli_inputs() {
    let output = run_cli(&["--help"]);
    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");

    assert!(
        output.status.success(),
        "CLI should exit successfully: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("Usage:"), "help should contain usage");
    assert!(
        stdout.contains("--query"),
        "help should describe direct input"
    );
    assert!(
        stdout.contains("--match-embedded-numbers"),
        "help should describe matching options"
    );
    assert!(
        output.stderr.is_empty(),
        "stderr should be empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn version_option_prints_package_version() {
    let output = run_cli(&["--version"]);

    assert!(
        output.status.success(),
        "CLI should exit successfully: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout should be valid UTF-8"),
        format!("sql-fingerprint {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(
        output.stderr.is_empty(),
        "stderr should be empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
