# sql-fingerprint-rs

Turn SQL queries into fingerprints: a normalized form where literals become `?`,
whitespace is collapsed, and keywords are lowercased. Queries that differ only in
their values then compare equal.

## Why this exists

This crate was written to fingerprint slow query logs in AWS Lambda.

The reference implementation is Percona Toolkit's
[`pt-fingerprint`](https://github.com/percona/percona-toolkit), but it is a Perl
program. Lambda's managed runtimes do not ship Perl, so running `pt-fingerprint`
there means building and maintaining a container image with Perl and its database
dependencies.

This crate performs the same transformation in Rust and compiles to a single
native binary. That binary can be shipped in a Lambda Layer and called from
Python or Node.js with `subprocess` / `child_process`, or used on its own as a
CLI. Rust callers can use the library API directly.

The behaviour is tuned for **MySQL**, matching `pt-fingerprint`. It is a
best-effort string transformation, not a SQL parser: it does not validate syntax
and does not try to interpret PostgreSQL or Oracle dialects.

## Example

Given these two queries:

```sql
SELECT name, password FROM user WHERE id = '12823';
select name,   password from user
   where id = 5;
```

both produce:

```sql
select name, password from user where id = ?
```

## Usage

### CLI

```sh
cargo install sql-fingerprint-rs

sql-fingerprint-rs --query "SELECT * FROM users WHERE id = 42"
sql-fingerprint-rs queries.sql
cat queries.sql | sql-fingerprint-rs
```

### Library

```rust
use sql_fingerprint_rs::{FingerprintOptions, Fingerprinter};

let options = FingerprintOptions::default().with_match_embedded_numbers(true);
let fingerprinter = Fingerprinter::new(options);

assert_eq!(
    fingerprinter.fingerprint("SELECT catch22, id FROM users WHERE id = 42"),
    "select catch22, id from users where id = ?"
);
```

### Lambda (Python / Node.js)

Place the binary in a Lambda Layer, for example at
`/opt/bin/sql-fingerprint-rs`, and invoke it without a shell.

```python
import subprocess

result = subprocess.run(
    ["/opt/bin/sql-fingerprint-rs", "--query", query],
    capture_output=True,
    text=True,
    check=True,
    timeout=5,
)
fingerprint = result.stdout.rstrip("\n")
```

```js
import { execFileSync } from "node:child_process";

const fingerprint = execFileSync(
  "/opt/bin/sql-fingerprint-rs",
  ["--query", query],
  { encoding: "utf8", timeout: 5000 },
).trimEnd();
```

Native bindings for Python (PyO3) and Node.js (napi-rs) can be added later if the
per-invocation process startup does not meet the latency requirement.

## Options

- `--match-md5-checksums`: replace a lowercase 32-character MD5 checksum with a
  single `?`.
- `--match-embedded-numbers`: preserve numbers embedded in identifiers, such as
  `catch22` or `rt_5min`.

## Compatibility

The behavior follows `QueryRewriter::fingerprint()` from Percona Toolkit
`pt-fingerprint` 3.7.1-4. The fingerprint is not guaranteed to be valid SQL, and
this is not a masking tool: it does not guarantee that every sensitive value is
removed.

## References

- Percona Toolkit [`pt-fingerprint`](https://github.com/percona/percona-toolkit)
- [`cou929/sql-fingerprint-js`](https://github.com/cou929/sql-fingerprint-js)

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
