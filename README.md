# sql-fingerprint-rs

Turn SQL queries into fingerprints: a normalized form where literals become `?`,
whitespace is collapsed, and keywords are lowercased. Queries that differ only in
their values then compare equal.

The behavior follows `pt-fingerprint` and is tuned for **MySQL**. It is a
best-effort string transformation, not a SQL parser, and does not validate syntax.

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

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
