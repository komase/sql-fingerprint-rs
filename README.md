# sql-fingerprint-rs

Converts a SQL statement into a fingerprint, the abstracted form of a query, so
that queries which differ only in literals can be grouped together.

This crate is a Rust port of Percona Toolkit's
[`pt-fingerprint`](https://github.com/percona/percona-toolkit). It is therefore
primarily intended for **MySQL** queries. It is a string transformation, not a
SQL parser, so it does not validate syntax and does not try to interpret
PostgreSQL or Oracle dialects.

## Description

A fingerprint is the abstracted form of a query: literals are replaced with
`?`, whitespace is collapsed, and so on. For example, these two queries

```sql
SELECT name, password FROM user WHERE id = '12823';
select name,   password from user
   where id = 5;
```

both fingerprint to:

```sql
select name, password from user where id = ?
```

## Usage

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

### CLI

```sh
cargo install sql-fingerprint-rs

sql-fingerprint-rs --query "SELECT * FROM users WHERE id = 42"
sql-fingerprint-rs queries.sql
cat queries.sql | sql-fingerprint-rs
```

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
