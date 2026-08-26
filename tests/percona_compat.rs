use sql_fingerprint::{FingerprintOptions, Fingerprinter, fingerprint};

#[test]
fn empty_query_returns_empty_string() {
    let actual = fingerprint("");

    assert_eq!(actual, "");
}

#[test]
fn query_without_changes_is_unchanged() {
    let query = "select name from users;";
    let actual = fingerprint(query);

    assert_eq!(actual, query);
}

#[test]
fn query_is_lowercased() {
    let query = "SELECT NAME FROM USERS;";
    let actual = fingerprint(query);
    let expected = "select name from users;";

    assert_eq!(actual, expected);
}

#[test]
fn consecutive_whitespace_is_collapsed() {
    let query = "SELECT   NAME \n FROM\tUSERS;";
    let actual = fingerprint(query);
    let expected = "select name from users;";

    assert_eq!(actual, expected);
}

#[test]
fn leading_supported_whitespace_is_removed() {
    let query = "\t\n\r\x0c  SELECT NAME FROM USERS;";
    let actual = fingerprint(query);
    let expected = "select name from users;";

    assert_eq!(actual, expected);
}

#[test]
fn trailing_newline_is_removed() {
    let query = "SELECT NAME FROM USERS;\n";
    let actual = fingerprint(query);
    let expected = "select name from users;";

    assert_eq!(actual, expected);
}

#[test]
fn trailing_spaces_are_collapsed_but_preserved() {
    let query = "SELECT NAME FROM USERS;   ";
    let actual = fingerprint(query);
    let expected = "select name from users; ";

    assert_eq!(actual, expected);
}

#[test]
fn trailing_carriage_return_is_collapsed_to_space() {
    let query = "SELECT NAME FROM USERS;\r\n";
    let actual = fingerprint(query);
    let expected = "select name from users; ";

    assert_eq!(actual, expected);
}

#[test]
fn non_ascii_characters_are_not_lowercased() {
    let query = "SELECT Ä, 名前 FROM USERS;";
    let actual = fingerprint(query);
    let expected = "select Ä, 名前 from users;";

    assert_eq!(actual, expected);
}

#[test]
fn integer_literals_are_replaced() {
    let query = "SELECT NAME, AGE FROM USERS WHERE id = 42;";
    let actual = fingerprint(query);
    let expected = "select name, age from users where id = ?;";

    assert_eq!(actual, expected);
}

#[test]
fn floating_point_literals_are_replaced() {
    let query = "select 0e0, +6e-30, -6.00 from foo where a = 5.5 or b=0.5 or c=.5";
    let actual = fingerprint(query);
    let expected = "select ?, ?, ? from foo where a = ? or b=? or c=?";

    assert_eq!(actual, expected);
}

#[test]
fn mysqldump_selects_are_grouped() {
    let query = "SELECT /*!40001 SQL_NO_CACHE */ * FROM `film`";
    let actual = fingerprint(query);
    let expected = "mysqldump";

    assert_eq!(actual, expected);
}

#[test]
fn lowercase_mysqldump_select_is_not_grouped() {
    let query = "select /*!40001 SQL_NO_CACHE */ * FROM `film`";
    let actual = fingerprint(query);
    let expected = "select /*!? sql_no_cache */ * from `film`";

    assert_eq!(actual, expected);
}

#[test]
fn mysqldump_select_with_leading_whitespace_is_not_grouped() {
    let query = " SELECT /*!40001 SQL_NO_CACHE */ * FROM `film`";
    let actual = fingerprint(query);
    let expected = "select /*!? sql_no_cache */ * from `film`";

    assert_eq!(actual, expected);
}

#[test]
fn percona_checksum_queries_are_grouped() {
    let query = "REPLACE /*foo.bar:3/3*/ INTO checksum.checksum (db, tbl) VALUES ('foo', 'bar')";
    let actual = fingerprint(query);
    let expected = "percona-toolkit";

    assert_eq!(actual, expected);
}

#[test]
fn administrator_commands_are_returned_unchanged() {
    let query = "administrator command: Init DB";
    let actual = fingerprint(query);
    let expected = query;

    assert_eq!(actual, expected);
}

#[test]
fn call_statements_are_reduced_to_the_procedure_name() {
    let query = "  CALL MyProcedure(1, 2)";
    let actual = fingerprint(query);
    let expected = "call myprocedure";

    assert_eq!(actual, expected);
}

#[test]
fn multi_value_inserts_are_shortened_to_the_first_value_list() {
    let query = "INSERT INTO users (id, age) VALUES (1, 20), (NOW(), 30)";
    let actual = fingerprint(query);
    let expected = "insert into users (id, age) values(?+)";

    assert_eq!(actual, expected);
}

#[test]
fn multi_value_query_variants_are_shortened_to_the_first_value_list() {
    let cases = [
        (
            "REPLACE INTO users (id) VALUES (1), (2)",
            "replace into users (id) values(?+)",
        ),
        (
            "INSERT IGNORE INTO users (id) VALUES (1), (2)",
            "insert ignore into users (id) values(?+)",
        ),
        (
            "INSERT INTO users (id)\nVALUES (1),\n(2)",
            "insert into users (id) values(?+)",
        ),
    ];

    for (query, expected) in cases {
        let actual = fingerprint(query);

        assert_eq!(actual, expected, "query: {query}");
    }
}

#[test]
fn block_comments_are_removed() {
    let query = "SELECT 1 /* secret 234 */ FROM users";
    let actual = fingerprint(query);
    let expected = "select ? from users";

    assert_eq!(actual, expected);
}

#[test]
fn block_comment_boundaries_match_percona() {
    let cases = [
        (
            "SHOW /*!50002 GLOBAL */ STATUS",
            "show /*!? global */ status",
        ),
        (
            "SELECT 1 /* secret\n234 */ FROM users",
            "select ? from users",
        ),
        ("SELECT 1 /* Secret 234", "select ? /* secret ?"),
    ];

    for (query, expected) in cases {
        let actual = fingerprint(query);

        assert_eq!(actual, expected, "query: {query}");
    }
}

#[test]
fn line_comments_are_removed() {
    let cases = [
        ("SELECT 1 -- secret 234\nFROM users", "select ? from users"),
        ("SELECT 1 # secret 234\nFROM users", "select ? from users"),
    ];

    for (query, expected) in cases {
        let actual = fingerprint(query);

        assert_eq!(actual, expected, "query: {query}");
    }
}

#[test]
fn line_comment_boundaries_match_percona() {
    let cases = [
        ("SELECT 1-- secret 234", "select ?"),
        (
            "SELECT 1 -- first\nFROM users # second\nWHERE id = 2",
            "select ? from users where id = ?",
        ),
        (
            "SELECT 1 -- secret '\nFROM users",
            "select ? ? secret ' from users",
        ),
        ("SELECT 1 -- secret\r\nFROM users", "select ? from users"),
    ];

    for (query, expected) in cases {
        let actual = fingerprint(query);

        assert_eq!(actual, expected, "query: {query}");
    }
}

#[test]
fn use_statements_are_reduced_to_a_placeholder() {
    let query = "USE Production";
    let actual = fingerprint(query);
    let expected = "use ?";

    assert_eq!(actual, expected);
}

#[test]
fn use_statement_boundaries_match_percona() {
    let cases = [
        ("USE Production\n", "use ?\n"),
        (" USE Production", "use production"),
        ("USE  Production", "use production"),
        ("USE Production ", "use production "),
        ("USE Production;", "use ?"),
    ];

    for (query, expected) in cases {
        let actual = fingerprint(query);

        assert_eq!(actual, expected, "query: {query:?}");
    }
}

#[test]
fn quoted_strings_and_backslash_escapes_are_replaced() {
    let cases = [
        (r#"SELECT 'hello', "world""#, "select ?, ?"),
        (r#"SELECT 'it\'s', "a\"b""#, "select ?, ?"),
        (r"SELECT '\\', 'x'", "select ?, ?"),
    ];

    for (query, expected) in cases {
        let actual = fingerprint(query);

        assert_eq!(actual, expected, "query: {query:?}");
    }
}

#[test]
fn boolean_literals_are_replaced() {
    let query = "SELECT * FROM users WHERE active = TRUE OR deleted = false";
    let actual = fingerprint(query);
    let expected = "select * from users where active = ? or deleted = ?";

    assert_eq!(actual, expected);
}

#[test]
fn boolean_names_inside_identifiers_are_not_replaced() {
    let query = "SELECT true_value, untrue, falsehood, is_false FROM flags";
    let actual = fingerprint(query);
    let expected = "select true_value, untrue, falsehood, is_false from flags";

    assert_eq!(actual, expected);
}

#[test]
fn default_fingerprinter_matches_the_convenience_function() {
    let query = "SELECT 42";
    let options = FingerprintOptions::default();
    let fingerprinter = Fingerprinter::new(options);

    assert_eq!(fingerprinter.fingerprint(query), fingerprint(query));
}

#[test]
fn embedded_numbers_can_be_preserved() {
    let query = "SELECT catch22, rt_5min";
    let options = FingerprintOptions::default().with_match_embedded_numbers(true);
    let fingerprinter = Fingerprinter::new(options);
    let actual = fingerprinter.fingerprint(query);
    let expected = "select catch22, rt_5min";

    assert_eq!(actual, expected);
}

#[test]
fn md5_checksums_can_be_matched_as_single_values() {
    let query = "SELECT file_fbc5e685a5d3d45aa1d0347fdb7c4d35 FROM artifacts";

    assert_eq!(
        fingerprint(query),
        "select file_fbc? from artifacts",
        "default options"
    );

    let options = FingerprintOptions::default().with_match_md5_checksums(true);
    let fingerprinter = Fingerprinter::new(options);

    assert_eq!(
        fingerprinter.fingerprint(query),
        "select file_? from artifacts",
        "MD5 matching enabled"
    );
}

#[test]
fn md5_checksum_boundaries_match_percona() {
    let options = FingerprintOptions::default().with_match_md5_checksums(true);
    let fingerprinter = Fingerprinter::new(options);
    let cases = [
        (
            "SELECT file.fbc5e685a5d3d45aa1d0347fdb7c4d35 FROM artifacts",
            "select file.? from artifacts",
        ),
        (
            "SELECT file-fbc5e685a5d3d45aa1d0347fdb7c4d35 FROM artifacts",
            "select file?? from artifacts",
        ),
        (
            "SELECT file_fbc5e685a5d3d45aa1d0347fdb7c4d3 FROM artifacts",
            "select file_fbc? from artifacts",
        ),
        (
            "SELECT fbc5e685a5d3d45aa1d0347fdb7c4d35 FROM artifacts",
            "select fbc? from artifacts",
        ),
    ];

    for (query, expected) in cases {
        let actual = fingerprinter.fingerprint(query);

        assert_eq!(actual, expected, "query: {query}");
    }
}

#[test]
fn null_literals_are_replaced_after_lowercasing() {
    let query = "SELECT NULL, null, nullable FROM users WHERE deleted_at IS NULL";
    let actual = fingerprint(query);
    let expected = "select ?, ?, nullable from users where deleted_at is ?";

    assert_eq!(actual, expected);
}

#[test]
fn in_and_values_lists_are_collapsed() {
    let cases = [
        (
            "SELECT * FROM users WHERE id IN (1, 2, 3)",
            "select * from users where id in(?+)",
        ),
        (
            "INSERT INTO users (id, name) VALUES (1, 'Alice')",
            "insert into users (id, name) values(?+)",
        ),
    ];

    for (query, expected) in cases {
        let actual = fingerprint(query);

        assert_eq!(actual, expected, "query: {query}");
    }
}
