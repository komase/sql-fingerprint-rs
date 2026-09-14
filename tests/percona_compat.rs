use sql_fingerprint_rs::{FingerprintOptions, Fingerprinter, fingerprint};

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

#[test]
fn repeated_unions_are_collapsed() {
    let cases = [
        (
            "SELECT a FROM t UNION SELECT a FROM t",
            "select a from t /*repeat union*/",
        ),
        (
            "SELECT a FROM t UNION ALL SELECT a FROM t",
            "select a from t /*repeat union all*/",
        ),
        (
            "SELECT a FROM t UNION SELECT a FROM t UNION SELECT a FROM t",
            "select a from t /*repeat union*/",
        ),
        (
            "SELECT a FROM t UNION SELECT a FROM t UNION ALL SELECT a FROM t",
            "select a from t /*repeat union all*/",
        ),
    ];

    for (query, expected) in cases {
        let actual = fingerprint(query);

        assert_eq!(actual, expected, "query: {query}");
    }
}

#[test]
fn repeated_union_candidates_containing_unions_are_collapsed() {
    // A UNION inside the repeated candidate must not be processed again after
    // the complete candidate has already been consumed.
    let query = "SELECT a UNION ALL SELECT b UNION SELECT a UNION ALL SELECT b";
    let expected = "select a union all select b /*repeat union*/";

    let actual = fingerprint(query);

    assert_eq!(actual, expected);
}

#[test]
fn multi_select_union_sequences_repeated_three_times_are_collapsed() {
    // A multi-SELECT candidate may repeat more than once, and the final
    // separator determines the marker's UNION variant.
    let query = "SELECT a UNION ALL SELECT b \
                 UNION SELECT a UNION ALL SELECT b \
                 UNION ALL SELECT a UNION ALL SELECT b";
    let expected = "select a union all select b /*repeat union all*/";

    let actual = fingerprint(query);

    assert_eq!(actual, expected);
}

#[test]
fn repeated_union_sequences_preserve_grouping_semantics() {
    let cases = [
        (
            // Only the repeated suffix is collapsed when an unrelated branch
            // precedes a multi-SELECT candidate.
            "SELECT prefix_value FROM t \
             UNION SELECT a UNION ALL SELECT b \
             UNION SELECT a UNION ALL SELECT b",
            "select prefix_value from t union select a union all select b /*repeat union*/",
        ),
        (
            // The separator between copies is independent of UNION operators
            // contained inside the repeated candidate.
            "SELECT a UNION SELECT b UNION ALL SELECT a UNION SELECT b",
            "select a union select b /*repeat union all*/",
        ),
        (
            // Nested UNIONs remain part of the repeated outer SELECT.
            "SELECT * FROM (SELECT a UNION SELECT b) x \
             UNION SELECT * FROM (SELECT a UNION SELECT b) x",
            "select * from (select a union select b) x /*repeat union*/",
        ),
    ];

    for (query, expected) in cases {
        let actual = fingerprint(query);

        assert_eq!(actual, expected, "query: {query}");
    }
}

#[test]
fn non_repeated_unions_are_preserved() {
    let cases = [
        (
            "SELECT a FROM t UNION SELECT b FROM t",
            "select a from t union select b from t",
        ),
        (
            "DELETE FROM t UNION DELETE FROM t",
            "delete from t union delete from t",
        ),
        (
            // Similar SELECT sequences are not repeats when an internal UNION
            // operator differs.
            "SELECT a UNION SELECT b UNION SELECT a UNION ALL SELECT b",
            "select a union select b union select a union all select b",
        ),
    ];

    for (query, expected) in cases {
        let actual = fingerprint(query);

        assert_eq!(actual, expected, "query: {query}");
    }
}

#[test]
fn repeated_unions_after_a_query_prefix_are_collapsed() {
    let query = "EXPLAIN SELECT a FROM t UNION SELECT a FROM t";
    let actual = fingerprint(query);
    let expected = "explain select a from t /*repeat union*/";

    assert_eq!(actual, expected);
}

#[test]
fn repeated_unions_after_a_different_branch_are_collapsed() {
    let query = "SELECT a FROM t UNION SELECT b FROM t UNION SELECT b FROM t";
    let actual = fingerprint(query);
    let expected = "select a from t union select b from t /*repeat union*/";

    assert_eq!(actual, expected);
}

#[test]
fn repeated_union_uses_the_leftmost_select_anchor() {
    // Perl anchors on the leftmost `select` and expands the shortest candidate
    // that repeats. A `select` appearing later in the same branch must not win
    // just because it is a prefix of the candidate Perl chooses.
    let cases = [
        (
            "select 1 union select a union select a, b \
             union select 1 union select a union select a, b",
            "select ? union select a union select a, b /*repeat union*/",
        ),
        (
            "select b Union All select a union select b UNION select a \
             union select b union all select a union select b union select a \
             union select b union select a from t",
            "select b union all select a union select b union select a /*repeat union*/ \
             union select b union select a from t",
        ),
    ];

    for (query, expected) in cases {
        let actual = fingerprint(query);

        assert_eq!(actual, expected, "query: {query}");
    }
}

#[test]
fn union_anchor_must_include_the_select_keyword() {
    // The repeated unit always contains `select ` with its trailing whitespace.
    // `select union select a` has only one whitespace between the leading SELECT
    // and UNION, so Perl cannot capture a repeat and leaves the query unchanged.
    let query = "select union select a";
    let actual = fingerprint(query);

    assert_eq!(actual, query);
}

#[test]
fn select_prefixes_are_not_treated_as_select_statements() {
    let query = "selection UNION selection";
    let actual = fingerprint(query);
    let expected = "selection union selection";

    assert_eq!(actual, expected);
}

#[test]
fn limit_clauses_are_reduced_to_a_single_placeholder() {
    let cases = [
        ("SELECT * FROM t LIMIT 10", "select * from t limit ?"),
        ("SELECT * FROM t LIMIT 10, 20", "select * from t limit ?"),
        ("SELECT * FROM t LIMIT 10,20", "select * from t limit ?"),
        (
            "SELECT * FROM t LIMIT 10 OFFSET 20",
            "select * from t limit ?",
        ),
    ];

    for (query, expected) in cases {
        let actual = fingerprint(query);

        assert_eq!(actual, expected, "query: {query}");
    }
}

#[test]
fn ascending_order_markers_after_order_by_are_removed() {
    let cases = [
        (
            "SELECT * FROM t ORDER BY name ASC",
            "select * from t order by name",
        ),
        (
            "SELECT * FROM t ORDER BY last_name ASC, first_name ASC",
            "select * from t order by last_name, first_name",
        ),
        (
            "SELECT * FROM t ORDER BY created_at DESC, name ASC",
            "select * from t order by created_at desc, name",
        ),
        ("SELECT ASC FROM t", "select asc from t"),
    ];

    for (query, expected) in cases {
        let actual = fingerprint(query);

        assert_eq!(actual, expected, "query: {query}");
    }
}

#[test]
fn numeric_literal_boundaries_match_percona() {
    let cases = [
        ("SELECT 1e10, 1E10", "select ?, ?e?"),
        ("SELECT -1.2e+3, -1.2E+3", "select ?, ?e?"),
        ("SELECT 0xff, 0xFF", "select ?, ?ff"),
        ("SELECT b'101', B'101', x'0f', X'0F'", "select ?, b?, ?, x?"),
    ];

    for (query, expected) in cases {
        let actual = fingerprint(query);

        assert_eq!(actual, expected, "query: {query}");
    }
}

#[test]
fn quoted_literal_boundaries_match_percona() {
    let cases = [
        ("SELECT '' AS empty_value", "select ? as empty_value"),
        ("SELECT 'a''b' AS value", "select ?'b' as value"),
        ("SELECT 'a' 'b' AS value", "select ? ? as value"),
        ("SELECT 'unterminated", "select 'unterminated"),
        ("SELECT \"unterminated", "select \"unterminated"),
    ];

    for (query, expected) in cases {
        let actual = fingerprint(query);

        assert_eq!(actual, expected, "query: {query}");
    }
}

#[test]
fn basic_write_statements_are_fingerprinted() {
    let cases = [
        (
            "INSERT INTO audit (message, created_at) VALUES ('login', '2026-09-01')",
            "insert into audit (message, created_at) values(?+)",
        ),
        (
            "UPDATE users SET name = 'Alice', age = 42 WHERE id = 7",
            "update users set name = ?, age = ? where id = ?",
        ),
        (
            "DELETE FROM users WHERE id IN (1, 2, 3)",
            "delete from users where id in(?+)",
        ),
    ];

    for (query, expected) in cases {
        let actual = fingerprint(query);

        assert_eq!(actual, expected, "query: {query}");
    }
}

#[test]
fn ascii_word_boundaries_match_percona() {
    let cases = [
        ("SELECT étrue, éfalse, éNULL", "select é?, é?, é?"),
        ("SELECT 名前true, 名前NULL", "select 名前?, 名前?"),
        ("SELECT true値, NULL値", "select ?値, ?値"),
        ("SELECT éIN (1, 2)", "select éin(?+)"),
        ("éSELECT a UNION SELECT a", "éselect a /*repeat union*/"),
        ("SELECT * FROM t éLIMIT 1, 2", "select * from t élimit ?"),
        (
            "SELECT * FROM t éORDER BY name ASC",
            "select * from t éorder by name",
        ),
    ];

    for (query, expected) in cases {
        let actual = fingerprint(query);

        assert_eq!(actual, expected, "query: {query}");
    }
}
