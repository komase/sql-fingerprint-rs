#![warn(missing_docs)]

//! Percona-compatible SQL query fingerprinting.
//!
//! This crate normalizes SQL text so structurally similar queries can be
//! grouped together. It follows the fingerprinting behavior of Percona
//! Toolkit's `pt-fingerprint`; it is not a SQL parser and does not guarantee
//! that every sensitive value is removed.

use regex::Regex;
use std::{borrow::Cow, sync::LazyLock};

macro_rules! static_regex {
    ($name:ident,$pattern:literal) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new($pattern).expect(concat!(stringify!($name), " must be a valid regex"))
        });
    };
}

static_regex!(NUMBER_RE, r"[0-9+-][0-9a-f.xb+-]*");
static_regex!(
    NUMBER_WITH_WORD_BOUNDARY_RE,
    r"(?-u:\b)[0-9+-][0-9a-f.xb+-]*"
);
static_regex!(MD5_RE, r"([._-])[a-f0-9]{32}");
static_regex!(NUMBER_LEFTOVER_RE, r"[xb.+-]\?");
static_regex!(NUMBER_LEFTOVER_WITH_MD5_RE, r"[xb+-]\?");
static_regex!(
    PERCONA_CHECKSUM_RE,
    r"/\*[A-Za-z0-9_]+\.[A-Za-z0-9_]+:[0-9]/[0-9]\*/"
);
static_regex!(CALL_RE, r"(?i)^\s*(call\s+\S+)\(");
static_regex!(
    VALUES_RE,
    r"(?is)^((?:INSERT|REPLACE)(?: IGNORE)?\s+INTO.+?VALUES\s*\(.*?\))\s*,\s*\("
);
static_regex!(BLOCK_COMMENT_RE, r"(?s)/\*[^!].*?\*/");
static_regex!(USE_RE, r"(?i)\Ause \S+(?:\n)?\z");
static_regex!(PREFIXED_ESCAPED_SINGLE_QUOTE_RE, r"([^\\])(\\')");
static_regex!(PREFIXED_ESCAPED_DOUBLE_QUOTE_RE, r#"([^\\])(\\")"#);
static_regex!(DOUBLE_BACKSLASH_RE, r"\\\\");
static_regex!(ESCAPED_SINGLE_QUOTE_RE, r"\\'");
static_regex!(ESCAPED_DOUBLE_QUOTE_RE, r#"\\""#);
static_regex!(DOUBLE_QUOTED_LITERAL_RE, r#"(?s)([^\\])(".*?[^\\]?")"#);
static_regex!(SINGLE_QUOTED_LITERAL_RE, r"(?s)([^\\])('.*?[^\\]?')");
static_regex!(BOOLEAN_RE, r"(?i)(?-u:\b)(?:false|true)(?-u:\b)");
static_regex!(NULL_RE, r"(?-u:\b)null(?-u:\b)");
static_regex!(LIST_RE, r"(?-u:\b)(in|values?)(?:[\s,]*\([\s?,]*\))+");
static_regex!(UNION_RE, r" union(?: all)? ");
static_regex!(SELECT_RE, r"(?-u:\b)select ");
static_regex!(LIMIT_RE, r"(?-u:\b)limit \?(?:, ?\?| offset \?)?");
static_regex!(ORDER_BY_RE, r"(?-u:\b)order by ");

fn is_mysqldump(query: &str) -> bool {
    query.starts_with("SELECT /*!40001 SQL_NO_CACHE */ * FROM `")
}

fn is_percona_checksum(query: &str) -> bool {
    PERCONA_CHECKSUM_RE.is_match(query)
}

fn is_admin_command(query: &str) -> bool {
    query.starts_with("administrator command: ")
}

fn call_fingerprint(query: &str) -> Option<String> {
    let captures = CALL_RE.captures(query)?;
    let matched = captures.get(1)?;
    Some(matched.as_str().to_ascii_lowercase())
}

fn shorten_multi_value_query(query: &str) -> Option<&str> {
    let captures = VALUES_RE.captures(query)?;
    let matched = captures.get(1)?;
    Some(matched.as_str())
}

fn is_collapsible_whitespace(character: char) -> bool {
    matches!(character, ' ' | '\n' | '\t' | '\r' | '\x0c')
}

fn use_fingerprint(query: &str) -> Option<String> {
    if !USE_RE.is_match(query) {
        return None;
    }

    if query.ends_with('\n') {
        Some("use ?\n".to_string())
    } else {
        Some("use ?".to_string())
    }
}

// Collapse each run of supported whitespace into one ASCII space.
fn collapse_supported_whitespace(query: &str) -> String {
    let mut collapsed = String::with_capacity(query.len());
    let mut previous_was_whitespace = false;

    for character in query.chars() {
        if is_collapsible_whitespace(character) {
            if !previous_was_whitespace {
                collapsed.push(' ');
                previous_was_whitespace = true;
            }
            continue;
        }
        previous_was_whitespace = false;
        collapsed.push(character);
    }
    collapsed
}

// Replace consecutive copies of the same SELECT sequence with one copy and a
// `/*repeat union...*/` marker.
fn collapse_repeated_union(query: &str) -> Cow<'_, str> {
    let separators: Vec<_> = UNION_RE.find_iter(query).collect();
    if separators.is_empty() {
        return Cow::Borrowed(query);
    }

    let mut separator_index = 0;
    let mut copy_from = 0;
    let mut rewritten: Option<String> = None;

    while separator_index < separators.len() {
        let separator = &separators[separator_index];
        // A repeated sequence can contain UNIONs, so an earlier collapse may
        // already have consumed this separator.
        if separator.start() < copy_from {
            separator_index += 1;
            continue;
        }
        let search_area = &query[copy_from..separator.start()];
        let after_separator = &query[separator.end()..];
        let mut repeated = None;

        // Find a SELECT suffix before this separator that repeats immediately
        // after it.
        for select_match in SELECT_RE.find_iter(search_area) {
            let select_start = copy_from + select_match.start();
            let candidate = &query[select_start..separator.start()];

            if after_separator.starts_with(candidate) {
                repeated = Some((select_start, candidate));
                break;
            }
        }
        let Some((select_start, candidate)) = repeated else {
            separator_index += 1;
            continue;
        };

        let mut cursor = separator.end() + candidate.len();
        let mut operator = separator.as_str().trim();
        separator_index += 1;

        // Consume further adjacent copies and retain the final UNION variant
        // for the repeat marker.
        while separator_index < separators.len() {
            let next_separator = &separators[separator_index];

            if next_separator.start() < cursor {
                separator_index += 1;
                continue;
            }
            if next_separator.start() != cursor {
                break;
            }

            let after_separator = &query[next_separator.end()..];
            if !after_separator.starts_with(candidate) {
                break;
            }
            cursor = next_separator.end() + candidate.len();
            operator = next_separator.as_str().trim();
            separator_index += 1;
        }

        let output = rewritten.get_or_insert_with(|| String::with_capacity(query.len()));
        output.push_str(&query[copy_from..select_start]);
        output.push_str(candidate);
        output.push_str(" /*repeat ");
        output.push_str(operator);
        output.push_str("*/");
        copy_from = cursor;
    }

    match rewritten {
        Some(mut rewritten) => {
            rewritten.push_str(&query[copy_from..]);
            Cow::Owned(rewritten)
        }
        None => Cow::Borrowed(query),
    }
}

// Preserve line endings and reject comment candidates containing quotes.
// Slicing occurs only at ASCII delimiters or the end of the string, which are
// always valid UTF-8 boundaries.
fn remove_line_comments(query: &str) -> Cow<'_, str> {
    let bytes = query.as_bytes();
    let mut rewritten: Option<String> = None;
    let mut copy_from = 0;
    let mut cursor = 0;

    while cursor < bytes.len() {
        let marker_len = if bytes[cursor] == b'#' {
            1
        } else if bytes[cursor] == b'-' && bytes.get(cursor + 1) == Some(&b'-') {
            2
        } else {
            cursor += 1;
            continue;
        };
        let mut end = cursor + marker_len;

        while end < bytes.len() && !matches!(bytes[end], b'\'' | b'"' | b'\r' | b'\n') {
            end += 1;
        }

        let reaches_line_end = end == bytes.len() || matches!(bytes[end], b'\r' | b'\n');

        if reaches_line_end {
            rewritten
                .get_or_insert_with(|| String::with_capacity(query.len()))
                .push_str(&query[copy_from..cursor]);
            copy_from = end;
            cursor = end;
        } else {
            cursor += 1;
        }
    }

    match rewritten {
        Some(mut rewritten) => {
            rewritten.push_str(&query[copy_from..]);
            Cow::Owned(rewritten)
        }
        None => Cow::Borrowed(query),
    }
}

fn remove_order_by_asc(query: &str) -> Cow<'_, str> {
    let Some(order_by) = ORDER_BY_RE.find(query) else {
        return Cow::Borrowed(query);
    };

    let mut search_from = order_by.end();
    let mut copy_from = 0;
    let mut rewritten: Option<String> = None;

    while let Some(relative_start) = query[search_from..].find(" asc") {
        let asc_start = search_from + relative_start;
        let output = rewritten.get_or_insert_with(|| String::with_capacity(query.len()));
        output.push_str(&query[copy_from..asc_start]);

        copy_from = asc_start + " asc".len();
        search_from = copy_from;
    }
    match rewritten {
        Some(mut rewritten) => {
            rewritten.push_str(&query[copy_from..]);
            Cow::Owned(rewritten)
        }
        None => Cow::Borrowed(query),
    }
}

/// Options that control optional fingerprint matching behavior.
///
/// All options are disabled by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FingerprintOptions {
    match_md5_checksums: bool,
    match_embedded_numbers: bool,
}

impl FingerprintOptions {
    /// Configures whether numbers embedded in identifiers are preserved.
    ///
    /// When enabled, only numbers beginning at an ASCII word boundary are
    /// replaced. For example, the number in `catch22` is preserved.
    pub fn with_match_embedded_numbers(mut self, match_embedded_numbers: bool) -> Self {
        self.match_embedded_numbers = match_embedded_numbers;
        self
    }

    /// Configures whether lowercase 32-character MD5 checksums are matched as
    /// single values.
    pub fn with_match_md5_checksums(mut self, match_md5_checksums: bool) -> Self {
        self.match_md5_checksums = match_md5_checksums;
        self
    }
}

/// A reusable SQL fingerprinter with fixed matching options.
#[derive(Debug, Clone, Default)]
pub struct Fingerprinter {
    options: FingerprintOptions,
}

impl Fingerprinter {
    /// Creates a fingerprinter with the supplied options.
    pub fn new(options: FingerprintOptions) -> Self {
        Self { options }
    }

    /// Produces a fingerprint for one SQL query.
    ///
    /// # Examples
    ///
    /// ```
    /// use sql_fingerprint::{FingerprintOptions, Fingerprinter};
    ///
    /// let options = FingerprintOptions::default()
    ///     .with_match_embedded_numbers(true);
    /// let fingerprinter = Fingerprinter::new(options);
    ///
    /// assert_eq!(
    ///     fingerprinter.fingerprint("SELECT catch22, id FROM users WHERE id = 42"),
    ///     "select catch22, id from users where id = ?"
    /// );
    /// ```
    pub fn fingerprint(&self, query: &str) -> String {
        if is_mysqldump(query) {
            return "mysqldump".to_string();
        }
        if is_percona_checksum(query) {
            return "percona-toolkit".to_string();
        }
        if is_admin_command(query) {
            return query.to_string();
        }
        if let Some(call) = call_fingerprint(query) {
            return call;
        }

        let query = shorten_multi_value_query(query).unwrap_or(query);
        let without_comments = BLOCK_COMMENT_RE.replace_all(query, "");
        let without_comments = remove_line_comments(&without_comments);
        if let Some(use_statement) = use_fingerprint(&without_comments) {
            return use_statement;
        }

        let normalized_literals =
            PREFIXED_ESCAPED_SINGLE_QUOTE_RE.replace_all(&without_comments, "${1}");
        let normalized_literals =
            PREFIXED_ESCAPED_DOUBLE_QUOTE_RE.replace_all(&normalized_literals, "${1}");
        let normalized_literals = DOUBLE_BACKSLASH_RE.replace_all(&normalized_literals, "");
        let normalized_literals = ESCAPED_SINGLE_QUOTE_RE.replace_all(&normalized_literals, "");
        let normalized_literals = ESCAPED_DOUBLE_QUOTE_RE.replace_all(&normalized_literals, "");
        let normalized_literals =
            DOUBLE_QUOTED_LITERAL_RE.replace_all(&normalized_literals, "${1}?");
        let normalized_literals =
            SINGLE_QUOTED_LITERAL_RE.replace_all(&normalized_literals, "${1}?");
        let normalized_literals = BOOLEAN_RE.replace_all(&normalized_literals, "?");

        let normalized_checksums = if self.options.match_md5_checksums {
            MD5_RE.replace_all(&normalized_literals, "${1}?")
        } else {
            Cow::Borrowed(normalized_literals.as_ref())
        };
        let normalized_numbers = if self.options.match_embedded_numbers {
            NUMBER_WITH_WORD_BOUNDARY_RE.replace_all(&normalized_checksums, "?")
        } else {
            NUMBER_RE.replace_all(&normalized_checksums, "?")
        };
        let normalized_numbers = if self.options.match_md5_checksums {
            NUMBER_LEFTOVER_WITH_MD5_RE.replace_all(&normalized_numbers, "?")
        } else {
            NUMBER_LEFTOVER_RE.replace_all(&normalized_numbers, "?")
        };

        // Remove leading collapsible whitespace.
        let trimmed = normalized_numbers.trim_start_matches(is_collapsible_whitespace);
        let trimmed = trimmed.strip_suffix('\n').unwrap_or(trimmed);
        let mut normalized_text = collapse_supported_whitespace(trimmed);
        normalized_text.make_ascii_lowercase();

        let normalized_nulls = NULL_RE.replace_all(&normalized_text, "?");
        let collapsed_lists = LIST_RE.replace_all(&normalized_nulls, "${1}(?+)");
        let collapsed_unions = collapse_repeated_union(&collapsed_lists);
        let normalized_limit = LIMIT_RE.replace(&collapsed_unions, "limit ?");
        remove_order_by_asc(normalized_limit.as_ref()).into_owned()
    }
}

/// Produces a fingerprint using the default matching options.
///
/// # Examples
///
/// ```
/// use sql_fingerprint::fingerprint;
///
/// assert_eq!(
///     fingerprint("SELECT * FROM users WHERE id = 42"),
///     "select * from users where id = ?"
/// );
/// ```
pub fn fingerprint(query: &str) -> String {
    let fingerprinter = Fingerprinter::new(FingerprintOptions::default());
    fingerprinter.fingerprint(query)
}
