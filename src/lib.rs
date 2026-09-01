use regex::Regex;
use std::{borrow::Cow, sync::LazyLock};

static NUMBER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[0-9+-][0-9a-f.xb+-]*").expect("number regex must be valid"));

static NUMBER_WITH_WORD_BOUNDARY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u:\b)[0-9+-][0-9a-f.xb+-]*")
        .expect("number with word boundary regex must be valid")
});

static MD5_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([._-])[a-f0-9]{32}").expect("MD5 checksum regex must be valid"));

static NUMBER_LEFTOVER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[xb.+-]\?").expect("number leftover regex must be valid"));

static NUMBER_LEFTOVER_WITH_MD5_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[xb+-]\?").expect("number leftover with MD5 regex must be valid")
});

static PERCONA_CHECKSUM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/\*[A-Za-z0-9_]+\.[A-Za-z0-9_]+:[0-9]/[0-9]\*/")
        .expect("Percona checksum regex must be valid")
});

static CALL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*(call\s+\S+)\(").expect("CALL regex must be valid"));

static VALUES_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)^((?:INSERT|REPLACE)(?: IGNORE)?\s+INTO.+?VALUES\s*\(.*?\))\s*,\s*\(")
        .expect("Values regex must be valid")
});

static BLOCK_COMMENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?s)/\*[^!].*?\*/").expect("COMMENT regex must be valid"));

static USE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\Ause \S+(?:\n)?\z").expect("USE regex must be valid"));

static PREFIXED_ESCAPED_SINGLE_QUOTE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([^\\])(\\')").expect("escaped single quote regex must be valid")
});

static PREFIXED_ESCAPED_DOUBLE_QUOTE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"([^\\])(\\")"#).expect("escaped double quote regex must be valid")
});

static DOUBLE_BACKSLASH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\\\").expect("double backslash regex must be valid"));

static ESCAPED_SINGLE_QUOTE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\\'").expect("single quote escape regex must be valid"));

static ESCAPED_DOUBLE_QUOTE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\\""#).expect("double quote escape regex must be valid"));

static DOUBLE_QUOTED_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)([^\\])(".*?[^\\]?")"#).expect("double-quoted literal regex must be valid")
});

static SINGLE_QUOTED_LITERAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)([^\\])('.*?[^\\]?')").expect("single-quoted literal regex must be valid")
});

static BOOLEAN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?-u:\b)(?:false|true)(?-u:\b)").expect("boolean literal regex must be valid")
});

static NULL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b)null(?-u:\b)").expect("null regex must be valid"));

static LIST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u:\b)(in|values?)(?:[\s,]*\([\s?,]*\))+")
        .expect("IN and VALUES list regex must be valid")
});

static UNION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r" union(?: all)? ").expect("union regex must be valid"));

static SELECT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b)select ").expect("select regex must be valid"));

static LIMIT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u:\b)limit \?(?:, ?\?| offset \?)?").expect("limit regex must be valid")
});

static ORDER_BY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b)order by ").expect("order by regex must be valid"));

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
        let search_area = &query[copy_from..separator.start()];
        let after_separator = &query[separator.end()..];
        let mut repeated = None;

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

        while separator_index < separators.len() {
            let next_separator = &separators[separator_index];

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
            end += 1
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

#[derive(Default)]
pub struct FingerprintOptions {
    match_md5_checksums: bool,
    match_embedded_numbers: bool,
}

impl FingerprintOptions {
    pub fn with_match_embedded_numbers(mut self, match_embedded_numbers: bool) -> Self {
        self.match_embedded_numbers = match_embedded_numbers;
        self
    }

    pub fn with_match_md5_checksums(mut self, match_md5_checksums: bool) -> Self {
        self.match_md5_checksums = match_md5_checksums;
        self
    }
}
pub struct Fingerprinter {
    options: FingerprintOptions,
}

impl Fingerprinter {
    pub fn new(options: FingerprintOptions) -> Self {
        Self { options }
    }

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
        let query = BLOCK_COMMENT_RE.replace_all(query, "");
        let query = remove_line_comments(&query);
        if let Some(use_statement) = use_fingerprint(&query) {
            return use_statement;
        }
        let query = PREFIXED_ESCAPED_SINGLE_QUOTE_RE.replace_all(&query, "${1}");
        let query = PREFIXED_ESCAPED_DOUBLE_QUOTE_RE.replace_all(&query, "${1}");
        let query = DOUBLE_BACKSLASH_RE.replace_all(&query, "");
        let query = ESCAPED_SINGLE_QUOTE_RE.replace_all(&query, "");
        let query = ESCAPED_DOUBLE_QUOTE_RE.replace_all(&query, "");
        let query = DOUBLE_QUOTED_LITERAL_RE.replace_all(&query, "${1}?");
        let query = SINGLE_QUOTED_LITERAL_RE.replace_all(&query, "${1}?");
        let query = BOOLEAN_RE.replace_all(&query, "?");
        let query = if self.options.match_md5_checksums {
            MD5_RE.replace_all(&query, "${1}?")
        } else {
            Cow::Borrowed(query.as_ref())
        };
        let number_replaced = if self.options.match_embedded_numbers {
            NUMBER_WITH_WORD_BOUNDARY_RE.replace_all(&query, "?")
        } else {
            NUMBER_RE.replace_all(&query, "?")
        };
        let query = if self.options.match_md5_checksums {
            NUMBER_LEFTOVER_WITH_MD5_RE.replace_all(&number_replaced, "?")
        } else {
            NUMBER_LEFTOVER_RE.replace_all(&number_replaced, "?")
        };

        // Remove leading collapsible whitespace.
        let query = query.trim_start_matches(is_collapsible_whitespace);
        let query = query.strip_suffix("\n").unwrap_or(query);
        // Collapse each run of supported whitespace into one ASCII space.
        let mut fingerprint = String::with_capacity(query.len());
        let mut previous_was_whitespace = false;
        for character in query.chars() {
            if is_collapsible_whitespace(character) {
                if !previous_was_whitespace {
                    fingerprint.push(' ');
                    previous_was_whitespace = true
                }
                continue;
            }
            previous_was_whitespace = false;
            fingerprint.push(character);
        }
        fingerprint.make_ascii_lowercase();
        let fingerprint = NULL_RE.replace_all(&fingerprint, "?").into_owned();
        let fingerprint = LIST_RE.replace_all(&fingerprint, "${1}(?+)").into_owned();
        let fingerprint = collapse_repeated_union(&fingerprint).into_owned();
        let fingerprint = LIMIT_RE.replace(&fingerprint, "limit ?").into_owned();
        remove_order_by_asc(fingerprint.as_ref()).into_owned()
    }
}

pub fn fingerprint(query: &str) -> String {
    let fingerprinter = Fingerprinter::new(FingerprintOptions::default());
    fingerprinter.fingerprint(query)
}
