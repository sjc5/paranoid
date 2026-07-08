//! Rewrites a `portable_query` SQL template's `$1`, `$2`, ... bind placeholders into
//! pre-rendered literal fragments, so the finished statement carries no bind parameters at
//! all and can be sent as a single simple-protocol `Query`.
//!
//! The template is scanned once, byte-by-byte, copying every span of SQL verbatim except
//! for placeholder tokens, which are replaced by the corresponding entry of `fragments`
//! (1-indexed, matching the order `.bind()` was called). Scanning must not mistake a `$`
//! that is part of a string literal, quoted identifier, or comment for a placeholder, so it
//! tracks those constructs precisely enough to skip over them:
//!
//! - `'...'` string literals, with the standard `''` doubled-quote escape. A backslash
//!   inside a plain `'...'` literal is an ordinary character (Postgres's default
//!   `standard_conforming_strings = on` behavior); a backslash is only an escape character
//!   inside an `E'...'` escape string, which this scanner recognizes by the literal `E`/`e`
//!   immediately preceding the opening quote.
//! - `"..."` quoted identifiers, with the standard `""` doubled-quote escape.
//! - `--` line comments, terminated by a newline or end of input.
//! - `/* ... */` block comments, which Postgres allows to nest, so nesting depth is tracked.
//!
//! Dollar-quoted string syntax (`$$...$$` or `$tag$...$tag$`) is rejected rather than
//! parsed: it is indistinguishable from a placeholder by a one-token lookahead, and
//! `portable_query` templates have no use for it, so any `$` not immediately followed by an
//! ASCII digit is treated as an error rather than silently misparsed.
//!
//! Byte-level scanning is safe here because every delimiter this scanner recognizes (`'`,
//! `"`, `-`, `/`, `*`, `$`, digits, newline) is a single ASCII byte, and UTF-8 continuation
//! bytes (`0x80..=0xBF`) never equal an ASCII byte, so they can never be mistaken for a
//! delimiter mid-codepoint.

use super::Error as DbError;

fn is_identifier_continuation_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80
}

fn utf8_sequence_len(lead_byte: u8) -> usize {
    if lead_byte & 0b1000_0000 == 0 {
        1
    } else if lead_byte & 0b1110_0000 == 0b1100_0000 {
        2
    } else if lead_byte & 0b1111_0000 == 0b1110_0000 {
        3
    } else if lead_byte & 0b1111_1000 == 0b1111_0000 {
        4
    } else {
        // Not a valid UTF-8 lead byte. `template` is a Rust `&str`, so this cannot occur;
        // treat it as a single byte defensively rather than panicking.
        1
    }
}

/// Rewrites `template`'s `$1`, `$2`, ... bind placeholders into the corresponding entry of
/// `fragments` (1-indexed), returning the finished, parameter-free SQL text.
///
/// Every placeholder in `template` must have a corresponding `fragments` entry (a `$n`
/// beyond how many values were bound is a caller error and is reported loudly). It is not
/// an error for `fragments` to contain more entries than `template` references; a bound
/// value whose placeholder is never used has no effect, matching how an unreferenced bind
/// parameter behaves under the Postgres extended protocol.
pub(crate) fn render_portable_query_sql(
    template: &str,
    fragments: &[String],
) -> Result<String, DbError> {
    let bytes = template.as_bytes();
    let mut out = String::with_capacity(template.len());
    let mut index = 0usize;

    while index < bytes.len() {
        match bytes[index] {
            b'\'' => {
                let is_escape_string = index >= 1
                    && (bytes[index - 1] == b'E' || bytes[index - 1] == b'e')
                    && (index < 2 || !is_identifier_continuation_byte(bytes[index - 2]));
                let start = index;
                index += 1;
                loop {
                    if index >= bytes.len() {
                        return Err(DbError::portable_query_template(
                            "unterminated string literal in portable_query SQL template",
                        ));
                    }
                    match bytes[index] {
                        b'\\' if is_escape_string => {
                            index += 2;
                        }
                        b'\'' => {
                            if bytes.get(index + 1) == Some(&b'\'') {
                                index += 2;
                            } else {
                                index += 1;
                                break;
                            }
                        }
                        _ => index += 1,
                    }
                }
                out.push_str(&template[start..index]);
            }
            b'"' => {
                let start = index;
                index += 1;
                loop {
                    if index >= bytes.len() {
                        return Err(DbError::portable_query_template(
                            "unterminated quoted identifier in portable_query SQL template",
                        ));
                    }
                    match bytes[index] {
                        b'"' => {
                            if bytes.get(index + 1) == Some(&b'"') {
                                index += 2;
                            } else {
                                index += 1;
                                break;
                            }
                        }
                        _ => index += 1,
                    }
                }
                out.push_str(&template[start..index]);
            }
            b'-' if bytes.get(index + 1) == Some(&b'-') => {
                let start = index;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
                out.push_str(&template[start..index]);
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                let start = index;
                index += 2;
                let mut depth = 1u32;
                while depth > 0 {
                    if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'*') {
                        depth += 1;
                        index += 2;
                    } else if bytes.get(index) == Some(&b'*') && bytes.get(index + 1) == Some(&b'/')
                    {
                        depth -= 1;
                        index += 2;
                    } else if index < bytes.len() {
                        index += 1;
                    } else {
                        return Err(DbError::portable_query_template(
                            "unterminated block comment in portable_query SQL template",
                        ));
                    }
                }
                out.push_str(&template[start..index]);
            }
            b'$' => {
                let digits_start = index + 1;
                let mut digits_end = digits_start;
                while bytes.get(digits_end).is_some_and(u8::is_ascii_digit) {
                    digits_end += 1;
                }
                if digits_end == digits_start {
                    return Err(DbError::portable_query_template(
                        "unsupported `$` construct in portable_query SQL template: only `$<digits>` bind placeholders are supported, not dollar-quoted strings",
                    ));
                }
                let digits = &template[digits_start..digits_end];
                let placeholder_index: usize = digits.parse().map_err(|_| {
                    DbError::portable_query_template(format!(
                        "bind placeholder `${digits}` is not a valid placeholder index"
                    ))
                })?;
                if placeholder_index == 0 {
                    return Err(DbError::portable_query_template(
                        "bind placeholder `$0` is not valid; portable_query placeholders are 1-indexed",
                    ));
                }
                let fragment = fragments.get(placeholder_index - 1).ok_or_else(|| {
                    DbError::portable_query_template(format!(
                        "bind placeholder `${placeholder_index}` has no corresponding `.bind()` call"
                    ))
                })?;
                out.push_str(fragment);
                index = digits_end;
            }
            other => {
                let sequence_len = utf8_sequence_len(other);
                out.push_str(&template[index..index + sequence_len]);
                index += sequence_len;
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(template: &str, fragments: &[&str]) -> Result<String, DbError> {
        let fragments: Vec<String> = fragments.iter().map(|value| (*value).to_owned()).collect();
        render_portable_query_sql(template, &fragments)
    }

    #[test]
    fn substitutes_placeholders_in_order() {
        assert_eq!(
            render("SELECT $1 WHERE x = $2", &["(1)::bigint", "E'a'"]).unwrap(),
            "SELECT (1)::bigint WHERE x = E'a'"
        );
    }

    #[test]
    fn substitutes_repeated_placeholder_multiple_times() {
        assert_eq!(
            render("SELECT $1, $1", &["(1)::bigint"]).unwrap(),
            "SELECT (1)::bigint, (1)::bigint"
        );
    }

    #[test]
    fn multi_digit_placeholder_indices_parse_correctly() {
        let fragments: Vec<&str> = (0..12).map(|_| "TRUE").collect();
        assert_eq!(render("SELECT $10", &fragments).unwrap(), "SELECT TRUE");
    }

    #[test]
    fn skips_dollar_inside_plain_string_literal() {
        assert_eq!(
            render("SELECT 'a$1b' WHERE x = $1", &["(1)::bigint"]).unwrap(),
            "SELECT 'a$1b' WHERE x = (1)::bigint"
        );
    }

    #[test]
    fn skips_doubled_single_quote_escape_in_plain_string() {
        assert_eq!(
            render("SELECT 'it''s $1 fine' WHERE x = $1", &["(1)::bigint"]).unwrap(),
            "SELECT 'it''s $1 fine' WHERE x = (1)::bigint"
        );
    }

    #[test]
    fn plain_string_backslash_is_not_an_escape_character() {
        assert_eq!(
            render(r"SELECT 'a\' WHERE x = $1", &["(1)::bigint"]).unwrap(),
            r"SELECT 'a\' WHERE x = (1)::bigint"
        );
    }

    #[test]
    fn escape_string_backslash_escapes_the_next_byte() {
        assert_eq!(
            render(r"SELECT E'a\' $1 b' WHERE x = $1", &["(1)::bigint"]).unwrap(),
            r"SELECT E'a\' $1 b' WHERE x = (1)::bigint"
        );
    }

    #[test]
    fn lowercase_escape_string_prefix_is_recognized() {
        assert_eq!(
            render(r"SELECT e'a\' $1 b' WHERE x = $1", &["(1)::bigint"]).unwrap(),
            r"SELECT e'a\' $1 b' WHERE x = (1)::bigint"
        );
    }

    #[test]
    fn identifier_ending_in_e_before_a_string_is_not_an_escape_string() {
        assert_eq!(
            render("SELECT TABLE'a$1b' WHERE x = $1", &["(1)::bigint"]).unwrap(),
            "SELECT TABLE'a$1b' WHERE x = (1)::bigint"
        );
    }

    #[test]
    fn skips_dollar_inside_quoted_identifier() {
        assert_eq!(
            render(r#"SELECT "a$1b" WHERE x = $1"#, &["(1)::bigint"]).unwrap(),
            r#"SELECT "a$1b" WHERE x = (1)::bigint"#
        );
    }

    #[test]
    fn skips_doubled_double_quote_escape_in_identifier() {
        assert_eq!(
            render(r#"SELECT "a""$1""b" WHERE x = $1"#, &["(1)::bigint"]).unwrap(),
            r#"SELECT "a""$1""b" WHERE x = (1)::bigint"#
        );
    }

    #[test]
    fn skips_dollar_inside_line_comment() {
        assert_eq!(
            render("SELECT $1 -- a $2 comment\nWHERE x = $1", &["(1)::bigint"]).unwrap(),
            "SELECT (1)::bigint -- a $2 comment\nWHERE x = (1)::bigint"
        );
    }

    #[test]
    fn line_comment_without_trailing_newline_is_terminated_by_end_of_input() {
        assert_eq!(
            render("SELECT $1 -- a $2 comment", &["(1)::bigint"]).unwrap(),
            "SELECT (1)::bigint -- a $2 comment"
        );
    }

    #[test]
    fn skips_dollar_inside_block_comment() {
        assert_eq!(
            render(
                "SELECT $1 /* a $2 comment */ WHERE x = $1",
                &["(1)::bigint"]
            )
            .unwrap(),
            "SELECT (1)::bigint /* a $2 comment */ WHERE x = (1)::bigint"
        );
    }

    #[test]
    fn nested_block_comments_track_depth() {
        assert_eq!(
            render(
                "SELECT $1 /* outer /* inner $2 */ still comment */ x",
                &["(1)::bigint"]
            )
            .unwrap(),
            "SELECT (1)::bigint /* outer /* inner $2 */ still comment */ x"
        );
    }

    #[test]
    fn unterminated_string_literal_is_rejected() {
        assert!(render("SELECT 'unterminated", &[]).is_err());
    }

    #[test]
    fn unterminated_quoted_identifier_is_rejected() {
        assert!(render(r#"SELECT "unterminated"#, &[]).is_err());
    }

    #[test]
    fn unterminated_block_comment_is_rejected() {
        assert!(render("SELECT /* unterminated", &[]).is_err());
    }

    #[test]
    fn dollar_quoted_string_syntax_is_rejected() {
        assert!(render("SELECT $$literal$$", &[]).is_err());
        assert!(render("SELECT $tag$literal$tag$", &[]).is_err());
    }

    #[test]
    fn placeholder_index_beyond_bound_values_is_rejected() {
        assert!(render("SELECT $1", &[]).is_err());
        assert!(render("SELECT $2", &["(1)::bigint"]).is_err());
    }

    #[test]
    fn zero_placeholder_index_is_rejected() {
        assert!(render("SELECT $0", &["(1)::bigint"]).is_err());
    }

    #[test]
    fn more_bound_values_than_placeholders_is_permitted() {
        assert_eq!(
            render("SELECT $1", &["(1)::bigint", "(2)::bigint"]).unwrap(),
            "SELECT (1)::bigint"
        );
    }

    #[test]
    fn no_placeholders_returns_template_unchanged() {
        assert_eq!(render("SELECT 1 FROM t", &[]).unwrap(), "SELECT 1 FROM t");
    }

    #[test]
    fn multibyte_characters_outside_delimiters_round_trip() {
        assert_eq!(
            render("SELECT $1 -- café\nWHERE name = 'café'", &["(1)::bigint"]).unwrap(),
            "SELECT (1)::bigint -- café\nWHERE name = 'café'"
        );
    }
}
