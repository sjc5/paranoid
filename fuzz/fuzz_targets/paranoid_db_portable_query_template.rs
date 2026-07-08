#![no_main]

use libfuzzer_sys::fuzz_target;

// Exercises the `portable_query` SQL template placeholder scanner, which is otherwise
// crate-internal. The scanner is only reachable through `paranoid::db_fuzz`, which exists
// only under `--cfg fuzzing` (set by cargo-fuzz), so `imp`'s body is gated the same way
// and this target compiles as a no-op in a normal, non-fuzzing workspace build.
fuzz_target!(|data: &[u8]| {
    #[cfg(fuzzing)]
    imp::exercise_portable_query_template_scanner(data);
    #[cfg(not(fuzzing))]
    let _ = data;
});

#[cfg(fuzzing)]
mod imp {
    use paranoid::db::Error as DbError;
    use paranoid::db_fuzz::render_portable_query_sql;

    /// Dispatches fuzz bytes into one of three checks against the `portable_query` SQL
    /// template placeholder scanner: a well-formed structured template with an exact
    /// correctness oracle, a deliberately malformed structured template asserted to be
    /// rejected, and raw unstructured bytes asserted only to never panic.
    pub(super) fn exercise_portable_query_template_scanner(data: &[u8]) {
        let Some((&selector, rest)) = data.split_first() else {
            return;
        };
        match selector % 3 {
            0 => exercise_well_formed_template(rest),
            1 => exercise_malformed_template(rest),
            _ => exercise_raw_bytes(data),
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum SegmentKind {
        Filler,
        StringLiteral,
        EscapeStringLiteral,
        QuotedIdentifier,
        LineComment,
        BlockComment,
        NestedBlockComment,
        Placeholder,
    }

    const SEGMENT_KIND_COUNT: u8 = 8;

    fn segment_kind_from_byte(byte: u8) -> SegmentKind {
        match byte % SEGMENT_KIND_COUNT {
            0 => SegmentKind::Filler,
            1 => SegmentKind::StringLiteral,
            2 => SegmentKind::EscapeStringLiteral,
            3 => SegmentKind::QuotedIdentifier,
            4 => SegmentKind::LineComment,
            5 => SegmentKind::BlockComment,
            6 => SegmentKind::NestedBlockComment,
            _ => SegmentKind::Placeholder,
        }
    }

    fn lossy_text_from_bytes(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    fn safe_filler_text(bytes: &[u8]) -> String {
        lossy_text_from_bytes(bytes)
            .chars()
            .filter(|character| character.is_alphanumeric() || *character == ' ')
            .collect()
    }

    fn escaped_standard_string_literal(bytes: &[u8]) -> String {
        let inner = lossy_text_from_bytes(bytes).replace('\'', "''");
        format!("'{inner}'")
    }

    fn escaped_e_string_literal(bytes: &[u8]) -> String {
        let inner = lossy_text_from_bytes(bytes)
            .replace('\\', "\\\\")
            .replace('\'', "\\'");
        format!("E'{inner}'")
    }

    fn escaped_quoted_identifier(bytes: &[u8]) -> String {
        let inner = lossy_text_from_bytes(bytes).replace('"', "\"\"");
        format!("\"{inner}\"")
    }

    fn line_comment(bytes: &[u8]) -> String {
        let inner = lossy_text_from_bytes(bytes).replace(['\n', '\r'], " ");
        format!("-- {inner}\n")
    }

    /// Strips every `/` and `*` character from `bytes`, not merely the two-character
    /// `/*`/`*/` delimiter sequences: a body that merely avoided those substrings could
    /// still accidentally re-form one when concatenated next to this function's own
    /// `/*`/`*/` wrapper (for example a body ending in a lone `/` immediately followed by
    /// the wrapper's `*/` reforms `/*`), so no `/` or `*` byte may survive anywhere in the
    /// body at all.
    fn block_comment_body(bytes: &[u8]) -> String {
        lossy_text_from_bytes(bytes)
            .chars()
            .filter(|character| *character != '/' && *character != '*')
            .collect()
    }

    fn block_comment(bytes: &[u8]) -> String {
        format!("/*{}*/", block_comment_body(bytes))
    }

    fn nested_block_comment(bytes: &[u8]) -> String {
        let midpoint = bytes.len() / 2;
        let (outer_bytes, inner_bytes) = bytes.split_at(midpoint);
        format!(
            "/*{} /*{}*/ {}*/",
            block_comment_body(outer_bytes),
            block_comment_body(inner_bytes),
            block_comment_body(outer_bytes)
        )
    }

    /// Builds a well-formed `portable_query` SQL template from fuzz bytes and asserts
    /// [`render_portable_query_sql`] both succeeds and produces exactly the expected
    /// output.
    ///
    /// The expected output is computed independently of the scanner: every segment other
    /// than a deliberately placed `$n` placeholder is known, at construction time, to be
    /// copied byte-for-byte into the result (that is the scanner's documented contract),
    /// so the oracle is a direct substring assembly rather than a reimplementation of the
    /// scanner's own byte-by-byte logic. Placeholder-looking text (`$1`, `$2`, ...) is
    /// deliberately embedded inside string/comment/identifier segment bodies as well, so a
    /// scanner regression that stopped skipping those constructs would show up as this
    /// oracle's `expected` output diverging from Postgres-directed reality.
    fn exercise_well_formed_template(data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let fragment_count = usize::from(data[0] % 9) + 1;
        let fragments: Vec<String> = (0..fragment_count)
            .map(|index| {
                let start = 1 + index * 5;
                format!(
                    "frag{}_{}",
                    index,
                    lossy_text_from_bytes(data.get(start..start + 4).unwrap_or(&[]))
                )
            })
            .collect();

        let mut template = String::new();
        let mut expected = String::new();
        let chunk_size = 7usize;
        let mut chunk_start = 1usize;
        while chunk_start < data.len() {
            let chunk = &data[chunk_start..(chunk_start + chunk_size).min(data.len())];
            chunk_start += chunk_size;
            let Some((&kind_byte, body)) = chunk.split_first() else {
                break;
            };
            template.push(' ');
            expected.push(' ');
            match segment_kind_from_byte(kind_byte) {
                SegmentKind::Filler => {
                    let text = safe_filler_text(body);
                    template.push_str(&text);
                    expected.push_str(&text);
                }
                SegmentKind::StringLiteral => {
                    let text = escaped_standard_string_literal(body);
                    template.push_str(&text);
                    expected.push_str(&text);
                }
                SegmentKind::EscapeStringLiteral => {
                    let text = escaped_e_string_literal(body);
                    template.push_str(&text);
                    expected.push_str(&text);
                }
                SegmentKind::QuotedIdentifier => {
                    let text = escaped_quoted_identifier(body);
                    template.push_str(&text);
                    expected.push_str(&text);
                }
                SegmentKind::LineComment => {
                    let text = line_comment(body);
                    template.push_str(&text);
                    expected.push_str(&text);
                }
                SegmentKind::BlockComment => {
                    let text = block_comment(body);
                    template.push_str(&text);
                    expected.push_str(&text);
                }
                SegmentKind::NestedBlockComment => {
                    let text = nested_block_comment(body);
                    template.push_str(&text);
                    expected.push_str(&text);
                }
                SegmentKind::Placeholder => {
                    let index = body
                        .first()
                        .map_or(0, |byte| usize::from(*byte) % fragment_count);
                    template.push('$');
                    template.push_str(&(index + 1).to_string());
                    expected.push_str(&fragments[index]);
                }
            }
        }

        let rendered = render_portable_query_sql(&template, &fragments)
            .expect("a well-formed portable_query template must render successfully");
        assert_eq!(
            rendered, expected,
            "rendered SQL diverged from the independently computed expected substitution"
        );
    }

    /// Builds a structurally deliberate malformed template (an unterminated string
    /// literal, an unterminated block comment, an unterminated quoted identifier, an
    /// invalid `$` construct, an out-of-range placeholder index, or `$0`) and asserts
    /// [`render_portable_query_sql`] rejects it with [`DbError::PortableQueryTemplate`]
    /// rather than panicking or silently succeeding.
    fn exercise_malformed_template(data: &[u8]) {
        let Some((&selector, rest)) = data.split_first() else {
            return;
        };
        let template = match selector % 6 {
            // A body containing its own terminating character (`'`, `*`/`/`, `"`)
            // could accidentally close the construct early instead of leaving it
            // unterminated, so each body is stripped of exactly the character(s) that
            // would let it close itself, guaranteeing the constructed template really
            // is unterminated regardless of what fuzz bytes were supplied.
            0 => format!("SELECT '{}", lossy_text_from_bytes(rest).replace('\'', "")),
            1 => format!("SELECT /*{}", block_comment_body(rest)),
            2 => format!("SELECT \"{}", lossy_text_from_bytes(rest).replace('"', "")),
            3 => "SELECT $$dollar_quoted$$".to_owned(),
            4 => "SELECT $0".to_owned(),
            _ => "SELECT $999999999999999999999999999999".to_owned(),
        };
        let fragments: Vec<String> = vec!["only_fragment".to_owned()];
        let result = render_portable_query_sql(&template, &fragments);
        match result {
            Err(DbError::PortableQueryTemplate { .. }) => {}
            Err(other) => panic!("unexpected error variant for malformed template: {other:?}"),
            Ok(rendered) => panic!(
                "malformed template unexpectedly rendered successfully: {template:?} -> \
                 {rendered:?}"
            ),
        }
    }

    /// Feeds unstructured, unfiltered fuzz bytes directly as the template text, with a
    /// small fixed fragment list, and asserts only that the scanner never panics and that
    /// any error it returns is the documented [`DbError::PortableQueryTemplate`] variant.
    fn exercise_raw_bytes(data: &[u8]) {
        let Ok(template) = std::str::from_utf8(data) else {
            return;
        };
        let fragments: Vec<String> = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
        match render_portable_query_sql(template, &fragments) {
            Ok(_) => {}
            Err(DbError::PortableQueryTemplate { .. }) => {}
            Err(other) => panic!("unexpected error variant for raw-byte template: {other:?}"),
        }
    }
}
