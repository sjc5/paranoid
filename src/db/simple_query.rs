//! Parameterized Postgres queries that are safe under **every** connection-pooler mode,
//! including statement-mode pooling, by rendering bound values as escaped SQL literals and
//! sending a single simple-protocol `Query` message.
//!
//! [`portable_query`](super::portable_query) disables persistent prepared statements, but a
//! *parameterized* query still uses the extended protocol (`Parse` then `Bind`) as two
//! pooler exchanges; under a transaction/statement-mode pooler the `Bind` can land on a
//! backend that never saw the `Parse` and fail with `SQLSTATE 26000`. That helper is only
//! safe when executed inside an explicit transaction. This builder has no such caveat: it
//! produces one [`RawSql`] with no parameters at all, so there is nothing for a pooler to
//! lose regardless of how the caller executes it.
//!
//! # Injection safety
//!
//! Values are rendered as literals, so encoding correctness *is* injection safety. Every
//! textual value is emitted with Postgres escape-string syntax (`E'...'`), escaping `\` then
//! `'`, which is deterministic regardless of the session's `standard_conforming_strings`
//! setting. Byte strings are emitted as `E'\\x<hex>'::bytea` (hex is `[0-9a-f]` only).
//! Numerics are Rust-typed and rendered without quotes (`NaN`/`±∞` use Postgres's `'NaN'` /
//! `'Infinity'` float literals). Arrays render with the `ARRAY[...]` constructor so each
//! element flows back through this same encoder, and any type without a dedicated variant
//! (`numeric`, `uuid`, `timestamptz`, `jsonb`, enums, domains, …) goes through
//! [`PostgresLiteral::TextCast`], where the value text is escaped identically. A cast target
//! type name is *structure*, so — like every other SQL fragment this builder accepts — it is
//! a caller-vouched [`AuditedSql`](super::AuditedSql), never interpolated from an unvouched
//! string. Values are always quoted/typed and can never widen structure; the *only* thing
//! this encoder refuses is a NUL byte in text, which Postgres text genuinely cannot store.
//! There is deliberately no `$n` placeholder parsing.

use std::fmt::Write as _;

use sqlx::RawSql;

use super::AuditedSql;
use super::Error as DbError;

/// A typed value to be rendered as a safe Postgres literal by [`SimpleQuery`].
#[derive(Clone, Debug, PartialEq)]
pub enum PostgresLiteral<'a> {
    /// SQL `NULL`.
    Null,
    /// `boolean`.
    Bool(bool),
    /// `smallint`.
    I16(i16),
    /// `integer`.
    I32(i32),
    /// `bigint`.
    I64(i64),
    /// `double precision`. `NaN` and `±∞` are rendered as Postgres's special float literals
    /// (`'NaN'`, `'Infinity'`, `'-Infinity'`), which it stores natively.
    F64(f64),
    /// `text`.
    Text(&'a str),
    /// `bytea`.
    Bytea(&'a [u8]),
    /// A textual value cast to an explicit Postgres type, e.g. `uuid`, `timestamptz`,
    /// `jsonb`, `numeric`, an enum, or a domain. `value` is escaped exactly like
    /// [`PostgresLiteral::Text`]; Postgres validates it at cast time. `pg_type` is a
    /// caller-vouched [`AuditedSql`] type name, so any valid form works — multi-word
    /// (`timestamp with time zone`), array (`int4[]`), schema-qualified, or quoted. Use for
    /// any type without a dedicated variant above.
    TextCast {
        /// The textual value; escaped exactly like [`PostgresLiteral::Text`].
        value: &'a str,
        /// The Postgres type to cast to, as a caller-vouched [`AuditedSql`] fragment.
        pg_type: AuditedSql<&'a str>,
    },
    /// A Postgres array, rendered with the `ARRAY[...]` constructor so each element is
    /// encoded by this same safe encoder — there are no array-literal quoting rules for a
    /// caller to get wrong. The value is cast to `element_pg_type` + `[]`, which also makes
    /// empty and all-`NULL` arrays unambiguous. Elements may themselves be
    /// [`PostgresLiteral::Array`] to construct a genuinely multidimensional Postgres array
    /// (Postgres itself accepts and stores this correctly), but Postgres requires every
    /// nested sub-array at a given nesting depth to have the same length; a mismatched
    /// nested length is rejected by Postgres at execution time with SQLSTATE `2202E`
    /// (`array_subscript_error`), not silently truncated or reshaped. Note for callers who
    /// intend to read such a value back through sqlx: sqlx has no `PgHasArrayType`
    /// implementation for `Vec<T>`, so a multidimensional array built this way cannot be
    /// decoded as `Vec<Vec<T>>` through sqlx's typed row access; reading it back (for
    /// example via a `::text` cast, or `unnest`) requires a different query shape than a
    /// same-typed insert.
    Array {
        /// The array elements, each encoded as a nested literal.
        elements: &'a [PostgresLiteral<'a>],
        /// The element type name, as a caller-vouched [`AuditedSql`] fragment (e.g. `int4`,
        /// `text`, `timestamp with time zone`).
        element_pg_type: AuditedSql<&'a str>,
    },
}

impl PostgresLiteral<'_> {
    fn encode_into(&self, out: &mut String) -> Result<(), DbError> {
        match self {
            Self::Null => out.push_str("NULL"),
            Self::Bool(value) => encode_bool_literal(*value, out),
            Self::I16(value) => encode_i16_literal(*value, out),
            Self::I32(value) => encode_i32_literal(*value, out),
            Self::I64(value) => encode_i64_literal(*value, out),
            Self::F64(value) => encode_f64_literal(*value, out),
            Self::Text(value) => encode_text_literal(value, out)?,
            Self::Bytea(value) => encode_bytea_literal(value, out),
            Self::TextCast { value, pg_type } => {
                encode_text_literal(value, out)?;
                out.push_str("::");
                out.push_str(pg_type.as_str());
            }
            Self::Array {
                elements,
                element_pg_type,
            } => {
                out.push_str("ARRAY[");
                for (index, element) in elements.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    element.encode_into(out)?;
                }
                out.push_str("]::");
                out.push_str(element_pg_type.as_str());
                out.push_str("[]");
            }
        }
        Ok(())
    }
}

/// Emits `value` as `TRUE`/`FALSE`. Shared with
/// [`portable_query`](super::portable_query)'s literal encoder so both surfaces render
/// `boolean` values identically.
pub(crate) fn encode_bool_literal(value: bool, out: &mut String) {
    out.push_str(if value { "TRUE" } else { "FALSE" });
}

// Parenthesized: Postgres's `::` cast binds tighter than unary minus, so an unparenthesized
// negative literal like `-32768::smallint` parses as `-(32768::smallint)` and overflows
// before negation is ever applied. Shared with `portable_query`'s literal encoder so both
// surfaces render integers identically.

/// Emits `value` as `(value)::smallint`.
pub(crate) fn encode_i16_literal(value: i16, out: &mut String) {
    write!(out, "({value})::smallint").expect("write to String is infallible");
}

/// Emits `value` as `(value)::integer`.
pub(crate) fn encode_i32_literal(value: i32, out: &mut String) {
    write!(out, "({value})::integer").expect("write to String is infallible");
}

/// Emits `value` as `(value)::bigint`.
pub(crate) fn encode_i64_literal(value: i64, out: &mut String) {
    write!(out, "({value})::bigint").expect("write to String is infallible");
}

/// Emits `value` as `(value)::double precision`. `NaN` and `±∞` are rendered as Postgres's
/// special float literals (`'NaN'`, `'Infinity'`, `'-Infinity'`), which it stores natively.
/// Shared with [`portable_query`](super::portable_query)'s literal encoder so both surfaces
/// render `double precision` values identically.
pub(crate) fn encode_f64_literal(value: f64, out: &mut String) {
    // `{:?}` gives a round-trippable decimal for finite values (e.g. `1.0`, not `1`).
    if value.is_nan() {
        out.push_str("'NaN'::double precision");
    } else if value == f64::INFINITY {
        out.push_str("'Infinity'::double precision");
    } else if value == f64::NEG_INFINITY {
        out.push_str("'-Infinity'::double precision");
    } else {
        write!(out, "{value:?}::double precision").expect("write to String is infallible");
    }
}

/// Emits `value` as a Postgres escape-string literal (`E'...'`), escaping `\` then `'`.
///
/// Escape-string syntax has fixed escaping rules independent of `standard_conforming_strings`,
/// so the result is safe regardless of the session setting. NUL is rejected because Postgres
/// text cannot contain it. Shared with
/// [`portable_query`](super::portable_query)'s literal encoder so both surfaces render
/// `text` values identically.
pub(crate) fn encode_text_literal(value: &str, out: &mut String) -> Result<(), DbError> {
    if value.as_bytes().contains(&0) {
        return Err(DbError::query_encoding(
            "text value contains a NUL byte, which Postgres text cannot represent",
        ));
    }
    out.push_str("E'");
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            other => out.push(other),
        }
    }
    out.push('\'');
    Ok(())
}

/// Emits `bytes` as `E'\x<hex>'::bytea`. The hex payload is `[0-9a-f]` only, so no escaping
/// of the value is required; the `E'\\x` prefix is escape-string-safe under any
/// `standard_conforming_strings` setting. Shared with
/// [`portable_query`](super::portable_query)'s literal encoder so both surfaces render
/// `bytea` values identically.
pub(crate) fn encode_bytea_literal(bytes: &[u8], out: &mut String) {
    out.push_str("E'\\\\x");
    for byte in bytes {
        write!(out, "{byte:02x}").expect("write to String is infallible");
    }
    out.push_str("'::bytea");
}

/// Builds a pooler-safe simple-protocol query by interleaving audited SQL fragments with
/// safely-encoded literal values.
///
/// SQL structure comes only from [`AuditedSql`] fragments (which the caller has vouched for);
/// values are always rendered as quoted/typed literals, so they cannot alter structure. The
/// result is a single [`RawSql`] with no bind parameters.
///
/// ```
/// # use paranoid::db::{SimpleQuery, PostgresLiteral, AuditedSql};
/// let _query = SimpleQuery::new()
///     .push_sql(AuditedSql::new("SELECT value FROM app_settings WHERE key = "))
///     .push_literal(PostgresLiteral::Text("theme"))
///     .and_then(|q| q.push_sql(AuditedSql::new(" AND tenant = ")).push_literal(PostgresLiteral::I64(7)))
///     .expect("valid literals")
///     .into_raw_sql();
/// ```
#[derive(Clone, Debug, Default)]
pub struct SimpleQuery {
    sql: String,
}

impl SimpleQuery {
    /// Starts an empty query.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a caller-audited SQL fragment verbatim (structure, identifiers, operators).
    pub fn push_sql(mut self, sql: AuditedSql<&str>) -> Self {
        self.sql.push_str(sql.into_inner());
        self
    }

    /// Appends a value rendered as a safe Postgres literal.
    ///
    /// Returns an error only when the value cannot be represented at all — currently just a
    /// NUL byte in text, which Postgres text cannot store — rather than emitting anything
    /// unsafe.
    pub fn push_literal(mut self, literal: PostgresLiteral<'_>) -> Result<Self, DbError> {
        literal.encode_into(&mut self.sql)?;
        Ok(self)
    }

    /// Returns the assembled SQL text (primarily for tests and diagnostics).
    pub fn as_sql(&self) -> &str {
        &self.sql
    }

    /// Finishes the builder into a simple-protocol [`RawSql`] with no bind parameters.
    ///
    /// Routed through
    /// [`unparameterized_simple_query`](super::unparameterized_simple_query): the rendered SQL
    /// carries no bind parameters, so it *is* an unparameterized simple-protocol query, and
    /// going through that constructor keeps the raw-SQLx entry point centralized (as the DB
    /// source guard requires).
    pub fn into_raw_sql(self) -> RawSql {
        super::unparameterized_simple_query(AuditedSql::new(self.sql))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(literal: PostgresLiteral<'_>) -> Result<String, DbError> {
        Ok(SimpleQuery::new()
            .push_literal(literal)?
            .as_sql()
            .to_owned())
    }

    #[test]
    fn scalars_encode_to_expected_literals() {
        assert_eq!(encode(PostgresLiteral::Null).unwrap(), "NULL");
        assert_eq!(encode(PostgresLiteral::Bool(true)).unwrap(), "TRUE");
        assert_eq!(encode(PostgresLiteral::Bool(false)).unwrap(), "FALSE");
        assert_eq!(encode(PostgresLiteral::I16(-5)).unwrap(), "(-5)::smallint");
        assert_eq!(encode(PostgresLiteral::I32(0)).unwrap(), "(0)::integer");
        assert_eq!(
            encode(PostgresLiteral::I64(9_223_372_036_854_775_807)).unwrap(),
            "(9223372036854775807)::bigint"
        );
    }

    #[test]
    fn text_uses_escape_string_syntax_and_escapes_quote_and_backslash() {
        assert_eq!(encode(PostgresLiteral::Text("theme")).unwrap(), "E'theme'");
        // A classic injection attempt is neutralized: the quote is escaped, so the trailing
        // SQL stays inside the string literal.
        assert_eq!(
            encode(PostgresLiteral::Text("'; DROP TABLE users; --")).unwrap(),
            "E'\\'; DROP TABLE users; --'"
        );
        assert_eq!(
            encode(PostgresLiteral::Text("back\\slash")).unwrap(),
            "E'back\\\\slash'"
        );
    }

    #[test]
    fn text_with_nul_is_rejected() {
        assert!(encode(PostgresLiteral::Text("a\0b")).is_err());
    }

    #[test]
    fn text_cast_with_nul_is_rejected() {
        assert!(
            encode(PostgresLiteral::TextCast {
                value: "a\0b",
                pg_type: AuditedSql::new("uuid"),
            })
            .is_err()
        );
    }

    #[test]
    fn array_element_nul_is_rejected_without_producing_partial_output() {
        let result = SimpleQuery::new().push_literal(PostgresLiteral::Array {
            elements: &[PostgresLiteral::Text("ok"), PostgresLiteral::Text("a\0b")],
            element_pg_type: AuditedSql::new("text"),
        });
        assert!(result.is_err());
    }

    #[test]
    fn bytea_encodes_as_hex_escape_string() {
        assert_eq!(
            encode(PostgresLiteral::Bytea(&[0x00, 0xde, 0xad, 0xff])).unwrap(),
            "E'\\\\x00deadff'::bytea"
        );
        assert_eq!(
            encode(PostgresLiteral::Bytea(&[])).unwrap(),
            "E'\\\\x'::bytea"
        );
    }

    #[test]
    fn non_finite_floats_encode_as_special_literals() {
        assert_eq!(
            encode(PostgresLiteral::F64(f64::NAN)).unwrap(),
            "'NaN'::double precision"
        );
        assert_eq!(
            encode(PostgresLiteral::F64(f64::INFINITY)).unwrap(),
            "'Infinity'::double precision"
        );
        assert_eq!(
            encode(PostgresLiteral::F64(f64::NEG_INFINITY)).unwrap(),
            "'-Infinity'::double precision"
        );
        assert!(
            encode(PostgresLiteral::F64(1.5))
                .unwrap()
                .starts_with("1.5")
        );
    }

    #[test]
    fn text_cast_emits_vouched_type_including_multiword() {
        assert_eq!(
            encode(PostgresLiteral::TextCast {
                value: "2026-07-02T00:00:00Z",
                pg_type: AuditedSql::new("timestamptz"),
            })
            .unwrap(),
            "E'2026-07-02T00:00:00Z'::timestamptz"
        );
        // A vouched multi-word type name is emitted verbatim — there is no character filter
        // to reject legitimate Postgres types.
        assert_eq!(
            encode(PostgresLiteral::TextCast {
                value: "2026-07-02T00:00:00Z",
                pg_type: AuditedSql::new("timestamp with time zone"),
            })
            .unwrap(),
            "E'2026-07-02T00:00:00Z'::timestamp with time zone"
        );
    }

    #[test]
    fn arrays_use_the_constructor_and_recurse_through_the_safe_encoder() {
        assert_eq!(
            encode(PostgresLiteral::Array {
                elements: &[
                    PostgresLiteral::I32(1),
                    PostgresLiteral::I32(2),
                    PostgresLiteral::Null,
                ],
                element_pg_type: AuditedSql::new("int4"),
            })
            .unwrap(),
            "ARRAY[(1)::integer,(2)::integer,NULL]::int4[]"
        );
        // Text elements are escaped exactly like a scalar text literal, so an injection
        // attempt inside an element stays inside its own quoted string.
        assert_eq!(
            encode(PostgresLiteral::Array {
                elements: &[PostgresLiteral::Text("a'b"), PostgresLiteral::Text("c\\d")],
                element_pg_type: AuditedSql::new("text"),
            })
            .unwrap(),
            "ARRAY[E'a\\'b',E'c\\\\d']::text[]"
        );
        // Empty arrays are unambiguous thanks to the element-type cast.
        assert_eq!(
            encode(PostgresLiteral::Array {
                elements: &[],
                element_pg_type: AuditedSql::new("int4"),
            })
            .unwrap(),
            "ARRAY[]::int4[]"
        );
    }

    #[test]
    fn interleaving_produces_expected_sql() {
        let query = SimpleQuery::new()
            .push_sql(AuditedSql::new("SELECT * FROM t WHERE k = "))
            .push_literal(PostgresLiteral::Text("k'v"))
            .unwrap()
            .push_sql(AuditedSql::new(" AND n = "))
            .push_literal(PostgresLiteral::I64(42))
            .unwrap();
        assert_eq!(
            query.as_sql(),
            "SELECT * FROM t WHERE k = E'k\\'v' AND n = (42)::bigint"
        );
    }
}
