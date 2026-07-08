//! [`IntoPortableQueryLiteral`], the trait that lets [`portable_query`](super::portable_query)
//! render a bound value as a safely-escaped Postgres literal instead of an extended-protocol
//! bind parameter.
//!
//! This reuses the exact escaping primitives [`SimpleQuery`](super::SimpleQuery) uses
//! ([`encode_text_literal`](super::simple_query::encode_text_literal) and friends) so both
//! surfaces render the same Rust value as the same Postgres literal text.
//!
//! Coverage is a closed, enumerated set of impls, not a blanket bridge to SQLx's own
//! `Encode`/`Type` traits: rendering a value as *text* is a different operation from
//! encoding it in SQLx's binary wire format, so each covered type has a literal encoding
//! written and tested here deliberately. Covered so far: `bool`, `i16`, `i32`, `i64`, `f64`,
//! `str`/`String`, `[u8]`/`Vec<u8>`/`[u8; N]`, `Option<T>` (`None` renders as `NULL`),
//! `time::OffsetDateTime` (rendered as RFC 3339 text cast to `timestamptz`), `time::Date`
//! (ISO 8601 text cast to `date`), `serde_json::Value` (compact JSON text cast to `jsonb`,
//! matching SQLx's default binding of that type), `uuid::Uuid` under the `db-uuid` feature
//! (hyphenated text cast to `uuid`), and `text[]`/`bytea[]`/`bigint[]` arrays (for
//! `= ANY($n)` clauses). `time::Time` and `time::PrimitiveDateTime` are not yet covered; a
//! caller that needs one of those needs a new impl added here, not a workaround at the
//! call site.

use super::Error as DbError;
use super::simple_query::{
    encode_bool_literal, encode_bytea_literal, encode_f64_literal, encode_i16_literal,
    encode_i32_literal, encode_i64_literal, encode_text_literal,
};

/// A Rust value that [`portable_query`](super::portable_query) can render as a safely-escaped
/// Postgres literal in place of a `$n` bind placeholder.
///
/// Encoding can fail only when a value cannot be represented as Postgres text at all —
/// currently just a NUL byte in text, which Postgres text cannot store — never by emitting
/// anything unsafe.
pub trait IntoPortableQueryLiteral {
    /// Appends `self`, rendered as a Postgres literal, to `out`.
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError>;
}

impl<T> IntoPortableQueryLiteral for &T
where
    T: IntoPortableQueryLiteral + ?Sized,
{
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        (**self).encode_portable_query_literal(out)
    }
}

impl IntoPortableQueryLiteral for bool {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        encode_bool_literal(*self, out);
        Ok(())
    }
}

impl IntoPortableQueryLiteral for i16 {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        encode_i16_literal(*self, out);
        Ok(())
    }
}

impl IntoPortableQueryLiteral for i32 {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        encode_i32_literal(*self, out);
        Ok(())
    }
}

impl IntoPortableQueryLiteral for i64 {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        encode_i64_literal(*self, out);
        Ok(())
    }
}

impl IntoPortableQueryLiteral for f64 {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        encode_f64_literal(*self, out);
        Ok(())
    }
}

impl IntoPortableQueryLiteral for time::OffsetDateTime {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        let formatted = self
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| {
                DbError::query_encoding(
                    "time::OffsetDateTime could not be formatted as RFC 3339 text",
                )
            })?;
        encode_text_literal(&formatted, out)?;
        out.push_str("::timestamptz");
        Ok(())
    }
}

impl IntoPortableQueryLiteral for time::Date {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        let formatted = self
            .format(&time::format_description::well_known::Iso8601::DATE)
            .map_err(|_| {
                DbError::query_encoding("time::Date could not be formatted as ISO 8601 text")
            })?;
        encode_text_literal(&formatted, out)?;
        out.push_str("::date");
        Ok(())
    }
}

impl IntoPortableQueryLiteral for serde_json::Value {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        // Compact JSON text cast to `jsonb`, matching SQLx's default binding for
        // `serde_json::Value`. `serde_json` escapes control characters (including
        // NUL, as `\u0000`) inside the produced text, so the rendered literal
        // itself is always NUL-free; Postgres applies its own `jsonb` validation
        // (e.g. rejecting `\u0000`) server-side, exactly as it does for a bound
        // parameter.
        let formatted = serde_json::to_string(self)
            .map_err(|_| DbError::query_encoding("serde_json::Value could not be serialized"))?;
        encode_text_literal(&formatted, out)?;
        out.push_str("::jsonb");
        Ok(())
    }
}

#[cfg(feature = "db-uuid")]
impl IntoPortableQueryLiteral for uuid::Uuid {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        // Hyphenated lowercase text cast to `uuid`. The hyphenated form is
        // fixed-charset ASCII, so the text encoding can never require escaping.
        encode_text_literal(&self.hyphenated().to_string(), out)?;
        out.push_str("::uuid");
        Ok(())
    }
}

impl IntoPortableQueryLiteral for str {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        encode_text_literal(self, out)
    }
}

impl IntoPortableQueryLiteral for String {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        self.as_str().encode_portable_query_literal(out)
    }
}

impl IntoPortableQueryLiteral for [u8] {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        encode_bytea_literal(self, out);
        Ok(())
    }
}

impl<const N: usize> IntoPortableQueryLiteral for [u8; N] {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        self.as_slice().encode_portable_query_literal(out)
    }
}

impl IntoPortableQueryLiteral for Vec<u8> {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        self.as_slice().encode_portable_query_literal(out)
    }
}

impl<T> IntoPortableQueryLiteral for Option<T>
where
    T: IntoPortableQueryLiteral,
{
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        match self {
            Some(value) => value.encode_portable_query_literal(out),
            None => {
                out.push_str("NULL");
                Ok(())
            }
        }
    }
}

fn encode_array_literal<T>(
    elements: &[T],
    pg_array_type: &str,
    encode_element: impl Fn(&T, &mut String) -> Result<(), DbError>,
    out: &mut String,
) -> Result<(), DbError> {
    out.push_str("ARRAY[");
    for (index, element) in elements.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        encode_element(element, out)?;
    }
    out.push_str("]::");
    out.push_str(pg_array_type);
    Ok(())
}

impl IntoPortableQueryLiteral for [String] {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        encode_array_literal(
            self,
            "text[]",
            |element, out| element.as_str().encode_portable_query_literal(out),
            out,
        )
    }
}

impl IntoPortableQueryLiteral for Vec<String> {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        self.as_slice().encode_portable_query_literal(out)
    }
}

impl IntoPortableQueryLiteral for [Vec<u8>] {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        encode_array_literal(
            self,
            "bytea[]",
            |element, out| element.as_slice().encode_portable_query_literal(out),
            out,
        )
    }
}

impl IntoPortableQueryLiteral for Vec<Vec<u8>> {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        self.as_slice().encode_portable_query_literal(out)
    }
}

impl IntoPortableQueryLiteral for [i64] {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        encode_array_literal(
            self,
            "bigint[]",
            |element, out| element.encode_portable_query_literal(out),
            out,
        )
    }
}

impl IntoPortableQueryLiteral for Vec<i64> {
    fn encode_portable_query_literal(&self, out: &mut String) -> Result<(), DbError> {
        self.as_slice().encode_portable_query_literal(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(value: impl IntoPortableQueryLiteral) -> Result<String, DbError> {
        let mut out = String::new();
        value.encode_portable_query_literal(&mut out)?;
        Ok(out)
    }

    #[test]
    fn scalars_encode_to_expected_literals() {
        assert_eq!(encode(true).unwrap(), "TRUE");
        assert_eq!(encode(false).unwrap(), "FALSE");
        assert_eq!(encode(1_i16).unwrap(), "(1)::smallint");
        assert_eq!(encode(1_i32).unwrap(), "(1)::integer");
        assert_eq!(encode(1_i64).unwrap(), "(1)::bigint");
        assert_eq!(encode(1.5_f64).unwrap(), "1.5::double precision");
        assert_eq!(encode("theme").unwrap(), "E'theme'");
        assert_eq!(encode("theme".to_owned()).unwrap(), "E'theme'");
        assert_eq!(
            encode(b"bytes".as_slice()).unwrap(),
            "E'\\\\x6279746573'::bytea"
        );
        assert_eq!(encode(vec![1u8, 2, 3]).unwrap(), "E'\\\\x010203'::bytea");
    }

    #[test]
    fn date_encodes_as_iso_8601_text_cast_to_date() {
        let date = time::Date::from_calendar_date(2026, time::Month::July, 8).unwrap();
        assert_eq!(encode(date).unwrap(), "E'2026-07-08'::date");
        assert_eq!(encode(Some(date)).unwrap(), "E'2026-07-08'::date");
        assert_eq!(encode(None::<time::Date>).unwrap(), "NULL");
    }

    #[test]
    fn json_encodes_compact_text_cast_to_jsonb_with_full_escaping() {
        let value = serde_json::json!({"key": "it's \"quoted\"", "n": 1});
        let encoded = encode(&value).unwrap();
        assert!(encoded.starts_with("E'"), "{encoded}");
        assert!(encoded.ends_with("'::jsonb"), "{encoded}");
        // The embedded single quote must be literal-escaped (E-string backslash
        // form, this encoder's convention), never raw.
        assert!(encoded.contains(r"it\'s"), "{encoded}");
        assert!(!encoded.contains("it's"), "{encoded}");
        // A JSON string containing a NUL escapes to \u0000 inside serde_json's
        // text, so the rendered literal itself never carries a raw NUL byte.
        let with_nul = serde_json::json!({"k": "a\u{0}b"});
        let encoded = encode(&with_nul).unwrap();
        assert!(!encoded.contains('\u{0}'));
        assert!(encoded.contains("\\u0000"), "{encoded}");
    }

    #[cfg(feature = "db-uuid")]
    #[test]
    fn uuid_encodes_as_hyphenated_text_cast_to_uuid() {
        let id = uuid::Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").unwrap();
        assert_eq!(
            encode(id).unwrap(),
            "E'67e55044-10b1-426f-9247-bb680e5fe0c8'::uuid"
        );
    }

    #[test]
    fn negative_scalar_extremes_do_not_overflow_before_cast() {
        assert_eq!(encode(i16::MIN).unwrap(), "(-32768)::smallint");
        assert_eq!(encode(i32::MIN).unwrap(), "(-2147483648)::integer");
        assert_eq!(encode(i64::MIN).unwrap(), "(-9223372036854775808)::bigint");
    }

    #[test]
    fn option_none_renders_as_null_and_some_delegates() {
        assert_eq!(encode(Option::<i64>::None).unwrap(), "NULL");
        assert_eq!(encode(Some(1_i64)).unwrap(), "(1)::bigint");
    }

    #[test]
    #[allow(
        clippy::needless_borrows_for_generic_args,
        reason = "deliberately passes a reference to prove the blanket &T impl delegates \
                  to the owned impl, not merely that the owned value itself encodes"
    )]
    fn references_delegate_to_owned_impls() {
        let value = 1_i64;
        assert_eq!(encode(&value).unwrap(), "(1)::bigint");
        let text = "theme".to_owned();
        assert_eq!(encode(&text).unwrap(), "E'theme'");
    }

    #[test]
    fn text_array_encodes_as_text_array() {
        let values = vec!["a".to_owned(), "b".to_owned()];
        assert_eq!(encode(values.clone()).unwrap(), "ARRAY[E'a',E'b']::text[]");
        assert_eq!(
            encode(values.as_slice()).unwrap(),
            "ARRAY[E'a',E'b']::text[]"
        );
        assert_eq!(encode(Vec::<String>::new()).unwrap(), "ARRAY[]::text[]");
    }

    #[test]
    fn bytea_array_encodes_as_bytea_array() {
        let values = vec![vec![1u8], vec![2u8]];
        assert_eq!(
            encode(values).unwrap(),
            "ARRAY[E'\\\\x01'::bytea,E'\\\\x02'::bytea]::bytea[]"
        );
    }

    #[test]
    fn bigint_array_encodes_with_per_element_cast() {
        let values: Vec<i64> = vec![1, 2];
        assert_eq!(
            encode(values).unwrap(),
            "ARRAY[(1)::bigint,(2)::bigint]::bigint[]"
        );
    }

    #[test]
    fn nul_byte_in_text_is_rejected() {
        assert!(encode("a\0b").is_err());
        let values = vec!["a\0b".to_owned()];
        assert!(encode(values).is_err());
    }

    #[test]
    fn offset_date_time_encodes_as_rfc3339_timestamptz() {
        let date = time::Date::from_calendar_date(2026, time::Month::July, 8).unwrap();
        let time_of_day = time::Time::from_hms_milli(12, 34, 56, 789).unwrap();
        let value = date.with_time(time_of_day).assume_utc();
        assert_eq!(
            encode(value).unwrap(),
            "E'2026-07-08T12:34:56.789Z'::timestamptz"
        );
    }

    #[test]
    fn offset_date_time_preserves_non_utc_offset() {
        let date = time::Date::from_calendar_date(2026, time::Month::July, 8).unwrap();
        let time_of_day = time::Time::from_hms(12, 34, 56).unwrap();
        let offset = time::UtcOffset::from_hms(-5, 0, 0).unwrap();
        let value = date.with_time(time_of_day).assume_offset(offset);
        assert_eq!(
            encode(value).unwrap(),
            "E'2026-07-08T12:34:56-05:00'::timestamptz"
        );
    }
}
