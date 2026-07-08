#![no_main]

use libfuzzer_sys::fuzz_target;
use paranoid::db::{AuditedSql, PostgresLiteral, SimpleQuery};

fuzz_target!(|data: &[u8]| {
    exercise_simple_query_literal_encoder(data);
});

fn exercise_simple_query_literal_encoder(data: &[u8]) {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    match selector % 9 {
        0 => check_null(),
        1 => check_bool(rest),
        2 => check_i16(rest),
        3 => check_i32(rest),
        4 => check_i64(rest),
        5 => check_f64(rest),
        6 => check_text(rest),
        7 => check_bytea(rest),
        8 => check_text_cast(rest),
        _ => unreachable!("selector % 9 is always in 0..9"),
    }
    check_array(data);
}

fn encode(literal: PostgresLiteral<'_>) -> Result<String, paranoid::db::Error> {
    SimpleQuery::new()
        .push_literal(literal)
        .map(|query| query.as_sql().to_owned())
}

fn check_null() {
    let sql = encode(PostgresLiteral::Null).expect("NULL never fails to encode");
    assert_eq!(sql, "NULL");
}

fn check_bool(rest: &[u8]) {
    let value = rest.first().is_some_and(|byte| byte & 1 == 1);
    let sql = encode(PostgresLiteral::Bool(value)).expect("bool never fails to encode");
    assert_eq!(sql, if value { "TRUE" } else { "FALSE" });
}

fn check_i16(rest: &[u8]) {
    let value = i16::from_le_bytes(take_bytes(rest));
    let sql = encode(PostgresLiteral::I16(value)).expect("i16 never fails to encode");
    assert_eq!(decode_cast_integer::<i16>(&sql, "smallint"), Some(value));
}

fn check_i32(rest: &[u8]) {
    let value = i32::from_le_bytes(take_bytes(rest));
    let sql = encode(PostgresLiteral::I32(value)).expect("i32 never fails to encode");
    assert_eq!(decode_cast_integer::<i32>(&sql, "integer"), Some(value));
}

fn check_i64(rest: &[u8]) {
    let value = i64::from_le_bytes(take_bytes(rest));
    let sql = encode(PostgresLiteral::I64(value)).expect("i64 never fails to encode");
    assert_eq!(decode_cast_integer::<i64>(&sql, "bigint"), Some(value));
}

fn check_f64(rest: &[u8]) {
    let value = f64::from_le_bytes(take_bytes(rest));
    let sql = encode(PostgresLiteral::F64(value)).expect("f64 never fails to encode");
    if value.is_nan() {
        assert_eq!(sql, "'NaN'::double precision");
        return;
    }
    if value == f64::INFINITY {
        assert_eq!(sql, "'Infinity'::double precision");
        return;
    }
    if value == f64::NEG_INFINITY {
        assert_eq!(sql, "'-Infinity'::double precision");
        return;
    }
    let decoded = sql
        .strip_suffix("::double precision")
        .and_then(|text| text.parse::<f64>().ok())
        .expect("finite float renders as a parseable double precision literal");
    assert_eq!(decoded.to_bits(), value.to_bits());
}

fn check_text(rest: &[u8]) {
    let value = String::from_utf8_lossy(rest).into_owned();
    match encode(PostgresLiteral::Text(&value)) {
        Ok(sql) => {
            let decoded = decode_escape_string_literal(&sql)
                .expect("successful text encoding is always a well-formed escape string");
            assert_eq!(decoded, value);
        }
        Err(error) => assert!(
            matches!(error, paranoid::db::Error::LiteralEncoding { .. }),
            "text encoding failed for a reason other than literal encoding: {error:?}"
        ),
    }
}

fn check_bytea(rest: &[u8]) {
    let sql = encode(PostgresLiteral::Bytea(rest)).expect("bytea never fails to encode");
    let decoded =
        decode_hex_escape_bytea(&sql).expect("bytea encoding is always a well-formed hex escape");
    assert_eq!(decoded, rest);
}

fn check_text_cast(rest: &[u8]) {
    let value = String::from_utf8_lossy(rest).into_owned();
    let literal = PostgresLiteral::TextCast {
        value: &value,
        pg_type: AuditedSql::new("uuid"),
    };
    match encode(literal) {
        Ok(sql) => {
            let escaped = sql
                .strip_suffix("::uuid")
                .expect("text cast always ends with the vouched cast type");
            let decoded = decode_escape_string_literal(escaped)
                .expect("successful text cast encoding is always a well-formed escape string");
            assert_eq!(decoded, value);
        }
        Err(error) => assert!(
            matches!(error, paranoid::db::Error::LiteralEncoding { .. }),
            "text cast encoding failed for a reason other than literal encoding: {error:?}"
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScalarElement {
    Null,
    Int(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TopElement {
    Scalar(ScalarElement),
    Nested(Vec<ScalarElement>),
}

/// Builds a bounded array specification (0..4 top-level elements, each either `NULL`, an
/// `i32`, or one nested sub-array of 0..4 scalar elements) from fuzz bytes. Nesting is
/// capped at a single level: `PostgresLiteral::Array` recurses uniformly regardless of
/// depth, so one level exercises the same encoder code path arbitrary depth would, without
/// the self-referential-lifetime bookkeeping unbounded recursion would require here.
fn build_array_spec(data: &[u8]) -> Vec<TopElement> {
    let element_count = data.first().map_or(0, |byte| byte % 4);
    (0..element_count)
        .map(|index| {
            let chunk = data.get(1 + usize::from(index) * 6..).unwrap_or(&[]);
            let kind = chunk.first().copied().unwrap_or(0);
            let value_bytes = chunk.get(1..).unwrap_or(&[]);
            if kind % 3 == 0 {
                TopElement::Scalar(ScalarElement::Null)
            } else if kind % 3 == 1 {
                TopElement::Scalar(ScalarElement::Int(i32::from_le_bytes(take_bytes(
                    value_bytes,
                ))))
            } else {
                TopElement::Nested(build_scalar_spec(value_bytes))
            }
        })
        .collect()
}

fn build_scalar_spec(data: &[u8]) -> Vec<ScalarElement> {
    let element_count = data.first().map_or(0, |byte| byte % 4);
    (0..element_count)
        .map(|index| {
            let chunk = data.get(1 + usize::from(index) * 5..).unwrap_or(&[]);
            let kind = chunk.first().copied().unwrap_or(0);
            let value_bytes = chunk.get(1..).unwrap_or(&[]);
            if kind % 2 == 0 {
                ScalarElement::Null
            } else {
                ScalarElement::Int(i32::from_le_bytes(take_bytes(value_bytes)))
            }
        })
        .collect()
}

fn scalar_as_literal(element: ScalarElement) -> PostgresLiteral<'static> {
    match element {
        ScalarElement::Null => PostgresLiteral::Null,
        ScalarElement::Int(value) => PostgresLiteral::I32(value),
    }
}

fn check_array(data: &[u8]) {
    let spec = build_array_spec(data);

    let nested_literals: Vec<Vec<PostgresLiteral<'static>>> = spec
        .iter()
        .map(|element| match element {
            TopElement::Nested(children) => {
                children.iter().copied().map(scalar_as_literal).collect()
            }
            TopElement::Scalar(_) => Vec::new(),
        })
        .collect();

    let top_literals: Vec<PostgresLiteral<'_>> = spec
        .iter()
        .zip(nested_literals.iter())
        .map(|(element, nested)| match element {
            TopElement::Scalar(scalar) => scalar_as_literal(*scalar),
            TopElement::Nested(_) => PostgresLiteral::Array {
                elements: nested.as_slice(),
                element_pg_type: AuditedSql::new("int4"),
            },
        })
        .collect();

    let literal = PostgresLiteral::Array {
        elements: &top_literals,
        element_pg_type: AuditedSql::new("int4"),
    };
    let sql = encode(literal).expect("an int4 array of ints/nulls never fails to encode");
    let body = sql
        .strip_prefix("ARRAY[")
        .and_then(|text| text.strip_suffix("]::int4[]"))
        .expect("array encoding always uses the ARRAY[...]::int4[] constructor");
    let decoded = decode_top_elements(body);
    assert_eq!(decoded, spec);
}

fn decode_top_elements(body: &str) -> Vec<TopElement> {
    if body.is_empty() {
        return Vec::new();
    }
    split_top_level_commas(body)
        .into_iter()
        .map(|token| {
            if let Some(inner) = token
                .strip_prefix("ARRAY[")
                .and_then(|text| text.strip_suffix("]::int4[]"))
            {
                TopElement::Nested(decode_scalar_elements(inner))
            } else {
                TopElement::Scalar(decode_scalar_element(token))
            }
        })
        .collect()
}

fn decode_scalar_elements(body: &str) -> Vec<ScalarElement> {
    if body.is_empty() {
        return Vec::new();
    }
    split_top_level_commas(body)
        .into_iter()
        .map(decode_scalar_element)
        .collect()
}

fn decode_scalar_element(token: &str) -> ScalarElement {
    if token == "NULL" {
        return ScalarElement::Null;
    }
    let value = decode_cast_integer::<i32>(token, "integer")
        .expect("a non-NULL array scalar element decodes as a cast integer");
    ScalarElement::Int(value)
}

fn split_top_level_commas(body: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut depth: i32 = 0;
    let mut token_start = 0;
    for (byte_index, character) in body.char_indices() {
        match character {
            '[' => depth += 1,
            ']' => depth -= 1,
            ',' if depth == 0 => {
                tokens.push(&body[token_start..byte_index]);
                token_start = byte_index + character.len_utf8();
            }
            _ => {}
        }
    }
    tokens.push(&body[token_start..]);
    tokens
}

fn decode_cast_integer<T>(sql: &str, cast: &str) -> Option<T>
where
    T: std::str::FromStr,
{
    let suffix = format!("::{cast}");
    let without_cast = sql.strip_suffix(suffix.as_str())?;
    let inner = without_cast.strip_prefix('(')?.strip_suffix(')')?;
    inner.parse::<T>().ok()
}

fn decode_escape_string_literal(sql: &str) -> Option<String> {
    let without_prefix = sql.strip_prefix("E'")?;
    let without_suffix = without_prefix.strip_suffix('\'')?;
    let mut result = String::new();
    let mut characters = without_suffix.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            match characters.next()? {
                '\\' => result.push('\\'),
                '\'' => result.push('\''),
                _ => return None,
            }
        } else if character == '\'' {
            return None;
        } else {
            result.push(character);
        }
    }
    Some(result)
}

fn decode_hex_escape_bytea(sql: &str) -> Option<Vec<u8>> {
    let hex = sql
        .strip_prefix("E'\\\\x")
        .and_then(|text| text.strip_suffix("'::bytea"))?;
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).ok())
        .collect()
}

fn take_bytes<const N: usize>(data: &[u8]) -> [u8; N] {
    let mut bytes = [0_u8; N];
    let copy_len = data.len().min(N);
    bytes[..copy_len].copy_from_slice(&data[..copy_len]);
    bytes
}
