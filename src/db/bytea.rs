use sqlx::postgres::{PgTypeInfo, PgValueFormat, PgValueRef};
use sqlx::{Decode, Postgres, Type, error::BoxDynError};

/// Owned protocol bytes decoded independently of PostgreSQL's bytea_output setting.
pub(crate) struct Bytea(pub(crate) Vec<u8>);

impl Type<Postgres> for Bytea {
    fn type_info() -> PgTypeInfo {
        <Vec<u8> as Type<Postgres>>::type_info()
    }
}

impl Decode<'_, Postgres> for Bytea {
    fn decode(value: PgValueRef<'_>) -> Result<Self, BoxDynError> {
        if value.format() == PgValueFormat::Binary || value.as_bytes()?.starts_with(br"\x") {
            return <Vec<u8> as Decode<Postgres>>::decode(value).map(Self);
        }
        decode_escape_bytes(value.as_bytes()?).map(Self)
    }
}

fn decode_escape_bytes(input: &[u8]) -> Result<Vec<u8>, BoxDynError> {
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] != b'\\' {
            output.push(input[index]);
            index += 1;
        } else if input.get(index + 1) == Some(&b'\\') {
            output.push(b'\\');
            index += 2;
        } else {
            let Some(digits) = input.get(index + 1..index + 4) else {
                return Err("incomplete bytea escape".into());
            };
            if !(b'0'..=b'3').contains(&digits[0])
                || !digits[1..]
                    .iter()
                    .all(|digit| (b'0'..=b'7').contains(digit))
            {
                return Err("invalid bytea octal escape".into());
            }
            output.push(((digits[0] - b'0') << 6) | ((digits[1] - b'0') << 3) | (digits[2] - b'0'));
            index += 4;
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_bytes_preserve_all_byte_values_and_literal_backslashes() {
        let encoded = (0..=255)
            .map(|byte| format!("\\{byte:03o}"))
            .collect::<String>();
        assert_eq!(
            decode_escape_bytes(encoded.as_bytes()).expect("all octal bytes"),
            (0..=255).collect::<Vec<u8>>()
        );
        assert_eq!(
            decode_escape_bytes(br"plain\\text\000\377").expect("mixed escape syntax"),
            b"plain\\text\0\xff"
        );
        assert!(decode_escape_bytes(b"").expect("empty bytea").is_empty());
    }

    #[test]
    fn escape_bytes_reject_invalid_and_incomplete_octal_sequences() {
        for input in [
            br"\".as_slice(),
            br"\0",
            br"\00",
            br"\400",
            br"\08a",
            br"\zzz",
        ] {
            assert!(
                decode_escape_bytes(input).is_err(),
                "invalid bytea must fail"
            );
        }
    }
}
