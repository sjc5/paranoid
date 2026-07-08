//! Round-trip tests proving the [`SimpleQuery`] literal encoder is both correct and
//! injection-safe against a real Postgres: every value, including adversarial strings, is
//! encoded, executed through the simple protocol, and read back byte-for-byte equal to the
//! original. If any encoding could break out of its literal, an adversarial case would
//! either corrupt the read-back value or execute injected SQL and fail these assertions.

use sqlx::Row;

use super::postgres_test_support::{connect_sqlx_pool_for_harness, standard_test_database_url};
use super::{AuditedSql, PostgresLiteral, SimpleQuery};

async fn harness_pool() -> sqlx::PgPool {
    connect_sqlx_pool_for_harness(
        &standard_test_database_url(),
        1,
        "paranoid.simple-query.roundtrip",
    )
    .await
}

/// Executes `SELECT (<literal>)::<cast>` through the parameter-less simple protocol and
/// returns the single value read back as `T`.
async fn round_trip<'v, T>(pool: &sqlx::PgPool, literal: PostgresLiteral<'v>, cast: &str) -> T
where
    T: for<'r> sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    let query = SimpleQuery::new()
        .push_sql(AuditedSql::new("SELECT ("))
        .push_literal(literal)
        .expect("literal encodes")
        .push_sql(AuditedSql::new(")::"))
        .push_sql(AuditedSql::new(cast))
        .push_sql(AuditedSql::new(" AS value"))
        .into_raw_sql();
    let row = query
        .fetch_one(pool)
        .await
        .expect("simple-protocol query runs");
    row.try_get::<T, _>("value")
        .expect("decode round-tripped value")
}

#[tokio::test]
async fn text_round_trips_including_adversarial_values() {
    let pool = harness_pool().await;
    let cases = [
        "",
        "theme",
        "O'Brien",
        "back\\slash",
        "both ' and \\ together",
        "'; DROP TABLE users; --",
        "E'\\x41'", // literal that looks like another encoding
        "line1\nline2\ttab",
        "unicode: café ☃ 🦀",
        "%s %d {} $1 $$ ${x}", // format-like noise must stay inert
    ];
    for case in cases {
        let read_back: String = round_trip(&pool, PostgresLiteral::Text(case), "text").await;
        assert_eq!(read_back, case, "text round-trip failed for {case:?}");
    }
}

#[tokio::test]
async fn bytea_round_trips_including_edge_bytes() {
    let pool = harness_pool().await;
    let cases: [&[u8]; 5] = [
        &[],
        &[0x00],
        &[0xff],
        &[0x00, 0x01, 0x27, 0x5c, 0xff], // includes ', \ as raw bytes
        b"binary '\\ payload",
    ];
    for case in cases {
        let read_back: Vec<u8> = round_trip(&pool, PostgresLiteral::Bytea(case), "bytea").await;
        assert_eq!(read_back, case, "bytea round-trip failed for {case:?}");
    }
}

#[tokio::test]
async fn integers_round_trip_including_bounds() {
    let pool = harness_pool().await;
    for value in [i16::MIN, -1, 0, 1, i16::MAX] {
        let read_back: i16 = round_trip(&pool, PostgresLiteral::I16(value), "smallint").await;
        assert_eq!(read_back, value);
    }
    for value in [i32::MIN, 0, i32::MAX] {
        let read_back: i32 = round_trip(&pool, PostgresLiteral::I32(value), "integer").await;
        assert_eq!(read_back, value);
    }
    for value in [i64::MIN, 0, i64::MAX] {
        let read_back: i64 = round_trip(&pool, PostgresLiteral::I64(value), "bigint").await;
        assert_eq!(read_back, value);
    }
}

#[tokio::test]
async fn bool_and_float_round_trip() {
    let pool = harness_pool().await;
    for value in [true, false] {
        let read_back: bool = round_trip(&pool, PostgresLiteral::Bool(value), "boolean").await;
        assert_eq!(read_back, value);
    }
    for value in [0.0_f64, -1.5, 12_345.678_9, f64::MIN, f64::MAX] {
        let read_back: f64 =
            round_trip(&pool, PostgresLiteral::F64(value), "double precision").await;
        assert_eq!(read_back, value);
    }
}

#[tokio::test]
async fn null_round_trips_as_none() {
    let pool = harness_pool().await;
    let read_back: Option<String> = round_trip(&pool, PostgresLiteral::Null, "text").await;
    assert_eq!(read_back, None);
}

#[tokio::test]
async fn text_cast_round_trips_for_uuid_timestamptz_and_jsonb() {
    let pool = harness_pool().await;

    let uuid_text = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    let read_uuid: String = round_trip(
        &pool,
        PostgresLiteral::TextCast {
            value: uuid_text,
            pg_type: AuditedSql::new("uuid"),
        },
        "text",
    )
    .await;
    assert_eq!(read_uuid, uuid_text);

    // jsonb containing quotes/backslashes must survive as data, not structure.
    let json_text = r#"{"k":"v'x","b":"a\\b","n":[1,2,3]}"#;
    let read_json: String = round_trip(
        &pool,
        PostgresLiteral::TextCast {
            value: json_text,
            pg_type: AuditedSql::new("jsonb"),
        },
        "text",
    )
    .await;
    // jsonb normalizes whitespace but preserves values; assert the escaped substrings survive.
    assert!(
        read_json.contains("v'x"),
        "jsonb lost quote value: {read_json}"
    );
    assert!(
        read_json.contains("a\\\\b"),
        "jsonb lost backslash value: {read_json}"
    );
}

#[tokio::test]
async fn int_and_text_arrays_round_trip_including_adversarial_elements() {
    let pool = harness_pool().await;

    let ints: Vec<i32> = round_trip(
        &pool,
        PostgresLiteral::Array {
            elements: &[
                PostgresLiteral::I32(i32::MIN),
                PostgresLiteral::I32(0),
                PostgresLiteral::I32(i32::MAX),
            ],
            element_pg_type: AuditedSql::new("int4"),
        },
        "int4[]",
    )
    .await;
    assert_eq!(ints, vec![i32::MIN, 0, i32::MAX]);

    // Each text element carries quotes/backslashes and an injection attempt; all must come
    // back as inert data in the right slots.
    let elements = [
        PostgresLiteral::Text("O'Brien"),
        PostgresLiteral::Text("a\\b"),
        PostgresLiteral::Text("'; DROP TABLE t; --"),
    ];
    let texts: Vec<String> = round_trip(
        &pool,
        PostgresLiteral::Array {
            elements: &elements,
            element_pg_type: AuditedSql::new("text"),
        },
        "text[]",
    )
    .await;
    assert_eq!(
        texts,
        vec![
            "O'Brien".to_owned(),
            "a\\b".to_owned(),
            "'; DROP TABLE t; --".to_owned(),
        ]
    );

    // Empty arrays are legal and round-trip as an empty vector.
    let empty: Vec<i32> = round_trip(
        &pool,
        PostgresLiteral::Array {
            elements: &[],
            element_pg_type: AuditedSql::new("int4"),
        },
        "int4[]",
    )
    .await;
    assert_eq!(empty, Vec::<i32>::new());
}

#[tokio::test]
async fn non_finite_floats_round_trip() {
    let pool = harness_pool().await;
    let nan: f64 = round_trip(&pool, PostgresLiteral::F64(f64::NAN), "double precision").await;
    assert!(nan.is_nan(), "NaN did not round-trip: {nan}");
    let inf: f64 = round_trip(
        &pool,
        PostgresLiteral::F64(f64::INFINITY),
        "double precision",
    )
    .await;
    assert_eq!(inf, f64::INFINITY);
    let neg_inf: f64 = round_trip(
        &pool,
        PostgresLiteral::F64(f64::NEG_INFINITY),
        "double precision",
    )
    .await;
    assert_eq!(neg_inf, f64::NEG_INFINITY);
}

#[tokio::test]
async fn text_cast_accepts_multiword_and_array_type_names() {
    let pool = harness_pool().await;

    // A multi-word type name (rejected by the old character-filter) now works because the
    // cast target is caller-vouched structure.
    let ts = "2026-07-04 12:00:00+00";
    let read_ts: String = round_trip(
        &pool,
        PostgresLiteral::TextCast {
            value: ts,
            pg_type: AuditedSql::new("timestamp with time zone"),
        },
        "text",
    )
    .await;
    assert!(
        read_ts.contains("2026-07-04"),
        "timestamptz lost value: {read_ts}"
    );

    // An array element type may itself be a vouched multi-word type.
    let read_arr: Vec<i64> = round_trip(
        &pool,
        PostgresLiteral::Array {
            elements: &[PostgresLiteral::I64(1), PostgresLiteral::I64(2)],
            element_pg_type: AuditedSql::new("bigint"),
        },
        "int8[]",
    )
    .await;
    assert_eq!(read_arr, vec![1_i64, 2]);
}

#[tokio::test]
async fn arrays_with_null_elements_round_trip_including_all_null_arrays() {
    let pool = harness_pool().await;

    let all_null: Vec<Option<i32>> = round_trip(
        &pool,
        PostgresLiteral::Array {
            elements: &[
                PostgresLiteral::Null,
                PostgresLiteral::Null,
                PostgresLiteral::Null,
            ],
            element_pg_type: AuditedSql::new("int4"),
        },
        "int4[]",
    )
    .await;
    assert_eq!(all_null, vec![None, None, None]);

    let mixed: Vec<Option<i32>> = round_trip(
        &pool,
        PostgresLiteral::Array {
            elements: &[
                PostgresLiteral::I32(1),
                PostgresLiteral::Null,
                PostgresLiteral::I32(3),
            ],
            element_pg_type: AuditedSql::new("int4"),
        },
        "int4[]",
    )
    .await;
    assert_eq!(mixed, vec![Some(1), None, Some(3)]);
}

#[tokio::test]
async fn nested_arrays_with_mismatched_lengths_are_rejected_by_postgres_not_silently_reshaped() {
    let pool = harness_pool().await;
    let inner_a = PostgresLiteral::Array {
        elements: &[PostgresLiteral::I32(1), PostgresLiteral::I32(2)],
        element_pg_type: AuditedSql::new("int4"),
    };
    let inner_b = PostgresLiteral::Array {
        elements: &[PostgresLiteral::I32(3)],
        element_pg_type: AuditedSql::new("int4"),
    };
    let query = SimpleQuery::new()
        .push_sql(AuditedSql::new("SELECT ("))
        .push_literal(PostgresLiteral::Array {
            elements: &[inner_a, inner_b],
            element_pg_type: AuditedSql::new("int4"),
        })
        .expect("literal encodes")
        .push_sql(AuditedSql::new(")::int4[] AS value"))
        .into_raw_sql();
    let error = query
        .fetch_one(&pool)
        .await
        .expect_err("Postgres must reject a non-rectangular nested array");
    let code = error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .expect("a rejected nested array should carry a Postgres SQLSTATE");
    assert_eq!(
        code, "2202E",
        "expected array_subscript_error for mismatched nested array lengths, got {code}"
    );
}

#[tokio::test]
async fn nested_arrays_construct_correct_multidimensional_postgres_arrays() {
    let pool = harness_pool().await;
    let inner_a = PostgresLiteral::Array {
        elements: &[PostgresLiteral::I32(1), PostgresLiteral::I32(2)],
        element_pg_type: AuditedSql::new("int4"),
    };
    let inner_b = PostgresLiteral::Array {
        elements: &[PostgresLiteral::I32(3), PostgresLiteral::I32(4)],
        element_pg_type: AuditedSql::new("int4"),
    };
    // sqlx has no `PgHasArrayType` implementation for `Vec<T>`, so a genuine
    // multidimensional Postgres array cannot be decoded through sqlx as `Vec<Vec<T>>`.
    // Cast the result to `text` instead, reading back Postgres's own canonical array
    // text representation, which proves the constructor built a real 2-D array (not
    // merely SQL that happens to parse) without depending on sqlx's decode support for
    // the shape it produces.
    let read_back: String = round_trip(
        &pool,
        PostgresLiteral::Array {
            elements: &[inner_a, inner_b],
            element_pg_type: AuditedSql::new("int4"),
        },
        "int4[]::text",
    )
    .await;
    assert_eq!(read_back, "{{1,2},{3,4}}");
}

#[tokio::test]
async fn nested_text_arrays_keep_adversarial_elements_as_inert_data() {
    let pool = harness_pool().await;
    let inner_a = PostgresLiteral::Array {
        elements: &[
            PostgresLiteral::Text("O'Brien"),
            PostgresLiteral::Text("a\\b"),
        ],
        element_pg_type: AuditedSql::new("text"),
    };
    let inner_b = PostgresLiteral::Array {
        elements: &[
            PostgresLiteral::Text("'; DROP TABLE t; --"),
            PostgresLiteral::Text("z"),
        ],
        element_pg_type: AuditedSql::new("text"),
    };
    let read_back: String = round_trip(
        &pool,
        PostgresLiteral::Array {
            elements: &[inner_a, inner_b],
            element_pg_type: AuditedSql::new("text"),
        },
        "text[]::text",
    )
    .await;
    assert!(read_back.contains("O'Brien"), "lost value: {read_back}");
    assert!(read_back.contains("a\\\\b"), "lost value: {read_back}");
    assert!(
        read_back.contains("DROP TABLE t"),
        "lost value: {read_back}"
    );
}

#[tokio::test]
async fn array_of_textcast_uuid_elements_round_trips() {
    let pool = harness_pool().await;
    let elements = [
        PostgresLiteral::TextCast {
            value: "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            pg_type: AuditedSql::new("uuid"),
        },
        PostgresLiteral::TextCast {
            value: "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
            pg_type: AuditedSql::new("uuid"),
        },
    ];
    let read_back: Vec<String> = round_trip(
        &pool,
        PostgresLiteral::Array {
            elements: &elements,
            element_pg_type: AuditedSql::new("uuid"),
        },
        "text[]",
    )
    .await;
    assert_eq!(
        read_back,
        vec![
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_owned(),
            "6ba7b811-9dad-11d1-80b4-00c04fd430c8".to_owned(),
        ]
    );
}

#[tokio::test]
async fn float_edge_values_round_trip_exact_bit_patterns() {
    let pool = harness_pool().await;
    let values = [
        0.0_f64,
        -0.0_f64,
        f64::MIN_POSITIVE,
        -f64::MIN_POSITIVE,
        f64::EPSILON,
        f64::MAX,
        f64::MIN,
    ];
    for value in values {
        let read_back: f64 =
            round_trip(&pool, PostgresLiteral::F64(value), "double precision").await;
        assert_eq!(
            read_back.to_bits(),
            value.to_bits(),
            "float bit pattern changed for {value:?}: got {read_back:?}"
        );
    }
}

#[tokio::test]
async fn injected_sql_in_text_does_not_execute() {
    let pool = harness_pool().await;
    // If the quote escaping were broken, this would run a second statement and change the
    // result type/shape. Instead it must come back as the literal string.
    let payload = "x') ; SELECT pg_sleep(0) ; SELECT ('y";
    let read_back: String = round_trip(&pool, PostgresLiteral::Text(payload), "text").await;
    assert_eq!(read_back, payload);
}

mod generated_value_round_trips {
    use super::{PostgresLiteral, harness_pool, round_trip};
    use proptest::prelude::*;
    use std::sync::OnceLock;

    fn shared_runtime() -> &'static tokio::runtime::Runtime {
        static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
        RUNTIME.get_or_init(|| {
            tokio::runtime::Runtime::new()
                .expect("build tokio runtime for generated round-trip property tests")
        })
    }

    fn shared_pool() -> sqlx::PgPool {
        static POOL: OnceLock<sqlx::PgPool> = OnceLock::new();
        POOL.get_or_init(|| shared_runtime().block_on(harness_pool()))
            .clone()
    }

    fn generated_text_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(any::<char>(), 0..48)
            .prop_map(|chars| chars.into_iter().collect::<String>())
            .prop_filter(
                "a Postgres text literal cannot represent an interior NUL byte",
                |value| !value.as_bytes().contains(&0),
            )
    }

    proptest! {
        #[test]
        fn text_round_trips_for_generated_strings(value in generated_text_strategy()) {
            let pool = shared_pool();
            let read_back: String =
                shared_runtime().block_on(round_trip(&pool, PostgresLiteral::Text(&value), "text"));
            prop_assert_eq!(read_back, value);
        }

        #[test]
        fn bytea_round_trips_for_generated_bytes(value in prop::collection::vec(any::<u8>(), 0..64)) {
            let pool = shared_pool();
            let read_back: Vec<u8> = shared_runtime().block_on(round_trip(
                &pool,
                PostgresLiteral::Bytea(&value),
                "bytea",
            ));
            prop_assert_eq!(read_back, value);
        }

        #[test]
        fn integers_round_trip_for_generated_values(value in any::<i64>()) {
            let pool = shared_pool();
            let read_back: i64 =
                shared_runtime().block_on(round_trip(&pool, PostgresLiteral::I64(value), "bigint"));
            prop_assert_eq!(read_back, value);
        }

        #[test]
        fn text_arrays_round_trip_for_generated_element_lists(
            values in prop::collection::vec(generated_text_strategy(), 0..8),
        ) {
            let pool = shared_pool();
            let elements: Vec<PostgresLiteral<'_>> = values
                .iter()
                .map(|value| PostgresLiteral::Text(value.as_str()))
                .collect();
            let read_back: Vec<String> = shared_runtime().block_on(round_trip(
                &pool,
                PostgresLiteral::Array {
                    elements: &elements,
                    element_pg_type: super::AuditedSql::new("text"),
                },
                "text[]",
            ));
            prop_assert_eq!(read_back, values);
        }
    }
}
