use super::*;
use proptest::prelude::*;

fn valid_kv_key_part_strategy() -> impl Strategy<Value = String> {
    let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-%\\é日"
        .chars()
        .collect::<Vec<_>>();
    prop::collection::vec(prop::sample::select(chars), 1..=24)
        .prop_map(|chars| chars.into_iter().collect())
}

fn invalid_kv_key_part_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        (valid_kv_key_part_strategy(), valid_kv_key_part_strategy())
            .prop_map(|(left, right)| format!("{left}:{right}")),
        (valid_kv_key_part_strategy(), valid_kv_key_part_strategy())
            .prop_map(|(left, right)| format!("{left}\0{right}")),
    ]
}

fn safe_raw_suffix_strategy() -> impl Strategy<Value = String> {
    let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-:%\\"
        .chars()
        .collect::<Vec<_>>();
    prop::collection::vec(prop::sample::select(chars), 0..=64)
        .prop_map(|chars| chars.into_iter().collect())
}

fn unsafe_raw_suffix_strategy() -> impl Strategy<Value = String> {
    (safe_raw_suffix_strategy(), safe_raw_suffix_strategy())
        .prop_map(|(left, right)| format!("{left}\0{right}"))
}

fn valid_pg_identifier_strategy(max_bytes: usize) -> impl Strategy<Value = String> {
    let first_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
        .chars()
        .collect::<Vec<_>>();
    let trailing_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
        .chars()
        .collect::<Vec<_>>();
    (
        prop::sample::select(first_chars),
        prop::collection::vec(
            prop::sample::select(trailing_chars),
            0..=max_bytes.saturating_sub(1),
        ),
    )
        .prop_map(|(first, trailing)| {
            let mut out = String::with_capacity(1 + trailing.len());
            out.push(first);
            out.extend(trailing);
            out
        })
}

fn expected_key_text(parts: &[String]) -> String {
    let mut expected = parts.join(KV_KEY_SEPARATOR);
    expected.push_str(KV_KEY_SEPARATOR);
    expected
}

fn expected_like_pattern(prefix: &KeyPrefix) -> String {
    let mut expected = String::new();
    for ch in prefix.as_str().chars() {
        if matches!(ch, '\\' | '%' | '_') {
            expected.push('\\');
        }
        expected.push(ch);
    }
    expected.push('%');
    expected
}

#[test]
fn migration_sql_uses_c_collation_and_text_pattern_ops() {
    let config = StoreConfig::default();
    let statements = build_migrate_statements(&config);
    let joined = statements.join("\n");

    assert!(
        joined.contains(r#"key TEXT COLLATE "C" PRIMARY KEY CHECK (octet_length(key) > 0 AND octet_length(key) <= 2048)"#)
    );
    assert!(joined.contains("value BYTEA NOT NULL"));
    assert!(joined.contains("expires_at TIMESTAMPTZ"));
    assert!(joined.contains("updated_at TIMESTAMPTZ NOT NULL"));
    assert!(joined.contains("key text_pattern_ops"));
    assert!(joined.contains("WHERE expires_at IS NOT NULL"));
}

#[test]
fn migration_sql_does_not_use_session_level_postgres_features() {
    let config = StoreConfig::default();
    let catalog = KvCatalog::new(&config);
    let queries = Queries::new(&catalog);
    let joined = [
        build_migrate_statements(&config).join("\n"),
        queries.delete_expired_keys_once,
        queries.delete_keys_with_prefix_once,
        queries.ensure_slot_keys_exist,
        queries.acquire_slot,
        queries.lock_key_for_atomic_mutation,
        queries.update_key_value_with_ttl_for_atomic_mutation,
        queries.update_key_value_no_expiration_for_atomic_mutation,
        queries.update_key_value_preserving_expiration_for_atomic_mutation,
        queries.delete_key_for_atomic_mutation,
        queries.scan_keys_with_prefix,
    ]
    .join("\n")
    .to_lowercase();

    for forbidden in ["advisory", "listen", "notify"] {
        assert!(
            !joined.contains(forbidden),
            "migration SQL must not contain {forbidden:?}"
        );
    }
}

#[test]
fn key_suffix_scan_sql_does_not_fetch_values() {
    let config = StoreConfig::default();
    let catalog = KvCatalog::new(&config);
    let query = Queries::new(&catalog).scan_keys_with_prefix.to_lowercase();

    assert!(query.trim_start().starts_with("select key from "));
    assert!(!query.contains("value"));
    assert!(query.contains("order by key"));
    assert!(query.contains("limit $3"));
}

#[test]
fn atomic_mutation_sql_uses_direct_locked_row_mutations() {
    let config = StoreConfig::default();
    let catalog = KvCatalog::new(&config);
    let queries = Queries::new(&catalog);

    assert!(queries.lock_key_for_atomic_mutation.contains("FOR UPDATE"));
    assert!(
        queries
            .lock_key_for_atomic_mutation
            .trim_start()
            .starts_with("WITH locked_existing AS"),
        "atomic mutation must lock existing rows or insert the placeholder in one retryable statement"
    );
    assert!(
        queries
            .lock_key_for_atomic_mutation
            .contains("ON CONFLICT (key) DO NOTHING"),
        "placeholder insertion must yield to concurrent creators"
    );
    assert!(
        queries
            .lock_key_for_atomic_mutation
            .contains("RETURNING true AS inserted_placeholder"),
        "placeholder insertion must return whether this transaction created the lock row"
    );

    for (operation, query) in [
        (
            "set value with ttl",
            queries.update_key_value_with_ttl_for_atomic_mutation,
        ),
        (
            "set value without expiration",
            queries.update_key_value_no_expiration_for_atomic_mutation,
        ),
        (
            "set value preserving expiration",
            queries.update_key_value_preserving_expiration_for_atomic_mutation,
        ),
    ] {
        let lower = query.to_lowercase();
        assert!(
            lower.trim_start().starts_with("update "),
            "{operation} query must be a direct UPDATE: {query}"
        );
        assert!(
            lower.contains("where key = $1"),
            "{operation} query must target the locked key: {query}"
        );
        assert!(
            !lower.contains("on conflict") && !lower.contains("insert into"),
            "{operation} query must not use upsert-style set SQL: {query}"
        );
    }

    let delete_lower = queries.delete_key_for_atomic_mutation.to_lowercase();
    assert!(delete_lower.trim_start().starts_with("delete "));
    assert!(delete_lower.contains("where key = $1"));
    assert!(!delete_lower.contains("expires_at"));
}

#[test]
fn slot_and_batch_sql_paths_are_set_based_and_pooler_safe() {
    let config = StoreConfig::default();
    let catalog = KvCatalog::new(&config);
    let queries = Queries::new(&catalog);

    let ensure_slot_keys_exist = queries.ensure_slot_keys_exist.to_lowercase();
    assert!(
        ensure_slot_keys_exist
            .trim_start()
            .starts_with("insert into ")
    );
    assert!(ensure_slot_keys_exist.contains("from unnest($1::text[])"));
    assert!(ensure_slot_keys_exist.contains("on conflict (key) do nothing"));
    assert!(!ensure_slot_keys_exist.contains("for update"));

    let acquire_slot = queries.acquire_slot.to_lowercase();
    assert!(acquire_slot.trim_start().starts_with("update "));
    assert!(acquire_slot.contains("where key = (select key"));
    assert!(acquire_slot.contains("key = any($3::text[])"));
    assert!(acquire_slot.contains("for update skip locked"));
    assert!(acquire_slot.contains("limit 1"));
    assert!(!acquire_slot.contains("insert into"));
    assert!(!acquire_slot.contains("on conflict"));

    for (operation, query) in [
        (
            "expired key cleanup",
            queries.delete_expired_keys_once.to_lowercase(),
        ),
        (
            "prefix deletion",
            queries.delete_keys_with_prefix_once.to_lowercase(),
        ),
    ] {
        assert!(
            query.trim_start().starts_with("with "),
            "{operation} query should be one set-based CTE: {query}"
        );
        assert!(
            query.contains("for update skip locked"),
            "{operation} query should use SKIP LOCKED for concurrent workers: {query}"
        );
        assert!(
            query.contains("limit $"),
            "{operation} query should enforce caller batch size in SQL: {query}"
        );
        assert!(
            query.contains("delete from "),
            "{operation} query should delete through the locked CTE: {query}"
        );
    }

    assert!(
        !queries
            .delete_keys_with_prefix_once
            .to_lowercase()
            .contains("statement_timestamp"),
        "prefix deletion query must physically delete expired and live prefix rows"
    );

    let namespace_delete = queries
        .delete_namespace_keys_with_prefix_once
        .to_lowercase();
    assert!(
        namespace_delete.trim_start().starts_with("with "),
        "namespace deletion query should be one set-based CTE: {namespace_delete}"
    );
    assert!(
        namespace_delete.contains("for update"),
        "namespace deletion query should lock candidate rows: {namespace_delete}"
    );
    assert!(
        !namespace_delete.contains("skip locked"),
        "namespace deletion query should wait for locked namespace rows: {namespace_delete}"
    );
    assert!(
        !namespace_delete.contains("statement_timestamp"),
        "namespace deletion query must physically delete expired and live namespace rows: {namespace_delete}"
    );
    assert!(
        namespace_delete.contains("limit $"),
        "namespace deletion query should enforce caller batch size in SQL: {namespace_delete}"
    );
    assert!(
        namespace_delete.contains("delete from "),
        "namespace deletion query should delete through the locked CTE: {namespace_delete}"
    );
}

#[test]
fn updated_at_index_can_be_omitted() {
    let config = StoreConfig {
        create_updated_at_index: false,
        ..StoreConfig::default()
    };
    let statements = build_migrate_statements(&config);
    let joined = statements.join("\n");

    assert_eq!(statements.len(), 3);
    assert!(!joined.contains("ON \"__paranoid_kv_store\" (updated_at)"));
}

#[test]
fn generated_index_names_are_short_and_identifier_safe() {
    let table_name_text = format!("t{}", "a".repeat(62));
    let table_name = PgQualifiedTableName::unqualified(&table_name_text).expect("table name");
    let config = StoreConfig::new(table_name).expect("kv config");

    for suffix in [
        EXPIRES_AT_INDEX_SUFFIX,
        KEY_PATTERN_INDEX_SUFFIX,
        UPDATED_AT_INDEX_SUFFIX,
    ] {
        let identifier = migration_index_identifier(&config, suffix);
        assert!(identifier.as_str().len() <= super::super::MAX_PG_IDENTIFIER_BYTES);
        assert!(super::super::PgIdentifier::new(identifier.as_str()).is_ok());
    }
}

#[test]
fn kv_store_config_defaults_customization_and_item_constructors_are_explicit() {
    let default_config = StoreConfig::default();
    assert_eq!(
        default_config.table_name,
        PgQualifiedTableName::unqualified(TEST_KV_TABLE_NAME).expect("test table")
    );
    assert_eq!(
        default_config.schema_ledger_table_name,
        test_schema_ledger_table_name()
    );
    assert!(default_config.create_updated_at_index);

    let custom_table = PgQualifiedTableName::unqualified("__paranoid_kv_custom").expect("table");
    let custom_config = StoreConfig::new(custom_table.clone()).expect("kv config");
    assert_eq!(custom_config.table_name, custom_table);
    assert!(custom_config.create_updated_at_index);

    let without_updated_at_index = StoreConfig {
        create_updated_at_index: false,
        ..custom_config.clone()
    };
    assert!(!without_updated_at_index.create_updated_at_index);

    let store = Store::new(custom_config).expect("kv store");
    let prefix = KeyPrefix::from_parts(["item", "nested"]).expect("prefix");
    let plain_item = Item::<String>::new_plain(store.clone(), prefix.clone());
    assert_eq!(plain_item.key_prefix(), &prefix);
    assert!(!plain_item.is_encrypted());

    let encrypted_item = Item::<String>::new_encrypted(
        store,
        prefix.clone(),
        || -> Result<Arc<Keyset>, CodecError> { unreachable!("keyset is not resolved") },
    );
    assert_eq!(encrypted_item.key_prefix(), &prefix);
    assert!(encrypted_item.is_encrypted());
}

#[test]
fn kv_table_names_must_not_overlap() {
    let ledger_table_name = test_schema_ledger_table_name();
    assert!(matches!(
        StoreConfig::new(ledger_table_name),
        Err(Error::TableNamesMustBeDistinct)
    ));

    let ambiguous_kv_table =
        PgQualifiedTableName::unqualified("__paranoid_same_table").expect("table");
    let ambiguous_ledger_table =
        PgQualifiedTableName::with_schema("public", "__paranoid_same_table").expect("table");
    let config = StoreConfig {
        table_name: ambiguous_kv_table,
        schema_ledger_table_name: ambiguous_ledger_table,
        create_updated_at_index: true,
    };
    assert!(matches!(
        Store::new(config),
        Err(Error::TableNamesMustBeDistinct)
    ));
}

#[test]
fn kv_key_from_parts_validates_and_joins_key_parts() {
    let key = Key::from_parts(["account", "session", "abc"]).expect("key");
    assert_eq!(key.as_str(), "account::session::abc::");

    assert!(matches!(
        Key::from_parts::<&str, _>([]),
        Err(Error::EmptyKey)
    ));
    assert!(matches!(Key::from_parts([""]), Err(Error::EmptyKeyPart)));
    assert!(matches!(
        Key::from_parts(["has:colon"]),
        Err(Error::KeyPartContainsSeparatorByte)
    ));
    assert!(matches!(
        Key::from_parts(["has\0null"]),
        Err(Error::KeyPartContainsNullByte)
    ));
}

#[test]
fn kv_key_construction_rejects_ambiguous_parts_at_every_entry_point() {
    for invalid_part in ["", "has:colon", "has::separator", "has\0null"] {
        assert!(
            Key::from_parts(["prefix", invalid_part]).is_err(),
            "Key::from_parts accepted {invalid_part:?}"
        );
        assert!(
            KeyPrefix::from_parts(["prefix", invalid_part]).is_err(),
            "KeyPrefix::from_parts accepted {invalid_part:?}"
        );

        let prefix = KeyPrefix::from_parts(["prefix"]).expect("prefix");
        assert!(
            Key::from_prefix_and_parts(&prefix, [invalid_part]).is_err(),
            "Key::from_prefix_and_parts accepted {invalid_part:?}"
        );
    }

    assert!(matches!(
        KeyPrefix::from_parts::<&str, _>([]),
        Err(Error::EmptyKey)
    ));
}

#[test]
fn kv_key_construction_properties_match_the_persisted_shape() {
    let cases: &[(&[&str], &[&str], &str)] = &[
        (&["alpha"], &[], "alpha::"),
        (&["alpha"], &["beta"], "alpha::beta::"),
        (
            &["alpha", "beta"],
            &["gamma", "delta"],
            "alpha::beta::gamma::delta::",
        ),
        (&["héllo", "日本語"], &["wörld"], "héllo::日本語::wörld::"),
    ];

    for (prefix_parts, suffix_parts, expected_key) in cases {
        let prefix = KeyPrefix::from_parts(prefix_parts.iter().copied()).expect("prefix");
        let key = Key::from_prefix_and_parts(&prefix, suffix_parts.iter().copied())
            .expect("key from prefix");
        let joined = Key::from_parts(prefix_parts.iter().chain(suffix_parts.iter()).copied())
            .expect("joined key");

        assert_eq!(key.as_str(), *expected_key);
        assert_eq!(key, joined);
        assert!(prefix.contains_key(&key));
        assert!(key.as_str().ends_with(KV_KEY_SEPARATOR));
        assert!(key.as_str().len() <= MAX_KV_KEY_BYTES);
    }
}

#[test]
fn kv_key_prefix_from_parts_and_key_suffix_parts_are_unambiguous() {
    let prefix = KeyPrefix::from_parts(["account", "abc"]).expect("prefix");
    let exact_prefix_key = Key::from_prefix_and_parts::<&str, _>(&prefix, []).expect("key");
    let suffixed_key = Key::from_prefix_and_parts(&prefix, ["session", "123"]).expect("key");

    assert_eq!(prefix.as_str(), "account::abc::");
    assert_eq!(exact_prefix_key.as_str(), "account::abc::");
    assert_eq!(suffixed_key.as_str(), "account::abc::session::123::");
    assert!(prefix.contains_key(&exact_prefix_key));
    assert!(prefix.contains_key(&suffixed_key));
    assert!(!prefix.contains_key(&Key::from_parts(["account", "abcd"]).expect("key")));
}

#[test]
fn kv_key_from_parts_enforces_max_key_length() {
    let exact_len_part = "a".repeat(MAX_KV_KEY_BYTES - KV_KEY_SEPARATOR.len());
    let key = Key::from_parts([exact_len_part.as_str()]).expect("exact key");
    assert_eq!(key.as_str().len(), MAX_KV_KEY_BYTES);

    let too_long_part = "a".repeat(MAX_KV_KEY_BYTES - KV_KEY_SEPARATOR.len() + 1);
    assert!(matches!(
        Key::from_parts([too_long_part.as_str()]),
        Err(Error::KeyTooLong { .. })
    ));
}

#[test]
fn kv_key_prefix_from_parts_enforces_max_key_length() {
    let exact_len_part = "a".repeat(MAX_KV_KEY_BYTES - KV_KEY_SEPARATOR.len());
    let prefix = KeyPrefix::from_parts([exact_len_part.as_str()]).expect("exact prefix");
    assert_eq!(prefix.as_str().len(), MAX_KV_KEY_BYTES);

    let too_long_part = "a".repeat(MAX_KV_KEY_BYTES - KV_KEY_SEPARATOR.len() + 1);
    assert!(matches!(
        KeyPrefix::from_parts([too_long_part.as_str()]),
        Err(Error::KeyTooLong { .. })
    ));
}

#[test]
fn kv_key_from_prefix_and_parts_enforces_max_key_length() {
    let prefix_part = "p".repeat(MAX_KV_KEY_BYTES - (2 * KV_KEY_SEPARATOR.len()) - 1);
    let prefix = KeyPrefix::from_parts([prefix_part.as_str()]).expect("prefix");
    let exact_key = Key::from_prefix_and_parts(&prefix, ["s"]).expect("exact key");
    assert_eq!(exact_key.as_str().len(), MAX_KV_KEY_BYTES);

    assert!(matches!(
        Key::from_prefix_and_parts(&prefix, ["ss"]),
        Err(Error::KeyTooLong { .. })
    ));
}

#[test]
fn kv_ttl_rejects_zero_too_small_and_too_large_values() {
    assert!(matches!(
        Ttl::expires_after(Duration::ZERO),
        Err(Error::TtlIsZero)
    ));
    assert!(matches!(
        Ttl::expires_after(Duration::from_millis(999)),
        Err(Error::TtlBelowMinimum { .. })
    ));
    assert!(matches!(
        Ttl::expires_after(Duration::from_micros(i64::MAX as u64 + 1)),
        Err(Error::TtlTooLarge)
    ));
    assert!(Ttl::expires_after(MIN_KV_TTL).is_ok());
    assert_eq!(Ttl::no_expiration().positive_microseconds().unwrap(), None);
    assert_eq!(
        Ttl::expires_after(Duration::from_secs(1) + Duration::from_nanos(1))
            .unwrap()
            .positive_microseconds()
            .unwrap(),
        Some(1_000_001)
    );
}

#[test]
fn kv_slot_acquisition_requires_expiring_ttl_even_before_database_work() {
    assert!(matches!(
        positive_expiring_ttl_microseconds(Ttl::no_expiration()),
        Err(Error::TtlNoExpirationNotAllowed)
    ));
    assert_eq!(
        positive_expiring_ttl_microseconds(
            Ttl::expires_after(Duration::from_secs(1)).expect("ttl")
        )
        .expect("positive ttl"),
        1_000_000
    );
}

#[test]
fn kv_scan_limit_and_delete_batch_size_are_bounded() {
    assert!(validate_scan_limit(MAX_KV_SCAN_LIMIT).is_ok());
    assert!(matches!(
        validate_scan_limit(0),
        Err(Error::ScanLimitIsZero)
    ));
    assert!(matches!(
        validate_scan_limit(MAX_KV_SCAN_LIMIT + 1),
        Err(Error::ScanLimitTooLarge { .. })
    ));

    assert!(validate_delete_batch_size(DEFAULT_KV_DELETE_BATCH_SIZE).is_ok());
    assert!(matches!(
        validate_delete_batch_size(0),
        Err(Error::DeleteBatchSizeIsZero)
    ));
    assert!(matches!(
        validate_delete_batch_size(MAX_KV_DELETE_BATCH_SIZE + 1),
        Err(Error::DeleteBatchSizeTooLarge { .. })
    ));
}

#[test]
fn kv_prefix_like_pattern_escapes_like_metacharacters() {
    let prefix = KeyPrefix::from_parts(["wild%_\\"]).expect("prefix");
    assert_eq!(prefix.as_str(), r"wild%_\::");
    assert_eq!(prefix_like_pattern(&prefix), r"wild\%\_\\::%");
}

#[test]
fn kv_scan_cursor_must_belong_to_prefix() {
    let prefix = KeyPrefix::from_parts(["tenant"]).expect("prefix");
    let matching = Key::from_prefix_and_parts(&prefix, ["a"]).expect("key");
    let outside = Key::from_parts(["tenantx", "a"]).expect("key");

    assert_eq!(
        scan_after_key_text(&prefix, Some(&matching)).expect("cursor"),
        matching.as_str()
    );
    assert!(matches!(
        scan_after_key_text(&prefix, Some(&outside)),
        Err(Error::ScanCursorOutsidePrefix)
    ));
}

#[test]
fn kv_raw_suffix_cursor_validation_matches_safe_string_domain() {
    let prefix = KeyPrefix::from_parts(["tenant", "items"]).expect("prefix");

    assert_eq!(
        key_from_prefix_and_raw_suffix(&prefix, "")
            .expect("empty raw suffix")
            .as_str(),
        prefix.as_str()
    );
    assert_eq!(
        key_from_prefix_and_raw_suffix(&prefix, "child")
            .expect("raw suffix")
            .as_str(),
        "tenant::items::child::"
    );
    assert_eq!(
        key_from_prefix_and_raw_suffix(&prefix, "child::grandchild")
            .expect("raw suffix containing persisted separator")
            .as_str(),
        "tenant::items::child::grandchild::"
    );
    assert!(matches!(
        key_from_prefix_and_raw_suffix(&prefix, "child\0bad"),
        Err(Error::KeyPartContainsNullByte)
    ));
}

#[test]
fn kv_property_style_key_construction_ttl_and_cursor_invariants() {
    let candidate_sets: &[&[&str]] = &[
        &[],
        &["alpha"],
        &["alpha", "beta"],
        &["alpha", "", "gamma"],
        &["has:colon"],
        &["has::separator"],
        &["has\0null"],
        &["unicode", "日本語"],
        &[&"x".repeat(MAX_KV_KEY_BYTES - KV_KEY_SEPARATOR.len())],
        &[&"x".repeat(MAX_KV_KEY_BYTES - KV_KEY_SEPARATOR.len() + 1)],
    ];

    for parts in candidate_sets {
        let key_result = Key::from_parts(parts.iter().copied());
        let prefix_result = KeyPrefix::from_parts(parts.iter().copied());
        let expected_valid = !parts.is_empty()
            && parts.iter().all(|part| {
                !part.is_empty() && !part.contains(':') && !part.as_bytes().contains(&0)
            })
            && parts
                .iter()
                .map(|part| part.len() + KV_KEY_SEPARATOR.len())
                .sum::<usize>()
                <= MAX_KV_KEY_BYTES;

        assert_eq!(
            key_result.is_ok(),
            expected_valid,
            "Key::from_parts({parts:?}) validity mismatch"
        );
        assert_eq!(
            prefix_result.is_ok(),
            expected_valid,
            "KeyPrefix::from_parts({parts:?}) validity mismatch"
        );

        if let (Ok(key), Ok(prefix)) = (key_result, prefix_result) {
            assert_eq!(key.as_str(), prefix.as_str());
            assert!(key.as_str().ends_with(KV_KEY_SEPARATOR));
            assert!(key.as_str().len() <= MAX_KV_KEY_BYTES);
            assert!(prefix.contains_key(&key));

            for suffix_parts in [Vec::<&str>::new(), vec!["suffix"], vec!["suffix", "tail"]] {
                let all_parts = parts
                    .iter()
                    .copied()
                    .chain(suffix_parts.iter().copied())
                    .collect::<Vec<_>>();
                let suffix_key = Key::from_prefix_and_parts(&prefix, suffix_parts.iter().copied());
                let joined_key = Key::from_parts(all_parts.iter().copied());
                assert_eq!(
                    suffix_key.is_ok(),
                    joined_key.is_ok(),
                    "prefix append validity must match whole-key validity for {parts:?} + {suffix_parts:?}"
                );
                if let (Ok(suffix_key), Ok(joined_key)) = (suffix_key, joined_key) {
                    assert_eq!(suffix_key, joined_key);
                    assert!(prefix.contains_key(&suffix_key));
                }
            }
        }
    }

    for duration in [
        Duration::ZERO,
        Duration::from_nanos(1),
        MIN_KV_TTL - Duration::from_nanos(1),
        MIN_KV_TTL,
        Duration::from_secs(60),
        Duration::from_micros(i64::MAX as u64 + 1),
    ] {
        let result = Ttl::expires_after(duration);
        match duration {
            Duration::ZERO => assert!(matches!(result, Err(Error::TtlIsZero))),
            d if d < MIN_KV_TTL => assert!(matches!(result, Err(Error::TtlBelowMinimum { .. }))),
            d if d.as_micros() > i64::MAX as u128 => {
                assert!(matches!(result, Err(Error::TtlTooLarge)));
            }
            _ => assert!(result.is_ok(), "expected valid TTL for {duration:?}"),
        }
    }

    let prefix = KeyPrefix::from_parts(["cursor", "tenant"]).expect("prefix");
    for suffix in ["", "child", "child::grandchild"] {
        let cursor = key_from_prefix_and_raw_suffix(&prefix, suffix).expect("cursor");
        assert_eq!(
            scan_after_key_text(&prefix, Some(&cursor)).expect("scan cursor"),
            cursor.as_str()
        );
    }
}

proptest! {
    #[test]
    fn kv_key_and_prefix_construction_round_trips_valid_generated_parts(
        parts in prop::collection::vec(valid_kv_key_part_strategy(), 1..=8),
        suffix_parts in prop::collection::vec(valid_kv_key_part_strategy(), 0..=4),
    ) {
        let key = Key::from_parts(parts.iter().map(String::as_str))
            .expect("generated key parts should be valid");
        let prefix = KeyPrefix::from_parts(parts.iter().map(String::as_str))
            .expect("generated prefix parts should be valid");

        prop_assert_eq!(key.as_str(), expected_key_text(&parts));
        prop_assert_eq!(prefix.as_str(), key.as_str());
        prop_assert!(prefix.contains_key(&key));
        prop_assert!(key.as_str().ends_with(KV_KEY_SEPARATOR));
        prop_assert!(key.as_str().len() <= MAX_KV_KEY_BYTES);

        let appended = Key::from_prefix_and_parts(
            &prefix,
            suffix_parts.iter().map(String::as_str),
        )
        .expect("generated suffix parts should be valid");
        let all_parts = parts
            .iter()
            .cloned()
            .chain(suffix_parts.iter().cloned())
            .collect::<Vec<_>>();
        let joined = Key::from_parts(all_parts.iter().map(String::as_str))
            .expect("joined generated parts should be valid");

        prop_assert_eq!(appended.as_str(), expected_key_text(&all_parts));
        prop_assert_eq!(appended.as_str(), joined.as_str());
        prop_assert!(prefix.contains_key(&appended));
    }

    #[test]
    fn kv_key_construction_rejects_invalid_generated_parts_at_every_entry_point(
        valid_prefix_parts in prop::collection::vec(valid_kv_key_part_strategy(), 1..=4),
        invalid_part in invalid_kv_key_part_strategy(),
    ) {
        let prefix = KeyPrefix::from_parts(valid_prefix_parts.iter().map(String::as_str))
            .expect("generated prefix parts should be valid");
        let mut whole_key_parts = valid_prefix_parts;
        whole_key_parts.push(invalid_part.clone());

        prop_assert!(Key::from_parts(whole_key_parts.iter().map(String::as_str)).is_err());
        prop_assert!(KeyPrefix::from_parts(whole_key_parts.iter().map(String::as_str)).is_err());
        prop_assert!(Key::from_prefix_and_parts(&prefix, [invalid_part.as_str()]).is_err());
    }

    #[test]
    fn kv_raw_suffix_cursor_and_like_pattern_properties(
        prefix_parts in prop::collection::vec(valid_kv_key_part_strategy(), 1..=4),
        raw_suffix in safe_raw_suffix_strategy(),
    ) {
        let prefix = KeyPrefix::from_parts(prefix_parts.iter().map(String::as_str))
            .expect("generated prefix parts should be valid");
        let key = key_from_prefix_and_raw_suffix(&prefix, &raw_suffix)
            .expect("safe raw suffix should be valid");

        let expected = if raw_suffix.is_empty() {
            prefix.as_str().to_owned()
        } else {
            format!("{}{raw_suffix}{KV_KEY_SEPARATOR}", prefix.as_str())
        };

        prop_assert_eq!(key.as_str(), expected);
        prop_assert!(prefix.contains_key(&key));
        prop_assert_eq!(
            scan_after_key_text(&prefix, Some(&key)).expect("cursor should belong to prefix"),
            key.as_str()
        );
        prop_assert_eq!(prefix_like_pattern(&prefix), expected_like_pattern(&prefix));
    }

    #[test]
    fn kv_raw_suffix_cursor_rejects_generated_null_bytes(
        prefix_parts in prop::collection::vec(valid_kv_key_part_strategy(), 1..=4),
        raw_suffix in unsafe_raw_suffix_strategy(),
    ) {
        let prefix = KeyPrefix::from_parts(prefix_parts.iter().map(String::as_str))
            .expect("generated prefix parts should be valid");

        prop_assert!(matches!(
            key_from_prefix_and_raw_suffix(&prefix, &raw_suffix),
            Err(Error::KeyPartContainsNullByte)
        ));
    }

    #[test]
    fn kv_generated_ttl_domain_matches_validation_contract(
        sub_minimum_nanos in 0u64..MIN_KV_TTL.as_nanos() as u64,
        valid_nanos in MIN_KV_TTL.as_nanos() as u64..=10_000_000_000u64,
        too_large_micros in (i64::MAX as u64 + 1)..=(i64::MAX as u64 + 100_000),
    ) {
        let sub_minimum = Duration::from_nanos(sub_minimum_nanos);
        let sub_minimum_result = Ttl::expires_after(sub_minimum);
        if sub_minimum.is_zero() {
            prop_assert!(matches!(sub_minimum_result, Err(Error::TtlIsZero)));
        } else {
            let expected_sub_minimum_error = matches!(
                sub_minimum_result,
                Err(Error::TtlBelowMinimum { minimum }) if minimum == MIN_KV_TTL
            );
            prop_assert!(expected_sub_minimum_error);
        }

        let valid_duration = Duration::from_nanos(valid_nanos);
        let valid_ttl = Ttl::expires_after(valid_duration)
            .expect("generated duration at or above minimum should be valid");
        let expected_microseconds = valid_nanos.div_ceil(1_000) as i64;
        prop_assert_eq!(
            valid_ttl.positive_microseconds().expect("ttl micros"),
            Some(expected_microseconds)
        );

        prop_assert!(matches!(
            Ttl::expires_after(Duration::from_micros(too_large_micros)),
            Err(Error::TtlTooLarge)
        ));
    }

    #[test]
    fn kv_generated_batch_and_limit_domains_match_public_bounds(
        scan_limit in 0u32..=(MAX_KV_SCAN_LIMIT + 1_000),
        delete_batch_size in 0u32..=(MAX_KV_DELETE_BATCH_SIZE + 1_000),
        get_multi_key_count in 0usize..=(MAX_KV_GET_MULTI_KEYS + 1_000),
        set_multi_entry_count in 0usize..=(MAX_KV_SET_MULTI_ENTRIES + 1_000),
        slot_candidate_count in 0usize..=(MAX_KV_ACQUIRE_SLOT_CANDIDATES + 1_000),
    ) {
        match scan_limit {
            0 => prop_assert!(matches!(validate_scan_limit(scan_limit), Err(Error::ScanLimitIsZero))),
            n if n > MAX_KV_SCAN_LIMIT => {
                let expected_error = matches!(
                    validate_scan_limit(n),
                    Err(Error::ScanLimitTooLarge { actual, max })
                        if actual == n && max == MAX_KV_SCAN_LIMIT
                );
                prop_assert!(expected_error);
            }
            n => prop_assert!(validate_scan_limit(n).is_ok()),
        }

        match delete_batch_size {
            0 => prop_assert!(matches!(
                validate_delete_batch_size(delete_batch_size),
                Err(Error::DeleteBatchSizeIsZero)
            )),
            n if n > MAX_KV_DELETE_BATCH_SIZE => {
                let expected_error = matches!(
                    validate_delete_batch_size(n),
                    Err(Error::DeleteBatchSizeTooLarge { actual, max })
                        if actual == n && max == MAX_KV_DELETE_BATCH_SIZE
                );
                prop_assert!(expected_error);
            }
            n => prop_assert!(validate_delete_batch_size(n).is_ok()),
        }

        if get_multi_key_count > MAX_KV_GET_MULTI_KEYS {
            let expected_error = matches!(
                validate_get_multi_key_count(get_multi_key_count),
                Err(Error::GetMultiKeyCountTooLarge { actual, max })
                    if actual == get_multi_key_count && max == MAX_KV_GET_MULTI_KEYS
            );
            prop_assert!(expected_error);
        } else {
            prop_assert!(validate_get_multi_key_count(get_multi_key_count).is_ok());
        }

        if set_multi_entry_count > MAX_KV_SET_MULTI_ENTRIES {
            let expected_error = matches!(
                validate_set_multi_entry_count(set_multi_entry_count),
                Err(Error::SetMultiEntryCountTooLarge { actual, max })
                    if actual == set_multi_entry_count && max == MAX_KV_SET_MULTI_ENTRIES
            );
            prop_assert!(expected_error);
        } else {
            prop_assert!(validate_set_multi_entry_count(set_multi_entry_count).is_ok());
        }

        if slot_candidate_count > MAX_KV_ACQUIRE_SLOT_CANDIDATES {
            let expected_error = matches!(
                validate_acquire_slot_candidate_count(slot_candidate_count),
                Err(Error::AcquireSlotCandidateCountTooLarge { actual, max })
                    if actual == slot_candidate_count && max == MAX_KV_ACQUIRE_SLOT_CANDIDATES
            );
            prop_assert!(expected_error);
        } else {
            prop_assert!(validate_acquire_slot_candidate_count(slot_candidate_count).is_ok());
        }
    }

    #[test]
    fn kv_generated_table_names_round_trip_through_config_and_migration_sql(
        table_name in valid_pg_identifier_strategy(super::super::MAX_PG_IDENTIFIER_BYTES),
    ) {
        let qualified = PgQualifiedTableName::unqualified(&table_name)
            .expect("generated table identifier should be valid");
        let config = StoreConfig::new(qualified.clone()).expect("kv config");

        prop_assert_eq!(config.table_name.clone(), qualified);
        prop_assert!(config.create_updated_at_index);

        let statements = build_migrate_statements(&config).join("\n");
        let quoted_table_name = format!("\"{table_name}\"");
        prop_assert!(
            statements.contains(&quoted_table_name),
            "migration SQL should include the generated quoted table name {quoted_table_name}"
        );
    }
}
