#![no_main]

use libfuzzer_sys::fuzz_target;
use paranoid::{db, fleet, kv, queue};
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    exercise_numeric_validators(data);

    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    exercise_postgres_identifier_validators(text);
    exercise_kv_validators(text);
    exercise_fleet_key_validators(text);
    exercise_queue_validators(text);
});

fn exercise_numeric_validators(data: &[u8]) {
    let duration = Duration::from_nanos(first_u64(data));
    let _ = kv::Ttl::expires_after(duration);

    let _ = queue::JobRunAtOrAfter::from_unix_microseconds(first_i64(data));
}

fn exercise_postgres_identifier_validators(text: &str) {
    let identifier = db::PgIdentifier::new(text);
    let _ = db::PgSchemaName::from_identifier_text(text);
    let _ = db::PgQualifiedTableName::unqualified(text);

    if let Ok(table) = identifier {
        let _ = db::PgQualifiedTableName::new(None, table);
    }

    if let Some((schema, table)) = text.split_once('.') {
        let _ = db::PgQualifiedTableName::with_schema(schema, table);
    }
}

fn exercise_kv_validators(text: &str) {
    let parts = split_text_parts(text);
    let key = kv::Key::from_parts(parts.iter().copied());
    let prefix = kv::KeyPrefix::from_parts(parts.iter().copied());

    if let (Ok(prefix), Some(first_part)) = (prefix, parts.first()) {
        let _ = kv::Key::from_prefix_and_parts(&prefix, [*first_part]);
    }

    if let Ok(table_name) = db::PgQualifiedTableName::unqualified(text) {
        let _ = kv::StoreConfig::new(table_name);
    }

    if let Ok(key) = key {
        let _ = key.as_str();
    }
}

fn exercise_fleet_key_validators(text: &str) {
    let _ = fleet::RootKey::new(text);
    let _ = fleet::MutexKey::new(text);
    let _ = fleet::CounterKey::new(text);
    let _ = fleet::CoalescingCacheKey::new(text);
    let _ = fleet::TopicKey::new(text);
    let _ = fleet::SubscriptionKey::new(text);
    let _ = fleet::CronKey::new(text);
    let _ = fleet::SemaphoreKey::new(text);
    let _ = fleet::ThrottlerKey::new(text);
    let _ = fleet::OnceKey::new(text);
}

fn exercise_queue_validators(text: &str) {
    if let Ok(table_name) = db::PgQualifiedTableName::unqualified(text) {
        let _ = queue::StoreConfig::new(table_name.clone(), table_name.clone(), table_name.clone());
    }

    if let Some((jobs, rest)) = text.split_once('.')
        && let Some((dead_letter, pauses)) = rest.split_once('.')
        && let (Ok(jobs), Ok(dead_letter), Ok(pauses)) = (
            db::PgQualifiedTableName::unqualified(jobs),
            db::PgQualifiedTableName::unqualified(dead_letter),
            db::PgQualifiedTableName::unqualified(pauses),
        )
    {
        let _ = queue::StoreConfig::new(jobs, dead_letter, pauses);
    }
}

fn split_text_parts(text: &str) -> Vec<&str> {
    text.split(['.', ':', '/', ',', '\n', '\r', '\t'])
        .filter(|part| !part.is_empty())
        .take(4)
        .collect()
}

fn first_u64(data: &[u8]) -> u64 {
    let mut bytes = [0_u8; 8];
    let copied_len = data.len().min(bytes.len());
    bytes[..copied_len].copy_from_slice(&data[..copied_len]);
    u64::from_le_bytes(bytes)
}

fn first_i64(data: &[u8]) -> i64 {
    first_u64(data) as i64
}
