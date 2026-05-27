use super::*;

impl Queries {
    pub(super) fn new(table_name: &PgQualifiedTableName) -> Self {
        let quoted_table_name = table_name.quoted().to_string();
        Self {
            get_bytes: build_get_bytes_query(&quoted_table_name),
            get_bytes_returning_database_timestamp:
                build_get_bytes_returning_database_timestamp_query(&quoted_table_name),
            get_bytes_multi: build_get_bytes_multi_query(&quoted_table_name),
            set_bytes_with_ttl: build_set_bytes_query(
                &quoted_table_name,
                "statement_timestamp() + ($3::bigint * INTERVAL '1 microsecond')",
                false,
            ),
            set_bytes_no_expiration: build_set_bytes_query(&quoted_table_name, "NULL", false),
            set_bytes_with_ttl_returning_database_timestamp: build_set_bytes_query(
                &quoted_table_name,
                "statement_timestamp() + ($3::bigint * INTERVAL '1 microsecond')",
                true,
            ),
            set_bytes_no_expiration_returning_database_timestamp: build_set_bytes_query(
                &quoted_table_name,
                "NULL",
                true,
            ),
            set_bytes_multi_with_ttl: build_set_bytes_multi_query(
                &quoted_table_name,
                "statement_timestamp() + ($3::bigint * INTERVAL '1 microsecond')",
            ),
            set_bytes_multi_no_expiration: build_set_bytes_multi_query(&quoted_table_name, "NULL"),
            set_bytes_if_not_exists_with_ttl: build_set_bytes_if_not_exists_query(
                &quoted_table_name,
                "statement_timestamp() + ($3::bigint * INTERVAL '1 microsecond')",
                false,
            ),
            set_bytes_if_not_exists_no_expiration: build_set_bytes_if_not_exists_query(
                &quoted_table_name,
                "NULL",
                false,
            ),
            set_bytes_if_not_exists_with_ttl_returning_database_timestamp:
                build_set_bytes_if_not_exists_query(
                    &quoted_table_name,
                    "statement_timestamp() + ($3::bigint * INTERVAL '1 microsecond')",
                    true,
                ),
            set_bytes_if_not_exists_no_expiration_returning_database_timestamp:
                build_set_bytes_if_not_exists_query(&quoted_table_name, "NULL", true),
            touch_key: build_touch_key_query(&quoted_table_name),
            set_key_ttl_with_ttl: build_set_key_ttl_query(
                &quoted_table_name,
                "statement_timestamp() + ($2::bigint * INTERVAL '1 microsecond')",
            ),
            set_key_ttl_no_expiration: build_set_key_ttl_query(&quoted_table_name, "NULL"),
            expire_key: build_expire_key_query(&quoted_table_name),
            delete_key: build_delete_key_query(&quoted_table_name),
            check_key_exists: build_check_key_exists_query(&quoted_table_name),
            delete_expired_keys_once: build_delete_expired_keys_once_query(&quoted_table_name),
            count_live_keys_with_prefix: build_count_live_keys_with_prefix_query(
                &quoted_table_name,
            ),
            scan_bytes_with_prefix: build_scan_bytes_with_prefix_query(&quoted_table_name),
            scan_keys_with_prefix: build_scan_keys_with_prefix_query(&quoted_table_name),
            delete_keys_with_prefix_once: build_delete_keys_with_prefix_once_query(
                &quoted_table_name,
                true,
            ),
            delete_namespace_keys_with_prefix_once: build_delete_keys_with_prefix_once_query(
                &quoted_table_name,
                false,
            ),
            ensure_slot_keys_exist: build_ensure_slot_keys_exist_query(&quoted_table_name),
            acquire_slot: build_acquire_slot_query(&quoted_table_name),
            lock_key_for_atomic_mutation: build_lock_key_for_atomic_mutation_query(
                &quoted_table_name,
            ),
            update_key_value_with_ttl_for_atomic_mutation:
                build_update_key_value_and_ttl_for_atomic_mutation_query(
                    &quoted_table_name,
                    "statement_timestamp() + ($3::bigint * INTERVAL '1 microsecond')",
                ),
            update_key_value_no_expiration_for_atomic_mutation:
                build_update_key_value_and_ttl_for_atomic_mutation_query(&quoted_table_name, "NULL"),
            update_key_value_preserving_expiration_for_atomic_mutation:
                build_update_key_value_preserving_expiration_for_atomic_mutation_query(
                    &quoted_table_name,
                ),
            delete_key_for_atomic_mutation: build_delete_key_for_atomic_mutation_query(
                &quoted_table_name,
            ),
        }
    }
}

fn build_get_bytes_query(quoted_table_name: &str) -> String {
    format!("SELECT value FROM {quoted_table_name} WHERE key = $1 AND {NOT_EXPIRED_FILTER}")
}

fn build_get_bytes_returning_database_timestamp_query(quoted_table_name: &str) -> String {
    let database_timestamp_expression = kv_timestamp_micros("statement_timestamp()");
    format!(
        "SELECT value, {database_timestamp_expression} \
         FROM {quoted_table_name} \
         WHERE key = $1 AND {NOT_EXPIRED_FILTER}"
    )
}

fn build_get_bytes_multi_query(quoted_table_name: &str) -> String {
    format!(
        "SELECT key, value FROM {quoted_table_name} WHERE key = ANY($1::text[]) AND {NOT_EXPIRED_FILTER}"
    )
}

fn build_set_bytes_query(
    quoted_table_name: &str,
    expires_at_expression: &str,
    returning_database_timestamp: bool,
) -> String {
    let returning_clause = if returning_database_timestamp {
        format!(" RETURNING {}", kv_timestamp_micros("updated_at"))
    } else {
        String::new()
    };
    format!(
        "INSERT INTO {quoted_table_name} (key, value, expires_at, updated_at) \
         VALUES ($1, $2, {expires_at_expression}, statement_timestamp()) \
         ON CONFLICT (key) DO UPDATE SET \
         value = EXCLUDED.value, expires_at = EXCLUDED.expires_at, updated_at = EXCLUDED.updated_at\
         {returning_clause}"
    )
}

fn build_set_bytes_multi_query(quoted_table_name: &str, expires_at_expression: &str) -> String {
    format!(
        "INSERT INTO {quoted_table_name} (key, value, expires_at, updated_at) \
         SELECT key, value, {expires_at_expression}, statement_timestamp() \
         FROM UNNEST($1::text[], $2::bytea[]) AS input(key, value) \
         ON CONFLICT (key) DO UPDATE SET \
         value = EXCLUDED.value, expires_at = EXCLUDED.expires_at, updated_at = EXCLUDED.updated_at"
    )
}

fn build_set_bytes_if_not_exists_query(
    quoted_table_name: &str,
    expires_at_expression: &str,
    returning_database_timestamp: bool,
) -> String {
    let returning_expression = if returning_database_timestamp {
        kv_timestamp_micros("updated_at")
    } else {
        "1".to_owned()
    };
    format!(
        "INSERT INTO {quoted_table_name} AS kv_target (key, value, expires_at, updated_at) \
         VALUES ($1, $2, {expires_at_expression}, statement_timestamp()) \
         ON CONFLICT (key) DO UPDATE SET \
         value = EXCLUDED.value, expires_at = EXCLUDED.expires_at, updated_at = EXCLUDED.updated_at \
         WHERE kv_target.expires_at IS NOT NULL AND kv_target.expires_at <= statement_timestamp() \
         RETURNING {returning_expression}"
    )
}

fn build_touch_key_query(quoted_table_name: &str) -> String {
    format!(
        "UPDATE {quoted_table_name} SET updated_at = statement_timestamp() \
         WHERE key = $1 AND {NOT_EXPIRED_FILTER}"
    )
}

fn build_set_key_ttl_query(quoted_table_name: &str, expires_at_expression: &str) -> String {
    format!(
        "UPDATE {quoted_table_name} \
         SET expires_at = {expires_at_expression}, updated_at = statement_timestamp() \
         WHERE key = $1 AND {NOT_EXPIRED_FILTER}"
    )
}

fn build_expire_key_query(quoted_table_name: &str) -> String {
    format!(
        "UPDATE {quoted_table_name} \
         SET expires_at = statement_timestamp(), updated_at = statement_timestamp() \
         WHERE key = $1 AND {NOT_EXPIRED_FILTER}"
    )
}

fn build_delete_key_query(quoted_table_name: &str) -> String {
    format!("DELETE FROM {quoted_table_name} WHERE key = $1 AND {NOT_EXPIRED_FILTER}")
}

fn build_check_key_exists_query(quoted_table_name: &str) -> String {
    format!(
        "SELECT EXISTS (SELECT 1 FROM {quoted_table_name} WHERE key = $1 AND {NOT_EXPIRED_FILTER})"
    )
}

fn build_delete_expired_keys_once_query(quoted_table_name: &str) -> String {
    format!(
        "WITH expired AS (\
         SELECT key FROM {quoted_table_name} \
         WHERE {EXPIRED_FILTER} \
         ORDER BY expires_at, key \
         LIMIT $1 \
         FOR UPDATE SKIP LOCKED\
         ) \
         DELETE FROM {quoted_table_name} \
         WHERE key IN (SELECT key FROM expired)"
    )
}

fn build_count_live_keys_with_prefix_query(quoted_table_name: &str) -> String {
    format!(
        "SELECT COUNT(*) FROM {quoted_table_name} \
         WHERE key LIKE $1 ESCAPE E'\\\\' AND {NOT_EXPIRED_FILTER}"
    )
}

fn build_scan_bytes_with_prefix_query(quoted_table_name: &str) -> String {
    format!(
        "SELECT key, value FROM {quoted_table_name} \
         WHERE key LIKE $1 ESCAPE E'\\\\' \
           AND key > $2 \
           AND {NOT_EXPIRED_FILTER} \
         ORDER BY key \
         LIMIT $3"
    )
}

fn build_scan_keys_with_prefix_query(quoted_table_name: &str) -> String {
    format!(
        "SELECT key FROM {quoted_table_name} \
         WHERE key LIKE $1 ESCAPE E'\\\\' \
           AND key > $2 \
           AND {NOT_EXPIRED_FILTER} \
         ORDER BY key \
         LIMIT $3"
    )
}

fn build_delete_keys_with_prefix_once_query(quoted_table_name: &str, skip_locked: bool) -> String {
    let skip_locked_sql = if skip_locked { " SKIP LOCKED" } else { "" };
    format!(
        "WITH prefixed AS (\
         SELECT key FROM {quoted_table_name} \
         WHERE key LIKE $1 ESCAPE E'\\\\' \
         ORDER BY key \
         LIMIT $2 \
         FOR UPDATE{skip_locked_sql}\
         ) \
         DELETE FROM {quoted_table_name} \
         WHERE key IN (SELECT key FROM prefixed)"
    )
}

fn build_ensure_slot_keys_exist_query(quoted_table_name: &str) -> String {
    format!(
        "INSERT INTO {quoted_table_name} (key, value, expires_at, updated_at) \
         SELECT key, ''::bytea, statement_timestamp() - INTERVAL '1 second', statement_timestamp() \
         FROM UNNEST($1::text[]) AS input(key) \
         ON CONFLICT (key) DO NOTHING"
    )
}

fn build_acquire_slot_query(quoted_table_name: &str) -> String {
    format!(
        "UPDATE {quoted_table_name} \
         SET value = $1, \
             expires_at = statement_timestamp() + ($2::bigint * INTERVAL '1 microsecond'), \
             updated_at = statement_timestamp() \
         WHERE key = (\
             SELECT key FROM {quoted_table_name} \
             WHERE key = ANY($3::text[]) AND {EXPIRED_FILTER} \
             LIMIT 1 \
             FOR UPDATE SKIP LOCKED\
         ) \
         RETURNING key"
    )
}

fn build_lock_key_for_atomic_mutation_query(quoted_table_name: &str) -> String {
    let existing_database_timestamp_expression = kv_timestamp_micros("statement_timestamp()");
    let inserted_database_timestamp_expression = kv_timestamp_micros("updated_at");
    format!(
        "WITH locked_existing AS (\
             SELECT false AS inserted_placeholder, \
                    value, \
                    {NOT_EXPIRED_FILTER} AS is_live, \
                    {existing_database_timestamp_expression} AS database_timestamp \
             FROM {quoted_table_name} \
             WHERE key = $1 \
             FOR UPDATE\
         ), inserted_placeholder AS (\
             INSERT INTO {quoted_table_name} (key, value, expires_at, updated_at) \
             SELECT $1, ''::bytea, statement_timestamp(), statement_timestamp() \
             WHERE NOT EXISTS (SELECT 1 FROM locked_existing) \
             ON CONFLICT (key) DO NOTHING \
             RETURNING true AS inserted_placeholder, \
                       value, \
                       false AS is_live, \
                       {inserted_database_timestamp_expression} AS database_timestamp\
         ) \
         SELECT inserted_placeholder, value, is_live, database_timestamp FROM locked_existing \
         UNION ALL \
         SELECT inserted_placeholder, value, is_live, database_timestamp FROM inserted_placeholder"
    )
}

fn build_update_key_value_and_ttl_for_atomic_mutation_query(
    quoted_table_name: &str,
    expires_at_expression: &str,
) -> String {
    format!(
        "UPDATE {quoted_table_name} \
         SET value = $2, expires_at = {expires_at_expression}, updated_at = statement_timestamp() \
         WHERE key = $1"
    )
}

fn build_update_key_value_preserving_expiration_for_atomic_mutation_query(
    quoted_table_name: &str,
) -> String {
    format!(
        "UPDATE {quoted_table_name} \
         SET value = $2, updated_at = statement_timestamp() \
         WHERE key = $1"
    )
}

fn build_delete_key_for_atomic_mutation_query(quoted_table_name: &str) -> String {
    format!("DELETE FROM {quoted_table_name} WHERE key = $1")
}

fn kv_timestamp_micros(timestamp_expression: &str) -> String {
    format!("(EXTRACT(EPOCH FROM {timestamp_expression}) * 1000000)::bigint")
}
