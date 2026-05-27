use super::*;

pub(in crate::db::queue) fn migration_index_identifier(
    kind: &str,
    table_name: &PgQualifiedTableName,
    suffix: &str,
) -> PgIdentifier {
    PgIdentifier::new(migration_object_name(
        kind,
        &table_name.quoted().to_string(),
        suffix,
    ))
    .expect("generated queue migration index name must be valid")
}

pub(in crate::db::queue) fn job_status_constraint_identifier(config: &StoreConfig) -> PgIdentifier {
    migration_check_identifier(&config.table_name, JOB_STATUS_CONSTRAINT_SUFFIX)
}

pub(in crate::db::queue) fn job_lifecycle_constraint_identifier(
    config: &StoreConfig,
) -> PgIdentifier {
    migration_check_identifier(&config.table_name, JOB_LIFECYCLE_CONSTRAINT_SUFFIX)
}

pub(in crate::db::queue) fn job_numeric_constraint_identifier(
    config: &StoreConfig,
) -> PgIdentifier {
    migration_check_identifier(&config.table_name, JOB_NUMERIC_CONSTRAINT_SUFFIX)
}

pub(in crate::db::queue) fn job_text_constraint_identifier(config: &StoreConfig) -> PgIdentifier {
    migration_check_identifier(&config.table_name, JOB_TEXT_CONSTRAINT_SUFFIX)
}

pub(in crate::db::queue) fn dead_letter_reason_constraint_identifier(
    config: &StoreConfig,
) -> PgIdentifier {
    migration_check_identifier(
        &config.dead_letter_table_name,
        DEAD_LETTER_REASON_CONSTRAINT_SUFFIX,
    )
}

pub(in crate::db::queue) fn dead_letter_numeric_constraint_identifier(
    config: &StoreConfig,
) -> PgIdentifier {
    migration_check_identifier(
        &config.dead_letter_table_name,
        DEAD_LETTER_NUMERIC_CONSTRAINT_SUFFIX,
    )
}

pub(in crate::db::queue) fn dead_letter_text_constraint_identifier(
    config: &StoreConfig,
) -> PgIdentifier {
    migration_check_identifier(
        &config.dead_letter_table_name,
        DEAD_LETTER_TEXT_CONSTRAINT_SUFFIX,
    )
}

pub(in crate::db::queue) fn pause_key_task_constraint_identifier(
    config: &StoreConfig,
) -> PgIdentifier {
    migration_check_identifier(&config.pause_table_name, PAUSE_KEY_TASK_CONSTRAINT_SUFFIX)
}

pub(in crate::db::queue) fn pause_text_constraint_identifier(config: &StoreConfig) -> PgIdentifier {
    migration_check_identifier(&config.pause_table_name, PAUSE_TEXT_CONSTRAINT_SUFFIX)
}

pub(in crate::db::queue) fn migration_check_identifier(
    table_name: &PgQualifiedTableName,
    suffix: &str,
) -> PgIdentifier {
    PgIdentifier::new(migration_object_name(
        CHECK_KIND,
        &table_name.quoted().to_string(),
        suffix,
    ))
    .expect("generated queue migration check name must be valid")
}

pub(in crate::db::queue) fn migration_object_name(
    kind: &str,
    table_name: &str,
    suffix: &str,
) -> String {
    let hash_input = [kind, table_name, suffix].join("\0");
    let hash = blake3::hash(hash_input.as_bytes());
    format!(
        "{}_{}_{}",
        kind,
        suffix,
        first_8_bytes_as_hex(hash.as_bytes())
    )
}

pub(in crate::db::queue) fn first_8_bytes_as_hex(bytes: &[u8; 32]) -> String {
    crate::db::first_8_bytes_as_lower_hex(bytes)
}
