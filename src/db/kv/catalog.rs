use super::*;
use crate::db::PgIdentifier;

pub(super) const EXPIRES_AT_INDEX_SUFFIX: &str = "expires_at";
pub(super) const KEY_PATTERN_INDEX_SUFFIX: &str = "key_pattern";
pub(super) const UPDATED_AT_INDEX_SUFFIX: &str = "updated_at";
#[cfg(test)]
pub(super) const TEST_KV_TABLE_NAME: &str = "__paranoid_kv_store";

const INDEX_KIND: &str = "idx";
const CREATE_KV_TABLE_TEMPLATE_PREFIX: &str = "CREATE TABLE IF NOT EXISTS ";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct KvCatalog {
    table_name: PgQualifiedTableName,
    create_updated_at_index: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum KvColumn {
    Key,
    Value,
    ExpiresAt,
    UpdatedAt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum KvIndex {
    ExpiresAt,
    KeyPattern,
    UpdatedAt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RequiredColumn {
    pub(super) name: &'static str,
    pub(super) data_type: &'static str,
    pub(super) not_null: bool,
    pub(super) allowed_collations: &'static [&'static str],
}

impl KvCatalog {
    pub(super) fn new(config: &StoreConfig) -> Self {
        Self {
            table_name: config.table_name.clone(),
            create_updated_at_index: config.create_updated_at_index,
        }
    }

    pub(super) fn table_name(&self) -> &PgQualifiedTableName {
        &self.table_name
    }

    pub(super) fn quoted_table_name(&self) -> String {
        self.table_name.quoted().to_string()
    }

    pub(super) fn required_columns(&self) -> [RequiredColumn; 4] {
        [
            RequiredColumn {
                name: KvColumn::Key.name(),
                data_type: "text",
                not_null: true,
                allowed_collations: &["C", "POSIX"],
            },
            RequiredColumn {
                name: KvColumn::Value.name(),
                data_type: "bytea",
                not_null: true,
                allowed_collations: &[],
            },
            RequiredColumn {
                name: KvColumn::ExpiresAt.name(),
                data_type: "timestamp with time zone",
                not_null: false,
                allowed_collations: &[],
            },
            RequiredColumn {
                name: KvColumn::UpdatedAt.name(),
                data_type: "timestamp with time zone",
                not_null: true,
                allowed_collations: &[],
            },
        ]
    }

    pub(super) fn create_table_statement(&self) -> String {
        let quoted_table_name = self.quoted_table_name();
        let key = KvColumn::Key.sql_identifier();
        let value = KvColumn::Value.sql_identifier();
        let expires_at = KvColumn::ExpiresAt.sql_identifier();
        let updated_at = KvColumn::UpdatedAt.sql_identifier();
        let key_length_check = self.key_length_check_sql();
        format!(
            r#"{CREATE_KV_TABLE_TEMPLATE_PREFIX}{quoted_table_name} (
    {key} TEXT COLLATE "C" PRIMARY KEY CHECK ({key_length_check}),
    {value} BYTEA NOT NULL,
    {expires_at} TIMESTAMPTZ,
    {updated_at} TIMESTAMPTZ NOT NULL
)"#
        )
    }

    pub(super) fn create_index_statements(&self) -> Vec<String> {
        let mut statements = Vec::with_capacity(if self.create_updated_at_index { 3 } else { 2 });
        statements.push(self.create_expires_at_index_statement());
        statements.push(self.create_key_pattern_index_statement());
        if self.create_updated_at_index {
            statements.push(self.create_updated_at_index_statement());
        }
        statements
    }

    #[cfg(test)]
    pub(super) fn all_migrate_statements(&self) -> Vec<String> {
        let mut statements = Vec::with_capacity(if self.create_updated_at_index { 4 } else { 3 });
        statements.push(self.create_table_statement());
        statements.extend(self.create_index_statements());
        statements
    }

    pub(super) fn migration_index_identifier_for_suffix(&self, suffix: &str) -> PgIdentifier {
        migration_index_identifier_for_table(self.table_name(), suffix)
    }

    pub(super) fn migration_index_identifier(&self, index: KvIndex) -> PgIdentifier {
        self.migration_index_identifier_for_suffix(index.suffix())
    }

    pub(super) fn key_length_check_sql(&self) -> String {
        format!(
            "octet_length({}) > 0 AND octet_length({}) <= {}",
            KvColumn::Key.sql_identifier(),
            KvColumn::Key.sql_identifier(),
            MAX_KV_KEY_BYTES
        )
    }

    pub(super) fn normalized_key_length_check_expression(&self) -> String {
        format!(
            "(octet_length({})>0)AND(octet_length({})<={})",
            KvColumn::Key.sql_identifier(),
            KvColumn::Key.sql_identifier(),
            MAX_KV_KEY_BYTES
        )
    }

    pub(super) fn not_expired_filter(&self) -> String {
        format!(
            "({} IS NULL OR {} > statement_timestamp())",
            KvColumn::ExpiresAt.sql_identifier(),
            KvColumn::ExpiresAt.sql_identifier()
        )
    }

    pub(super) fn expired_filter(&self) -> String {
        format!(
            "({} IS NOT NULL AND {} <= statement_timestamp())",
            KvColumn::ExpiresAt.sql_identifier(),
            KvColumn::ExpiresAt.sql_identifier()
        )
    }

    pub(super) fn expires_at_index_predicate_sql(&self) -> String {
        format!("{} IS NOT NULL", KvColumn::ExpiresAt.sql_identifier())
    }

    pub(super) fn parenthesized_expires_at_index_predicate_sql(&self) -> String {
        format!("({})", self.expires_at_index_predicate_sql())
    }

    pub(super) fn create_expires_at_index_statement(&self) -> String {
        let expires_at = KvColumn::ExpiresAt.sql_identifier();
        let predicate = self.expires_at_index_predicate_sql();
        format!(
            "CREATE INDEX IF NOT EXISTS {} ON {} ({expires_at})\nWHERE {predicate}",
            self.migration_index_identifier(KvIndex::ExpiresAt).quoted(),
            self.table_name.quoted()
        )
    }

    pub(super) fn create_key_pattern_index_statement(&self) -> String {
        format!(
            "CREATE INDEX IF NOT EXISTS {} ON {} ({} text_pattern_ops)",
            self.migration_index_identifier(KvIndex::KeyPattern)
                .quoted(),
            self.table_name.quoted(),
            KvColumn::Key.sql_identifier()
        )
    }

    pub(super) fn create_updated_at_index_statement(&self) -> String {
        format!(
            "CREATE INDEX IF NOT EXISTS {} ON {} ({})",
            self.migration_index_identifier(KvIndex::UpdatedAt).quoted(),
            self.table_name.quoted(),
            KvColumn::UpdatedAt.sql_identifier()
        )
    }
}

impl KvColumn {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Value => "value",
            Self::ExpiresAt => "expires_at",
            Self::UpdatedAt => "updated_at",
        }
    }

    pub(super) const fn sql_identifier(self) -> &'static str {
        self.name()
    }
}

impl KvIndex {
    pub(super) const fn suffix(self) -> &'static str {
        match self {
            Self::ExpiresAt => EXPIRES_AT_INDEX_SUFFIX,
            Self::KeyPattern => KEY_PATTERN_INDEX_SUFFIX,
            Self::UpdatedAt => UPDATED_AT_INDEX_SUFFIX,
        }
    }
}

pub(super) fn migration_index_identifier_for_table(
    table_name: &PgQualifiedTableName,
    suffix: &str,
) -> PgIdentifier {
    let object_name = migration_object_name(INDEX_KIND, &table_name.quoted().to_string(), suffix);
    PgIdentifier::new(object_name).expect("generated migration index name must be valid")
}

fn migration_object_name(kind: &str, table_name: &str, suffix: &str) -> String {
    let hash_input = [kind, table_name, suffix].join("\0");
    let hash = blake3::hash(hash_input.as_bytes());
    format!(
        "{}_{}_{}",
        kind,
        suffix,
        first_8_bytes_as_hex(hash.as_bytes())
    )
}

fn first_8_bytes_as_hex(bytes: &[u8; 32]) -> String {
    crate::db::first_8_bytes_as_lower_hex(bytes)
}
