use super::{LEASE_TOKEN_BYTES, MAX_LEASE_HOLDER_ID_BYTES, MAX_LEASE_KEY_BYTES, StoreConfig};
use crate::db::PgIdentifier;
#[cfg(test)]
use crate::db::PgQualifiedTableName;

const INDEX_KIND: &str = "idx";
#[cfg(test)]
const FENCING_COUNTER_TABLE_SUFFIX: &str = "fencing_counters";
const CREATE_LEASE_TABLE_TEMPLATE_PREFIX: &str = "CREATE TABLE IF NOT EXISTS ";
const BYTEWISE_TEXT_COLLATIONS: [&str; 2] = ["C", "POSIX"];
const NO_COLLATIONS: [&str; 0] = [];

pub(super) const LEASE_STATE_COLUMNS: [LeaseColumn; 6] = [
    LeaseColumn::Key,
    LeaseColumn::HolderId,
    LeaseColumn::FencingToken,
    LeaseColumn::LeaseToken,
    LeaseColumn::ExpiresAt,
    LeaseColumn::UpdatedAt,
];
pub(super) const LEASE_FENCING_COUNTER_COLUMNS: [LeaseColumn; 3] = [
    LeaseColumn::Key,
    LeaseColumn::LastFencingToken,
    LeaseColumn::UpdatedAt,
];
pub(super) const LEASE_STATE_CHECKED_COLUMNS: [LeaseColumn; 4] = [
    LeaseColumn::Key,
    LeaseColumn::HolderId,
    LeaseColumn::FencingToken,
    LeaseColumn::LeaseToken,
];
pub(super) const LEASE_FENCING_COUNTER_CHECKED_COLUMNS: [LeaseColumn; 2] =
    [LeaseColumn::Key, LeaseColumn::LastFencingToken];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LeaseColumn {
    Key,
    HolderId,
    FencingToken,
    LeaseToken,
    ExpiresAt,
    UpdatedAt,
    LastFencingToken,
}

impl LeaseColumn {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::HolderId => "holder_id",
            Self::FencingToken => "fencing_token",
            Self::LeaseToken => "lease_token",
            Self::ExpiresAt => "expires_at",
            Self::UpdatedAt => "updated_at",
            Self::LastFencingToken => "last_fencing_token",
        }
    }

    pub(super) const fn create_table_type(self) -> &'static str {
        match self {
            Self::Key | Self::HolderId => "TEXT",
            Self::FencingToken | Self::LastFencingToken => "BIGINT",
            Self::LeaseToken => "BYTEA",
            Self::ExpiresAt | Self::UpdatedAt => "TIMESTAMPTZ",
        }
    }

    pub(super) const fn validation_type(self) -> &'static str {
        match self {
            Self::Key | Self::HolderId => "text",
            Self::FencingToken | Self::LastFencingToken => "bigint",
            Self::LeaseToken => "bytea",
            Self::ExpiresAt | Self::UpdatedAt => "timestamp with time zone",
        }
    }

    pub(super) fn allowed_collations(self) -> &'static [&'static str] {
        match self {
            Self::Key | Self::HolderId => &BYTEWISE_TEXT_COLLATIONS,
            Self::FencingToken
            | Self::LeaseToken
            | Self::ExpiresAt
            | Self::UpdatedAt
            | Self::LastFencingToken => &NO_COLLATIONS,
        }
    }

    pub(super) fn normalized_check_constraint(self) -> Option<String> {
        match self.check_constraint() {
            Some(LeaseCheckConstraint::NonEmptyMaxOctetLength(max_octets)) => {
                let column = self.name();
                Some(format!(
                    "(octet_length({column})>0)AND(octet_length({column})<={max_octets})"
                ))
            }
            Some(LeaseCheckConstraint::Positive) => Some(format!("{}>0", self.name())),
            Some(LeaseCheckConstraint::ExactOctetLength(octets)) => {
                Some(format!("octet_length({})={octets}", self.name()))
            }
            None => None,
        }
    }

    pub(super) fn human_check_constraint(self) -> Option<String> {
        match self.check_constraint() {
            Some(LeaseCheckConstraint::NonEmptyMaxOctetLength(max_octets)) => {
                let column = self.name();
                Some(format!(
                    "octet_length({column}) > 0 AND octet_length({column}) <= {max_octets}"
                ))
            }
            Some(LeaseCheckConstraint::Positive) => Some(format!("{} > 0", self.name())),
            Some(LeaseCheckConstraint::ExactOctetLength(octets)) => {
                Some(format!("octet_length({}) = {octets}", self.name()))
            }
            None => None,
        }
    }

    pub(super) fn qualified(self, table_alias: &str) -> String {
        format!("{table_alias}.{}", self.name())
    }

    fn check_constraint(self) -> Option<LeaseCheckConstraint> {
        match self {
            Self::Key => Some(LeaseCheckConstraint::NonEmptyMaxOctetLength(
                MAX_LEASE_KEY_BYTES,
            )),
            Self::HolderId => Some(LeaseCheckConstraint::NonEmptyMaxOctetLength(
                MAX_LEASE_HOLDER_ID_BYTES,
            )),
            Self::FencingToken | Self::LastFencingToken => Some(LeaseCheckConstraint::Positive),
            Self::LeaseToken => Some(LeaseCheckConstraint::ExactOctetLength(LEASE_TOKEN_BYTES)),
            Self::ExpiresAt | Self::UpdatedAt => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseCheckConstraint {
    NonEmptyMaxOctetLength(usize),
    Positive,
    ExactOctetLength(usize),
}

pub(super) fn create_lease_table_statement(config: &StoreConfig) -> String {
    let column_definitions = LEASE_STATE_COLUMNS
        .iter()
        .map(|column| create_table_column_definition(*column, *column == LeaseColumn::Key))
        .collect::<Vec<_>>()
        .join(",\n    ");
    format!(
        "{CREATE_LEASE_TABLE_TEMPLATE_PREFIX}{} (\n    {column_definitions}\n)",
        config.table_name.quoted()
    )
}

pub(super) fn create_fencing_counter_table_statement(config: &StoreConfig) -> String {
    let column_definitions = LEASE_FENCING_COUNTER_COLUMNS
        .iter()
        .map(|column| create_table_column_definition(*column, *column == LeaseColumn::Key))
        .collect::<Vec<_>>()
        .join(",\n    ");
    format!(
        "{CREATE_LEASE_TABLE_TEMPLATE_PREFIX}{} (\n    {column_definitions}\n)",
        config.fencing_counter_table_name.quoted()
    )
}

pub(super) fn create_expires_at_index_statement(config: &StoreConfig) -> String {
    let expires_at = LeaseColumn::ExpiresAt.name();
    format!(
        "CREATE INDEX IF NOT EXISTS {} ON {} ({expires_at})",
        migration_index_identifier(config, expires_at).quoted(),
        config.table_name.quoted()
    )
}

pub(super) fn expires_at_unix_microseconds_expression() -> String {
    let expires_at = LeaseColumn::ExpiresAt.name();
    format!("(floor(EXTRACT(EPOCH FROM {expires_at}) * 1000000)::bigint)")
}

#[cfg(test)]
pub(super) fn derive_fencing_counter_table_name(
    table_name: &PgQualifiedTableName,
) -> PgQualifiedTableName {
    let candidate_table_name = format!(
        "{}_{}",
        table_name.table().as_str(),
        FENCING_COUNTER_TABLE_SUFFIX
    );
    let counter_table = PgIdentifier::new(&candidate_table_name).unwrap_or_else(|_| {
        let hash = blake3::hash(table_name.quoted().to_string().as_bytes());
        PgIdentifier::new(format!(
            "__lease_fencing_{}",
            first_8_bytes_as_hex(hash.as_bytes())
        ))
        .expect("generated lease fencing counter table name must be valid")
    });
    PgQualifiedTableName::new(table_name.schema().cloned(), counter_table)
}

pub(super) fn migration_index_identifier(
    config: &StoreConfig,
    suffix: &'static str,
) -> PgIdentifier {
    let object_name =
        migration_object_name(INDEX_KIND, &config.table_name.quoted().to_string(), suffix);
    PgIdentifier::new(object_name).expect("generated migration index name must be valid")
}

fn create_table_column_definition(column: LeaseColumn, primary_key: bool) -> String {
    let name = column.name();
    let column_type = column.create_table_type();
    let collation = if column.allowed_collations().is_empty() {
        ""
    } else {
        r#" COLLATE "C""#
    };
    let nullability_or_primary_key = if primary_key {
        " PRIMARY KEY"
    } else {
        " NOT NULL"
    };
    let check_constraint = column
        .human_check_constraint()
        .map(|constraint| format!(" CHECK ({constraint})"))
        .unwrap_or_default();
    format!("{name} {column_type}{collation}{nullability_or_primary_key}{check_constraint}")
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
