use super::*;

const INDEX_KIND: &str = "idx";
const FENCING_COUNTER_TABLE_SUFFIX: &str = "fencing_counters";
const LEASE_EXPIRES_AT_UNIX_MICROSECONDS: &str =
    "(floor(EXTRACT(EPOCH FROM expires_at) * 1000000)::bigint)";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Queries {
    pub(super) claim_lease: String,
    pub(super) renew_lease: String,
    pub(super) release_lease: String,
    pub(super) fetch_live_lease_holder: String,
}

impl Queries {
    pub(super) fn new(config: &StoreConfig) -> Self {
        let quoted_table_name = config.table_name.quoted().to_string();
        let quoted_fencing_counter_table_name =
            config.fencing_counter_table_name.quoted().to_string();
        Self {
            claim_lease: build_claim_lease_query(
                &quoted_table_name,
                &quoted_fencing_counter_table_name,
            ),
            renew_lease: build_renew_lease_query(&quoted_table_name),
            release_lease: build_release_lease_query(&quoted_table_name),
            fetch_live_lease_holder: build_fetch_live_lease_holder_query(&quoted_table_name),
        }
    }
}

fn build_claim_lease_query(
    quoted_table_name: &str,
    quoted_fencing_counter_table_name: &str,
) -> String {
    format!(
        "WITH existing_lease AS (\
             SELECT fencing_token, expires_at \
             FROM {quoted_table_name} \
             WHERE key = $1 \
             FOR UPDATE\
         ), \
         claimable AS (\
             SELECT \
                 $1::text AS key, \
                 COALESCE((SELECT fencing_token FROM existing_lease), 0) AS existing_fencing_token \
             WHERE NOT EXISTS (\
                 SELECT 1 \
                 FROM existing_lease \
                 WHERE expires_at > statement_timestamp()\
             )\
         ), \
         next_fencing_token AS (\
             INSERT INTO {quoted_fencing_counter_table_name} AS counter_target \
                 (key, last_fencing_token, updated_at) \
             SELECT key, existing_fencing_token + 1, statement_timestamp() \
             FROM claimable \
             ON CONFLICT (key) DO UPDATE SET \
                 last_fencing_token = GREATEST(\
                     counter_target.last_fencing_token + 1, \
                     EXCLUDED.last_fencing_token\
                 ), \
                 updated_at = statement_timestamp() \
             RETURNING last_fencing_token\
         ), \
         upserted_lease AS (\
             INSERT INTO {quoted_table_name} AS lease_target \
                 (key, holder_id, fencing_token, lease_token, expires_at, updated_at) \
             SELECT \
                 $1, $2, next_fencing_token.last_fencing_token, $3, \
                 statement_timestamp() + ($4::bigint * INTERVAL '1 microsecond'), \
                 statement_timestamp() \
             FROM next_fencing_token \
             ON CONFLICT (key) DO UPDATE SET \
                 holder_id = EXCLUDED.holder_id, \
                 fencing_token = EXCLUDED.fencing_token, \
                 lease_token = EXCLUDED.lease_token, \
                 expires_at = EXCLUDED.expires_at, \
                 updated_at = EXCLUDED.updated_at \
             WHERE lease_target.expires_at <= statement_timestamp() \
             RETURNING holder_id, fencing_token, lease_token, \
                 {LEASE_EXPIRES_AT_UNIX_MICROSECONDS} AS expires_at_unix_microseconds\
         ) \
         SELECT holder_id, fencing_token, lease_token, expires_at_unix_microseconds \
         FROM upserted_lease"
    )
}

fn build_renew_lease_query(quoted_table_name: &str) -> String {
    format!(
        "UPDATE {quoted_table_name} \
         SET lease_token = $5, \
             expires_at = statement_timestamp() + ($6::bigint * INTERVAL '1 microsecond'), \
             updated_at = statement_timestamp() \
         WHERE key = $1 \
           AND holder_id = $2 \
           AND fencing_token = $3 \
           AND lease_token = $4 \
           AND expires_at > statement_timestamp() \
         RETURNING holder_id, fencing_token, lease_token, \
             {LEASE_EXPIRES_AT_UNIX_MICROSECONDS}"
    )
}

fn build_release_lease_query(quoted_table_name: &str) -> String {
    format!(
        "DELETE FROM {quoted_table_name} \
         WHERE key = $1 \
           AND holder_id = $2 \
           AND fencing_token = $3 \
           AND lease_token = $4 \
           AND expires_at > statement_timestamp()"
    )
}

fn build_fetch_live_lease_holder_query(quoted_table_name: &str) -> String {
    format!(
        "SELECT holder_id, fencing_token, {LEASE_EXPIRES_AT_UNIX_MICROSECONDS} \
         FROM {quoted_table_name} \
         WHERE key = $1 \
           AND expires_at > statement_timestamp()"
    )
}

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
