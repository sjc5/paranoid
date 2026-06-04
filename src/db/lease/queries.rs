use super::*;

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
    let key = LeaseColumn::Key.name();
    let holder_id = LeaseColumn::HolderId.name();
    let fencing_token = LeaseColumn::FencingToken.name();
    let lease_token = LeaseColumn::LeaseToken.name();
    let expires_at = LeaseColumn::ExpiresAt.name();
    let updated_at = LeaseColumn::UpdatedAt.name();
    let last_fencing_token = LeaseColumn::LastFencingToken.name();
    let counter_target_last_fencing_token =
        LeaseColumn::LastFencingToken.qualified("counter_target");
    let excluded_last_fencing_token = LeaseColumn::LastFencingToken.qualified("EXCLUDED");
    let excluded_holder_id = LeaseColumn::HolderId.qualified("EXCLUDED");
    let excluded_fencing_token = LeaseColumn::FencingToken.qualified("EXCLUDED");
    let excluded_lease_token = LeaseColumn::LeaseToken.qualified("EXCLUDED");
    let excluded_expires_at = LeaseColumn::ExpiresAt.qualified("EXCLUDED");
    let excluded_updated_at = LeaseColumn::UpdatedAt.qualified("EXCLUDED");
    let lease_target_expires_at = LeaseColumn::ExpiresAt.qualified("lease_target");
    let expires_at_unix_microseconds = expires_at_unix_microseconds_expression();

    format!(
        "WITH existing_lease AS (\
             SELECT {fencing_token}, {expires_at} \
             FROM {quoted_table_name} \
             WHERE {key} = $1 \
             FOR UPDATE\
         ), \
         claimable AS (\
             SELECT \
                 $1::text AS {key}, \
                 COALESCE((SELECT {fencing_token} FROM existing_lease), 0) AS existing_fencing_token \
             WHERE NOT EXISTS (\
                 SELECT 1 \
                 FROM existing_lease \
                 WHERE {expires_at} > statement_timestamp()\
             )\
         ), \
         next_fencing_token AS (\
             INSERT INTO {quoted_fencing_counter_table_name} AS counter_target \
                 ({key}, {last_fencing_token}, {updated_at}) \
             SELECT {key}, existing_fencing_token + 1, statement_timestamp() \
             FROM claimable \
             ON CONFLICT ({key}) DO UPDATE SET \
                 {last_fencing_token} = GREATEST(\
                     {counter_target_last_fencing_token} + 1, \
                     {excluded_last_fencing_token}\
                 ), \
                 {updated_at} = statement_timestamp() \
             RETURNING {last_fencing_token}\
         ), \
         upserted_lease AS (\
             INSERT INTO {quoted_table_name} AS lease_target \
                 ({key}, {holder_id}, {fencing_token}, {lease_token}, {expires_at}, {updated_at}) \
             SELECT \
                 $1, $2, next_fencing_token.{last_fencing_token}, $3, \
                 statement_timestamp() + ($4::bigint * INTERVAL '1 microsecond'), \
                 statement_timestamp() \
             FROM next_fencing_token \
             ON CONFLICT ({key}) DO UPDATE SET \
                 {holder_id} = {excluded_holder_id}, \
                 {fencing_token} = {excluded_fencing_token}, \
                 {lease_token} = {excluded_lease_token}, \
                 {expires_at} = {excluded_expires_at}, \
                 {updated_at} = {excluded_updated_at} \
             WHERE {lease_target_expires_at} <= statement_timestamp() \
             RETURNING {holder_id}, {fencing_token}, {lease_token}, \
                 {expires_at_unix_microseconds} AS expires_at_unix_microseconds\
         ) \
         SELECT {holder_id}, {fencing_token}, {lease_token}, expires_at_unix_microseconds \
         FROM upserted_lease"
    )
}

fn build_renew_lease_query(quoted_table_name: &str) -> String {
    let key = LeaseColumn::Key.name();
    let holder_id = LeaseColumn::HolderId.name();
    let fencing_token = LeaseColumn::FencingToken.name();
    let lease_token = LeaseColumn::LeaseToken.name();
    let expires_at = LeaseColumn::ExpiresAt.name();
    let updated_at = LeaseColumn::UpdatedAt.name();
    let expires_at_unix_microseconds = expires_at_unix_microseconds_expression();

    format!(
        "UPDATE {quoted_table_name} \
         SET {lease_token} = $5, \
             {expires_at} = statement_timestamp() + ($6::bigint * INTERVAL '1 microsecond'), \
             {updated_at} = statement_timestamp() \
         WHERE {key} = $1 \
           AND {holder_id} = $2 \
           AND {fencing_token} = $3 \
           AND {lease_token} = $4 \
           AND {expires_at} > statement_timestamp() \
         RETURNING {holder_id}, {fencing_token}, {lease_token}, \
             {expires_at_unix_microseconds}"
    )
}

fn build_release_lease_query(quoted_table_name: &str) -> String {
    let key = LeaseColumn::Key.name();
    let holder_id = LeaseColumn::HolderId.name();
    let fencing_token = LeaseColumn::FencingToken.name();
    let lease_token = LeaseColumn::LeaseToken.name();
    let expires_at = LeaseColumn::ExpiresAt.name();

    format!(
        "DELETE FROM {quoted_table_name} \
         WHERE {key} = $1 \
           AND {holder_id} = $2 \
           AND {fencing_token} = $3 \
           AND {lease_token} = $4 \
           AND {expires_at} > statement_timestamp()"
    )
}

fn build_fetch_live_lease_holder_query(quoted_table_name: &str) -> String {
    let key = LeaseColumn::Key.name();
    let holder_id = LeaseColumn::HolderId.name();
    let fencing_token = LeaseColumn::FencingToken.name();
    let expires_at = LeaseColumn::ExpiresAt.name();
    let expires_at_unix_microseconds = expires_at_unix_microseconds_expression();

    format!(
        "SELECT {holder_id}, {fencing_token}, {expires_at_unix_microseconds} \
         FROM {quoted_table_name} \
         WHERE {key} = $1 \
           AND {expires_at} > statement_timestamp()"
    )
}
