use super::sql::*;
use super::*;

pub(in crate::db::queue) async fn execute_queue_migration_statements_in_current_transaction(
    tx: &mut Tx<'_>,
    config: &StoreConfig,
) -> Result<(), Error> {
    for statement in build_queue_schema_migration_statements(config) {
        tx.record_database_operation(
            DatabaseOperationKind::Execute,
            QUEUE_OPERATION_SCHEMA_MIGRATE_STATEMENT,
            Some(statement.as_str()),
        );
        pooler_safe_query(sqlx::AssertSqlSafe(statement.as_str()))
            .execute(tx.inner.as_mut())
            .await
            .map_err(DbError::query)?;
    }
    Ok(())
}
