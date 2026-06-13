use super::*;

pub(in crate::auth_core) async fn fetch_exists_for_update<'q, F>(
    tx: &mut Tx<'_>,
    label: &'static str,
    statement: &'q str,
    bind: F,
) -> Result<bool, PostgresAuthStoreError>
where
    F: FnOnce(
        sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    ) -> Result<
        sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
        PostgresAuthStoreError,
    >,
{
    tx.record_database_operation(DatabaseOperationKind::FetchOptional, label, Some(statement));
    let row = bind(pooler_safe_query(sqlx::AssertSqlSafe(statement)))?
        .fetch_optional(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?;
    Ok(row.is_some())
}

pub(in crate::auth_core) async fn execute_one_row_update<'q, F>(
    tx: &mut Tx<'_>,
    label: &'static str,
    statement: &'q str,
    bind: F,
) -> Result<(), PostgresAuthStoreError>
where
    F: FnOnce(
        sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    ) -> Result<
        sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
        PostgresAuthStoreError,
    >,
{
    tx.record_database_operation(DatabaseOperationKind::Execute, label, Some(statement));
    let affected = bind(pooler_safe_query(sqlx::AssertSqlSafe(statement)))?
        .execute(tx.sqlx_transaction().as_mut())
        .await
        .map_err(DbError::query)?
        .rows_affected();
    if affected != 1 {
        return Err(PostgresAuthStoreError::PreconditionFailed(
            "expected exactly one row to be updated",
        ));
    }
    Ok(())
}
