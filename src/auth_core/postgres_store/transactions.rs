use super::*;

pub(in crate::auth_core) async fn finish_auth_store_transaction<T>(
    operation: &'static str,
    tx: Tx<'_>,
    result: Result<T, PostgresAuthStoreError>,
) -> Result<T, PostgresAuthStoreError> {
    match result {
        Ok(value) => {
            tx.commit().await?;
            Ok(value)
        }
        Err(error) => {
            let rollback_result = tx.rollback().await;
            if let Err(rollback_error) = rollback_result {
                return Err(PostgresAuthStoreError::Database(
                    DbError::DatabaseOperationRollbackFailed {
                        operation,
                        operation_error: Box::new(db_error_from_auth_error(error)),
                        rollback_error: Box::new(rollback_error),
                    },
                ));
            }
            Err(error)
        }
    }
}

pub(in crate::auth_core) async fn finish_auth_store_write_transaction<T>(
    operation: &'static str,
    tx: WriteTx<'_>,
    result: Result<T, PostgresAuthStoreError>,
) -> Result<T, PostgresAuthStoreError> {
    match result {
        Ok(value) => {
            tx.commit().await?;
            Ok(value)
        }
        Err(error) => {
            let rollback_result = tx.rollback().await;
            if let Err(rollback_error) = rollback_result {
                return Err(PostgresAuthStoreError::Database(
                    DbError::DatabaseOperationRollbackFailed {
                        operation,
                        operation_error: Box::new(db_error_from_auth_error(error)),
                        rollback_error: Box::new(rollback_error),
                    },
                ));
            }
            Err(error)
        }
    }
}

pub(in crate::auth_core) async fn finish_auth_store_validation_transaction<T>(
    operation: &'static str,
    tx: Tx<'_>,
    result: Result<T, PostgresAuthStoreError>,
) -> Result<T, PostgresAuthStoreError> {
    match result {
        Ok(value) => {
            tx.rollback().await?;
            Ok(value)
        }
        Err(error) => {
            let rollback_result = tx.rollback().await;
            if let Err(rollback_error) = rollback_result {
                return Err(PostgresAuthStoreError::Database(
                    DbError::DatabaseOperationRollbackFailed {
                        operation,
                        operation_error: Box::new(db_error_from_auth_error(error)),
                        rollback_error: Box::new(rollback_error),
                    },
                ));
            }
            Err(error)
        }
    }
}

pub(in crate::auth_core) fn db_error_from_auth_error(error: PostgresAuthStoreError) -> DbError {
    match error {
        PostgresAuthStoreError::Database(error) => error,
        other => DbError::schema_mismatch(other.to_string()),
    }
}
