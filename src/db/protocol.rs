use super::{DatabaseOperationKind, Error, PgQualifiedTableName, Tx, pooler_safe_query_as};
use std::error::Error as StdError;
use std::sync::Arc;

pub(crate) const SUPPORTED_EPOCH: i32 = 1;
pub(crate) const SUPPORTED_FINGERPRINT: &str = "paranoid.protocol.pre9-state.v1";

/// Identity of the transaction admission boundary shared by one Paranoid installation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Protocol {
    table_name: PgQualifiedTableName,
    admission_sql: Arc<str>,
}

/// An installation cannot admit this release to perform database work.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// The active epoch or its immutable definition is unsupported by this release.
    #[error(
        "Paranoid protocol epoch {active_epoch} is incompatible with supported epoch {supported_epoch}: {reason}"
    )]
    Incompatible {
        /// Active database compatibility epoch.
        active_epoch: i32,
        /// Compatibility epoch implemented by this release.
        supported_epoch: i32,
        /// Exact compatibility mismatch.
        reason: &'static str,
    },
    /// Required protocol metadata or transaction semantics are invalid.
    #[error("Paranoid protocol state is invalid: {reason}")]
    State {
        /// Reason why admission cannot safely proceed.
        reason: &'static str,
    },
}

impl Protocol {
    /// Binds stores to an explicitly selected protocol relation without database work.
    pub fn new(table_name: PgQualifiedTableName) -> Self {
        let table = table_name.quoted();
        let admission_sql = format!(
            "LOCK TABLE ONLY {table} IN ACCESS SHARE MODE; \
             SELECT singleton, epoch, fingerprint, \
             pg_catalog.current_setting('transaction_isolation') \
             FROM ONLY {table} LIMIT 2"
        )
        .into();
        Self {
            table_name,
            admission_sql,
        }
    }

    /// Returns the configured installation protocol relation.
    pub fn table_name(&self) -> &PgQualifiedTableName {
        &self.table_name
    }

    pub(crate) async fn admit(&self, tx: &mut Tx<'_>) -> Result<(), Error> {
        let identity = self.table_name.quoted().to_string();
        if tx.admitted_protocols.contains(&identity) {
            return Ok(());
        }
        tx.record_database_operation(
            DatabaseOperationKind::FetchAll,
            "paranoid.protocol.admit",
            Some(&self.admission_sql),
        );
        let rows = pooler_safe_query_as::<(i32, i32, String, String)>(sqlx::AssertSqlSafe(
            self.admission_sql.as_ref(),
        ))
        .fetch_all(tx.inner.as_mut())
        .await
        .map_err(protocol_query_error)?;
        let [(singleton, epoch, fingerprint, isolation)] = rows.as_slice() else {
            return Err(ProtocolError::State {
                reason: "expected exactly one protocol control record",
            }
            .into());
        };
        if *singleton != 1 || *epoch < 1 || fingerprint.is_empty() || fingerprint.len() > 256 {
            return Err(ProtocolError::State {
                reason: "protocol control record is outside its declared domain",
            }
            .into());
        }
        if isolation != "read committed" {
            return Err(ProtocolError::State {
                reason: "protocol admission requires a READ COMMITTED transaction",
            }
            .into());
        }
        if *epoch != SUPPORTED_EPOCH || fingerprint != SUPPORTED_FINGERPRINT {
            return Err(ProtocolError::Incompatible {
                active_epoch: *epoch,
                supported_epoch: SUPPORTED_EPOCH,
                reason: if *epoch == SUPPORTED_EPOCH {
                    "fingerprint mismatch"
                } else {
                    "unsupported epoch"
                },
            }
            .into());
        }
        tx.admitted_protocols.insert(identity);
        Ok(())
    }
}

fn protocol_query_error(error: sqlx::Error) -> Error {
    if matches!(
        error,
        sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_) | sqlx::Error::ColumnNotFound(_)
    ) {
        return ProtocolError::State {
            reason: "protocol control record cannot be decoded",
        }
        .into();
    }
    let code = error.as_database_error().and_then(|value| value.code());
    if matches!(code.as_deref(), Some("42P01" | "42703" | "42809")) {
        ProtocolError::State {
            reason: "protocol relation is absent or has an incompatible shape",
        }
        .into()
    } else {
        Error::query(error)
    }
}

/// Returns whether an error or its retained causes contain a non-retriable protocol admission failure.
pub fn contains_protocol_failure(mut error: &(dyn StdError + 'static)) -> bool {
    loop {
        if error.downcast_ref::<ProtocolError>().is_some() {
            return true;
        }
        if let Some(error) = error.downcast_ref::<super::queue::Error>()
            && contains_queue_protocol_failure(error)
        {
            return true;
        }
        match error.source() {
            Some(source) => error = source,
            None => return false,
        }
    }
}

fn contains_queue_protocol_failure(error: &super::queue::Error) -> bool {
    use super::queue::Error as QueueError;
    match error {
        QueueError::WorkerRuntimeMultipleFailures { failures } => failures
            .iter()
            .any(|error| contains_protocol_failure(error)),
        QueueError::WorkerHeartbeatFailureAndJobFinalizationFailed {
            heartbeat_error,
            finalization_error,
        } => {
            contains_protocol_failure(heartbeat_error.as_ref())
                || contains_protocol_failure(finalization_error.as_ref())
        }
        QueueError::WorkerJobPersistenceFailureAndRequeueFailed {
            persistence_error,
            requeue_error,
        } => {
            contains_protocol_failure(persistence_error.as_ref())
                || contains_protocol_failure(requeue_error.as_ref())
        }
        QueueError::WorkerRuntimeFailureAndClaimedJobCleanupFailed {
            worker_error,
            cleanup_error,
        } => {
            contains_protocol_failure(worker_error.as_ref())
                || contains_protocol_failure(cleanup_error.as_ref())
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::queue::Error as QueueError;

    fn incompatible() -> QueueError {
        QueueError::from(Error::from(ProtocolError::Incompatible {
            active_epoch: 2,
            supported_epoch: 1,
            reason: "unsupported epoch",
        }))
    }

    #[test]
    fn protocol_failure_classification_preserves_all_worker_failure_branches() {
        for primary_is_protocol in [false, true] {
            let pair = || {
                if primary_is_protocol {
                    (Box::new(incompatible()), Box::new(QueueError::JobNotFound))
                } else {
                    (Box::new(QueueError::JobNotFound), Box::new(incompatible()))
                }
            };
            let (heartbeat_error, finalization_error) = pair();
            let (persistence_error, requeue_error) = pair();
            let (worker_error, cleanup_error) = pair();
            let failures = vec![
                QueueError::WorkerHeartbeatFailureAndJobFinalizationFailed {
                    heartbeat_error,
                    finalization_error,
                },
                QueueError::WorkerJobPersistenceFailureAndRequeueFailed {
                    persistence_error,
                    requeue_error,
                },
                QueueError::WorkerRuntimeFailureAndClaimedJobCleanupFailed {
                    worker_error,
                    cleanup_error,
                },
            ];
            for failure in failures {
                assert!(contains_protocol_failure(&failure));
                let nested = QueueError::WorkerRuntimeMultipleFailures {
                    failures: vec![QueueError::JobNotFound, failure],
                };
                assert!(contains_protocol_failure(&nested));
            }
        }
        assert!(!contains_protocol_failure(
            &QueueError::WorkerRuntimeMultipleFailures {
                failures: vec![QueueError::JobNotFound],
            }
        ));
    }
}
