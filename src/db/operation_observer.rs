use std::fmt;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DatabaseOperationKind {
    BeginTransaction,
    CommitTransaction,
    RollbackTransaction,
    Execute,
    FetchAll,
    FetchOne,
    FetchOptional,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DatabaseOperationRecord {
    pub(crate) kind: DatabaseOperationKind,
    pub(crate) label: &'static str,
    pub(crate) statement: Option<String>,
}

type BeforeDatabaseOperationHook = Arc<dyn Fn(DatabaseOperationRecord) + Send + Sync + 'static>;

#[derive(Clone, Default)]
pub(crate) struct DatabaseOperationObserver {
    records: Arc<Mutex<Vec<DatabaseOperationRecord>>>,
    before_operation_hook: Option<BeforeDatabaseOperationHook>,
}

impl fmt::Debug for DatabaseOperationObserver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseOperationObserver")
            .field("records", &self.records)
            .field(
                "has_before_operation_hook",
                &self.before_operation_hook.is_some(),
            )
            .finish()
    }
}

impl DatabaseOperationObserver {
    #[cfg(test)]
    pub(crate) fn with_before_operation_hook(
        hook: impl Fn(DatabaseOperationRecord) + Send + Sync + 'static,
    ) -> Self {
        Self {
            records: Arc::new(Mutex::new(Vec::new())),
            before_operation_hook: Some(Arc::new(hook)),
        }
    }

    pub(crate) fn record(
        &self,
        kind: DatabaseOperationKind,
        label: &'static str,
        statement: Option<&str>,
    ) {
        let record = DatabaseOperationRecord {
            kind,
            label,
            statement: statement.map(ToOwned::to_owned),
        };
        self.records
            .lock()
            .expect("database operation observer lock poisoned")
            .push(record.clone());
        if let Some(before_operation_hook) = &self.before_operation_hook {
            before_operation_hook(record);
        }
    }

    #[cfg(test)]
    pub(crate) fn records(&self) -> Vec<DatabaseOperationRecord> {
        self.records
            .lock()
            .expect("database operation observer lock poisoned")
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn clear(&self) {
        self.records
            .lock()
            .expect("database operation observer lock poisoned")
            .clear();
    }
}

pub(crate) fn record_database_operation(
    observer: Option<&DatabaseOperationObserver>,
    kind: DatabaseOperationKind,
    label: &'static str,
    statement: Option<&str>,
) {
    if let Some(observer) = observer {
        observer.record(kind, label, statement);
    }
}
