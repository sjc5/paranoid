use std::fmt;
use std::sync::{Arc, Mutex};

/// Kind of Postgres wire operation observed by a [`DatabaseOperationObserver`].
///
/// This instrumentation exists to let Paranoid (and, under the
/// `component-authoring` feature, component authors) assert exact minimum-query behavior in their own
/// Postgres-backed test suites.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseOperationKind {
    /// A transaction was begun.
    BeginTransaction,
    /// A transaction was committed.
    CommitTransaction,
    /// A transaction was rolled back.
    RollbackTransaction,
    /// A statement was executed for its side effect.
    Execute,
    /// A query fetched all matching rows.
    FetchAll,
    /// A query fetched exactly one row.
    FetchOne,
    /// A query fetched at most one row.
    FetchOptional,
}

/// One observed Postgres wire operation, as recorded by a [`DatabaseOperationObserver`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseOperationRecord {
    /// The kind of operation observed.
    pub kind: DatabaseOperationKind,
    /// The call-site label attached to the operation.
    pub label: &'static str,
    /// The rendered SQL statement, when the operation carried one.
    pub statement: Option<String>,
}

type BeforeDatabaseOperationHook = Arc<dyn Fn(DatabaseOperationRecord) + Send + Sync + 'static>;

/// Records every Postgres wire operation performed through a cloned pool or
/// transaction, for exact minimum-query assertions in Postgres-backed test
/// suites.
///
/// Attach one to a pool via `clone_with_database_operation_observer`, then
/// inspect the accumulated `records()` after driving the operation under test.
#[derive(Clone, Default)]
pub struct DatabaseOperationObserver {
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
    /// Creates an observer that invokes `hook` synchronously as each operation is recorded.
    ///
    /// This lets a test inject a side effect (such as a concurrent racing write) at an
    /// exact point in a multi-step database operation.
    #[cfg(any(test, feature = "component-authoring"))]
    pub fn with_before_operation_hook(
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

    /// Returns every operation recorded so far, in recorded order.
    #[cfg(any(test, feature = "component-authoring"))]
    pub fn records(&self) -> Vec<DatabaseOperationRecord> {
        self.records
            .lock()
            .expect("database operation observer lock poisoned")
            .clone()
    }

    /// Discards every operation recorded so far.
    #[cfg(any(test, feature = "component-authoring"))]
    pub fn clear(&self) {
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
