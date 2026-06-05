use std::{
    fs,
    path::{Path, PathBuf},
};

#[test]
fn auth_postgres_code_uses_pooler_safe_query_constructors() {
    let forbidden_needles = [
        "sqlx::query(",
        "sqlx::query_as",
        "sqlx::query_scalar",
        "sqlx::raw_sql",
    ];
    let mut violations = Vec::new();
    for path in auth_core_postgres_production_source_files() {
        let source = read_source_file(&path);
        for needle in forbidden_needles {
            if source.contains(needle) {
                violations.push(format!("{} contains {needle}", relative_path(&path)));
            }
        }
    }

    violations.sort();
    assert!(
        violations.is_empty(),
        "Auth Postgres code must use db::pooler_safe_query/db::pooler_safe_query_as/db::pooler_safe_query_scalar/db::unparameterized_simple_query so SQLx persistent prepared statements stay disabled and simple-protocol SQL stays explicit:\n{}",
        violations.join("\n")
    );
}

#[test]
fn auth_postgres_code_does_not_bypass_internal_pool_wrappers() {
    let mut violations = Vec::new();
    for path in auth_core_postgres_production_source_files() {
        let source = read_source_file(&path);
        if source.contains(".sqlx_pool()") {
            violations.push(format!("{} contains .sqlx_pool()", relative_path(&path)));
        }
    }

    violations.sort();
    assert!(
        violations.is_empty(),
        "Auth Postgres code must not call the public raw SQLx pool accessor internally. Use Pool::begin_transaction plus auth/store runtime transaction boundaries instead:\n{}",
        violations.join("\n")
    );
}

#[test]
fn auth_postgres_sql_does_not_use_session_level_postgres_features() {
    let forbidden_needles = [
        "pg_advisory",
        "listen ",
        "notify ",
        "create temp",
        "create temporary",
        "set session",
        "prepare ",
        "deallocate ",
    ];
    let mut violations = Vec::new();
    for path in auth_core_postgres_production_source_files() {
        let source = read_source_file(&path);
        let source_lowercase = source.to_lowercase();
        for needle in forbidden_needles {
            if source_contains_forbidden_sql_phrase(&source_lowercase, needle) {
                violations.push(format!("{} contains {needle:?}", relative_path(&path)));
            }
        }
    }

    violations.sort();
    assert!(
        violations.is_empty(),
        "Auth Postgres SQL must avoid session-level Postgres features and connection-pooler-hostile prepared-statement commands:\n{}",
        violations.join("\n")
    );
}

#[test]
fn auth_postgres_set_config_calls_are_transaction_local() {
    let allowed_transaction_local_statement_timeout = "set_config('statement_timeout', $1, true)";
    let mut violations = Vec::new();
    for path in auth_core_postgres_production_source_files() {
        let source = read_source_file(&path);
        for (line_index, line) in source.lines().enumerate() {
            let line_lowercase = line.to_lowercase();
            if line_lowercase.contains("set_config(")
                && !line_lowercase.contains(allowed_transaction_local_statement_timeout)
            {
                violations.push(format!(
                    "{}:{} contains a non-approved set_config call",
                    relative_path(&path),
                    line_index + 1
                ));
            }
        }
    }

    violations.sort();
    assert!(
        violations.is_empty(),
        "Auth Postgres SQL may only use set_config for transaction-local statement timeouts; session-scoped set_config violates transaction-pooler safety:\n{}",
        violations.join("\n")
    );
}

#[test]
fn auth_postgres_sql_uses_statement_timestamp_for_database_owned_time() {
    let forbidden_clock_functions = [
        "current_timestamp",
        "transaction_timestamp(",
        "clock_timestamp(",
        "now(",
    ];
    let mut violations = Vec::new();
    for path in auth_core_postgres_production_source_files() {
        let source = read_source_file(&path);
        let source_lowercase = source.to_lowercase();
        for needle in forbidden_clock_functions {
            if source_contains_forbidden_database_clock_call(&source_lowercase, needle) {
                violations.push(format!("{} contains {needle:?}", relative_path(&path)));
            }
        }
    }

    violations.sort();
    assert!(
        violations.is_empty(),
        "Auth Postgres SQL must use statement_timestamp() for database-owned lifecycle time instead of transaction, wall-clock, or application-side clock shortcuts:\n{}",
        violations.join("\n")
    );
}

#[test]
fn auth_schema_migration_records_version_only_after_physical_validation() {
    let source = read_crate_source_file("src/auth_core/postgres_store.rs");
    assert!(
        !source.contains("record_component_schema_version_in_current_transaction("),
        "Auth schema migration must use the public-shaped component schema API instead of the private schema-ledger recorder"
    );
    let body = rust_function_body_by_name(&source, "migrate_schema_in_current_transaction");
    assert_source_order(
        body,
        "validate_physical_schema_in_current_transaction(tx, &table_names).await?",
        "migrate_auth_component_schema_in_current_transaction(tx, &self.config, &table_names)",
        "Auth migration must physically validate the migrated schema before invoking the component schema ledger migration",
    );
    assert_source_order(
        body,
        ".validate_schema_in_current_transaction(tx)",
        "migrate_auth_component_schema_in_current_transaction(tx, &self.config, &table_names)",
        "Auth migration must validate registered method schemas before recording the auth component schema version",
    );

    let component_body = rust_function_body_by_name(
        &source,
        "migrate_auth_component_schema_in_current_transaction",
    );
    assert_source_order(
        component_body,
        "migrate_component_schema_in_current_transaction(",
        "validate_auth_component_schema_in_current_transaction_with_table_names(",
        "Auth migration must revalidate the component schema after the public component schema helper records the ledger row",
    );
}

fn auth_core_postgres_production_source_files() -> Vec<PathBuf> {
    let auth_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/auth_core");
    let mut entries = fs::read_dir(&auth_root)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", auth_root.display()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| {
            panic!(
                "failed to read directory entry in {}: {error}",
                auth_root.display()
            )
        });
    entries.sort_by_key(|entry| entry.path());

    let mut source_files = Vec::new();
    for path in entries
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
    {
        let source = read_source_file(&path);
        if auth_source_file_contains_postgres_marker(&path, &source) {
            source_files.push(path);
        }
    }
    source_files
}

fn auth_source_file_contains_postgres_marker(path: &Path, source: &str) -> bool {
    path.file_name()
        .is_some_and(|file_name| file_name.to_string_lossy().contains("postgres"))
        || source.contains("pooler_safe_query")
        || source.contains("pooler_safe_query_as")
        || source.contains("pooler_safe_query_scalar")
        || source.contains("unparameterized_simple_query")
        || source.contains("PgQualifiedTableName")
        || source.contains("PgSchemaName")
        || source.contains("sqlx::")
}

fn read_source_file(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn read_crate_source_file(relative_path: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    read_source_file(&path)
}

fn relative_path(path: &Path) -> String {
    path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
        .unwrap_or(path)
        .display()
        .to_string()
}

#[derive(Clone, Copy)]
struct RustFunctionBlock<'a> {
    signature: &'a str,
    body: &'a str,
}

fn rust_function_blocks(source: &str) -> Vec<RustFunctionBlock<'_>> {
    let mut functions = Vec::new();
    let mut search_start = 0;
    while let Some(offset) = source[search_start..].find("fn ") {
        let fn_start = search_start + offset;
        let Some(open_brace_offset) = source[fn_start..].find('{') else {
            break;
        };
        let open_brace = fn_start + open_brace_offset;
        let Some(close_brace) = find_matching_brace(source, open_brace) else {
            break;
        };
        functions.push(RustFunctionBlock {
            signature: &source[fn_start..open_brace],
            body: &source[open_brace + 1..close_brace],
        });
        search_start = close_brace + 1;
    }
    functions
}

fn rust_function_body_by_name<'a>(source: &'a str, function_name: &str) -> &'a str {
    rust_function_blocks(source)
        .into_iter()
        .find(|function| rust_function_name(function.signature) == Some(function_name))
        .unwrap_or_else(|| panic!("missing function {function_name}"))
        .body
}

fn rust_function_name(signature: &str) -> Option<&str> {
    let after_fn = signature.split_once("fn ")?.1;
    let name_end = after_fn
        .find(|ch: char| !(ch == '_' || ch.is_ascii_alphanumeric()))
        .unwrap_or(after_fn.len());
    Some(&after_fn[..name_end])
}

fn assert_source_order(source: &str, first: &str, second: &str, message: &str) {
    let first_position = source
        .find(first)
        .unwrap_or_else(|| panic!("missing source needle {first:?}"));
    let second_position = source
        .find(second)
        .unwrap_or_else(|| panic!("missing source needle {second:?}"));
    assert!(first_position < second_position, "{message}");
}

fn find_matching_brace(source: &str, open_brace: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in source.as_bytes()[open_brace..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open_brace + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn source_contains_forbidden_sql_phrase(source_lowercase: &str, needle: &str) -> bool {
    let mut search_start = 0;
    while let Some(offset) = source_lowercase[search_start..].find(needle) {
        let absolute_start = search_start + offset;
        let preceded_by_identifier_char = source_lowercase[..absolute_start]
            .chars()
            .next_back()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric());
        if !preceded_by_identifier_char {
            return true;
        }
        search_start = absolute_start + needle.len();
    }
    false
}

fn source_contains_forbidden_database_clock_call(source_lowercase: &str, needle: &str) -> bool {
    let mut search_start = 0;
    while let Some(offset) = source_lowercase[search_start..].find(needle) {
        let absolute_start = search_start + offset;
        let preceding_char = source_lowercase[..absolute_start].chars().next_back();
        let preceded_by_identifier_char =
            preceding_char.is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric());
        let preceded_by_rust_namespace_or_method =
            preceding_char.is_some_and(|ch| ch == ':' || ch == '.');
        if !preceded_by_identifier_char && !preceded_by_rust_namespace_or_method {
            return true;
        }
        search_start = absolute_start + needle.len();
    }
    false
}
