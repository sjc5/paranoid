/// Normalizes a Postgres check constraint expression for byte-stable comparison.
///
/// Component authors use this to compare
/// their own component's expected check constraint expressions against what Postgres
/// reports back from `pg_get_constraintdef`, independent of incidental whitespace or a
/// single layer of redundant outer parentheses.
#[cfg(feature = "component-authoring")]
pub fn normalize_check_constraint_expression(expression: &str) -> String {
    normalize_check_constraint_expression_inner(expression)
}

#[cfg(not(feature = "component-authoring"))]
pub(crate) fn normalize_check_constraint_expression(expression: &str) -> String {
    normalize_check_constraint_expression_inner(expression)
}

fn normalize_check_constraint_expression_inner(expression: &str) -> String {
    let mut normalized = expression
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();

    while expression_has_single_outer_parentheses(&normalized) {
        normalized = normalized[1..normalized.len() - 1].to_owned();
    }

    normalized
}

fn expression_has_single_outer_parentheses(expression: &str) -> bool {
    if !expression.starts_with('(') || !expression.ends_with(')') {
        return false;
    }

    let mut depth = 0_i32;
    let final_index = expression.len() - 1;
    for (index, character) in expression.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 && index != final_index {
                    return false;
                }
            }
            _ => {}
        }
    }

    depth == 0
}

/// Catalog expressions with no dependencies beyond their own relation and pinned built-ins.
/// PostgreSQL omits dependencies on pinned objects; custom functions, operators,
/// types, or collations cannot supply a required built-in constraint.
pub(crate) const BUILTIN_CHECK_EXPRESSIONS_SQL: &str = r#"
SELECT pg_catalog.pg_get_expr(con.conbin, con.conrelid)
FROM pg_catalog.pg_constraint con
WHERE con.conrelid OPERATOR(pg_catalog.=) pg_catalog.to_regclass($1)
    AND con.contype OPERATOR(pg_catalog.=) 'c'
    AND con.convalidated
    AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_depend dep
        WHERE dep.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_constraint'::pg_catalog.regclass
            AND dep.objid OPERATOR(pg_catalog.=) con.oid
            AND NOT (
                dep.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_class'::pg_catalog.regclass
                AND dep.refobjid OPERATOR(pg_catalog.=) con.conrelid
            )
    )
"#;

/// Normalizes only catalog expressions selected by `BUILTIN_CHECK_EXPRESSIONS_SQL`.
pub(crate) fn normalize_builtin_check_expression(expression: &str) -> String {
    let mut normalized = normalize_check_constraint_expression(expression)
        .replace("pg_catalog.octet_length(", "octet_length(")
        .replace("::pg_catalog.text", "::text");
    for operator in ["=", ">", "<="] {
        normalized = normalized.replace(&format!("OPERATOR(pg_catalog.{operator})"), operator);
    }
    normalized
}
