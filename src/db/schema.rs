pub(crate) fn normalize_check_constraint_expression(expression: &str) -> String {
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
