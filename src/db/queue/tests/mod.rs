use super::*;

fn normalized_sql(query: &str) -> String {
    query.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn default_queue_config_for_sql_tests() -> StoreConfig {
    StoreConfig::default()
}

fn positional_placeholder_numbers(query: &str) -> Vec<usize> {
    let bytes = query.as_bytes();
    let mut numbers = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'$' {
            index += 1;
            continue;
        }
        index += 1;
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if start == index {
            continue;
        }
        let number = query[start..index]
            .parse::<usize>()
            .expect("placeholder digits should fit usize");
        numbers.push(number);
    }
    numbers
}

fn sorted_unique_positional_placeholder_numbers(query: &str) -> Vec<usize> {
    let mut numbers = positional_placeholder_numbers(query);
    numbers.sort_unstable();
    numbers.dedup();
    numbers
}

mod api_and_validation;
mod enqueue;
mod operation_queries;
mod worker_config;
mod worker_runtime;
