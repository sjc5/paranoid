use super::*;

pub(super) fn paused_task_key(task_name: &str) -> String {
    format!("{TASK_PAUSE_KEY_PREFIX}{task_name}")
}

pub(super) fn paused_task_name_from_pause_key(pause_key: &str) -> Option<String> {
    let task_name = pause_key.strip_prefix(TASK_PAUSE_KEY_PREFIX)?;
    validate_task_name(task_name).ok()?;
    Some(task_name.to_owned())
}

pub(super) fn aggregate_pause_entries(pause_entries: Vec<String>) -> (bool, Vec<String>) {
    let mut queue_paused = false;
    let mut paused_task_names = Vec::with_capacity(pause_entries.len());
    for pause_entry in pause_entries {
        if pause_entry == GLOBAL_PAUSE_KEY {
            queue_paused = true;
            continue;
        }
        if let Some(task_name) = paused_task_name_from_pause_key(&pause_entry) {
            paused_task_names.push(task_name);
        }
    }
    paused_task_names.sort();
    (queue_paused, paused_task_names)
}
