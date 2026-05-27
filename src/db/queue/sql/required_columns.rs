use super::*;

pub(in crate::db::queue) fn required_job_columns() -> [RequiredColumn; 17] {
    [
        required_bytea_column("id", false),
        required_text_column("task_name", false, true),
        RequiredColumn {
            name: "payload",
            data_type: "jsonb",
            is_nullable: false,
            collation_required: false,
        },
        required_text_column("status", false, true),
        required_timestamp_column("run_at_or_after", false),
        required_text_column("last_error", true, true),
        required_integer_column("retry_count", false),
        required_integer_column("max_retries", false),
        required_bigint_column("timeout_nanos", false),
        required_text_column("dedupe_key", true, true),
        required_text_column("worker_id", true, true),
        required_timestamp_column("claimed_by_worker_at", true),
        required_timestamp_column("execution_started_at", true),
        required_timestamp_column("execution_heartbeat_at", true),
        required_timestamp_column("finished_at", true),
        required_timestamp_column("created_at", false),
        required_timestamp_column("updated_at", false),
    ]
}

pub(in crate::db::queue) fn required_dead_letter_columns() -> [RequiredColumn; 13] {
    [
        required_bytea_column("id", false),
        required_bytea_column("original_job_id", false),
        required_text_column("task_name", false, true),
        RequiredColumn {
            name: "payload",
            data_type: "jsonb",
            is_nullable: false,
            collation_required: false,
        },
        required_text_column("last_error", false, true),
        required_integer_column("retry_count", false),
        required_integer_column("max_retries", false),
        required_bigint_column("timeout_nanos", false),
        required_text_column("dedupe_key", true, true),
        required_text_column("reason", false, true),
        required_timestamp_column("dead_lettered_at", false),
        required_timestamp_column("created_at", false),
        required_timestamp_column("updated_at", false),
    ]
}

pub(in crate::db::queue) fn required_pause_columns() -> [RequiredColumn; 4] {
    [
        required_text_column("key", false, true),
        required_text_column("task_name", true, true),
        required_timestamp_column("paused_at", false),
        required_timestamp_column("updated_at", false),
    ]
}

pub(in crate::db::queue) fn required_text_column(
    name: &'static str,
    is_nullable: bool,
    collation_required: bool,
) -> RequiredColumn {
    RequiredColumn {
        name,
        data_type: "text",
        is_nullable,
        collation_required,
    }
}

pub(in crate::db::queue) fn required_bytea_column(
    name: &'static str,
    is_nullable: bool,
) -> RequiredColumn {
    RequiredColumn {
        name,
        data_type: "bytea",
        is_nullable,
        collation_required: false,
    }
}

pub(in crate::db::queue) fn required_integer_column(
    name: &'static str,
    is_nullable: bool,
) -> RequiredColumn {
    RequiredColumn {
        name,
        data_type: "integer",
        is_nullable,
        collation_required: false,
    }
}

pub(in crate::db::queue) fn required_bigint_column(
    name: &'static str,
    is_nullable: bool,
) -> RequiredColumn {
    RequiredColumn {
        name,
        data_type: "bigint",
        is_nullable,
        collation_required: false,
    }
}

pub(in crate::db::queue) fn required_timestamp_column(
    name: &'static str,
    is_nullable: bool,
) -> RequiredColumn {
    RequiredColumn {
        name,
        data_type: "timestamp with time zone",
        is_nullable,
        collation_required: false,
    }
}
