use super::*;
use proptest::prelude::*;

#[test]
fn runtime_mutation_queries_use_statement_timestamp_clock() {
    let config = default_queue_config_for_sql_tests();
    let queries = [
        ("single enqueue", build_single_enqueue_query(&config), true),
        ("batch enqueue", build_batch_enqueue_query(&config, 2), true),
        ("dedupe enqueue", build_dedupe_enqueue_query(&config), true),
        (
            "claim available jobs",
            build_claim_available_jobs_query(&config),
            true,
        ),
        (
            "mark job started",
            build_mark_job_started_query(&config),
            true,
        ),
        (
            "mark job completed",
            build_mark_job_completed_query(&config),
            true,
        ),
        (
            "touch execution heartbeat",
            build_touch_execution_heartbeat_query(&config),
            true,
        ),
        (
            "mark job failed",
            build_mark_job_failed_query(&config),
            true,
        ),
        (
            "schedule owned retry",
            build_schedule_owned_running_job_retry_query(&config),
            true,
        ),
        (
            "move owned running job to dead letter",
            build_move_owned_running_job_to_dead_letter_query(&config),
            true,
        ),
        (
            "retry failed job",
            build_retry_failed_job_by_id_query(&config),
            true,
        ),
        (
            "retry available failed jobs",
            build_retry_available_failed_jobs_query(&config),
            true,
        ),
        (
            "force requeue running job",
            build_force_requeue_running_job_by_id_query(&config),
            true,
        ),
        (
            "move failed job to dead letter",
            build_move_failed_job_to_dead_letter_query(&config),
            true,
        ),
        (
            "move failed jobs to dead letter batch",
            build_move_failed_jobs_to_dead_letter_batch_query(&config, 2),
            true,
        ),
        (
            "requeue dead letter job",
            build_requeue_dead_letter_job_query(&config),
            true,
        ),
        (
            "delete dead letter job",
            build_delete_dead_letter_job_query(&config),
            false,
        ),
        (
            "upsert pause key",
            build_upsert_pause_key_query(&config),
            true,
        ),
        (
            "cleanup jobs",
            build_cleanup_jobs_older_than_once_query(&config),
            true,
        ),
        (
            "cleanup dead letters",
            build_cleanup_available_dead_letter_jobs_older_than_once_query(&config),
            true,
        ),
        (
            "reclaim never started",
            build_reclaim_never_started_running_jobs_query(&config),
            true,
        ),
        (
            "reclaim expired to failed",
            build_reclaim_expired_running_jobs_to_failed_query(&config),
            true,
        ),
        (
            "reclaim expired to pending",
            build_reclaim_expired_running_jobs_to_pending_for_retry_query(&config),
            true,
        ),
    ];

    for (label, query, must_use_statement_timestamp) in queries {
        assert!(
            !query.contains("NOW()"),
            "{label} query must use statement_timestamp(), not NOW(): {query}"
        );
        if must_use_statement_timestamp {
            assert!(
                query.contains("statement_timestamp()"),
                "{label} query must use database statement time: {query}"
            );
        }
    }

    let cleanup_jobs = normalized_sql(&build_cleanup_jobs_older_than_once_query(&config));
    assert!(
        cleanup_jobs.contains("statement_timestamp() - ($2::bigint * INTERVAL '1 microsecond')"),
        "job cleanup threshold must be derived from statement time and microsecond args: {cleanup_jobs}"
    );

    let cleanup_dead_letters =
        normalized_sql(&build_cleanup_available_dead_letter_jobs_older_than_once_query(&config));
    assert!(
        cleanup_dead_letters
            .contains("statement_timestamp() - ($1::bigint * INTERVAL '1 microsecond')"),
        "dead-letter cleanup threshold must be derived from statement time and microsecond args: {cleanup_dead_letters}"
    );
}

#[test]
fn dynamic_queue_sql_uses_contiguous_positional_placeholders() {
    let config = default_queue_config_for_sql_tests();

    for batch_size in 1_usize..=8 {
        let query = build_batch_enqueue_query(&config, batch_size);
        let expected = (1..=(batch_size * 2 + 7)).collect::<Vec<_>>();
        assert_eq!(
            sorted_unique_positional_placeholder_numbers(&query),
            expected,
            "batch enqueue placeholders should be contiguous for batch size {batch_size}: {query}"
        );
    }

    assert_eq!(
        sorted_unique_positional_placeholder_numbers(&build_dedupe_enqueue_query(&config)),
        (1..=10).collect::<Vec<_>>()
    );
    assert_eq!(
        sorted_unique_positional_placeholder_numbers(&build_claim_available_jobs_query(&config)),
        (1..=6).collect::<Vec<_>>()
    );
    assert_eq!(
        sorted_unique_positional_placeholder_numbers(&build_retry_available_failed_jobs_query(
            &config
        )),
        (1..=5).collect::<Vec<_>>()
    );

    for job_count in 1_usize..=16 {
        let query = build_move_failed_jobs_to_dead_letter_batch_query(&config, job_count);
        let expected = (1..=(job_count * 2 + 2)).collect::<Vec<_>>();
        assert_eq!(
            sorted_unique_positional_placeholder_numbers(&query),
            expected,
            "dead-letter batch placeholders should be contiguous for job count {job_count}: {query}"
        );
    }
}

proptest! {
    #[test]
    fn dynamic_queue_sql_uses_contiguous_positional_placeholders_for_generated_batch_sizes(
        batch_size in 1_usize..=64,
        dead_letter_job_count in 1_usize..=64,
    ) {
        let config = default_queue_config_for_sql_tests();

        let batch_query = build_batch_enqueue_query(&config, batch_size);
        prop_assert_eq!(
            sorted_unique_positional_placeholder_numbers(&batch_query),
            (1..=(batch_size * 2 + 7)).collect::<Vec<_>>(),
            "batch enqueue placeholders should be contiguous for batch size {}: {}",
            batch_size,
            batch_query
        );

        let dead_letter_query =
            build_move_failed_jobs_to_dead_letter_batch_query(&config, dead_letter_job_count);
        prop_assert_eq!(
            sorted_unique_positional_placeholder_numbers(&dead_letter_query),
            (1..=(dead_letter_job_count * 2 + 2)).collect::<Vec<_>>(),
            "dead-letter batch placeholders should be contiguous for job count {}: {}",
            dead_letter_job_count,
            dead_letter_query
        );
    }

    #[test]
    fn positional_placeholder_parser_extracts_generated_numeric_tokens(
        placeholders in prop::collection::vec(0_usize..=10_000, 0..=64),
    ) {
        let mut query = String::from("$ ignored $abc $$ ");
        for placeholder in &placeholders {
            query.push_str(&format!(" before ${placeholder}::text after "));
        }
        query.push_str(" trailing $ and $abc");

        prop_assert_eq!(positional_placeholder_numbers(&query), placeholders);
    }
}

#[test]
fn positional_placeholder_parser_handles_arbitrary_sql_text_boundaries() {
    let cases = [
        ("", Vec::<usize>::new()),
        ("no placeholders", Vec::new()),
        ("$ without digits and $x still ignored", Vec::new()),
        ("SELECT $1, $2, $10", vec![1, 2, 10]),
        ("SELECT $$quoted$$, $3::bytea, '$4 literal'", vec![3, 4]),
        ("SELECT $001, $1, $000", vec![1, 1, 0]),
        (
            "SELECT $9abc, ($10)::text, $11_ignored_suffix",
            vec![9, 10, 11],
        ),
    ];

    for (query, expected) in cases {
        assert_eq!(
            positional_placeholder_numbers(query),
            expected,
            "placeholder parser should extract the numeric token after '$' in {query:?}"
        );
    }

    let synthetic = (1..=64)
        .map(|placeholder| format!(" ${placeholder}::text "))
        .collect::<String>();
    assert_eq!(
        positional_placeholder_numbers(&synthetic),
        (1..=64).collect::<Vec<_>>()
    );
}

#[test]
fn dead_letter_batch_id_pair_value_placeholders_are_typed_and_ordered() {
    for job_count in 1_usize..=16 {
        let id_values = build_dead_letter_move_id_values(job_count);
        let expected_pairs = (0..job_count)
            .map(|index| {
                let original_placeholder = index * 2 + 1;
                let dead_letter_placeholder = original_placeholder + 1;
                format!("(${original_placeholder}::bytea, ${dead_letter_placeholder}::bytea)")
            })
            .collect::<Vec<_>>()
            .join(", ");

        assert_eq!(id_values, expected_pairs);
        assert_eq!(
            id_values.matches("::bytea").count(),
            job_count * 2,
            "each dead-letter ID pair must contain two bytea placeholders"
        );
    }
}

#[test]
fn queue_sql_catalog_matches_builders_and_reuses_dynamic_queries() {
    let config = default_queue_config_for_sql_tests();
    let catalog = SqlCatalog::new(&config);

    assert_eq!(
        catalog.single_enqueue_query(),
        build_single_enqueue_query(&config)
    );
    assert_eq!(
        catalog.dedupe_enqueue_query(),
        build_dedupe_enqueue_query(&config)
    );
    assert_eq!(
        catalog.fetch_status_counts_query(),
        build_fetch_status_counts_query(&config)
    );
    assert_eq!(
        catalog.fetch_job_count_by_status_query(),
        build_fetch_job_count_by_status_query(&config)
    );
    assert_eq!(
        catalog.fetch_worker_pressure_counts_query(),
        build_fetch_worker_pressure_counts_query(&config)
    );
    assert_eq!(
        catalog.fetch_pause_entries_query(),
        build_fetch_pause_entries_query(&config)
    );
    assert_eq!(
        catalog.fetch_pending_or_running_task_names_query(),
        build_fetch_pending_or_running_task_names_query(&config)
    );
    assert_eq!(catalog.list_jobs_query(), build_list_jobs_query(&config));
    assert_eq!(
        catalog.list_dead_letter_jobs_query(),
        build_list_dead_letter_jobs_query(&config)
    );
    assert_eq!(
        catalog.cleanup_jobs_older_than_once_query(),
        build_cleanup_jobs_older_than_once_query(&config)
    );
    assert_eq!(
        catalog.cleanup_available_dead_letter_jobs_older_than_once_query(),
        build_cleanup_available_dead_letter_jobs_older_than_once_query(&config)
    );
    assert_eq!(
        catalog.claim_available_jobs_query(),
        build_claim_available_jobs_query(&config)
    );
    assert_eq!(
        catalog.retry_failed_job_by_id_query(),
        build_retry_failed_job_by_id_query(&config)
    );

    let batch_enqueue_query = catalog.batch_enqueue_query(4);
    let batch_enqueue_query_again = catalog.batch_enqueue_query(4);
    assert!(Arc::ptr_eq(
        &batch_enqueue_query,
        &batch_enqueue_query_again
    ));
    assert_eq!(
        batch_enqueue_query.as_ref(),
        build_batch_enqueue_query(&config, 4)
    );

    let dead_letter_batch_query = catalog.move_failed_jobs_to_dead_letter_batch_query(3);
    let dead_letter_batch_query_again = catalog.move_failed_jobs_to_dead_letter_batch_query(3);
    assert!(Arc::ptr_eq(
        &dead_letter_batch_query,
        &dead_letter_batch_query_again
    ));
    assert_eq!(
        dead_letter_batch_query.as_ref(),
        build_move_failed_jobs_to_dead_letter_batch_query(&config, 3)
    );
}

#[test]
fn enqueue_queries_embed_pause_dedupe_and_insert_outcomes_in_one_statement() {
    let config = default_queue_config_for_sql_tests();

    for (label, query) in [
        ("single enqueue", build_single_enqueue_query(&config)),
        ("batch enqueue", build_batch_enqueue_query(&config, 3)),
        ("dedupe enqueue", build_dedupe_enqueue_query(&config)),
    ] {
        let normalized = normalized_sql(&query);
        assert!(
            normalized.starts_with("WITH pause_state AS"),
            "{label} must begin with pause_state so pause checks and insertion share one statement: {normalized}"
        );
        assert!(
            normalized.contains(&format!("FROM {}", config.pause_table_name.quoted())),
            "{label} must read pause state in the same statement: {normalized}"
        );
        assert!(
            normalized.contains(&format!("INSERT INTO {}", config.table_name.quoted())),
            "{label} must perform insertion in the same statement as pause checks: {normalized}"
        );
        assert!(
            normalized.contains("WHERE NOT pause_state.queue_paused"),
            "{label} must gate insertion on global pause state inside the statement: {normalized}"
        );
        assert!(
            normalized.contains("AND NOT pause_state.task_paused"),
            "{label} must gate insertion on task pause state inside the statement: {normalized}"
        );
        assert!(
            normalized.contains("insert_outcome"),
            "{label} must return the outcome from the same statement: {normalized}"
        );
    }

    let dedupe = normalized_sql(&build_dedupe_enqueue_query(&config));
    assert!(
        dedupe.contains("existing_active AS"),
        "dedupe enqueue must check existing active jobs in the same statement: {dedupe}"
    );
    assert!(
        dedupe.contains("ON CONFLICT (task_name, dedupe_key)"),
        "dedupe enqueue must rely on the active dedupe index instead of a separate read/write protocol: {dedupe}"
    );
    assert!(
        dedupe.contains("(SELECT id FROM existing_active) AS existing_id"),
        "dedupe enqueue must return the existing active id from the same statement: {dedupe}"
    );
}

#[test]
fn listing_queries_use_bounded_cursor_and_set_filter_shapes() {
    let config = default_queue_config_for_sql_tests();
    let jobs = normalized_sql(&build_list_jobs_query(&config));
    assert!(
        jobs.contains("CARDINALITY($1::text[]) = 0 OR status = ANY($1::text[])"),
        "job listing must use one set-valued status filter: {jobs}"
    );
    assert!(
        jobs.contains("$2::text IS NULL OR task_name = $2"),
        "job listing must use nullable task filter in one query: {jobs}"
    );
    assert!(
        jobs.contains("$3::bytea IS NULL OR id > $3"),
        "job listing must use bytewise cursor filter in one query: {jobs}"
    );
    assert!(
        jobs.contains("ORDER BY id ASC LIMIT $4"),
        "job listing must be bounded and stably ordered: {jobs}"
    );

    let dead_letters = normalized_sql(&build_list_dead_letter_jobs_query(&config));
    assert!(
        dead_letters.contains("$1::text IS NULL OR task_name = $1"),
        "dead-letter listing must use nullable task filter in one query: {dead_letters}"
    );
    assert!(
        dead_letters.contains("$2::bytea IS NULL OR id > $2"),
        "dead-letter listing must use bytewise cursor filter in one query: {dead_letters}"
    );
    assert!(
        dead_letters.contains("ORDER BY id ASC LIMIT $3"),
        "dead-letter listing must be bounded and stably ordered: {dead_letters}"
    );
}

#[test]
fn cleanup_queries_are_bounded_skip_locked_deletes() {
    let config = default_queue_config_for_sql_tests();
    let jobs = normalized_sql(&build_cleanup_jobs_older_than_once_query(&config));
    assert!(
        jobs.starts_with("WITH to_delete AS"),
        "job cleanup must use a bounded candidate CTE: {jobs}"
    );
    assert!(
        jobs.contains("status = $1"),
        "job cleanup must be status-scoped: {jobs}"
    );
    assert!(
        jobs.contains("finished_at IS NOT NULL"),
        "job cleanup must only consider terminal rows with terminal timestamps: {jobs}"
    );
    assert!(
        jobs.contains("ORDER BY finished_at ASC, id ASC LIMIT $3 FOR UPDATE SKIP LOCKED"),
        "job cleanup must order, bound, and skip locked candidates: {jobs}"
    );
    assert!(
        jobs.contains("DELETE FROM"),
        "job cleanup must delete in the same statement: {jobs}"
    );
    assert!(
        jobs.contains("WHERE id IN (SELECT id FROM to_delete)"),
        "job cleanup must only delete locked candidates: {jobs}"
    );

    let dead_letters =
        normalized_sql(&build_cleanup_available_dead_letter_jobs_older_than_once_query(&config));
    assert!(
        dead_letters.starts_with("WITH to_delete AS"),
        "dead-letter cleanup must use a bounded candidate CTE: {dead_letters}"
    );
    assert!(
        dead_letters.contains("dead_lettered_at < statement_timestamp()"),
        "dead-letter cleanup threshold must use database statement time: {dead_letters}"
    );
    assert!(
        dead_letters
            .contains("ORDER BY dead_lettered_at ASC, id ASC LIMIT $2 FOR UPDATE SKIP LOCKED"),
        "dead-letter cleanup must order, bound, and skip locked candidates: {dead_letters}"
    );
    assert!(
        dead_letters.contains("WHERE id IN (SELECT id FROM to_delete)"),
        "dead-letter cleanup must only delete locked candidates: {dead_letters}"
    );
}

#[test]
fn claim_query_checks_pause_state_inside_candidate_lock_query() {
    let config = default_queue_config_for_sql_tests();
    let normalized = normalized_sql(&build_claim_available_jobs_query(&config));

    assert!(
        normalized.starts_with("WITH candidates AS"),
        "claim query must start by selecting candidates: {normalized}"
    );
    assert!(
        normalized.contains("AND NOT EXISTS ( SELECT 1 FROM"),
        "claim query must check pause state while selecting candidates: {normalized}"
    );
    assert!(
        normalized.contains("p.key = $6"),
        "claim query must check global pause state inside the candidate query: {normalized}"
    );
    assert!(
        normalized.contains("p.key = 'task:' || j.task_name"),
        "claim query must check task pause state inside the candidate query: {normalized}"
    );
    assert!(
        normalized.contains("FOR UPDATE SKIP LOCKED"),
        "claim query must use SKIP LOCKED for concurrent workers: {normalized}"
    );
    assert!(
        normalized.contains("UPDATE"),
        "claim query must claim jobs in the same statement: {normalized}"
    );
}

#[test]
fn retry_available_failed_jobs_query_retries_at_most_one_failed_job_per_active_dedupe_key() {
    let config = default_queue_config_for_sql_tests();
    let normalized = normalized_sql(&build_retry_available_failed_jobs_query(&config));

    assert!(
        normalized.starts_with("WITH lockable AS"),
        "retry-many query must start with a bounded lockable candidate set: {normalized}"
    );
    assert!(
        normalized.contains("FOR UPDATE OF failed SKIP LOCKED"),
        "retry-many query must skip locked failed rows: {normalized}"
    );
    assert!(
        normalized.contains("ROW_NUMBER() OVER"),
        "retry-many query must rank duplicate failed dedupe rows before update: {normalized}"
    );
    assert!(
        normalized.contains("PARTITION BY task_name, dedupe_key"),
        "retry-many query must group duplicate active dedupe keys: {normalized}"
    );
    assert!(
        normalized.contains("dedupe_key IS NULL OR active_dedupe_retry_rank = 1"),
        "retry-many query must keep all non-dedupe rows but only one row per active dedupe key: {normalized}"
    );
}

#[test]
fn owned_worker_transition_queries_guard_worker_ownership_and_clear_runtime_columns() {
    let config = default_queue_config_for_sql_tests();

    for (label, query) in [
        ("mark started", build_mark_job_started_query(&config)),
        ("mark completed", build_mark_job_completed_query(&config)),
        (
            "touch heartbeat",
            build_touch_execution_heartbeat_query(&config),
        ),
        ("mark failed", build_mark_job_failed_query(&config)),
        (
            "schedule retry",
            build_schedule_owned_running_job_retry_query(&config),
        ),
        (
            "move owned dead letter",
            build_move_owned_running_job_to_dead_letter_query(&config),
        ),
        (
            "return owned unstarted",
            build_return_owned_unstarted_running_job_to_pending_query(&config),
        ),
        (
            "return owned started",
            build_return_owned_started_running_job_to_pending_query(&config),
        ),
    ] {
        let normalized = normalized_sql(&query);
        assert!(
            normalized.contains("FOR UPDATE SKIP LOCKED"),
            "{label} query must not block behind row locks: {normalized}"
        );
        assert!(
            normalized.contains("visible AS"),
            "{label} query must keep a non-locking existence check: {normalized}"
        );
        assert!(
            normalized.contains("worker_id IS DISTINCT FROM"),
            "{label} query must distinguish ownership mismatch from lock contention: {normalized}"
        );
        assert!(
            normalized.contains("'locked'"),
            "{label} query must surface locked rows explicitly: {normalized}"
        );
    }

    let started = normalized_sql(&build_mark_job_started_query(&config));
    assert!(
        started.contains("WHERE id = $1 AND status = $2 AND worker_id = $3"),
        "started transition must require current worker ownership: {started}"
    );

    let completed = normalized_sql(&build_mark_job_completed_query(&config));
    assert!(
        completed.contains("WHERE id = $1 AND status = $2 AND worker_id = $3"),
        "completion transition must require current worker ownership: {completed}"
    );
    for cleared_column in [
        "worker_id = NULL",
        "claimed_by_worker_at = NULL",
        "execution_started_at = NULL",
        "execution_heartbeat_at = NULL",
    ] {
        assert!(
            completed.contains(cleared_column),
            "completion transition must clear {cleared_column}: {completed}"
        );
    }

    let failed = normalized_sql(&build_mark_job_failed_query(&config));
    assert!(
        failed.contains("retry_count = retry_count + CASE WHEN $3 THEN 1 ELSE 0 END"),
        "failure transition must atomically gate retry count increment: {failed}"
    );
    assert!(
        failed.contains("WHERE id = $4 AND status = $5 AND worker_id = $6"),
        "failure transition must require current worker ownership: {failed}"
    );

    let retry = normalized_sql(&build_schedule_owned_running_job_retry_query(&config));
    assert!(
        retry.contains(
            "run_at_or_after = statement_timestamp() + ($3::bigint * INTERVAL '1 microsecond')"
        ),
        "retry transition must schedule from database statement time: {retry}"
    );
    assert!(
        retry.contains("WHERE id = $5 AND status = $6 AND worker_id = $7"),
        "retry transition must require current worker ownership: {retry}"
    );
    assert!(
        retry.contains("RETURNING ((EXTRACT(EPOCH FROM run_at_or_after) * 1000000)::bigint)"),
        "retry transition must return the database-derived next run time: {retry}"
    );

    let owned_dead_letter =
        normalized_sql(&build_move_owned_running_job_to_dead_letter_query(&config));
    assert!(
        owned_dead_letter.contains("WHERE id = $1 AND status = $2 AND worker_id = $3"),
        "owned dead-letter transition must require current worker ownership: {owned_dead_letter}"
    );
    assert!(
        owned_dead_letter
            .contains("retry_count + CASE WHEN $6::boolean THEN 1 ELSE 0 END AS retry_count"),
        "owned dead-letter transition must atomically gate retry count increment: {owned_dead_letter}"
    );
}

#[test]
fn owned_worker_requeue_queries_distinguish_unstarted_and_started_jobs() {
    let config = default_queue_config_for_sql_tests();

    let unstarted = normalized_sql(&build_return_owned_unstarted_running_job_to_pending_query(
        &config,
    ));
    assert!(
        unstarted.contains(
            "WHERE id = $1 AND status = $2 AND worker_id = $3 AND execution_started_at IS NULL"
        ),
        "unstarted requeue must require ownership and absence of handler start: {unstarted}"
    );

    let started = normalized_sql(&build_return_owned_started_running_job_to_pending_query(
        &config,
    ));
    assert!(
        started.contains(
            "WHERE id = $1 AND status = $2 AND worker_id = $3 AND execution_started_at IS NOT NULL"
        ),
        "started requeue must require ownership and handler start: {started}"
    );

    let available_unstarted = normalized_sql(
        &build_return_available_owned_unstarted_running_jobs_to_pending_query(&config),
    );
    assert!(
        available_unstarted
            .contains("WHERE worker_id = $2 AND status = $3 AND execution_started_at IS NULL"),
        "bulk unstarted requeue must be worker-scoped: {available_unstarted}"
    );
    assert!(
        available_unstarted.contains("FOR UPDATE SKIP LOCKED"),
        "bulk unstarted requeue must skip locked worker-owned rows: {available_unstarted}"
    );
    assert!(
        available_unstarted.contains("WHERE id IN (SELECT id FROM candidates)"),
        "bulk unstarted requeue must only update rows it locked: {available_unstarted}"
    );

    let available_started = normalized_sql(
        &build_return_available_owned_started_running_jobs_to_pending_query(&config),
    );
    assert!(
        available_started
            .contains("WHERE worker_id = $2 AND status = $3 AND execution_started_at IS NOT NULL"),
        "bulk started requeue must be worker-scoped: {available_started}"
    );
    assert!(
        available_started.contains("FOR UPDATE SKIP LOCKED"),
        "bulk started requeue must skip locked worker-owned rows: {available_started}"
    );
    assert!(
        available_started.contains("WHERE id IN (SELECT id FROM candidates)"),
        "bulk started requeue must only update rows it locked: {available_started}"
    );
}

#[test]
fn reclaim_and_dead_letter_batch_queries_are_bounded_and_atomic() {
    let config = default_queue_config_for_sql_tests();

    let never_started = normalized_sql(&build_reclaim_never_started_running_jobs_query(&config));
    assert!(
        never_started.contains(
            "ORDER BY execution_heartbeat_at ASC, id ASC LIMIT $4 FOR UPDATE SKIP LOCKED"
        ),
        "never-started reclaim must order by the running-job heartbeat index, bound, and skip locked candidates: {never_started}"
    );
    assert!(
        never_started.contains("execution_started_at IS NULL"),
        "never-started reclaim must not touch started jobs: {never_started}"
    );
    assert!(
        never_started.contains("status = $1")
            && never_started.contains("worker_id = NULL")
            && never_started.contains("claimed_by_worker_at = NULL")
            && never_started.contains("execution_started_at = NULL")
            && never_started.contains("execution_heartbeat_at = NULL")
            && never_started.contains("finished_at = NULL"),
        "never-started reclaim must return ownership-free pending jobs: {never_started}"
    );
    assert!(
        never_started.contains("WHERE id IN (SELECT id FROM candidates)"),
        "never-started reclaim must only update locked candidates: {never_started}"
    );

    let expired_to_failed =
        normalized_sql(&build_reclaim_expired_running_jobs_to_failed_query(&config));
    assert!(
        expired_to_failed.contains(
            "ORDER BY execution_heartbeat_at ASC, id ASC LIMIT $4 FOR UPDATE SKIP LOCKED"
        ),
        "expired-to-failed reclaim must order by the running-job heartbeat index, bound, and skip locked candidates: {expired_to_failed}"
    );
    assert!(
        expired_to_failed.contains("retry_count >= max_retries"),
        "expired-to-failed reclaim must only consume exhausted jobs: {expired_to_failed}"
    );
    assert!(
        expired_to_failed.contains("status = $1")
            && expired_to_failed.contains("retry_count = retry_count + 1")
            && expired_to_failed.contains("last_error = COALESCE(last_error || ' | ', '')")
            && expired_to_failed.contains("worker_id = NULL")
            && expired_to_failed.contains("claimed_by_worker_at = NULL")
            && expired_to_failed.contains("execution_started_at = NULL")
            && expired_to_failed.contains("execution_heartbeat_at = NULL")
            && expired_to_failed.contains("finished_at = statement_timestamp()"),
        "expired-to-failed reclaim must clear ownership and finish the exhausted job: {expired_to_failed}"
    );
    assert!(
        expired_to_failed.contains("WHERE id IN (SELECT id FROM candidates)"),
        "expired-to-failed reclaim must only update locked candidates: {expired_to_failed}"
    );

    let expired_to_pending =
        normalized_sql(&build_reclaim_expired_running_jobs_to_pending_for_retry_query(&config));
    assert!(
        expired_to_pending.contains(
            "ORDER BY execution_heartbeat_at ASC, id ASC LIMIT $4 FOR UPDATE SKIP LOCKED"
        ),
        "expired-to-pending reclaim must order by the running-job heartbeat index, bound, and skip locked candidates: {expired_to_pending}"
    );
    assert!(
        expired_to_pending.contains("retry_count < max_retries"),
        "expired-to-pending reclaim must only retry jobs with remaining budget: {expired_to_pending}"
    );
    assert!(
        expired_to_pending.contains("status = $1")
            && expired_to_pending.contains("retry_count = retry_count + 1")
            && expired_to_pending.contains("last_error = COALESCE(last_error || ' | ', '')")
            && expired_to_pending.contains("worker_id = NULL")
            && expired_to_pending.contains("claimed_by_worker_at = NULL")
            && expired_to_pending.contains("execution_started_at = NULL")
            && expired_to_pending.contains("execution_heartbeat_at = NULL")
            && expired_to_pending.contains("finished_at = NULL"),
        "expired-to-pending reclaim must clear ownership and return retryable jobs to pending: {expired_to_pending}"
    );
    assert!(
        expired_to_pending.contains("WHERE id IN (SELECT id FROM candidates)"),
        "expired-to-pending reclaim must only update locked candidates: {expired_to_pending}"
    );

    let batch_dead_letter = normalized_sql(&build_move_failed_jobs_to_dead_letter_batch_query(
        &config, 2,
    ));
    assert!(
        batch_dead_letter.starts_with("WITH id_map(original_job_id, dead_letter_id) AS"),
        "batch dead-letter query must bind all candidate ids in one statement: {batch_dead_letter}"
    );
    assert!(
        batch_dead_letter.contains("WHERE jobs.status = $5 FOR UPDATE OF jobs SKIP LOCKED"),
        "batch dead-letter query must only move failed rows: {batch_dead_letter}"
    );
    assert!(
        batch_dead_letter.contains("RETURNING id, original_job_id, task_name, last_error"),
        "batch dead-letter query must return moved-row identities: {batch_dead_letter}"
    );
}

#[test]
fn by_id_operator_mutation_queries_skip_locked_rows_instead_of_waiting() {
    let config = default_queue_config_for_sql_tests();

    for (label, query) in [
        ("cancel pending", build_cancel_pending_job_query(&config)),
        ("retry failed", build_retry_failed_job_by_id_query(&config)),
        (
            "force requeue running",
            build_force_requeue_running_job_by_id_query(&config),
        ),
        (
            "move failed to dead letter",
            build_move_failed_job_to_dead_letter_query(&config),
        ),
        (
            "requeue dead letter",
            build_requeue_dead_letter_job_query(&config),
        ),
        (
            "delete dead letter",
            build_delete_dead_letter_job_query(&config),
        ),
    ] {
        let normalized = normalized_sql(&query);
        assert!(
            normalized.contains("FOR UPDATE SKIP LOCKED"),
            "{label} query must not block behind row locks: {normalized}"
        );
        assert!(
            normalized.contains("visible AS"),
            "{label} query must keep a non-locking existence check: {normalized}"
        );
        if normalized.contains("SELECT CASE") {
            assert!(
                normalized.contains("WHEN EXISTS (SELECT 1 FROM visible) THEN 'locked'"),
                "{label} query must surface locked rows explicitly: {normalized}"
            );
        } else {
            assert!(
                normalized.contains("visible_exists"),
                "{label} query must return visible row state for locked rows: {normalized}"
            );
        }
    }

    let requeue_dead_letter = normalized_sql(&build_requeue_dead_letter_job_query(&config));
    assert!(
        requeue_dead_letter.contains("EXISTS(SELECT 1 FROM deleted) AS deleted_source"),
        "dead-letter requeue must report whether the source row was removed atomically: {requeue_dead_letter}"
    );
}

#[test]
fn queue_observability_queries_have_bounded_read_shapes() {
    let config = default_queue_config_for_sql_tests();
    let status_counts = normalized_sql(&build_fetch_status_counts_query(&config));
    assert!(
        status_counts.contains("SELECT COUNT(*) FILTER"),
        "status query should aggregate main table counts in one read: {status_counts}"
    );
    assert!(
        status_counts.contains("SELECT COUNT(*)::bigint FROM"),
        "status query should include dead-letter count in the same statement: {status_counts}"
    );

    let worker_pressure = normalized_sql(&build_fetch_worker_pressure_counts_query(&config));
    assert!(
        worker_pressure.contains("COUNT(*) FILTER (WHERE status = 'pending')"),
        "worker pressure count query should aggregate pending jobs: {worker_pressure}"
    );
    assert!(
        worker_pressure.contains("COUNT(*) FILTER (WHERE status = 'running')"),
        "worker pressure count query should aggregate running jobs: {worker_pressure}"
    );
    assert!(
        !worker_pressure.contains(&config.pause_table_name.quoted().to_string()),
        "worker pressure counts should not join pause metadata: {worker_pressure}"
    );

    let pause_entries = normalized_sql(&build_fetch_pause_entries_query(&config));
    assert!(
        pause_entries.contains("WHERE key = $1 OR key LIKE $2"),
        "pause entry query should fetch global and task pause keys together: {pause_entries}"
    );
    assert!(
        pause_entries.contains("ORDER BY key"),
        "pause entry query should return stable ordering: {pause_entries}"
    );
}

#[test]
fn transition_outcome_classifiers_cover_state_lock_and_conflict_branches() {
    queue_job_state_transition_result_from_outcome(
        "cancel pending job",
        Error::JobNotPending,
        "applied",
    )
    .expect("applied state transition");
    assert!(matches!(
        queue_job_state_transition_result_from_outcome(
            "cancel pending job",
            Error::JobNotPending,
            "not_found",
        ),
        Err(Error::JobNotFound)
    ));
    assert!(matches!(
        queue_job_state_transition_result_from_outcome(
            "cancel pending job",
            Error::JobNotPending,
            "locked",
        ),
        Err(Error::JobLockedByConcurrentTransaction)
    ));
    assert!(matches!(
        queue_job_state_transition_result_from_outcome(
            "cancel pending job",
            Error::JobNotPending,
            "state_mismatch",
        ),
        Err(Error::JobNotPending)
    ));
    assert!(matches!(
        queue_job_state_transition_result_from_outcome(
            "cancel pending job",
            Error::JobNotPending,
            "mystery",
        ),
        Err(Error::UnexpectedOutcome {
            operation: "cancel pending job",
            outcome,
        }) if outcome == "mystery"
    ));

    queue_retry_failed_job_result_from_outcome("applied").expect("applied retry");
    assert!(matches!(
        queue_retry_failed_job_result_from_outcome("not_found"),
        Err(Error::JobNotFound)
    ));
    assert!(matches!(
        queue_retry_failed_job_result_from_outcome("locked"),
        Err(Error::JobLockedByConcurrentTransaction)
    ));
    assert!(matches!(
        queue_retry_failed_job_result_from_outcome("state_mismatch"),
        Err(Error::JobNotFailed)
    ));
    assert!(matches!(
        queue_retry_failed_job_result_from_outcome("dedupe_conflict"),
        Err(Error::RetryConflictWithActiveDedupeJob)
    ));

    owned_running_job_update_result_from_outcome(
        "mark owned running job completed",
        Error::JobNotRunning,
        "applied",
    )
    .expect("applied owned update");
    assert!(matches!(
        owned_running_job_update_result_from_outcome(
            "mark owned running job completed",
            Error::JobNotRunning,
            "not_found",
        ),
        Err(Error::JobNotRunning)
    ));
    assert!(matches!(
        owned_running_job_update_result_from_outcome(
            "mark owned running job completed",
            Error::JobNotRunning,
            "state_mismatch",
        ),
        Err(Error::JobNotRunning)
    ));
    assert!(matches!(
        owned_running_job_update_result_from_outcome(
            "mark owned running job completed",
            Error::JobNotRunning,
            "locked",
        ),
        Err(Error::JobLockedByConcurrentTransaction)
    ));

    assert_eq!(
        schedule_owned_running_job_retry_result_from_outcome("applied", Some(123))
            .expect("applied retry schedule"),
        123
    );
    assert!(matches!(
        schedule_owned_running_job_retry_result_from_outcome("applied", None),
        Err(Error::UnexpectedOutcome {
            operation: "schedule owned running job retry",
            outcome,
        }) if outcome == "applied without next run time"
    ));
    assert!(matches!(
        schedule_owned_running_job_retry_result_from_outcome("locked", None),
        Err(Error::JobLockedByConcurrentTransaction)
    ));
    assert!(matches!(
        schedule_owned_running_job_retry_result_from_outcome("state_mismatch", None),
        Err(Error::JobNotRunning)
    ));

    let dead_letter_id = JobId::new().expect("valid id");
    assert_eq!(
        move_owned_running_job_to_dead_letter_result_from_outcome(
            "applied",
            Some(dead_letter_id.as_bytes().to_vec()),
        )
        .expect("applied owned dead-letter move"),
        dead_letter_id
    );
    assert!(matches!(
        move_owned_running_job_to_dead_letter_result_from_outcome("applied", None),
        Err(Error::UnexpectedOutcome {
            operation: "move owned running job to dead letter",
            outcome,
        }) if outcome == "applied without inserted dead-letter id"
    ));
    assert!(matches!(
        move_owned_running_job_to_dead_letter_result_from_outcome("locked", None),
        Err(Error::JobLockedByConcurrentTransaction)
    ));
    assert!(matches!(
        move_owned_running_job_to_dead_letter_result_from_outcome("not_found", None),
        Err(Error::JobNotRunning)
    ));
}

#[test]
fn dead_letter_row_state_classifiers_reject_impossible_partial_mutations() {
    let dead_letter_id = JobId::new().expect("valid dead-letter id");
    assert_eq!(
        move_failed_job_to_dead_letter_result_from_row_state(
            Some(dead_letter_id.as_bytes().to_vec()),
            false,
            false,
            false,
            false,
        )
        .expect("inserted dead-letter id wins"),
        dead_letter_id
    );
    assert!(matches!(
        move_failed_job_to_dead_letter_result_from_row_state(None, false, false, false, false),
        Err(Error::JobNotFound)
    ));
    assert!(matches!(
        move_failed_job_to_dead_letter_result_from_row_state(None, false, false, true, true),
        Err(Error::JobLockedByConcurrentTransaction)
    ));
    assert!(matches!(
        move_failed_job_to_dead_letter_result_from_row_state(None, true, false, true, false),
        Err(Error::JobNotFailed)
    ));
    assert!(matches!(
        move_failed_job_to_dead_letter_result_from_row_state(None, true, true, true, true),
        Err(Error::UnexpectedOutcome {
            operation: "move failed job to dead letter",
            outcome,
        }) if outcome == "failed job matched but no dead-letter row was inserted"
    ));

    let replacement_id = JobId::new().expect("valid replacement id");
    assert_eq!(
        requeue_dead_letter_job_result_from_row_state(
            Some(replacement_id.as_bytes().to_vec()),
            false,
            false,
            false,
            true,
        )
        .expect("inserted replacement id wins when source was deleted"),
        replacement_id
    );
    assert!(matches!(
        requeue_dead_letter_job_result_from_row_state(
            Some(replacement_id.as_bytes().to_vec()),
            true,
            true,
            false,
            false,
        ),
        Err(Error::UnexpectedOutcome {
            operation: "requeue dead-letter job",
            outcome,
        }) if outcome == "inserted replacement job without deleting dead-letter source"
    ));
    assert!(matches!(
        requeue_dead_letter_job_result_from_row_state(None, false, false, false, false),
        Err(Error::DeadLetterJobNotFound)
    ));
    assert!(matches!(
        requeue_dead_letter_job_result_from_row_state(None, false, true, false, false),
        Err(Error::DeadLetterJobLockedByConcurrentTransaction)
    ));
    assert!(matches!(
        requeue_dead_letter_job_result_from_row_state(None, true, true, true, false),
        Err(Error::RetryConflictWithActiveDedupeJob)
    ));
    assert!(matches!(
        requeue_dead_letter_job_result_from_row_state(None, true, true, false, false),
        Err(Error::UnexpectedOutcome {
            operation: "requeue dead-letter job",
            outcome,
        }) if outcome == "dead-letter source matched but no replacement job was inserted"
    ));

    delete_dead_letter_job_result_from_outcome("applied").expect("applied delete");
    assert!(matches!(
        delete_dead_letter_job_result_from_outcome("not_found"),
        Err(Error::DeadLetterJobNotFound)
    ));
    assert!(matches!(
        delete_dead_letter_job_result_from_outcome("locked"),
        Err(Error::DeadLetterJobLockedByConcurrentTransaction)
    ));
    assert!(matches!(
        delete_dead_letter_job_result_from_outcome("mystery"),
        Err(Error::UnexpectedOutcome {
            operation: "delete dead-letter job",
            outcome,
        }) if outcome == "mystery"
    ));
}
