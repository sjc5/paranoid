use super::*;

#[test]
fn enqueue_queries_gate_insert_on_pause_state_inside_single_statement() {
    let config = default_queue_config_for_sql_tests();
    let queries = [
        build_single_enqueue_query(&config),
        build_batch_enqueue_query(&config, 2),
        build_dedupe_enqueue_query(&config),
    ];

    for query in queries {
        let normalized = normalized_sql(&query);
        assert!(
            normalized.starts_with("WITH pause_state AS"),
            "enqueue query must start with pause-state CTE: {normalized}"
        );
        assert!(
            normalized.contains("INSERT INTO"),
            "enqueue query must perform the insert in the same statement: {normalized}"
        );
        assert!(
            normalized.contains("WHERE NOT pause_state.queue_paused"),
            "enqueue insert must be gated by global pause state: {normalized}"
        );
        assert!(
            normalized.contains("NOT pause_state.task_paused"),
            "enqueue insert must be gated by task pause state: {normalized}"
        );
        assert!(
            normalized.contains("WHEN (SELECT queue_paused FROM pause_state)"),
            "enqueue query must classify global pause without a second read: {normalized}"
        );
        assert!(
            normalized.contains("WHEN (SELECT task_paused FROM pause_state)"),
            "enqueue query must classify task pause without a second read: {normalized}"
        );
    }
}

#[test]
fn batch_enqueue_query_uses_one_pause_check_and_shared_batch_options() {
    let config = default_queue_config_for_sql_tests();
    let normalized = normalized_sql(&build_batch_enqueue_query(&config, 3));
    let expected_values = "pending_jobs(id, payload) AS ( VALUES ($1::bytea, $2::jsonb), ($3::bytea, $4::jsonb), ($5::bytea, $6::jsonb) )";

    assert!(
        normalized.contains(expected_values),
        "batch enqueue query must bind only per-job id and payload values in VALUES: {normalized}"
    );
    assert!(
        normalized.contains("COALESCE(BOOL_OR(key = $12), FALSE) AS queue_paused"),
        "batch enqueue query must use one global pause placeholder after shared options: {normalized}"
    );
    assert!(
        normalized.contains("COALESCE(BOOL_OR(key = $13), FALSE) AS task_paused"),
        "batch enqueue query must use one task pause placeholder after shared options: {normalized}"
    );
    assert!(
        normalized.contains("pending_jobs.id, $7, pending_jobs.payload, $8"),
        "batch enqueue query must share task and status placeholders for every row: {normalized}"
    );
    assert!(
        normalized.contains("CROSS JOIN pause_state WHERE NOT pause_state.queue_paused"),
        "batch enqueue insert must be gated by pause state inside the same statement: {normalized}"
    );
    assert!(
        normalized.contains("(SELECT COUNT(*)::bigint FROM inserted) AS inserted_count"),
        "batch enqueue query must return inserted count for all-or-nothing validation: {normalized}"
    );
}

#[test]
fn dedupe_enqueue_query_preserves_committed_existing_job_fast_path() {
    let config = default_queue_config_for_sql_tests();
    let normalized = normalized_sql(&build_dedupe_enqueue_query(&config));

    assert!(
        normalized.starts_with("WITH pause_state AS"),
        "dedupe enqueue must start with pause-state CTE: {normalized}"
    );
    assert!(
        normalized.contains("existing_active AS"),
        "dedupe enqueue must read an already-committed active dedupe job inside the same statement: {normalized}"
    );
    assert!(
        normalized.contains(
            "WHERE task_name = $2 AND dedupe_key = $8 AND status IN ('pending', 'running')"
        ),
        "dedupe enqueue existing-active lookup must be task/dedupe scoped to active jobs: {normalized}"
    );
    assert!(
        normalized.contains("inserted AS"),
        "dedupe enqueue must insert inside the same statement: {normalized}"
    );
    assert!(
        normalized.contains("ON CONFLICT (task_name, dedupe_key)"),
        "dedupe enqueue must rely on the partial unique active-dedupe index: {normalized}"
    );
    assert!(
        normalized.contains("WHERE dedupe_key IS NOT NULL AND status IN ('pending', 'running')"),
        "dedupe enqueue conflict target must match active-dedupe index predicate: {normalized}"
    );
    assert!(
        !normalized.contains("AND NOT EXISTS (SELECT 1 FROM existing_active)"),
        "dedupe enqueue must not gate insert on stale existing-active snapshot state: {normalized}"
    );
    assert!(
        normalized.contains("DO NOTHING"),
        "dedupe enqueue must not surface expected active-dedupe conflicts as database errors: {normalized}"
    );
    assert!(
        normalized.contains("(SELECT id FROM inserted) AS inserted_id"),
        "dedupe enqueue must return the inserted id from the same statement: {normalized}"
    );
    assert!(
        normalized.contains("(SELECT id FROM existing_active) AS existing_id"),
        "dedupe enqueue must return the committed active dedupe id from the same statement: {normalized}"
    );

    let queue_paused_case = normalized
        .find("WHEN (SELECT queue_paused FROM pause_state)")
        .expect("dedupe enqueue must classify global pause");
    let task_paused_case = normalized
        .find("WHEN (SELECT task_paused FROM pause_state)")
        .expect("dedupe enqueue must classify task pause");
    let inserted_case = normalized
        .find("WHEN EXISTS (SELECT 1 FROM inserted)")
        .expect("dedupe enqueue must classify inserted rows");
    let not_inserted_case = normalized
        .find("ELSE 'not_inserted'")
        .expect("dedupe enqueue must classify non-inserted rows");

    assert!(
        queue_paused_case < task_paused_case
            && task_paused_case < inserted_case
            && inserted_case < not_inserted_case,
        "dedupe enqueue outcome precedence must remain pause, then insert, then non-insert: {normalized}"
    );
}

#[test]
fn prepared_batch_enqueue_validates_size_and_payload_serialization_by_index() {
    assert!(matches!(
        PreparedEnqueueBatch::new(
            "task.batch",
            &[1_u8],
            EnqueueBatchOptions {
                max_retries: Some(u32::MAX),
                ..EnqueueBatchOptions::default()
            },
        ),
        Err(Error::InvalidMaxRetries)
    ));
    assert!(matches!(
        PreparedEnqueueBatch::new(
            "task.batch",
            &[1_u8],
            EnqueueBatchOptions {
                timeout: JobTimeout::ExpiresAfter(Duration::ZERO),
                ..EnqueueBatchOptions::default()
            },
        ),
        Err(Error::InvalidTimeout)
    ));

    let oversized_payloads = vec![0_u8; MAX_QUEUE_ENQUEUE_BATCH_SIZE as usize + 1];
    let Err(oversized_error) = PreparedEnqueueBatch::new(
        "task.batch",
        &oversized_payloads,
        EnqueueBatchOptions::default(),
    ) else {
        panic!("oversized batch should be rejected before serialization");
    };
    assert!(matches!(
        oversized_error,
        Error::EnqueueBatchSizeTooLarge { .. }
    ));

    struct FailingSerialize;

    impl Serialize for FailingSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom("intentional serialize failure"))
        }
    }

    let payloads = [FailingSerialize, FailingSerialize];
    let Err(payload_error) =
        PreparedEnqueueBatch::new("task.batch", &payloads, EnqueueBatchOptions::default())
    else {
        panic!("payload serialization should fail with index context");
    };
    assert!(matches!(
        payload_error,
        Error::EnqueueBatchPayloadJson {
            payload_index: 0,
            ..
        }
    ));
    let Err(oversized_payload_error) = PreparedEnqueueBatch::new_with_payload_json_limit(
        "task.batch",
        &["ok", "too large"],
        EnqueueBatchOptions::default(),
        4,
    ) else {
        panic!("oversized batch payload should be rejected with index context");
    };
    assert!(matches!(
        oversized_payload_error,
        Error::EnqueueBatchPayloadJsonTooLarge {
            payload_index: 1,
            actual_minimum,
            max: 4,
        } if actual_minimum > 4
    ));

    let prepared =
        PreparedEnqueueBatch::new("task.batch", &[1_u8, 2, 3], EnqueueBatchOptions::default())
            .expect("valid prepared batch");
    assert_eq!(prepared.jobs.len(), 3);
    assert_eq!(
        prepared
            .jobs
            .iter()
            .map(|job| job.job_id)
            .collect::<HashSet<_>>()
            .len(),
        3
    );
    assert_eq!(
        prepared
            .jobs
            .iter()
            .map(|job| job.payload_json.as_str())
            .collect::<Vec<_>>(),
        ["1", "2", "3"]
    );
}

#[test]
fn prepared_single_enqueue_reports_payload_serialization_error_without_database_work() {
    struct FailingSerialize;

    impl Serialize for FailingSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom(
                "intentional single-payload failure",
            ))
        }
    }

    let Err(payload_error) =
        PreparedEnqueue::new("task.enqueue", &FailingSerialize, EnqueueOptions::default())
    else {
        panic!("payload serialization should fail before enqueue SQL is built");
    };
    assert!(matches!(payload_error, Error::PayloadJson { .. }));
    assert!(
        payload_error
            .to_string()
            .contains("queue payload could not be encoded as JSON")
    );

    let Err(oversized_payload_error) = PreparedEnqueue::new_with_payload_json_limit(
        "task.enqueue",
        &"too large",
        EnqueueOptions::default(),
        4,
    ) else {
        panic!("oversized payload should fail before enqueue SQL is built");
    };
    assert!(matches!(
        oversized_payload_error,
        Error::PayloadJsonTooLarge {
            actual_minimum,
            max: 4,
        } if actual_minimum > 4
    ));
}

#[test]
fn enqueue_outcome_classifier_rejects_impossible_rows_without_database_fixtures() {
    let job_id = JobId::new().expect("valid id");
    let job_id_bytes = job_id.as_bytes().to_vec();

    let inserted =
        queue_enqueue_result_from_insert_outcome("enqueue", Some(job_id_bytes.clone()), "inserted")
            .expect("inserted row should decode");
    assert_eq!(
        inserted,
        EnqueueResult {
            job_id,
            deduplicated: false
        }
    );

    assert!(matches!(
        queue_enqueue_result_from_insert_outcome("enqueue", None, "inserted"),
        Err(Error::UnexpectedOutcome {
            operation: "enqueue",
            outcome,
        }) if outcome == "inserted without id"
    ));
    assert!(matches!(
        queue_enqueue_result_from_insert_outcome("enqueue", Some(vec![1, 2, 3]), "inserted"),
        Err(Error::JobId(id::Error::InvalidIdLength { actual: 3 }))
    ));
    assert!(matches!(
        queue_enqueue_result_from_insert_outcome("enqueue", None, "queue_paused"),
        Err(Error::QueuePaused)
    ));
    assert!(matches!(
        queue_enqueue_result_from_insert_outcome("enqueue", None, "task_paused"),
        Err(Error::TaskPaused)
    ));
    assert!(matches!(
        queue_enqueue_result_from_insert_outcome("enqueue", None, "mystery"),
        Err(Error::UnexpectedOutcome {
            operation: "enqueue",
            outcome,
        }) if outcome == "mystery"
    ));
}

#[test]
fn dedupe_enqueue_outcome_classifier_preserves_retry_vs_reuse_boundary() {
    let inserted_id = JobId::new().expect("valid inserted id");
    let existing_id = JobId::new().expect("valid existing id");

    match queue_dedupe_enqueue_result_from_insert_outcome(
        "dedupe enqueue",
        Some(inserted_id.as_bytes().to_vec()),
        None,
        "inserted",
    )
    .expect("inserted dedupe outcome should apply")
    {
        DedupeEnqueueAttemptOutcome::Applied(result) => {
            assert_eq!(
                result,
                EnqueueResult {
                    job_id: inserted_id,
                    deduplicated: false
                }
            );
        }
        DedupeEnqueueAttemptOutcome::RetryAfterInvisibleConflict => {
            panic!("inserted dedupe outcome must not request retry")
        }
    }

    match queue_dedupe_enqueue_result_from_insert_outcome(
        "dedupe enqueue",
        None,
        Some(existing_id.as_bytes().to_vec()),
        "not_inserted",
    )
    .expect("existing dedupe outcome should apply")
    {
        DedupeEnqueueAttemptOutcome::Applied(result) => {
            assert_eq!(
                result,
                EnqueueResult {
                    job_id: existing_id,
                    deduplicated: true
                }
            );
        }
        DedupeEnqueueAttemptOutcome::RetryAfterInvisibleConflict => {
            panic!("visible existing dedupe row must not request retry")
        }
    }

    match queue_dedupe_enqueue_result_from_insert_outcome(
        "dedupe enqueue",
        None,
        None,
        "not_inserted",
    )
    .expect("invisible conflict should be a retryable classifier result")
    {
        DedupeEnqueueAttemptOutcome::Applied(result) => {
            panic!("invisible conflict must not apply result {result:?}")
        }
        DedupeEnqueueAttemptOutcome::RetryAfterInvisibleConflict => {}
    }

    assert!(matches!(
        queue_dedupe_enqueue_result_from_insert_outcome(
            "dedupe enqueue",
            None,
            Some(vec![1, 2, 3]),
            "not_inserted",
        ),
        Err(Error::JobId(id::Error::InvalidIdLength { actual: 3 }))
    ));
    assert!(matches!(
        queue_dedupe_enqueue_result_from_insert_outcome(
            "dedupe enqueue",
            None,
            None,
            "queue_paused"
        ),
        Err(Error::QueuePaused)
    ));
    assert!(matches!(
        queue_dedupe_enqueue_result_from_insert_outcome(
            "dedupe enqueue",
            None,
            None,
            "task_paused"
        ),
        Err(Error::TaskPaused)
    ));
    assert!(matches!(
        queue_dedupe_enqueue_result_from_insert_outcome("dedupe enqueue", None, None, "mystery"),
        Err(Error::UnexpectedOutcome {
            operation: "dedupe enqueue",
            outcome,
        }) if outcome == "mystery"
    ));
}

#[test]
fn batch_enqueue_outcome_classifier_is_all_or_nothing() {
    let prepared =
        PreparedEnqueueBatch::new("task.batch", &[1_u8, 2, 3], EnqueueBatchOptions::default())
            .expect("valid prepared batch");
    let expected_job_ids = prepared
        .jobs
        .iter()
        .map(|job| job.job_id)
        .collect::<Vec<_>>();

    let inserted = queue_batch_enqueue_results_from_insert_outcome(prepared.jobs, 3, "inserted")
        .expect("complete batch insert should decode");
    assert_eq!(
        inserted
            .iter()
            .map(|result| result.job_id)
            .collect::<Vec<_>>(),
        expected_job_ids
    );
    assert!(inserted.iter().all(|result| !result.deduplicated));

    let prepared =
        PreparedEnqueueBatch::new("task.batch", &[1_u8, 2, 3], EnqueueBatchOptions::default())
            .expect("valid prepared batch");
    assert!(matches!(
        queue_batch_enqueue_results_from_insert_outcome(prepared.jobs, 2, "inserted"),
        Err(Error::UnexpectedOutcome {
            operation: "batch enqueue",
            outcome,
        }) if outcome == "inserted 2 rows, expected 3"
    ));

    assert!(matches!(
        queue_batch_enqueue_results_from_insert_outcome(Vec::new(), 0, "queue_paused"),
        Err(Error::QueuePaused)
    ));
    assert!(matches!(
        queue_batch_enqueue_results_from_insert_outcome(Vec::new(), 0, "task_paused"),
        Err(Error::TaskPaused)
    ));
    assert!(matches!(
        queue_batch_enqueue_results_from_insert_outcome(Vec::new(), 0, "not_inserted"),
        Err(Error::UnexpectedOutcome {
            operation: "batch enqueue",
            outcome,
        }) if outcome == "not_inserted"
    ));
}
