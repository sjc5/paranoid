use super::*;

#[test]
fn queue_worker_config_retry_and_timeout_resolution_cover_edge_cases() {
    let resolved = ResolvedWorkerConfig::new(WorkerConfig::default()).expect("default config");
    assert_eq!(resolved.poll_interval, DEFAULT_QUEUE_WORKER_POLL_INTERVAL);
    assert_eq!(
        resolved.startup_jitter_max_delay,
        Duration::from_millis(250)
    );
    assert_eq!(resolved.concurrency, DEFAULT_QUEUE_WORKER_CONCURRENCY);
    assert_eq!(
        resolved.stale_threshold,
        DEFAULT_QUEUE_WORKER_STALE_THRESHOLD
    );
    assert_eq!(
        resolved.execution_heartbeat_interval,
        DEFAULT_QUEUE_WORKER_EXECUTION_HEARTBEAT_INTERVAL
    );
    assert_eq!(
        resolved.database_operation_timeout,
        DEFAULT_QUEUE_WORKER_DATABASE_OPERATION_TIMEOUT
    );
    assert!(matches!(
        resolved.default_job_timeout,
        WorkerDefaultJobTimeout::ExpiresAfter(DEFAULT_QUEUE_WORKER_JOB_TIMEOUT)
    ));
    assert!(resolved.dead_letter_enabled);

    assert!(matches!(
        ResolvedWorkerConfig::new(WorkerConfig {
            concurrency: MAX_QUEUE_WORKER_CONCURRENCY + 1,
            ..WorkerConfig::default()
        }),
        Err(Error::WorkerConcurrencyTooLarge { .. })
    ));
    assert!(matches!(
        ResolvedWorkerConfig::new(WorkerConfig {
            stale_threshold: Duration::from_secs(2),
            execution_heartbeat_interval: Duration::from_secs(2),
            ..WorkerConfig::default()
        }),
        Err(Error::InvalidWorkerConfig { .. })
    ));
    assert!(matches!(
        ResolvedWorkerConfig::new(WorkerConfig {
            default_job_timeout: WorkerDefaultJobTimeout::ExpiresAfter(Duration::ZERO),
            ..WorkerConfig::default()
        }),
        Err(Error::InvalidWorkerConfig { .. })
    ));
    ResolvedWorkerConfig::new(WorkerConfig {
        startup_jitter_max_delay: Some(Duration::ZERO),
        default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
        ..WorkerConfig::default()
    })
    .expect("disabled worker default timeout");
    let explicit_startup_jitter = ResolvedWorkerConfig::new(WorkerConfig {
        startup_jitter_max_delay: Some(Duration::from_millis(7)),
        ..WorkerConfig::default()
    })
    .expect("explicit startup jitter");
    assert_eq!(
        explicit_startup_jitter.startup_jitter_max_delay,
        Duration::from_millis(7)
    );
    let explicit_database_operation_timeout = ResolvedWorkerConfig::new(WorkerConfig {
        database_operation_timeout: Duration::from_millis(17),
        ..WorkerConfig::default()
    })
    .expect("explicit database operation timeout");
    assert_eq!(
        explicit_database_operation_timeout.database_operation_timeout,
        Duration::from_millis(17)
    );
    assert!(matches!(
        ResolvedWorkerConfig::new(WorkerConfig {
            database_operation_timeout: Duration::ZERO,
            ..WorkerConfig::default()
        }),
        Err(Error::InvalidWorkerConfig { .. })
    ));
    ResolvedWorkerConfig::new(WorkerConfig {
        default_job_timeout: WorkerDefaultJobTimeout::ExpiresAfter(Duration::from_secs(10)),
        ..WorkerConfig::default()
    })
    .expect("explicit worker default timeout with default stale threshold");
    assert!(matches!(
        ResolvedWorkerConfig::new(WorkerConfig {
            stale_threshold: Duration::from_secs(1),
            execution_heartbeat_interval: Duration::from_millis(100),
            default_job_timeout: WorkerDefaultJobTimeout::ExpiresAfter(Duration::from_secs(2)),
            ..WorkerConfig::default()
        }),
        Err(Error::InvalidWorkerConfig { .. })
    ));

    let retry_error = TaskError::retryable("retry");
    let default_policy =
        resolve_queue_retry_policy(RetryPolicy::default()).expect("default retry policy");
    assert!(matches!(
        &default_policy.strategy,
        RetryBackoffStrategy::Exponential {
            base: DEFAULT_QUEUE_RETRY_EXPONENTIAL_BASE
        }
    ));
    assert_eq!(default_policy.max_backoff, DEFAULT_QUEUE_RETRY_MAX_BACKOFF);

    let fixed_policy = resolve_queue_retry_policy(RetryPolicy {
        strategy: RetryBackoffStrategy::Fixed {
            backoff: Duration::from_millis(10),
        },
        jitter_fraction: 0.0,
        ..RetryPolicy::default()
    })
    .expect("fixed retry policy");
    assert_eq!(
        compute_queue_retry_backoff(&fixed_policy, 99, &retry_error).expect("fixed backoff"),
        Duration::from_millis(10)
    );

    let tiny_fixed_policy = resolve_queue_retry_policy(RetryPolicy {
        strategy: RetryBackoffStrategy::Fixed {
            backoff: Duration::from_nanos(1),
        },
        jitter_fraction: 0.0,
        ..RetryPolicy::default()
    })
    .expect("tiny fixed retry policy");
    assert_eq!(
        compute_queue_retry_backoff(&tiny_fixed_policy, 1, &retry_error)
            .expect("minimum fixed backoff"),
        MIN_QUEUE_RETRY_BACKOFF
    );

    let custom_policy = resolve_queue_retry_policy(RetryPolicy {
        strategy: RetryBackoffStrategy::Custom(Arc::new(|retry_count, _error| {
            Duration::from_secs(u64::from(retry_count))
        })),
        max_backoff: Duration::from_millis(250),
        jitter_fraction: 0.0,
    })
    .expect("custom retry policy");
    assert_eq!(
        compute_queue_retry_backoff(&custom_policy, 10, &retry_error).expect("custom backoff"),
        Duration::from_millis(250)
    );

    assert!(matches!(
        resolve_queue_retry_policy(RetryPolicy {
            strategy: RetryBackoffStrategy::Fixed {
                backoff: Duration::ZERO,
            },
            ..RetryPolicy::default()
        }),
        Err(Error::InvalidRetryPolicy { .. })
    ));
    assert!(matches!(
        resolve_queue_retry_policy(RetryPolicy {
            strategy: RetryBackoffStrategy::Exponential { base: 1.0 },
            ..RetryPolicy::default()
        }),
        Err(Error::InvalidRetryPolicy { .. })
    ));
    assert!(matches!(
        resolve_queue_retry_policy(RetryPolicy {
            jitter_fraction: f64::NAN,
            ..RetryPolicy::default()
        }),
        Err(Error::InvalidRetryPolicy { .. })
    ));

    assert_eq!(
        resolve_queue_job_timeout(
            JobTimeout::WorkerDefault,
            WorkerDefaultJobTimeout::NoTimeout
        ),
        None
    );
    assert_eq!(
        resolve_queue_job_timeout(
            JobTimeout::WorkerDefault,
            WorkerDefaultJobTimeout::default()
        ),
        Some(DEFAULT_QUEUE_WORKER_JOB_TIMEOUT)
    );
    assert_eq!(
        resolve_queue_job_timeout(
            JobTimeout::WorkerDefault,
            WorkerDefaultJobTimeout::ExpiresAfter(Duration::from_secs(3))
        ),
        Some(Duration::from_secs(3))
    );
    assert_eq!(
        resolve_queue_job_timeout(JobTimeout::NoTimeout, WorkerDefaultJobTimeout::default()),
        None
    );
    assert_eq!(
        resolve_queue_job_timeout(
            JobTimeout::ExpiresAfter(Duration::from_nanos(123)),
            WorkerDefaultJobTimeout::default()
        ),
        Some(Duration::from_nanos(123))
    );
}

#[test]
fn queue_worker_config_numeric_domains_are_stable_across_boundaries() {
    assert!(matches!(
        ResolvedWorkerConfig::new(WorkerConfig {
            concurrency: 0,
            ..WorkerConfig::default()
        }),
        Err(Error::InvalidWorkerConfig { .. })
    ));
    for concurrency in [
        1,
        DEFAULT_QUEUE_WORKER_CONCURRENCY,
        MAX_QUEUE_WORKER_CONCURRENCY,
    ] {
        let resolved = ResolvedWorkerConfig::new(WorkerConfig {
            concurrency,
            ..WorkerConfig::default()
        })
        .expect("valid worker concurrency");
        assert_eq!(resolved.concurrency, concurrency);
    }
    for concurrency in [MAX_QUEUE_WORKER_CONCURRENCY + 1, u32::MAX] {
        assert!(
            matches!(
                ResolvedWorkerConfig::new(WorkerConfig {
                    concurrency,
                    ..WorkerConfig::default()
                }),
                Err(Error::WorkerConcurrencyTooLarge { actual, max })
                    if actual == concurrency && max == MAX_QUEUE_WORKER_CONCURRENCY
            ),
            "concurrency {concurrency} should be outside the database-safe domain"
        );
    }

    assert!(matches!(
        ResolvedWorkerConfig::new(WorkerConfig {
            poll_interval: Duration::ZERO,
            startup_jitter_max_delay: Some(Duration::ZERO),
            ..WorkerConfig::default()
        }),
        Err(Error::InvalidWorkerConfig { .. })
    ));
    for poll_interval in [Duration::from_millis(1), DEFAULT_QUEUE_WORKER_POLL_INTERVAL] {
        let resolved = ResolvedWorkerConfig::new(WorkerConfig {
            poll_interval,
            startup_jitter_max_delay: Some(Duration::ZERO),
            ..WorkerConfig::default()
        })
        .expect("valid poll interval");
        assert_eq!(resolved.poll_interval, poll_interval);
    }

    let resolved = ResolvedWorkerConfig::new(WorkerConfig {
        poll_interval: Duration::from_millis(100),
        startup_jitter_max_delay: None,
        ..WorkerConfig::default()
    })
    .expect("default startup jitter");
    assert_eq!(resolved.startup_jitter_max_delay, Duration::from_millis(25));

    for shutdown_grace_period in [
        Duration::ZERO,
        Duration::from_millis(1),
        DEFAULT_QUEUE_WORKER_SHUTDOWN_GRACE_PERIOD,
    ] {
        let resolved = ResolvedWorkerConfig::new(WorkerConfig {
            shutdown_grace_period,
            ..WorkerConfig::default()
        })
        .expect("valid shutdown grace period");
        assert_eq!(resolved.shutdown_grace_period, shutdown_grace_period);
    }
}

#[test]
fn queue_worker_fleet_maintenance_config_resolves_reclaim_and_cleanup_batching() {
    let queue_config = StoreConfig::default();
    let resolved =
        ResolvedWorkerMaintenanceConfig::new(&queue_config, WorkerMaintenanceConfig::default())
            .expect("default Fleet maintenance config");
    assert_eq!(
        resolved.cleanup_batch_size,
        DEFAULT_QUEUE_CLEANUP_BATCH_SIZE
    );
    assert_eq!(
        resolved.reclaim_batch_size,
        DEFAULT_QUEUE_RECLAIM_BATCH_SIZE
    );
    assert_eq!(
        resolved.delay_between_cleanup_batches,
        DEFAULT_QUEUE_CLEANUP_BATCH_DELAY
    );

    let explicit = ResolvedWorkerMaintenanceConfig::new(
        &queue_config,
        WorkerMaintenanceConfig {
            reclaim_batch_size: 6,
            cleanup_batch_size: 7,
            delay_between_cleanup_batches: Duration::from_millis(3),
            ..WorkerMaintenanceConfig::default()
        },
    )
    .expect("explicit cleanup batching config");
    assert_eq!(explicit.reclaim_batch_size, 6);
    assert_eq!(explicit.cleanup_batch_size, 7);
    assert_eq!(
        explicit.delay_between_cleanup_batches,
        Duration::from_millis(3)
    );

    let invalid_batch_size = ResolvedWorkerMaintenanceConfig::new(
        &queue_config,
        WorkerMaintenanceConfig {
            reclaim_batch_size: 0,
            ..WorkerMaintenanceConfig::default()
        },
    )
    .expect_err("zero reclaim batch should be rejected");
    assert!(matches!(invalid_batch_size, Error::ReclaimBatchSizeIsZero));

    let invalid_batch_size = ResolvedWorkerMaintenanceConfig::new(
        &queue_config,
        WorkerMaintenanceConfig {
            reclaim_batch_size: MAX_QUEUE_RECLAIM_BATCH_SIZE + 1,
            ..WorkerMaintenanceConfig::default()
        },
    )
    .expect_err("oversized reclaim batch should be rejected");
    assert!(matches!(
        invalid_batch_size,
        Error::ReclaimBatchSizeTooLarge { .. }
    ));

    let invalid_batch_size = ResolvedWorkerMaintenanceConfig::new(
        &queue_config,
        WorkerMaintenanceConfig {
            cleanup_batch_size: 0,
            ..WorkerMaintenanceConfig::default()
        },
    )
    .expect_err("zero cleanup batch should be rejected");
    assert!(matches!(invalid_batch_size, Error::CleanupBatchSizeIsZero));

    let invalid_batch_size = ResolvedWorkerMaintenanceConfig::new(
        &queue_config,
        WorkerMaintenanceConfig {
            cleanup_batch_size: MAX_QUEUE_CLEANUP_BATCH_SIZE + 1,
            ..WorkerMaintenanceConfig::default()
        },
    )
    .expect_err("oversized cleanup batch should be rejected");
    assert!(matches!(
        invalid_batch_size,
        Error::CleanupBatchSizeTooLarge { .. }
    ));
}

#[test]
fn queue_retry_policy_resolution_preserves_explicit_zero_jitter_for_all_modes() {
    let fixed = resolve_queue_retry_policy(RetryPolicy {
        strategy: RetryBackoffStrategy::Fixed {
            backoff: Duration::from_secs(1),
        },
        jitter_fraction: 0.0,
        ..RetryPolicy::default()
    })
    .expect("fixed retry policy with zero jitter");
    assert_eq!(fixed.jitter_fraction, 0.0);

    let exponential = resolve_queue_retry_policy(RetryPolicy {
        strategy: RetryBackoffStrategy::Exponential { base: 2.0 },
        max_backoff: Duration::from_secs(30),
        jitter_fraction: 0.0,
    })
    .expect("exponential retry policy with zero jitter");
    assert_eq!(exponential.jitter_fraction, 0.0);

    let custom = resolve_queue_retry_policy(RetryPolicy {
        strategy: RetryBackoffStrategy::Custom(Arc::new(|_, _| Duration::from_secs(1))),
        jitter_fraction: 0.0,
        ..RetryPolicy::default()
    })
    .expect("custom retry policy with zero jitter");
    assert_eq!(custom.jitter_fraction, 0.0);
}

#[tokio::test]
async fn queue_worker_startup_jitter_wait_is_shutdown_responsive() {
    let shutdown_signal = RuntimeCancellationSignal::new();
    let waiting_task = tokio::spawn({
        let shutdown_signal = shutdown_signal.clone();
        async move {
            wait_for_queue_worker_startup_jitter_delay_or_shutdown(
                &shutdown_signal,
                Duration::from_secs(60),
            )
            .await
        }
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    shutdown_signal.request_cancellation();

    let start = std::time::Instant::now();
    let entered_run_loop = tokio::time::timeout(Duration::from_millis(150), waiting_task)
        .await
        .expect("startup jitter wait should exit promptly after shutdown")
        .expect("startup jitter wait task should not panic")
        .expect("startup jitter wait should not fail");
    assert!(!entered_run_loop);
    assert!(
        start.elapsed() < Duration::from_millis(100),
        "startup jitter wait ignored shutdown until {:?}",
        start.elapsed()
    );

    let immediate_start = wait_for_queue_worker_startup_jitter_before_run_loop(
        &RuntimeCancellationSignal::new(),
        Duration::ZERO,
    )
    .await
    .expect("zero startup jitter should not fail");
    assert!(immediate_start);

    assert_eq!(
        compute_queue_worker_startup_jitter_delay(Duration::ZERO)
            .expect("zero startup jitter delay"),
        Duration::ZERO
    );
}

#[test]
fn queue_retry_policy_rejects_invalid_numeric_edges() {
    assert!(matches!(
        resolve_queue_retry_policy(RetryPolicy {
            strategy: RetryBackoffStrategy::Exponential {
                base: f64::INFINITY,
            },
            ..RetryPolicy::default()
        }),
        Err(Error::InvalidRetryPolicy { .. })
    ));
    assert!(matches!(
        resolve_queue_retry_policy(RetryPolicy {
            strategy: RetryBackoffStrategy::Exponential { base: 2.0 },
            jitter_fraction: -0.01,
            ..RetryPolicy::default()
        }),
        Err(Error::InvalidRetryPolicy { .. })
    ));
    assert!(matches!(
        resolve_queue_retry_policy(RetryPolicy {
            strategy: RetryBackoffStrategy::Exponential { base: 2.0 },
            max_backoff: Duration::from_nanos(1),
            jitter_fraction: 0.0,
        }),
        Err(Error::InvalidRetryPolicy { .. })
    ));

    assert!(matches!(
        resolve_queue_retry_policy(RetryPolicy {
            strategy: RetryBackoffStrategy::Exponential { base: 2.0 },
            max_backoff: Duration::ZERO,
            jitter_fraction: 0.0,
        }),
        Err(Error::InvalidRetryPolicy { .. })
    ));
}

#[test]
fn queue_retry_policy_properties_cover_modes_and_numeric_bounds() {
    for jitter_fraction in [0.0, 0.2, 1.0, 2.0] {
        let policy = resolve_queue_retry_policy(RetryPolicy {
            jitter_fraction,
            ..RetryPolicy::default()
        })
        .expect("finite non-negative jitter is accepted");
        assert_eq!(policy.jitter_fraction, jitter_fraction);
    }
    for jitter_fraction in [f64::NAN, f64::INFINITY, -f64::EPSILON, -1.0] {
        assert!(
            matches!(
                resolve_queue_retry_policy(RetryPolicy {
                    jitter_fraction,
                    ..RetryPolicy::default()
                }),
                Err(Error::InvalidRetryPolicy { .. })
            ),
            "jitter fraction {jitter_fraction:?} should be rejected"
        );
    }

    for exponential_base in [1.000_001, 2.0, 10.0] {
        let policy = resolve_queue_retry_policy(RetryPolicy {
            strategy: RetryBackoffStrategy::Exponential {
                base: exponential_base,
            },
            jitter_fraction: 0.0,
            ..RetryPolicy::default()
        })
        .expect("valid exponential base");
        assert!(matches!(
            policy.strategy,
            RetryBackoffStrategy::Exponential {
                base
            } if base == exponential_base
        ));
    }
    for exponential_base in [f64::NAN, f64::INFINITY, 0.0, 1.0] {
        assert!(
            matches!(
                resolve_queue_retry_policy(RetryPolicy {
                    strategy: RetryBackoffStrategy::Exponential {
                        base: exponential_base,
                    },
                    jitter_fraction: 0.0,
                    ..RetryPolicy::default()
                }),
                Err(Error::InvalidRetryPolicy { .. })
            ),
            "exponential base {exponential_base:?} should be rejected"
        );
    }

    for backoff in [
        Duration::from_nanos(1),
        MIN_QUEUE_RETRY_BACKOFF,
        DEFAULT_QUEUE_RETRY_MAX_BACKOFF,
        Duration::from_secs(60),
    ] {
        let normalized =
            normalize_queue_retry_backoff(backoff, Some(DEFAULT_QUEUE_RETRY_MAX_BACKOFF));
        assert!(normalized >= MIN_QUEUE_RETRY_BACKOFF);
        assert!(normalized <= DEFAULT_QUEUE_RETRY_MAX_BACKOFF);
    }

    let retry_error = TaskError::retryable("retry");
    let fixed = resolve_queue_retry_policy(RetryPolicy {
        strategy: RetryBackoffStrategy::Fixed {
            backoff: Duration::from_millis(5),
        },
        jitter_fraction: 0.0,
        ..RetryPolicy::default()
    })
    .expect("fixed retry policy");
    for retry_count in [0, 1, 10, u32::MAX] {
        assert_eq!(
            compute_queue_retry_backoff(&fixed, retry_count, &retry_error)
                .expect("fixed retry backoff"),
            Duration::from_millis(5)
        );
    }
}

#[test]
fn queue_retry_backoff_computation_covers_clamping_and_saturating_conversion() {
    let retry_error = TaskError::retryable("retry");
    let exponential = resolve_queue_retry_policy(RetryPolicy {
        strategy: RetryBackoffStrategy::Exponential { base: 2.0 },
        max_backoff: Duration::from_secs(30),
        jitter_fraction: 0.0,
    })
    .expect("exponential retry policy");
    assert_eq!(
        compute_queue_retry_backoff(&exponential, 3, &retry_error).expect("exponential backoff"),
        Duration::from_secs(8)
    );

    let subsecond_max = resolve_queue_retry_policy(RetryPolicy {
        strategy: RetryBackoffStrategy::Exponential { base: 2.0 },
        max_backoff: Duration::from_millis(200),
        jitter_fraction: 0.0,
    })
    .expect("subsecond max retry policy");
    assert_eq!(
        compute_queue_retry_backoff(&subsecond_max, 20, &retry_error)
            .expect("subsecond max backoff"),
        Duration::from_millis(200)
    );

    assert_eq!(
        duration_from_retry_backoff_seconds(-0.5, Some(Duration::from_secs(2))),
        Duration::ZERO
    );
    assert_eq!(
        duration_from_retry_backoff_seconds(f64::NAN, Some(Duration::from_secs(2))),
        Duration::ZERO
    );
    assert_eq!(
        duration_from_retry_backoff_seconds(f64::INFINITY, Some(Duration::from_secs(2))),
        Duration::from_secs(2)
    );

    let large_jitter = resolve_queue_retry_policy(RetryPolicy {
        strategy: RetryBackoffStrategy::Exponential { base: 2.0 },
        max_backoff: Duration::from_secs(2),
        jitter_fraction: 2.0,
    })
    .expect("large jitter retry policy");
    for _ in 0..512 {
        let backoff = compute_queue_retry_backoff(&large_jitter, 20, &retry_error)
            .expect("large jitter backoff");
        assert!(backoff >= MIN_QUEUE_RETRY_BACKOFF);
        assert!(backoff <= Duration::from_secs(2));
    }
}

#[test]
fn queue_worker_timing_validation_covers_derived_and_explicit_boundaries() {
    ResolvedWorkerConfig::new(WorkerConfig {
        stale_threshold: Duration::from_secs(4),
        execution_heartbeat_interval: Duration::from_secs(1),
        default_job_timeout: WorkerDefaultJobTimeout::ExpiresAfter(Duration::from_secs(2)),
        ..WorkerConfig::default()
    })
    .expect("stale threshold exactly 2x explicit timeout is valid");

    assert!(matches!(
        ResolvedWorkerConfig::new(WorkerConfig {
            stale_threshold: Duration::from_millis(500),
            default_job_timeout: WorkerDefaultJobTimeout::NoTimeout,
            ..WorkerConfig::default()
        }),
        Err(Error::InvalidWorkerConfig { .. })
    ));
}

#[tokio::test]
async fn queue_worker_claim_retry_backoff_wait_is_shutdown_responsive() {
    let shutdown_signal = RuntimeCancellationSignal::new();
    let wait_task_shutdown_signal = shutdown_signal.clone();
    let wait_started_at = std::time::Instant::now();
    let wait_task = tokio::spawn(async move {
        wait_for_worker_claim_retry_backoff_or_shutdown(
            &wait_task_shutdown_signal,
            Duration::from_secs(60),
        )
        .await;
    });

    tokio::time::sleep(Duration::from_millis(25)).await;
    shutdown_signal.request_cancellation();
    tokio::time::timeout(Duration::from_millis(500), wait_task)
        .await
        .expect("claim retry backoff wait should exit promptly after shutdown")
        .expect("claim retry backoff wait task should not panic");
    assert!(
        wait_started_at.elapsed() < Duration::from_millis(500),
        "claim retry backoff wait ignored shutdown until {:?}",
        wait_started_at.elapsed()
    );

    let live_shutdown_signal = RuntimeCancellationSignal::new();
    let full_wait = wait_for_worker_claim_retry_backoff_or_shutdown(
        &live_shutdown_signal,
        Duration::from_millis(100),
    );
    tokio::time::timeout(Duration::from_millis(25), full_wait)
        .await
        .expect_err("claim retry backoff wait should not finish early without shutdown");
}

#[test]
fn queue_registry_status_reason_and_summary_helpers_are_stable() {
    let mut registry = TaskRegistry::new();
    assert!(registry.is_empty());
    registry
        .register_json_task_handler("task.zeta", |_context, _payload: u8| async move { Ok(()) })
        .expect("register zeta");
    registry
        .register_json_task_handler("task.alpha", |_context, _payload: u8| async move { Ok(()) })
        .expect("register alpha");
    assert_eq!(registry.registered_task_count(), 2);
    let mut names = registry.registered_task_names();
    assert_eq!(names, ["task.alpha", "task.zeta"]);
    names[0] = "mutated".to_owned();
    assert_eq!(
        registry.registered_task_names(),
        ["task.alpha", "task.zeta"]
    );
    assert!(registry.handler("task.alpha").is_some());
    assert!(registry.handler("missing").is_none());
    assert!(matches!(
        registry.register_json_task_handler("task.alpha", |_context, _payload: u8| async move {
            Ok(())
        }),
        Err(Error::TaskAlreadyRegistered)
    ));
    assert!(matches!(
        registry
            .register_json_task_handler("bad task", |_context, _payload: u8| async move { Ok(()) }),
        Err(Error::InvalidTaskName)
    ));

    for (status, text) in [
        (JobStatus::Pending, "pending"),
        (JobStatus::Running, "running"),
        (JobStatus::Completed, "completed"),
        (JobStatus::Failed, "failed"),
    ] {
        assert_eq!(status.as_str(), text);
        assert_eq!(JobStatus::parse(text).expect("parse status"), status);
        for invalid_variant in [
            text.to_uppercase(),
            format!("{text} "),
            format!(" {text}"),
            format!("{text}_extra"),
        ] {
            assert!(
                matches!(
                    JobStatus::parse(&invalid_variant),
                    Err(Error::InvalidPersistedJobStatus { .. })
                ),
                "status variant {invalid_variant:?} should be rejected"
            );
        }
    }
    assert!(matches!(
        JobStatus::parse("bogus"),
        Err(Error::InvalidPersistedJobStatus { .. })
    ));

    for (reason, text) in [
        (DeadLetterReason::MaxRetriesExceeded, "max_retries_exceeded"),
        (DeadLetterReason::PermanentError, "permanent_error"),
        (DeadLetterReason::OperatorAction, "operator_action"),
        (DeadLetterReason::ExecutionExpired, "execution_expired"),
    ] {
        assert_eq!(reason.as_str(), text);
        assert_eq!(DeadLetterReason::parse(text).expect("parse reason"), reason);
        for invalid_variant in [
            text.to_uppercase(),
            format!("{text} "),
            format!(" {text}"),
            format!("{text}_extra"),
        ] {
            assert!(
                matches!(
                    DeadLetterReason::parse(&invalid_variant),
                    Err(Error::InvalidPersistedDeadLetterReason { .. })
                ),
                "dead-letter reason variant {invalid_variant:?} should be rejected"
            );
        }
    }
    assert!(matches!(
        DeadLetterReason::parse("bogus"),
        Err(Error::InvalidPersistedDeadLetterReason { .. })
    ));

    let status_counts = StatusCounts {
        pending_count: 1,
        running_count: 2,
        completed_count: 3,
        failed_count: 4,
        dead_letter_count: 5,
    };
    assert_eq!(status_counts.total_count(), 15);

    let batch_result = MoveFailedJobsToDeadLetterBatchResult {
        requested_count: 3,
        moved_jobs: Vec::new(),
    };
    assert_eq!(batch_result.skipped_count(), 3);

    let retryable = TaskError::retryable("retryable");
    assert_eq!(retryable.message(), "retryable");
    assert_eq!(retryable.to_string(), "retryable");
    assert!(!retryable.is_permanent());
    let permanent = TaskError::permanent("permanent");
    assert_eq!(permanent.message(), "permanent");
    assert!(permanent.is_permanent());
}
