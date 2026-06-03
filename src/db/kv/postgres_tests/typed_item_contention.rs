use super::*;

#[tokio::test]
async fn kv_item_get_or_init_initializes_once_under_contention() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "init-contention"]).expect("prefix"),
    );
    let initialized_count = Arc::new(AtomicUsize::new(0));
    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let handles = (0..20)
        .map(|index| {
            let task_item = item.clone();
            let task_pool = test_database.paranoid_pool.clone();
            let task_initialized_count = Arc::clone(&initialized_count);
            tokio::spawn(async move {
                let result = task_item
                    .get_or_init(
                        &task_pool,
                        ["shared"],
                        TestKvPayload {
                            label: format!("candidate-{index}"),
                            count: index,
                        },
                        KvTtl::no_expiration(),
                    )
                    .await
                    .expect("get_or_init");
                if result.initialized {
                    task_initialized_count.fetch_add(1, Ordering::SeqCst);
                }
                if result.initialized {
                    assert_eq!(result.value.label, format!("candidate-{index}"));
                }
                result.value
            })
        })
        .collect::<Vec<_>>();

    let mut observed_values = Vec::new();
    for handle in handles {
        observed_values.push(handle.await.expect("join get_or_init task"));
    }

    assert_eq!(initialized_count.load(Ordering::SeqCst), 1);
    let stored = item
        .get(&test_database.paranoid_pool, ["shared"])
        .await
        .expect("stored value");
    assert!(stored.label.starts_with("candidate-"));
    assert_eq!(observed_values.len(), 20);
    assert!(observed_values.iter().all(|value| value == &stored));

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}

#[tokio::test]
async fn kv_item_acquire_slot_validates_inputs_and_claims_multiple_slots_under_contention() {
    let test_database = TestDatabase::connect().await;

    let store = KvStore::new(test_database.config.clone()).expect("kv store");
    let item = KvItem::<TestKvPayload>::new_plain(
        store.clone(),
        KvKeyPrefix::from_parts(["item", "slots"]).expect("prefix"),
    );
    let payload = TestKvPayload {
        label: "holder".to_owned(),
        count: 1,
    };

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate");

    let no_candidates: Vec<&str> = Vec::new();
    assert_eq!(
        item.acquire_slot(
            &test_database.paranoid_pool,
            &no_candidates,
            &payload,
            KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
        )
        .await
        .expect("empty acquire"),
        None
    );
    assert!(matches!(
        item.acquire_slot(
            &test_database.paranoid_pool,
            &no_candidates,
            &payload,
            KvTtl::no_expiration(),
        )
        .await,
        Err(KvError::TtlNoExpirationNotAllowed)
    ));
    assert_eq!(
        fetch_table_row_count(&test_database.sqlx_pool, &test_database.config.table_name).await,
        0
    );
    assert!(matches!(
        item.acquire_slot(
            &test_database.paranoid_pool,
            &["slot"],
            &payload,
            KvTtl::no_expiration(),
        )
        .await,
        Err(KvError::TtlNoExpirationNotAllowed)
    ));
    assert!(matches!(
        item.acquire_slot(
            &test_database.paranoid_pool,
            &["bad:suffix"],
            &payload,
            KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
        )
        .await,
        Err(KvError::KeyPartContainsSeparatorByte)
    ));
    assert!(matches!(
        item.acquire_slot(
            &test_database.paranoid_pool,
            &[""],
            &payload,
            KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
        )
        .await,
        Err(KvError::EmptyKeyPart)
    ));
    assert!(matches!(
        item.acquire_slot(
            &test_database.paranoid_pool,
            &["dupe", "dupe"],
            &payload,
            KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
        )
        .await,
        Err(KvError::DuplicateKeyInBulkOperation)
    ));
    let too_many_suffixes = (0..=MAX_KV_ACQUIRE_SLOT_CANDIDATES)
        .map(|index| format!("slot-{index}"))
        .collect::<Vec<_>>();
    assert!(matches!(
        item.acquire_slot(
            &test_database.paranoid_pool,
            &too_many_suffixes,
            &payload,
            KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
        )
        .await,
        Err(KvError::AcquireSlotCandidateCountTooLarge { .. })
    ));
    assert_eq!(
        fetch_table_row_count(&test_database.sqlx_pool, &test_database.config.table_name).await,
        0
    );

    let candidates = ["a", "b", "c", "d", "e"];
    let handles = (0..20)
        .map(|index| {
            let task_item = item.clone();
            let task_pool = test_database.paranoid_pool.clone();
            let task_candidates = candidates;
            tokio::spawn(async move {
                task_item
                    .acquire_slot(
                        &task_pool,
                        &task_candidates,
                        &TestKvPayload {
                            label: format!("holder-{index}"),
                            count: index,
                        },
                        KvTtl::expires_after(Duration::from_secs(60)).expect("ttl"),
                    )
                    .await
                    .expect("acquire slot")
            })
        })
        .collect::<Vec<_>>();

    let mut acquired = HashSet::new();
    for handle in handles {
        if let Some(suffix) = handle.await.expect("join acquire task") {
            assert!(
                acquired.insert(suffix),
                "slot suffix should be acquired by only one contender"
            );
        }
    }
    assert_eq!(
        acquired,
        candidates
            .into_iter()
            .map(str::to_owned)
            .collect::<HashSet<_>>()
    );

    drop_test_table(&test_database.sqlx_pool, &test_database.config.table_name).await;
}
