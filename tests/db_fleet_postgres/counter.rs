use super::*;

#[tokio::test]
async fn fleet_counter_add_get_set_and_negative_values() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let counter_key = CounterKey::new("page-views").expect("counter key");
    let counter = store.new_counter(counter_key.clone()).expect("new counter");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    assert_eq!(counter.key(), &counter_key);
    assert_eq!(
        counter
            .fetch_value(&test_database.paranoid_pool)
            .await
            .expect("fetch absent counter"),
        0
    );
    assert_eq!(
        counter
            .add(&test_database.paranoid_pool, 5)
            .await
            .expect("add five"),
        5
    );
    assert_eq!(
        counter
            .add(&test_database.paranoid_pool, 10)
            .await
            .expect("add ten"),
        15
    );
    assert_eq!(
        counter
            .add(&test_database.paranoid_pool, -3)
            .await
            .expect("subtract three"),
        12
    );

    counter
        .set_value(&test_database.paranoid_pool, -50)
        .await
        .expect("set negative value");
    assert_eq!(
        counter
            .fetch_value(&test_database.paranoid_pool)
            .await
            .expect("fetch negative value"),
        -50
    );
    assert_eq!(
        counter
            .add(&test_database.paranoid_pool, 0)
            .await
            .expect("add zero"),
        -50
    );
    counter
        .set_value(&test_database.paranoid_pool, 0)
        .await
        .expect("set zero");
    assert_eq!(
        counter
            .fetch_value(&test_database.paranoid_pool)
            .await
            .expect("fetch zero"),
        0
    );
    assert_eq!(
        counter
            .add(&test_database.paranoid_pool, 1)
            .await
            .expect("add one from zero"),
        1
    );
    assert_eq!(
        counter
            .add(&test_database.paranoid_pool, 1)
            .await
            .expect("add one again"),
        2
    );
    assert_eq!(
        counter
            .add(&test_database.paranoid_pool, -1)
            .await
            .expect("subtract one"),
        1
    );

    let large_value = 1_i64 << 50;
    counter
        .set_value(&test_database.paranoid_pool, large_value)
        .await
        .expect("set large value");
    assert_eq!(
        counter
            .add(&test_database.paranoid_pool, 1)
            .await
            .expect("add one to large value"),
        large_value + 1
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_counter_concurrent_adds_are_atomic() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let counter = Arc::new(
        store
            .new_counter(CounterKey::new("concurrent-counter").expect("counter key"))
            .expect("new counter"),
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    let worker_count = 20;
    let barrier = Arc::new(Barrier::new(worker_count));
    let mut handles = Vec::with_capacity(worker_count);

    for delta in 1..=worker_count {
        let counter = Arc::clone(&counter);
        let barrier = Arc::clone(&barrier);
        let pool = test_database.paranoid_pool.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            counter
                .add(&pool, i64::try_from(delta).expect("test delta fits i64"))
                .await
                .expect("concurrent add");
        }));
    }

    for handle in handles {
        handle.await.expect("join worker");
    }

    let expected = i64::try_from(worker_count * (worker_count + 1) / 2).expect("test sum fits i64");
    assert_eq!(
        counter
            .fetch_value(&test_database.paranoid_pool)
            .await
            .expect("fetch after concurrent adds"),
        expected
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_counter_composes_inside_current_transaction_and_rolls_back() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let counter = store
        .new_counter(CounterKey::new("transactional-counter").expect("counter key"))
        .expect("new counter");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    counter
        .set_value(&test_database.paranoid_pool, 100)
        .await
        .expect("set initial value");

    let mut rollback_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin rollback transaction");
    assert_eq!(
        counter
            .add_in_current_transaction(&mut rollback_tx, 50)
            .await
            .expect("add in rollback transaction"),
        150
    );
    assert_eq!(
        counter
            .fetch_value_in_current_transaction(&mut rollback_tx)
            .await
            .expect("fetch inside rollback transaction"),
        150
    );
    rollback_tx.rollback().await.expect("rollback transaction");
    assert_eq!(
        counter
            .fetch_value(&test_database.paranoid_pool)
            .await
            .expect("fetch after rollback"),
        100
    );

    let mut commit_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin commit transaction");
    counter
        .set_value_in_current_transaction(&mut commit_tx, 7)
        .await
        .expect("set in commit transaction");
    assert_eq!(
        counter
            .add_in_current_transaction(&mut commit_tx, 4)
            .await
            .expect("add in commit transaction"),
        11
    );
    commit_tx.commit().await.expect("commit transaction");
    assert_eq!(
        counter
            .fetch_value(&test_database.paranoid_pool)
            .await
            .expect("fetch after commit"),
        11
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}

#[tokio::test]
async fn fleet_counter_rejects_arithmetic_overflow_without_mutating_value() {
    let test_database = TestDatabase::connect().await;

    let store = Store::new(test_database.config.clone()).expect("fleet store");
    let counter = store
        .new_counter(CounterKey::new("overflow-counter").expect("counter key"))
        .expect("new counter");

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
    store
        .migrate_schema(&test_database.paranoid_pool)
        .await
        .expect("migrate Fleet schema");

    counter
        .set_value(&test_database.paranoid_pool, i64::MAX)
        .await
        .expect("set max value");
    let err = counter
        .add(&test_database.paranoid_pool, 1)
        .await
        .expect_err("overflowing add should fail");
    assert!(
        matches!(err, Error::CounterArithmeticOverflow),
        "error = {err:?}"
    );
    assert_eq!(
        counter
            .fetch_value(&test_database.paranoid_pool)
            .await
            .expect("fetch after overflow"),
        i64::MAX
    );

    counter
        .set_value(&test_database.paranoid_pool, i64::MIN)
        .await
        .expect("set min value");
    let err = counter
        .add(&test_database.paranoid_pool, -1)
        .await
        .expect_err("underflowing add should fail");
    assert!(
        matches!(err, Error::CounterArithmeticOverflow),
        "error = {err:?}"
    );
    assert_eq!(
        counter
            .fetch_value(&test_database.paranoid_pool)
            .await
            .expect("fetch after underflow"),
        i64::MIN
    );

    drop_fleet_test_tables(&test_database.sqlx_pool, &test_database.config).await;
}
