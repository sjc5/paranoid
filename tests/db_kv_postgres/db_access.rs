use super::*;

#[tokio::test]
async fn paranoid_pool_exposes_sqlx_pool_and_transaction_for_app_owned_queries() {
    let Some(test_database) = TestDatabase::connect().await else {
        return;
    };

    let app_table_name = unique_test_table_name();
    drop_test_table(test_database.paranoid_pool.sqlx_pool(), &app_table_name).await;

    db_unparameterized_simple_query(sqlx::AssertSqlSafe(format!(
        r#"CREATE TABLE {} (id TEXT COLLATE "C" PRIMARY KEY, value TEXT COLLATE "C" NOT NULL)"#,
        app_table_name.quoted()
    )))
    .execute(test_database.paranoid_pool.sqlx_pool())
    .await
    .expect("create app-owned table through exposed SQLx pool");

    let mut commit_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin app transaction");
    db_query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO {} (id, value) VALUES ($1, $2)",
        app_table_name.quoted()
    )))
    .bind("committed")
    .bind("visible after commit")
    .execute(commit_tx.sqlx_transaction().as_mut())
    .await
    .expect("insert app row through exposed SQLx transaction");
    commit_tx.commit().await.expect("commit app transaction");

    let mut read_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin read transaction");
    let committed_value = db_query_scalar::<String>(sqlx::AssertSqlSafe(format!(
        "SELECT value FROM {} WHERE id = $1",
        app_table_name.quoted()
    )))
    .bind("committed")
    .fetch_one(read_tx.sqlx_transaction().as_mut())
    .await
    .expect("fetch committed app row through exposed SQLx transaction");
    read_tx.commit().await.expect("commit read transaction");
    assert_eq!(committed_value, "visible after commit");

    let mut rollback_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin rollback transaction");
    db_query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO {} (id, value) VALUES ($1, $2)",
        app_table_name.quoted()
    )))
    .bind("rolled-back")
    .bind("not visible")
    .execute(rollback_tx.sqlx_transaction().as_mut())
    .await
    .expect("insert rolled-back app row through exposed SQLx transaction");
    rollback_tx
        .rollback()
        .await
        .expect("rollback app transaction");

    let mut count_tx = test_database
        .paranoid_pool
        .begin_transaction()
        .await
        .expect("begin count transaction");
    let rolled_back_count = db_query_scalar::<i64>(sqlx::AssertSqlSafe(format!(
        "SELECT COUNT(*) FROM {} WHERE id = $1",
        app_table_name.quoted()
    )))
    .bind("rolled-back")
    .fetch_one(count_tx.sqlx_transaction().as_mut())
    .await
    .expect("count rolled-back app row through exposed SQLx transaction");
    count_tx.commit().await.expect("commit count transaction");
    assert_eq!(rolled_back_count, 0);

    drop_test_table(test_database.paranoid_pool.sqlx_pool(), &app_table_name).await;
}
