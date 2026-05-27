use super::super::*;
use super::*;

#[derive(Debug)]
pub(in crate::db::queue) struct SqlCatalog {
    config: StoreConfig,
    batch_enqueue_queries_by_size: RwLock<HashMap<usize, Arc<str>>>,
    move_failed_jobs_to_dead_letter_batch_queries_by_size: RwLock<HashMap<usize, Arc<str>>>,
    single_enqueue_query: Arc<str>,
    dedupe_enqueue_query: Arc<str>,
    select_job_by_id_query: Arc<str>,
    fetch_status_counts_query: Arc<str>,
    fetch_job_count_by_status_query: Arc<str>,
    fetch_worker_pressure_counts_query: Arc<str>,
    fetch_pause_entries_query: Arc<str>,
    fetch_pending_or_running_task_names_query: Arc<str>,
    upsert_pause_key_query: Arc<str>,
    delete_pause_key_query: Arc<str>,
    pause_key_exists_query: Arc<str>,
    claim_available_jobs_query: Arc<str>,
    mark_job_started_query: Arc<str>,
    mark_job_completed_query: Arc<str>,
    touch_execution_heartbeat_query: Arc<str>,
    mark_job_failed_query: Arc<str>,
    schedule_owned_running_job_retry_query: Arc<str>,
    move_owned_running_job_to_dead_letter_query: Arc<str>,
    return_owned_unstarted_running_job_to_pending_query: Arc<str>,
    return_owned_started_running_job_to_pending_query: Arc<str>,
    return_available_owned_unstarted_running_jobs_to_pending_query: Arc<str>,
    return_available_owned_started_running_jobs_to_pending_query: Arc<str>,
    cancel_pending_job_query: Arc<str>,
    retry_failed_job_by_id_query: Arc<str>,
    retry_available_failed_jobs_query: Arc<str>,
    force_requeue_running_job_by_id_query: Arc<str>,
    move_failed_job_to_dead_letter_query: Arc<str>,
    list_jobs_query: Arc<str>,
    list_dead_letter_jobs_query: Arc<str>,
    requeue_dead_letter_job_query: Arc<str>,
    delete_dead_letter_job_query: Arc<str>,
    cleanup_jobs_older_than_once_query: Arc<str>,
    cleanup_available_dead_letter_jobs_older_than_once_query: Arc<str>,
    reclaim_never_started_running_jobs_query: Arc<str>,
    reclaim_expired_running_jobs_to_failed_query: Arc<str>,
    reclaim_expired_running_jobs_to_pending_for_retry_query: Arc<str>,
}

impl SqlCatalog {
    pub(in crate::db::queue) fn new(config: &StoreConfig) -> Self {
        Self {
            config: config.clone(),
            batch_enqueue_queries_by_size: RwLock::new(HashMap::new()),
            move_failed_jobs_to_dead_letter_batch_queries_by_size: RwLock::new(HashMap::new()),
            single_enqueue_query: query_arc(build_single_enqueue_query(config)),
            dedupe_enqueue_query: query_arc(build_dedupe_enqueue_query(config)),
            select_job_by_id_query: query_arc(build_select_job_by_id_query(config)),
            fetch_status_counts_query: query_arc(build_fetch_status_counts_query(config)),
            fetch_job_count_by_status_query: query_arc(build_fetch_job_count_by_status_query(
                config,
            )),
            fetch_worker_pressure_counts_query: query_arc(
                build_fetch_worker_pressure_counts_query(config),
            ),
            fetch_pause_entries_query: query_arc(build_fetch_pause_entries_query(config)),
            fetch_pending_or_running_task_names_query: query_arc(
                build_fetch_pending_or_running_task_names_query(config),
            ),
            upsert_pause_key_query: query_arc(build_upsert_pause_key_query(config)),
            delete_pause_key_query: query_arc(build_delete_pause_key_query(config)),
            pause_key_exists_query: query_arc(build_pause_key_exists_query(config)),
            claim_available_jobs_query: query_arc(build_claim_available_jobs_query(config)),
            mark_job_started_query: query_arc(build_mark_job_started_query(config)),
            mark_job_completed_query: query_arc(build_mark_job_completed_query(config)),
            touch_execution_heartbeat_query: query_arc(build_touch_execution_heartbeat_query(
                config,
            )),
            mark_job_failed_query: query_arc(build_mark_job_failed_query(config)),
            schedule_owned_running_job_retry_query: query_arc(
                build_schedule_owned_running_job_retry_query(config),
            ),
            move_owned_running_job_to_dead_letter_query: query_arc(
                build_move_owned_running_job_to_dead_letter_query(config),
            ),
            return_owned_unstarted_running_job_to_pending_query: query_arc(
                build_return_owned_unstarted_running_job_to_pending_query(config),
            ),
            return_owned_started_running_job_to_pending_query: query_arc(
                build_return_owned_started_running_job_to_pending_query(config),
            ),
            return_available_owned_unstarted_running_jobs_to_pending_query: query_arc(
                build_return_available_owned_unstarted_running_jobs_to_pending_query(config),
            ),
            return_available_owned_started_running_jobs_to_pending_query: query_arc(
                build_return_available_owned_started_running_jobs_to_pending_query(config),
            ),
            cancel_pending_job_query: query_arc(build_cancel_pending_job_query(config)),
            retry_failed_job_by_id_query: query_arc(build_retry_failed_job_by_id_query(config)),
            retry_available_failed_jobs_query: query_arc(build_retry_available_failed_jobs_query(
                config,
            )),
            force_requeue_running_job_by_id_query: query_arc(
                build_force_requeue_running_job_by_id_query(config),
            ),
            move_failed_job_to_dead_letter_query: query_arc(
                build_move_failed_job_to_dead_letter_query(config),
            ),
            list_jobs_query: query_arc(build_list_jobs_query(config)),
            list_dead_letter_jobs_query: query_arc(build_list_dead_letter_jobs_query(config)),
            requeue_dead_letter_job_query: query_arc(build_requeue_dead_letter_job_query(config)),
            delete_dead_letter_job_query: query_arc(build_delete_dead_letter_job_query(config)),
            cleanup_jobs_older_than_once_query: query_arc(
                build_cleanup_jobs_older_than_once_query(config),
            ),
            cleanup_available_dead_letter_jobs_older_than_once_query: query_arc(
                build_cleanup_available_dead_letter_jobs_older_than_once_query(config),
            ),
            reclaim_never_started_running_jobs_query: query_arc(
                build_reclaim_never_started_running_jobs_query(config),
            ),
            reclaim_expired_running_jobs_to_failed_query: query_arc(
                build_reclaim_expired_running_jobs_to_failed_query(config),
            ),
            reclaim_expired_running_jobs_to_pending_for_retry_query: query_arc(
                build_reclaim_expired_running_jobs_to_pending_for_retry_query(config),
            ),
        }
    }

    pub(in crate::db::queue) fn config(&self) -> &StoreConfig {
        &self.config
    }

    pub(in crate::db::queue) fn batch_enqueue_query(&self, batch_size: usize) -> Arc<str> {
        self.cached_query(
            &self.batch_enqueue_queries_by_size,
            batch_size,
            build_batch_enqueue_query,
        )
    }

    pub(in crate::db::queue) fn move_failed_jobs_to_dead_letter_batch_query(
        &self,
        job_count: usize,
    ) -> Arc<str> {
        self.cached_query(
            &self.move_failed_jobs_to_dead_letter_batch_queries_by_size,
            job_count,
            build_move_failed_jobs_to_dead_letter_batch_query,
        )
    }

    fn cached_query(
        &self,
        cache: &RwLock<HashMap<usize, Arc<str>>>,
        key: usize,
        build: fn(&StoreConfig, usize) -> String,
    ) -> Arc<str> {
        {
            let guard = cache
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(query) = guard.get(&key) {
                return Arc::clone(query);
            }
        }

        let built_query = query_arc(build(&self.config, key));
        let mut guard = cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(guard.entry(key).or_insert_with(|| built_query))
    }

    pub(in crate::db::queue) fn single_enqueue_query(&self) -> &str {
        &self.single_enqueue_query
    }

    pub(in crate::db::queue) fn dedupe_enqueue_query(&self) -> &str {
        &self.dedupe_enqueue_query
    }

    pub(in crate::db::queue) fn select_job_by_id_query(&self) -> &str {
        &self.select_job_by_id_query
    }

    pub(in crate::db::queue) fn fetch_status_counts_query(&self) -> &str {
        &self.fetch_status_counts_query
    }

    pub(in crate::db::queue) fn fetch_job_count_by_status_query(&self) -> &str {
        &self.fetch_job_count_by_status_query
    }

    pub(in crate::db::queue) fn fetch_worker_pressure_counts_query(&self) -> &str {
        &self.fetch_worker_pressure_counts_query
    }

    pub(in crate::db::queue) fn fetch_pause_entries_query(&self) -> &str {
        &self.fetch_pause_entries_query
    }

    pub(in crate::db::queue) fn fetch_pending_or_running_task_names_query(&self) -> &str {
        &self.fetch_pending_or_running_task_names_query
    }

    pub(in crate::db::queue) fn upsert_pause_key_query(&self) -> &str {
        &self.upsert_pause_key_query
    }

    pub(in crate::db::queue) fn delete_pause_key_query(&self) -> &str {
        &self.delete_pause_key_query
    }

    pub(in crate::db::queue) fn pause_key_exists_query(&self) -> &str {
        &self.pause_key_exists_query
    }

    pub(in crate::db::queue) fn claim_available_jobs_query(&self) -> &str {
        &self.claim_available_jobs_query
    }

    pub(in crate::db::queue) fn mark_job_started_query(&self) -> &str {
        &self.mark_job_started_query
    }

    pub(in crate::db::queue) fn mark_job_completed_query(&self) -> &str {
        &self.mark_job_completed_query
    }

    pub(in crate::db::queue) fn touch_execution_heartbeat_query(&self) -> &str {
        &self.touch_execution_heartbeat_query
    }

    pub(in crate::db::queue) fn mark_job_failed_query(&self) -> &str {
        &self.mark_job_failed_query
    }

    pub(in crate::db::queue) fn schedule_owned_running_job_retry_query(&self) -> &str {
        &self.schedule_owned_running_job_retry_query
    }

    pub(in crate::db::queue) fn move_owned_running_job_to_dead_letter_query(&self) -> &str {
        &self.move_owned_running_job_to_dead_letter_query
    }

    pub(in crate::db::queue) fn return_owned_unstarted_running_job_to_pending_query(&self) -> &str {
        &self.return_owned_unstarted_running_job_to_pending_query
    }

    pub(in crate::db::queue) fn return_owned_started_running_job_to_pending_query(&self) -> &str {
        &self.return_owned_started_running_job_to_pending_query
    }

    pub(in crate::db::queue) fn return_available_owned_unstarted_running_jobs_to_pending_query(
        &self,
    ) -> &str {
        &self.return_available_owned_unstarted_running_jobs_to_pending_query
    }

    pub(in crate::db::queue) fn return_available_owned_started_running_jobs_to_pending_query(
        &self,
    ) -> &str {
        &self.return_available_owned_started_running_jobs_to_pending_query
    }

    pub(in crate::db::queue) fn cancel_pending_job_query(&self) -> &str {
        &self.cancel_pending_job_query
    }

    pub(in crate::db::queue) fn retry_failed_job_by_id_query(&self) -> &str {
        &self.retry_failed_job_by_id_query
    }

    pub(in crate::db::queue) fn retry_available_failed_jobs_query(&self) -> &str {
        &self.retry_available_failed_jobs_query
    }

    pub(in crate::db::queue) fn force_requeue_running_job_by_id_query(&self) -> &str {
        &self.force_requeue_running_job_by_id_query
    }

    pub(in crate::db::queue) fn move_failed_job_to_dead_letter_query(&self) -> &str {
        &self.move_failed_job_to_dead_letter_query
    }

    pub(in crate::db::queue) fn list_jobs_query(&self) -> &str {
        &self.list_jobs_query
    }

    pub(in crate::db::queue) fn list_dead_letter_jobs_query(&self) -> &str {
        &self.list_dead_letter_jobs_query
    }

    pub(in crate::db::queue) fn requeue_dead_letter_job_query(&self) -> &str {
        &self.requeue_dead_letter_job_query
    }

    pub(in crate::db::queue) fn delete_dead_letter_job_query(&self) -> &str {
        &self.delete_dead_letter_job_query
    }

    pub(in crate::db::queue) fn cleanup_jobs_older_than_once_query(&self) -> &str {
        &self.cleanup_jobs_older_than_once_query
    }

    pub(in crate::db::queue) fn cleanup_available_dead_letter_jobs_older_than_once_query(
        &self,
    ) -> &str {
        &self.cleanup_available_dead_letter_jobs_older_than_once_query
    }

    pub(in crate::db::queue) fn reclaim_never_started_running_jobs_query(&self) -> &str {
        &self.reclaim_never_started_running_jobs_query
    }

    pub(in crate::db::queue) fn reclaim_expired_running_jobs_to_failed_query(&self) -> &str {
        &self.reclaim_expired_running_jobs_to_failed_query
    }

    pub(in crate::db::queue) fn reclaim_expired_running_jobs_to_pending_for_retry_query(
        &self,
    ) -> &str {
        &self.reclaim_expired_running_jobs_to_pending_for_retry_query
    }
}

fn query_arc(query: String) -> Arc<str> {
    Arc::from(query)
}
