use super::*;

pub(super) fn default_heartbeat_cron_config(key: &str) -> CronConfig {
    CronConfig {
        key: CronKey::new(key).expect("cron key"),
        interval: MIN_CRON_INTERVAL,
        claim_duration: None,
        heartbeat_interval: None,
        acquire_retry_interval: Some(Duration::from_millis(25)),
        max_consecutive_renewal_failures: None,
    }
}
