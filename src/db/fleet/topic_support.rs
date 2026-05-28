use super::*;

pub(super) fn validate_subscription_poll_limit(poll_limit: u32) -> Result<(), Error> {
    if poll_limit == 0 || poll_limit > MAX_SUBSCRIPTION_POLL_LIMIT {
        return Err(Error::InvalidSubscriptionPollLimit {
            value: poll_limit,
            max: MAX_SUBSCRIPTION_POLL_LIMIT,
        });
    }
    Ok(())
}

pub(super) fn validate_non_negative_topic_sequence(sequence: i64) -> Result<(), Error> {
    if sequence < 0 {
        return Err(Error::TopicSequenceMustBeNonNegative);
    }
    Ok(())
}

pub(super) fn topic_sequence_key_suffix(sequence: i64) -> Result<String, Error> {
    validate_non_negative_topic_sequence(sequence)?;
    Ok(format!("{sequence:020}"))
}

pub(super) fn parse_topic_sequence_key_suffix(key_suffix: &str) -> Result<i64, Error> {
    if key_suffix.len() != 20 || !key_suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::InvalidTopicEventSequenceSuffix {
            key_suffix: key_suffix.to_owned(),
        });
    }
    key_suffix
        .parse::<i64>()
        .map_err(|_| Error::InvalidTopicEventSequenceSuffix {
            key_suffix: key_suffix.to_owned(),
        })
}

pub(super) fn scanned_topic_events_to_public_events<T>(
    rows: Vec<KvItemScannedValue<TopicEventEnvelope<T>>>,
) -> Result<Vec<TopicEvent<T>>, Error> {
    rows.into_iter()
        .map(|row| {
            let sequence = parse_topic_sequence_key_suffix(&row.key_suffix)?;
            Ok(TopicEvent {
                sequence,
                published_at_unix_microseconds: row.value.published_at_unix_microseconds,
                data: row.value.data,
            })
        })
        .collect()
}

pub(super) fn normalize_subscription_poll_interval(poll_interval: Duration) -> Duration {
    poll_interval.max(MIN_SUBSCRIPTION_POLL_INTERVAL)
}

#[allow(clippy::result_large_err)]
pub(super) fn subscription_poll_error_retry_delay_from_policy<E, OnPollError>(
    error: Error,
    on_poll_error: &mut OnPollError,
) -> Result<Duration, SubscriptionRunError<E>>
where
    OnPollError: FnMut(&Error) -> SubscriptionPollErrorAction,
    E: std::error::Error + Send + Sync + 'static,
{
    if !is_retryable_subscription_poll_error(&error) {
        return Err(SubscriptionRunError::Fleet(error));
    }
    match on_poll_error(&error) {
        SubscriptionPollErrorAction::ContinueAfter(retry_delay) => {
            Ok(normalize_subscription_poll_interval(retry_delay))
        }
        SubscriptionPollErrorAction::Stop => Err(SubscriptionRunError::Fleet(error)),
    }
}

pub(super) fn is_retryable_subscription_poll_error(error: &Error) -> bool {
    match error {
        Error::Database(source) | Error::Coordination(CoordinationError::Database(source)) => {
            is_retryable_database_operation_error(source)
        }
        Error::Kv(KvError::Database(source)) => is_retryable_database_operation_error(source),
        _ => false,
    }
}

#[allow(clippy::result_large_err)]
pub(super) fn combine_subscription_run_and_polling_guard_release_results<E>(
    run_result: Result<(), SubscriptionRunError<E>>,
    release_result: Result<bool, Error>,
) -> Result<(), SubscriptionRunError<E>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    match (run_result, release_result) {
        (Ok(()), Ok(true)) => Ok(()),
        (Ok(()), Ok(false)) => Err(SubscriptionRunError::PollingGuardLost),
        (Ok(()), Err(source)) => Err(SubscriptionRunError::PollingGuardRelease { source }),
        (Err(SubscriptionRunError::Handler { source }), Ok(false)) => {
            Err(SubscriptionRunError::HandlerAndPollingGuardLost { source })
        }
        (Err(SubscriptionRunError::Handler { source }), Err(release_error)) => {
            Err(SubscriptionRunError::HandlerAndPollingGuardRelease {
                source,
                release_error,
            })
        }
        (Err(SubscriptionRunError::Fleet(source)), Ok(false)) => {
            Err(SubscriptionRunError::FleetAndPollingGuardLost { source })
        }
        (Err(SubscriptionRunError::Fleet(source)), Err(release_error)) => {
            Err(SubscriptionRunError::FleetAndPollingGuardRelease {
                source,
                release_error,
            })
        }
        (Err(SubscriptionRunError::PollingGuardLost), Err(release_error)) => {
            Err(SubscriptionRunError::PollingGuardLostAndRelease { release_error })
        }
        (Err(error), Ok(_)) => Err(error),
        (Err(error), Err(_)) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_poll_interval_is_never_below_minimum() {
        assert_eq!(
            normalize_subscription_poll_interval(Duration::ZERO),
            MIN_SUBSCRIPTION_POLL_INTERVAL
        );
        assert_eq!(
            normalize_subscription_poll_interval(MIN_SUBSCRIPTION_POLL_INTERVAL / 2),
            MIN_SUBSCRIPTION_POLL_INTERVAL
        );
        assert_eq!(
            normalize_subscription_poll_interval(MIN_SUBSCRIPTION_POLL_INTERVAL),
            MIN_SUBSCRIPTION_POLL_INTERVAL
        );

        let above_minimum = MIN_SUBSCRIPTION_POLL_INTERVAL + Duration::from_millis(1);
        assert_eq!(
            normalize_subscription_poll_interval(above_minimum),
            above_minimum
        );
    }
}
