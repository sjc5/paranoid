use std::time::Duration;

pub(crate) fn random_unit_f64_from_system() -> Result<f64, String> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(|error| error.to_string())?;
    let mantissa = u64::from_le_bytes(bytes) >> 11;
    Ok((mantissa as f64) * (1.0 / ((1_u64 << 53) as f64)))
}

pub(crate) fn duration_from_nonnegative_f64_seconds(
    seconds: f64,
    max_duration: Option<Duration>,
) -> Duration {
    let bounded_seconds = if let Some(max_duration) = max_duration
        && !max_duration.is_zero()
        && !seconds.is_nan()
        && seconds > max_duration.as_secs_f64()
    {
        max_duration.as_secs_f64()
    } else {
        seconds
    };
    if bounded_seconds.is_nan() || bounded_seconds <= 0.0 {
        return Duration::ZERO;
    }
    if bounded_seconds.is_infinite() || bounded_seconds >= Duration::MAX.as_secs_f64() {
        return Duration::MAX;
    }
    Duration::from_secs_f64(bounded_seconds)
}
