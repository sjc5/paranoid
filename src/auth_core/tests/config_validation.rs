use super::*;

#[test]
fn config_rejects_stale_secret_grace_that_is_not_a_bounded_race_window() {
    let cases = [
        {
            let mut config = config();
            config.stale_secret_grace_lifetime = DurationSeconds::new(0);
            (
                "zero stale-secret grace",
                config,
                Error::InvalidConfig("stale_secret_grace_lifetime must be non-zero"),
            )
        },
        {
            let mut config = config();
            config.stale_secret_grace_lifetime = config.session_refresh_window;
            (
                "stale-secret grace reaches session refresh window",
                config,
                Error::InvalidConfig(
                    "stale_secret_grace_lifetime must be shorter than session_refresh_window",
                ),
            )
        },
        {
            let mut config = config();
            config.trusted_device_credential_lifetime = DurationSeconds::new(5);
            config.stale_secret_grace_lifetime = DurationSeconds::new(5);
            (
                "stale-secret grace reaches trusted-device credential lifetime",
                config,
                Error::InvalidConfig(
                    "stale_secret_grace_lifetime must be shorter than trusted_device_credential_lifetime",
                ),
            )
        },
    ];

    for (label, config, expected_error) in cases {
        assert_eq!(config.validate(), Err(expected_error), "{label}");
    }
}
