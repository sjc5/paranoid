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

#[test]
fn config_rejects_out_of_band_replacement_cooldown_that_cannot_bound_identifier_lockout() {
    let cases = [
        {
            let mut config = config();
            config.out_of_band_challenge_replacement_cooldown = DurationSeconds::new(0);
            (
                "zero out-of-band replacement cooldown",
                config,
                Error::InvalidConfig("out_of_band_challenge_replacement_cooldown must be non-zero"),
            )
        },
        {
            let mut config = config();
            config.out_of_band_challenge_replacement_cooldown =
                config.out_of_band_challenge_lifetime;
            (
                "out-of-band replacement cooldown reaches challenge lifetime",
                config,
                Error::InvalidConfig(
                    "out_of_band_challenge_replacement_cooldown must be shorter than out_of_band_challenge_lifetime",
                ),
            )
        },
    ];

    for (label, config, expected_error) in cases {
        assert_eq!(config.validate(), Err(expected_error), "{label}");
    }
}

#[test]
fn config_rejects_delayed_lifecycle_timing_that_cannot_mature_before_expiry() {
    let cases = [
        {
            let mut config = config();
            config
                .credential_lifecycle_policy
                .credential_reset
                .ordinary_credential
                .delayed_action_timing = Some(DelayedLifecycleActionTimingPolicy {
                delay: DurationSeconds::new(0),
                expires_after: DurationSeconds::new(10),
            });
            (
                "zero credential-reset delay",
                config,
                Error::InvalidConfig("delayed lifecycle action delay must be non-zero"),
            )
        },
        {
            let mut config = config();
            config
                .credential_lifecycle_policy
                .credential_reset
                .ordinary_credential
                .delayed_action_timing = Some(DelayedLifecycleActionTimingPolicy {
                delay: DurationSeconds::new(10),
                expires_after: DurationSeconds::new(10),
            });
            (
                "credential-reset expiry at maturity",
                config,
                Error::InvalidConfig("delayed lifecycle action expiry must be after maturity"),
            )
        },
        {
            let mut config = config();
            config
                .credential_lifecycle_policy
                .credential_reset
                .second_factor_credential
                .delayed_action_timing = Some(DelayedLifecycleActionTimingPolicy {
                delay: DurationSeconds::new(0),
                expires_after: DurationSeconds::new(10),
            });
            (
                "zero second-factor credential-reset delay",
                config,
                Error::InvalidConfig("delayed lifecycle action delay must be non-zero"),
            )
        },
        {
            let mut config = config();
            config
                .credential_lifecycle_policy
                .subject_auth_state_deletion
                .delayed_action_timing = DelayedLifecycleActionTimingPolicy {
                delay: DurationSeconds::new(20),
                expires_after: DurationSeconds::new(10),
            };
            (
                "subject deletion expiry before maturity",
                config,
                Error::InvalidConfig("delayed lifecycle action expiry must be after maturity"),
            )
        },
        {
            let mut config = config();
            config
                .credential_lifecycle_policy
                .admin_support_intervention
                .delayed_action_timing = Some(DelayedLifecycleActionTimingPolicy {
                delay: DurationSeconds::new(20),
                expires_after: DurationSeconds::new(10),
            });
            (
                "admin support expiry before maturity",
                config,
                Error::InvalidConfig("delayed lifecycle action expiry must be after maturity"),
            )
        },
    ];

    for (label, config, expected_error) in cases {
        assert_eq!(config.validate(), Err(expected_error), "{label}");
    }
}

#[test]
fn config_rejects_invalid_admin_support_intervention_policy() {
    let cases = [
        {
            let mut config = config();
            config
                .credential_lifecycle_policy
                .admin_support_intervention
                .intervention_lifetime = DurationSeconds::new(0);
            (
                "zero admin support lifetime",
                config,
                Error::InvalidConfig("admin support intervention lifetime must be non-zero"),
            )
        },
        {
            let mut config = config();
            config
                .credential_lifecycle_policy
                .admin_support_intervention
                .effective_recovery_authority_ids = Vec::new();
            (
                "empty admin support authorities",
                config,
                Error::InvalidConfig("admin support intervention authorities must be non-empty"),
            )
        },
        {
            let mut config = config();
            config
                .credential_lifecycle_policy
                .admin_support_intervention
                .effective_recovery_authority_ids =
                vec![id("support-authority"), id("support-authority")];
            (
                "duplicate admin support authorities",
                config,
                Error::InvalidConfig(
                    "admin support intervention authorities must not contain duplicates",
                ),
            )
        },
    ];

    for (label, config, expected_error) in cases {
        assert_eq!(config.validate(), Err(expected_error), "{label}");
    }
}
