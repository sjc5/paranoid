use super::{ComponentSchemaVersion, DbError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecordedComponentSchemaVersion {
    pub(crate) version: i32,
    pub(crate) fingerprint: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ComponentSchemaMigrationTarget<'a> {
    pub(crate) version: i32,
    pub(crate) fingerprint: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ComponentSchemaMigrationStep<'a> {
    pub(crate) from: ComponentSchemaMigrationTarget<'a>,
    pub(crate) to: ComponentSchemaMigrationTarget<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ComponentSchemaMigrationPlan<'a> {
    FreshInstall,
    AlreadyCurrent,
    Upgrade {
        from: RecordedComponentSchemaVersion,
        steps: Vec<ComponentSchemaMigrationStep<'a>>,
    },
}

impl<'a> ComponentSchemaMigrationTarget<'a> {
    pub(crate) const fn new(version: i32, fingerprint: &'a str) -> Self {
        Self {
            version,
            fingerprint,
        }
    }
}

impl<'a> ComponentSchemaMigrationStep<'a> {
    #[cfg(test)]
    pub(crate) const fn new(
        from: ComponentSchemaMigrationTarget<'a>,
        to: ComponentSchemaMigrationTarget<'a>,
    ) -> Self {
        Self { from, to }
    }
}

impl<'a> From<ComponentSchemaVersion<'a>> for ComponentSchemaMigrationTarget<'a> {
    fn from(version: ComponentSchemaVersion<'a>) -> Self {
        Self::new(version.version, version.fingerprint)
    }
}

pub(crate) fn plan_component_schema_migration<'a>(
    component_schema_version: ComponentSchemaVersion<'_>,
    recorded: Option<RecordedComponentSchemaVersion>,
    upgrade_steps: &'a [ComponentSchemaMigrationStep<'a>],
) -> Result<ComponentSchemaMigrationPlan<'a>, DbError> {
    let current = ComponentSchemaMigrationTarget::from(component_schema_version);
    validate_migration_target(
        component_schema_version.component,
        component_schema_version.instance_key,
        "current target",
        current,
    )?;
    validate_upgrade_steps(
        component_schema_version.component,
        component_schema_version.instance_key,
        current,
        upgrade_steps,
    )?;

    let Some(recorded) = recorded else {
        return Ok(ComponentSchemaMigrationPlan::FreshInstall);
    };

    if recorded.version == current.version {
        if recorded.fingerprint == current.fingerprint {
            return Ok(ComponentSchemaMigrationPlan::AlreadyCurrent);
        }
        return Err(DbError::schema_mismatch(format!(
            "schema ledger row for component {:?} instance {:?} recorded fingerprint {:?}, expected {:?}",
            component_schema_version.component,
            component_schema_version.instance_key,
            recorded.fingerprint,
            current.fingerprint
        )));
    }

    if recorded.version > current.version {
        return Err(DbError::schema_mismatch(format!(
            "schema ledger row for component {:?} instance {:?} recorded version {}, which is newer than supported version {}",
            component_schema_version.component,
            component_schema_version.instance_key,
            recorded.version,
            current.version
        )));
    }

    let mut selected_steps = Vec::new();
    let mut cursor_version = recorded.version;
    let mut cursor_fingerprint = recorded.fingerprint.as_str();

    loop {
        let matching_steps = upgrade_steps
            .iter()
            .copied()
            .filter(|step| {
                step.from.version == cursor_version && step.from.fingerprint == cursor_fingerprint
            })
            .collect::<Vec<_>>();
        let [step] = matching_steps.as_slice() else {
            let reason = if matching_steps.is_empty() {
                format!(
                    "schema ledger row for component {:?} instance {:?} recorded unsupported version {} fingerprint {:?}; no migration step reaches supported version {} fingerprint {:?}",
                    component_schema_version.component,
                    component_schema_version.instance_key,
                    cursor_version,
                    cursor_fingerprint,
                    current.version,
                    current.fingerprint
                )
            } else {
                format!(
                    "schema migration chain for component {:?} instance {:?} has multiple steps from version {} fingerprint {:?}",
                    component_schema_version.component,
                    component_schema_version.instance_key,
                    cursor_version,
                    cursor_fingerprint
                )
            };
            return Err(DbError::schema_mismatch(reason));
        };

        selected_steps.push(*step);
        if step.to.version == current.version && step.to.fingerprint == current.fingerprint {
            return Ok(ComponentSchemaMigrationPlan::Upgrade {
                from: recorded,
                steps: selected_steps,
            });
        }

        if step.to.version >= current.version {
            return Err(DbError::schema_mismatch(format!(
                "schema migration chain for component {:?} instance {:?} reached version {} fingerprint {:?}, not supported version {} fingerprint {:?}",
                component_schema_version.component,
                component_schema_version.instance_key,
                step.to.version,
                step.to.fingerprint,
                current.version,
                current.fingerprint
            )));
        }

        cursor_version = step.to.version;
        cursor_fingerprint = step.to.fingerprint;
    }
}

fn validate_upgrade_steps(
    component: &str,
    instance_key: &str,
    current: ComponentSchemaMigrationTarget<'_>,
    upgrade_steps: &[ComponentSchemaMigrationStep<'_>],
) -> Result<(), DbError> {
    for step in upgrade_steps {
        validate_migration_target(component, instance_key, "step source", step.from)?;
        validate_migration_target(component, instance_key, "step target", step.to)?;
        if step.to.version <= step.from.version {
            return Err(DbError::schema_mismatch(format!(
                "schema migration step for component {component:?} instance {instance_key:?} must advance versions, got {} -> {}",
                step.from.version, step.to.version
            )));
        }
        if step.to.version > current.version {
            return Err(DbError::schema_mismatch(format!(
                "schema migration step for component {component:?} instance {instance_key:?} targets future version {}, supported version is {}",
                step.to.version, current.version
            )));
        }
    }
    Ok(())
}

fn validate_migration_target(
    component: &str,
    instance_key: &str,
    label: &str,
    target: ComponentSchemaMigrationTarget<'_>,
) -> Result<(), DbError> {
    if target.version <= 0 {
        return Err(DbError::schema_mismatch(format!(
            "schema migration {label} for component {component:?} instance {instance_key:?} must have a positive version, got {}",
            target.version
        )));
    }
    if target.fingerprint.is_empty() {
        return Err(DbError::schema_mismatch(format!(
            "schema migration {label} for component {component:?} instance {instance_key:?} must have a non-empty fingerprint"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPONENT: &str = "test";
    const INSTANCE: &str = "table=test";

    fn current() -> ComponentSchemaVersion<'static> {
        ComponentSchemaVersion {
            component: COMPONENT,
            instance_key: INSTANCE,
            version: 3,
            fingerprint: "current",
        }
    }

    fn recorded(version: i32, fingerprint: &str) -> RecordedComponentSchemaVersion {
        RecordedComponentSchemaVersion {
            version,
            fingerprint: fingerprint.to_owned(),
        }
    }

    #[test]
    fn planner_classifies_missing_ledger_as_fresh_install() {
        assert_eq!(
            plan_component_schema_migration(current(), None, &[]).expect("plan"),
            ComponentSchemaMigrationPlan::FreshInstall
        );
    }

    #[test]
    fn planner_classifies_matching_ledger_as_current() {
        assert_eq!(
            plan_component_schema_migration(current(), Some(recorded(3, "current")), &[])
                .expect("plan"),
            ComponentSchemaMigrationPlan::AlreadyCurrent
        );
    }

    #[test]
    fn planner_rejects_same_version_with_different_fingerprint() {
        let err = plan_component_schema_migration(current(), Some(recorded(3, "other")), &[])
            .expect_err("conflicting fingerprint");
        assert!(
            err.to_string().contains("recorded fingerprint"),
            "error = {err:?}"
        );
    }

    #[test]
    fn planner_rejects_future_recorded_version() {
        let err = plan_component_schema_migration(current(), Some(recorded(4, "future")), &[])
            .expect_err("future version");
        assert!(
            err.to_string().contains("newer than supported"),
            "error = {err:?}"
        );
    }

    #[test]
    fn planner_rejects_older_version_without_supported_step() {
        let err = plan_component_schema_migration(current(), Some(recorded(1, "old")), &[])
            .expect_err("unsupported stale version");
        assert!(
            err.to_string().contains("unsupported version"),
            "error = {err:?}"
        );
    }

    #[test]
    fn planner_builds_ordered_upgrade_chain() {
        let steps = [
            ComponentSchemaMigrationStep::new(
                ComponentSchemaMigrationTarget::new(1, "v1"),
                ComponentSchemaMigrationTarget::new(2, "v2"),
            ),
            ComponentSchemaMigrationStep::new(
                ComponentSchemaMigrationTarget::new(2, "v2"),
                ComponentSchemaMigrationTarget::new(3, "current"),
            ),
        ];

        assert_eq!(
            plan_component_schema_migration(current(), Some(recorded(1, "v1")), &steps)
                .expect("upgrade plan"),
            ComponentSchemaMigrationPlan::Upgrade {
                from: recorded(1, "v1"),
                steps: steps.to_vec(),
            }
        );
    }

    #[test]
    fn planner_rejects_chain_that_reaches_wrong_current_fingerprint() {
        let steps = [ComponentSchemaMigrationStep::new(
            ComponentSchemaMigrationTarget::new(1, "v1"),
            ComponentSchemaMigrationTarget::new(3, "wrong"),
        )];

        let err = plan_component_schema_migration(current(), Some(recorded(1, "v1")), &steps)
            .expect_err("wrong final fingerprint");
        assert!(
            err.to_string().contains("not supported version"),
            "error = {err:?}"
        );
    }
}
