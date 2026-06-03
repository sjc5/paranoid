use super::*;

pub(super) trait ChildProcessRunner {
    fn run_child_command(
        &mut self,
        command: Vec<OsString>,
        projected_env: BTreeMap<EnvVarName, SecretBytes>,
    ) -> Result<(), Error>;
}

#[derive(Debug, Default)]
pub(super) struct SystemChildProcessRunner;

impl ChildProcessRunner for SystemChildProcessRunner {
    fn run_child_command(
        &mut self,
        command: Vec<OsString>,
        projected_env: BTreeMap<EnvVarName, SecretBytes>,
    ) -> Result<(), Error> {
        let status = spawn_with_projected_env(command, projected_env)?;
        if status.success() {
            Ok(())
        } else {
            Err(Error::ChildCommandFailed { status })
        }
    }
}

pub(super) fn spawn_with_projected_env(
    command: Vec<OsString>,
    projected: BTreeMap<EnvVarName, SecretBytes>,
) -> Result<ExitStatus, Error> {
    let mut child = build_child_command_with_projected_env(command, projected)?;
    child.status().map_err(Error::Io)
}

pub(super) fn build_child_command_with_projected_env(
    command: Vec<OsString>,
    projected: BTreeMap<EnvVarName, SecretBytes>,
) -> Result<Command, Error> {
    let mut command_iter = command.into_iter();
    let program = command_iter.next().ok_or(Error::MissingChildCommand)?;
    let mut child = Command::new(program);
    child.args(command_iter);

    for (name, value) in projected {
        let mut value_text = String::from_utf8(value.expose_secret().to_vec())
            .map_err(|_| Error::SecretValueNotUtf8 { name: name.clone() })?;
        child.env(name.as_str(), value_text.as_str());
        value_text.zeroize();
    }

    Ok(child)
}
