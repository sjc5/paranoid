use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TerminalTextStyle {
    Heading,
    Success,
    Warning,
    Muted,
}

pub(super) trait VaultTerminal {
    fn prompt_hidden_secret(&mut self, prompt: &str) -> Result<SecretBytes, Error>;

    fn select_menu_index(
        &mut self,
        prompt: &str,
        help_message: &str,
        options: &[String],
    ) -> Result<usize, Error>;

    fn write_line(&mut self, line: &str) -> Result<(), Error>;

    fn write_styled_line(&mut self, line: &str, _style: TerminalTextStyle) -> Result<(), Error> {
        self.write_line(line)
    }
}

#[derive(Debug, Default)]
pub(super) struct SystemTerminal;

impl VaultTerminal for SystemTerminal {
    fn prompt_hidden_secret(&mut self, prompt: &str) -> Result<SecretBytes, Error> {
        let mut value = rpassword::prompt_password(prompt).map_err(Error::Io)?;
        let secret = SecretBytes::try_from(value.as_bytes())?;
        value.zeroize();
        Ok(secret)
    }

    fn select_menu_index(
        &mut self,
        prompt: &str,
        help_message: &str,
        options: &[String],
    ) -> Result<usize, Error> {
        if options.is_empty() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vault menu cannot be empty",
            )));
        }
        let selected = inquire::Select::new(prompt, options.to_vec())
            .with_help_message(help_message)
            .with_page_size(options.len().clamp(1, 12))
            .with_render_config(vault_menu_render_config())
            .raw_prompt_skippable()
            .map_err(inquire_error)?;
        Ok(selected.map_or(options.len() - 1, |selected| selected.index))
    }

    fn write_line(&mut self, line: &str) -> Result<(), Error> {
        write_system_terminal_line(line, None)
    }

    fn write_styled_line(&mut self, line: &str, style: TerminalTextStyle) -> Result<(), Error> {
        write_system_terminal_line(line, Some(style))
    }
}

fn write_system_terminal_line(line: &str, style: Option<TerminalTextStyle>) -> Result<(), Error> {
    let should_style =
        style.is_some() && io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    let mut stdout = io::stdout().lock();
    if should_style {
        stdout
            .write_all(terminal_style_start_sequence(style.expect("style is present")).as_bytes())
            .map_err(Error::Io)?;
    }
    stdout.write_all(line.as_bytes()).map_err(Error::Io)?;
    if should_style {
        stdout.write_all(b"\x1b[0m").map_err(Error::Io)?;
    }
    stdout.write_all(b"\n").map_err(Error::Io)?;
    stdout.flush().map_err(Error::Io)
}

fn terminal_style_start_sequence(style: TerminalTextStyle) -> &'static str {
    match style {
        TerminalTextStyle::Heading => "\x1b[36m",
        TerminalTextStyle::Success => "\x1b[32m",
        TerminalTextStyle::Warning => "\x1b[33m",
        TerminalTextStyle::Muted => "\x1b[90m",
    }
}

fn vault_menu_render_config() -> inquire::ui::RenderConfig<'static> {
    let mut render_config = inquire::ui::RenderConfig::default();
    if std::env::var_os("NO_COLOR").is_none() {
        render_config = render_config
            .with_prompt_prefix(inquire::ui::Styled::new("?").with_fg(inquire::ui::Color::DarkCyan))
            .with_answered_prompt_prefix(
                inquire::ui::Styled::new(">").with_fg(inquire::ui::Color::DarkCyan),
            )
            .with_highlighted_option_prefix(
                inquire::ui::Styled::new(">").with_fg(inquire::ui::Color::DarkCyan),
            )
            .with_selected_option(Some(
                inquire::ui::StyleSheet::new().with_fg(inquire::ui::Color::DarkCyan),
            ))
            .with_help_message(inquire::ui::StyleSheet::new().with_fg(inquire::ui::Color::DarkGrey))
            .with_answer(inquire::ui::StyleSheet::new().with_fg(inquire::ui::Color::DarkCyan));
    }
    render_config
}

fn inquire_error(error: inquire::InquireError) -> Error {
    Error::Io(io::Error::other(error))
}
