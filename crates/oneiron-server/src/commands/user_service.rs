//! `oneiron user-service`: the optional user service of ARCH-0028
//! `#plugin-first-run` step 4. It keeps the local vault the hook would start
//! running between sessions and after login, through the person's own
//! supervisor, so step 2 finds it running in every later session. It is a
//! setup step the person runs (canon: "The setup steps live in the skill or
//! the MCP doc"); a hook never installs it. It mints nothing and reads no
//! grant: it manages this user's own process on this user's own machine.
//!
//! - `install` writes the unit and starts it: on Linux the systemd user unit
//!   `oneiron.service`, rendered from the shipped `deploy/systemd/oneiron.service`;
//!   on macOS the launchd agent `com.oneiron.server`, with the shipped
//!   agent's label, `RunAtLoad`, `KeepAlive` and log files, and no
//!   `Sockets`: the server binds its configured address itself. Either runs
//!   the `serve` the hook's step 4 runs ([`local_servers::local_serve_args`]).
//!   Every unit it writes carries [`MARKER`]; it never overwrites a file
//!   without it, and it refuses a first install while a server it did not
//!   start already runs the vault, so the vault keeps one writer.
//! - `remove` stops the service and deletes the unit `install` wrote.
//! - `status` prints whether it is installed.
//!
//! The hook's step 4 starts an installed service ([`installed`]) instead of
//! a `serve` of its own.

use std::ffi::OsString;
use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use serde_json::json;

use super::local_servers;
use crate::cli::{UserServiceCommand, UserServiceInstallArgs};
use crate::config::ServeArgs;

/// The line every unit `install` writes carries. A file without it is not
/// this command's, and it neither rewrites nor deletes one.
const MARKER: &str = "Written by oneiron user-service install.";
/// The systemd user unit, named as the shipped template is.
const SYSTEMD_UNIT: &str = "oneiron.service";
/// The launchd agent's label, as the shipped agent names it.
const LAUNCHD_LABEL: &str = "com.oneiron.server";
const SYSTEMD_TEMPLATE: &str = include_str!("../../../../deploy/systemd/oneiron.service");
/// A unit is a few kilobytes; a larger file is not read.
const MAX_UNIT_BYTES: u64 = 64 * 1024;
const NO_VAULT: &str = "no initialized vault for the service to run; set one up with `oneiron \
                        init <vault folder>` first";

/// The person's own service manager.
#[derive(Clone, Copy)]
enum Supervisor {
    /// The systemd user manager, through `systemctl --user`.
    Systemd,
    /// launchd's per-user domain, through `launchctl`.
    Launchd,
}

const SUPERVISOR: Supervisor = if cfg!(target_os = "macos") {
    Supervisor::Launchd
} else {
    Supervisor::Systemd
};

/// What sits at the unit's path.
enum UnitFile {
    Absent,
    /// A unit `install` wrote.
    Ours,
    /// Anything else: a hand-installed unit, a link, another user's file.
    Foreign,
}

pub fn user_service(command: UserServiceCommand) -> anyhow::Result<()> {
    match command {
        UserServiceCommand::Install(args) => install(&args)?,
        UserServiceCommand::Remove => remove()?,
        UserServiceCommand::Status => {}
    }
    let _ = writeln!(std::io::stdout().lock(), "{}", status());
    Ok(())
}

/// The service `install` wrote for this user, which the hook's step 4
/// starts.
pub(crate) struct InstalledService {
    path: PathBuf,
    supervisor: Supervisor,
}

impl InstalledService {
    /// The unit's file.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Asks the supervisor to start the service, and returns once it has
    /// taken the start, without waiting for the server: the hook waits for
    /// its runtime file. A supervisor still busy at `deadline` is left, and
    /// the start fails.
    pub(crate) fn start(&self, deadline: Instant) -> anyhow::Result<()> {
        match self.supervisor {
            Supervisor::Systemd => {
                systemctl(&["start", "--no-block", SYSTEMD_UNIT], Some(deadline))
            }
            Supervisor::Launchd => launchctl(
                &["kickstart".into(), launchd_service_target().into()],
                Some(deadline),
            ),
        }
    }
}

/// The service, when `install` wrote it: its unit is this user's own file,
/// not a link, that no one else can write, and it carries [`MARKER`].
pub(crate) fn installed() -> Option<InstalledService> {
    let path = SUPERVISOR.unit_path()?;
    matches!(unit_file(&path), UnitFile::Ours).then(|| InstalledService {
        path,
        supervisor: SUPERVISOR,
    })
}

fn install(args: &UserServiceInstallArgs) -> anyhow::Result<()> {
    let path = SUPERVISOR
        .unit_path()
        .ok_or_else(|| anyhow::anyhow!("no home folder to write the user service in"))?;
    let previous = unit_file(&path);
    anyhow::ensure!(
        !matches!(previous, UnitFile::Foreign),
        "{} was not written by `oneiron user-service install`, so it stays as it is; remove it \
         yourself to install the user service",
        path.display()
    );
    let config = local_servers::config_file(&ServeArgs {
        config: args.config.clone(),
        ..ServeArgs::default()
    })
    .ok_or_else(|| anyhow::anyhow!("{NO_VAULT}"))?;
    let config = std::path::absolute(&config)?;
    let settings_file = args
        .settings_file
        .as_deref()
        .map(std::path::absolute)
        .transpose()?;
    if let Some(settings_file) = &settings_file {
        anyhow::ensure!(
            settings_file.is_file(),
            "no settings file at {}",
            settings_file.display()
        );
    }
    let vault = local_servers::initialized_vault(&config, settings_file.as_deref())
        .ok_or_else(|| anyhow::anyhow!("{NO_VAULT} (config {})", config.display()))?;
    // A first install meets a vault the hook or the person started: the
    // service could not open it, and would retry for as long as it runs.
    if matches!(previous, UnitFile::Absent)
        && let Some(server) = running_server(&vault)
    {
        anyhow::bail!(
            "the vault in {} is running now as pid {} at {}, started without the user service; \
             stop it, then install again, so the service is the vault's one writer",
            vault.display(),
            server.pid,
            server.url
        );
    }
    let oneiron = match &args.oneiron {
        Some(oneiron) => std::path::absolute(oneiron)?,
        None => std::env::current_exe().context("this binary's path, for the service to run")?,
    };
    let body = SUPERVISOR.render(&oneiron, &config, settings_file.as_deref())?;
    write_unit(&path, body.as_bytes())?;
    SUPERVISOR.load(&path)
}

fn remove() -> anyhow::Result<()> {
    let Some(path) = SUPERVISOR.unit_path() else {
        return Ok(());
    };
    match unit_file(&path) {
        UnitFile::Absent => Ok(()),
        UnitFile::Foreign => anyhow::bail!(
            "{} was not written by `oneiron user-service install`, so it stays as it is",
            path.display()
        ),
        UnitFile::Ours => {
            SUPERVISOR.unload()?;
            fs::remove_file(&path).with_context(|| format!("delete {}", path.display()))?;
            SUPERVISOR.forget()
        }
    }
}

/// `{"installed", "path", "supervisor"}`: whether the unit `install` wrote
/// is there, where it is or would be, and which supervisor runs it.
fn status() -> serde_json::Value {
    let path = SUPERVISOR.unit_path();
    let installed = path
        .as_deref()
        .is_some_and(|path| matches!(unit_file(path), UnitFile::Ours));
    json!({
        "installed": installed,
        "path": path,
        "supervisor": SUPERVISOR.name(),
    })
}

impl Supervisor {
    fn name(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::Launchd => "launchd",
        }
    }

    /// Where this user's unit lives: `$XDG_CONFIG_HOME/systemd/user/` (else
    /// `~/.config/systemd/user/`), or `~/Library/LaunchAgents/`.
    fn unit_path(self) -> Option<PathBuf> {
        match self {
            Self::Systemd => {
                dirs::config_dir().map(|dir| dir.join("systemd/user").join(SYSTEMD_UNIT))
            }
            Self::Launchd => dirs::home_dir().map(|home| {
                home.join("Library/LaunchAgents")
                    .join(format!("{LAUNCHD_LABEL}.plist"))
            }),
        }
    }

    fn render(
        self,
        oneiron: &Path,
        config: &Path,
        settings_file: Option<&Path>,
    ) -> anyhow::Result<String> {
        match self {
            Self::Systemd => systemd_unit(oneiron, config, settings_file),
            Self::Launchd => {
                let home = dirs::home_dir()
                    .ok_or_else(|| anyhow::anyhow!("no home folder for the agent's logs"))?;
                launchd_agent(oneiron, config, settings_file, &home)
            }
        }
    }

    /// Loads the unit just written and (re)starts it: a unit written anew
    /// replaces the one running.
    fn load(self, path: &Path) -> anyhow::Result<()> {
        match self {
            Self::Systemd => {
                systemctl(&["daemon-reload"], None)?;
                systemctl(&["enable", SYSTEMD_UNIT], None)?;
                systemctl(&["restart", SYSTEMD_UNIT], None)
            }
            Self::Launchd => {
                // A non-zero answer here is an agent that was not loaded.
                let _ = launchctl(&["bootout".into(), launchd_service_target().into()], None);
                launchctl(
                    &["bootstrap".into(), launchd_domain().into(), path.into()],
                    None,
                )
            }
        }
    }

    /// Stops the service and keeps it from starting at login.
    fn unload(self) -> anyhow::Result<()> {
        match self {
            Self::Systemd => systemctl(&["disable", "--now", SYSTEMD_UNIT], None),
            Self::Launchd => {
                // A non-zero answer here is an agent that was not loaded,
                // which is what `remove` leaves.
                let _ = launchctl(&["bootout".into(), launchd_service_target().into()], None);
                Ok(())
            }
        }
    }

    /// After the unit's file is gone: the manager drops the unit it read.
    fn forget(self) -> anyhow::Result<()> {
        match self {
            Self::Systemd => systemctl(&["daemon-reload"], None),
            Self::Launchd => Ok(()),
        }
    }
}

/// The systemd user unit: the shipped `deploy/systemd/oneiron.service`, with
/// [`MARKER`] first and `ExecStart=` running `oneiron` with
/// [`local_servers::local_serve_args`]. It drops the template's
/// `PrivateTmp=`: a user manager makes a private `/tmp` only inside a user
/// namespace, which some distributions refuse to unprivileged users, and the
/// `serve` the hook starts runs without one too.
fn systemd_unit(
    oneiron: &Path,
    config: &Path,
    settings_file: Option<&Path>,
) -> anyhow::Result<String> {
    let exec_start = service_argv(oneiron, config, settings_file)?
        .iter()
        .map(|word| systemd_word(word))
        .collect::<Vec<_>>()
        .join(" ");
    let mut unit = format!("# {MARKER}\n");
    for line in SYSTEMD_TEMPLATE.lines() {
        if line.starts_with("PrivateTmp=") {
            continue;
        }
        if line.starts_with("ExecStart=") {
            unit.push_str("ExecStart=");
            unit.push_str(&exec_start);
        } else {
            unit.push_str(line);
        }
        unit.push('\n');
    }
    Ok(unit)
}

/// The launchd agent for `oneiron` with [`local_servers::local_serve_args`],
/// logging to the shipped agent's files under `home`.
fn launchd_agent(
    oneiron: &Path,
    config: &Path,
    settings_file: Option<&Path>,
    home: &Path,
) -> anyhow::Result<String> {
    let arguments: String = service_argv(oneiron, config, settings_file)?
        .iter()
        .map(|word| format!("    <string>{}</string>\n", xml_text(word)))
        .collect();
    let logs = home.join("Library/Logs");
    let log = |name: &str| -> anyhow::Result<String> {
        Ok(xml_text(&utf8(logs.join(name).into_os_string())?))
    };
    let (out, err) = (log("oneiron-server.log")?, log("oneiron-server.err.log")?);
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- {MARKER} -->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCHD_LABEL}</string>

  <key>ProgramArguments</key>
  <array>
{arguments}  </array>

  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>{out}</string>
  <key>StandardErrorPath</key>
  <string>{err}</string>
</dict>
</plist>
"#
    ))
}

/// The service's command line: `oneiron` and the arguments of the hook's
/// step 4. A unit file is text, so each word is UTF-8.
fn service_argv(
    oneiron: &Path,
    config: &Path,
    settings_file: Option<&Path>,
) -> anyhow::Result<Vec<String>> {
    std::iter::once(oneiron.as_os_str().to_owned())
        .chain(local_servers::local_serve_args(config, settings_file))
        .map(utf8)
        .collect()
}

fn utf8(word: OsString) -> anyhow::Result<String> {
    word.into_string().map_err(|word| {
        anyhow::anyhow!(
            "{} is not UTF-8, which a unit file cannot hold",
            word.to_string_lossy()
        )
    })
}

/// One `ExecStart=` word: `%` and `$` doubled, as systemd reads them
/// literally then, and quoted when it holds a space or a quote.
fn systemd_word(word: &str) -> String {
    let word = word.replace('%', "%%").replace('$', "$$");
    let plain = !word.is_empty()
        && !word
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\' | ';'));
    if plain {
        return word;
    }
    format!("\"{}\"", word.replace('\\', "\\\\").replace('"', "\\\""))
}

fn xml_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn unit_file(path: &Path) -> UnitFile {
    if fs::symlink_metadata(path).is_err() {
        return UnitFile::Absent;
    }
    let Some(file) = local_servers::open_own(path) else {
        return UnitFile::Foreign;
    };
    let mut body = Vec::new();
    if file.take(MAX_UNIT_BYTES).read_to_end(&mut body).is_err() {
        return UnitFile::Foreign;
    }
    if String::from_utf8_lossy(&body).contains(MARKER) {
        UnitFile::Ours
    } else {
        UnitFile::Foreign
    }
}

/// Writes the unit whole, in one rename, readable by all and writable by
/// this user alone, as unit files are.
fn write_unit(path: &Path, body: &[u8]) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no folder", path.display()))?;
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} has no file name", path.display()))?;
    let mut staged_name = OsString::from(".");
    staged_name.push(name);
    staged_name.push(format!(".{}.tmp", std::process::id()));
    let staged = dir.join(staged_name);
    let _ = fs::remove_file(&staged);
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&staged)
        .and_then(|mut file| {
            file.write_all(body)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&staged, path));
    if let Err(error) = written {
        let _ = fs::remove_file(&staged);
        return Err(error).with_context(|| format!("write {}", path.display()));
    }
    Ok(())
}

/// A live server whose runtime file names `vault` as its folder.
fn running_server(vault: &Path) -> Option<local_servers::LocalServer> {
    let vault = fs::canonicalize(vault).ok()?;
    local_servers::listed()
        .into_iter()
        .map(|(_, server)| server)
        .find(|server| {
            local_servers::alive(server.pid)
                && fs::canonicalize(&server.state_dir).is_ok_and(|dir| dir == vault)
        })
}

fn launchd_domain() -> String {
    format!("gui/{}", rustix::process::getuid().as_raw())
}

fn launchd_service_target() -> String {
    format!("{}/{LAUNCHD_LABEL}", launchd_domain())
}

fn systemctl(args: &[&str], deadline: Option<Instant>) -> anyhow::Result<()> {
    let args: Vec<OsString> = std::iter::once("--user")
        .chain(args.iter().copied())
        .map(OsString::from)
        .collect();
    supervise("systemctl", &args, deadline)
}

fn launchctl(args: &[OsString], deadline: Option<Instant>) -> anyhow::Result<()> {
    supervise("launchctl", args, deadline)
}

/// Runs the supervisor's `program`, found on `PATH`, and fails in its own
/// words when it does not succeed. With a `deadline`, one still running then
/// is killed, and the call fails.
fn supervise(program: &str, args: &[OsString], deadline: Option<Instant>) -> anyhow::Result<()> {
    let shown = || {
        std::iter::once(program.to_owned())
            .chain(args.iter().map(|arg| arg.to_string_lossy().into_owned()))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let mut child = oneiron_spawn::command(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("`{}` did not run", shown()))?;
    if let Some(deadline) = deadline {
        while child.try_wait()?.is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("`{}` did not answer in time", shown());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let output = child.wait_with_output()?;
    anyhow::ensure!(
        output.status.success(),
        "`{}` failed ({}): {}",
        shown(),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{MARKER, launchd_agent, systemd_word};

    fn strings(section: &str) -> Vec<String> {
        section
            .split("<string>")
            .skip(1)
            .map(|rest| {
                rest.split_once("</string>")
                    .expect("a closed string")
                    .0
                    .to_owned()
            })
            .collect()
    }

    /// The macOS agent, rendered on any host: the shipped label, the hook's
    /// `serve`, `RunAtLoad` and `KeepAlive`, the shipped log files, and no
    /// `Sockets`, since the server binds its configured address itself.
    #[test]
    fn launchd_agent_runs_the_hook_config_without_a_socket() {
        let agent = launchd_agent(
            Path::new("/opt/oneiron/bin/oneiron"),
            Path::new("/home/owen/.config/oneiron/oneiron.toml"),
            Some(Path::new("/home/owen/settings&co.toml")),
            Path::new("/home/owen"),
        )
        .expect("the agent renders");

        assert!(agent.contains(&format!("<!-- {MARKER} -->")), "{agent}");
        let (_, after_label) = agent.split_once("<key>Label</key>").expect("a label");
        assert_eq!(
            strings(after_label).first().map(String::as_str),
            Some("com.oneiron.server")
        );
        let (_, after_arguments) = agent
            .split_once("<key>ProgramArguments</key>")
            .expect("program arguments");
        let (arguments, _) = after_arguments
            .split_once("</array>")
            .expect("a closed array");
        assert_eq!(
            strings(arguments),
            [
                "/opt/oneiron/bin/oneiron",
                "serve",
                "--config",
                "/home/owen/.config/oneiron/oneiron.toml",
                "--settings-file",
                "/home/owen/settings&amp;co.toml",
                "--host",
                "127.0.0.1",
            ]
        );
        for key in ["RunAtLoad", "KeepAlive"] {
            assert!(
                agent.contains(&format!("<key>{key}</key>\n  <true/>")),
                "{key} is true: {agent}"
            );
        }
        assert!(!agent.contains("Sockets"), "{agent}");
        assert!(
            agent.contains("<string>/home/owen/Library/Logs/oneiron-server.log</string>")
                && agent
                    .contains("<string>/home/owen/Library/Logs/oneiron-server.err.log</string>"),
            "{agent}"
        );
    }

    /// An `ExecStart=` word keeps `%` and `$` literal and quotes a space.
    #[test]
    fn systemd_words_are_literal() {
        assert_eq!(
            systemd_word("/opt/oneiron/bin/oneiron"),
            "/opt/oneiron/bin/oneiron"
        );
        assert_eq!(systemd_word("/home/owen/100%"), "/home/owen/100%%");
        assert_eq!(systemd_word("/home/owen/$vault"), "/home/owen/$$vault");
        assert_eq!(
            systemd_word("/home/owen/My Vault/oneiron.toml"),
            "\"/home/owen/My Vault/oneiron.toml\""
        );
        assert_eq!(systemd_word(r#"/home/owen/a"b"#), r#""/home/owen/a\"b""#);
    }
}
