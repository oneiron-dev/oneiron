//! Which vault a session binds (ARCH-0028 `#plugin-first-run`, owner ruling
//! PLUGIN-FIRSTRUN = D), the first that applies:
//!
//! 1. a pin: the hook's `--url`, else `ONEIRON_URL`, else `url` in
//!    `hook.toml` in the per-user oneiron folder;
//! 2. a running local vault: a runtime file ([`local_servers`]) whose pid
//!    lives and whose server answers `GET /.well-known/oneiron`, the newest
//!    when several do;
//! 3. the hosted vault, when the person is logged into the cloud. This
//!    engine keeps no login yet (`oneiron connect` brings it), so the step is
//!    passed over;
//! 4. a local server, started from the config every command reads when none
//!    is named. With no config there is no vault to start, and the line
//!    names the setup step.
//!
//! The session's first line names the vault bound.

use std::io::Read as _;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use oneiron::authority::PairingDescriptor;
use serde::Deserialize;

use crate::config::ServeArgs;
use crate::local_servers::{self, LocalServer};

/// The pin, in the per-user oneiron folder.
const PIN_FILE: &str = "hook.toml";
/// What a started server logs to, in the run folder.
const SERVE_LOG: &str = "serve.log";
/// The longest one probe waits.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// A pin or a descriptor is a few hundred bytes; a larger one is not read.
const MAX_READ_BYTES: u64 = 64 * 1024;
const NO_VAULT: &str = "Oneiron: no vault bound; set one up with `oneiron init ~/.oneiron/default` \
                        (docs/ops/claude-code-hooks.md).";

pub(super) struct Bound {
    /// The origin to recall from, when a vault there answers.
    pub(super) url: Option<String>,
    /// What the session is told; the first line names the vault.
    pub(super) lines: Vec<String>,
}

impl Bound {
    fn none(line: String) -> Self {
        Self {
            url: None,
            lines: vec![line],
        }
    }
}

/// Binds a vault for a session, in the order above.
pub(super) fn session(flag: Option<&str>, oneiron: &Path, deadline: Instant) -> Bound {
    if let Some(pin) = pin(flag) {
        if !answers(&pin.url, deadline) {
            return Bound::none(format!(
                "Oneiron: the vault pinned by {} at {} is not answering; this session has no vault.",
                pin.by, pin.url
            ));
        }
        return Bound {
            lines: vec![format!(
                "Oneiron: this session uses the vault at {}, pinned by {}.",
                pin.url, pin.by
            )],
            url: Some(pin.url),
        };
    }
    let running = running(deadline);
    if let Some(newest) = running.first() {
        let mut lines = vec![uses(newest, running.len())];
        if running.len() > 1
            && let Some(pin) = pin_file()
        {
            lines.push(format!(
                "Oneiron: to keep using this vault, pin it: echo 'url = \"{}\"' > '{}'",
                newest.url,
                pin.display()
            ));
        }
        return Bound {
            url: Some(newest.url.clone()),
            lines,
        };
    }
    // Step 3, the hosted vault, waits for a login to read.
    start(oneiron, deadline)
}

/// The vault a prompt recalls from: the pin, else the newest running local
/// vault. A prompt never starts a server and prints no line of its own.
pub(super) fn quietly(flag: Option<&str>, deadline: Instant) -> Option<String> {
    if let Some(pin) = pin(flag) {
        return Some(pin.url);
    }
    running(deadline)
        .into_iter()
        .next()
        .map(|server| server.url)
}

/// The config of the running local vault a hand-over queues to: the one at
/// the pin when a runtime file names it, else the newest. A hand-over only
/// writes a file, so it asks no server.
pub(super) fn running_config() -> Option<PathBuf> {
    let pinned = pin(None).map(|pin| pin.url);
    let mut alive: Vec<LocalServer> = local_servers::listed()
        .into_iter()
        .map(|(_, server)| server)
        .filter(|server| local_servers::alive(server.pid))
        .collect();
    newest_first(&mut alive);
    let mut alive = alive.into_iter();
    let chosen = match pinned {
        Some(url) => alive.find(|server| server.url == url),
        None => alive.next(),
    };
    chosen?.config
}

struct Pin {
    url: String,
    /// What set it, for the line: the flag, the variable or the file.
    by: String,
}

fn pin(flag: Option<&str>) -> Option<Pin> {
    if let Some(url) = flag.filter(|url| !url.is_empty()) {
        return Some(Pin {
            url: url.to_owned(),
            by: "--url".to_owned(),
        });
    }
    if let Some(url) = std::env::var("ONEIRON_URL")
        .ok()
        .filter(|url| !url.is_empty())
    {
        return Some(Pin {
            url,
            by: "ONEIRON_URL".to_owned(),
        });
    }
    #[derive(Deserialize)]
    struct PinFile {
        url: Option<String>,
    }
    let path = pin_file()?;
    let mut body = String::new();
    std::fs::File::open(&path)
        .ok()?
        .take(MAX_READ_BYTES)
        .read_to_string(&mut body)
        .ok()?;
    let url = toml::from_str::<PinFile>(&body)
        .ok()?
        .url
        .filter(|url| !url.is_empty())?;
    Some(Pin {
        url,
        by: path.display().to_string(),
    })
}

fn pin_file() -> Option<PathBuf> {
    local_servers::user_dir().map(|dir| dir.join(PIN_FILE))
}

/// The running local vaults, newest first. A runtime file whose pid is gone
/// is removed; one whose server does not answer is passed over, and stays:
/// its server may still be starting.
fn running(deadline: Instant) -> Vec<LocalServer> {
    let mut running: Vec<LocalServer> = local_servers::listed()
        .into_iter()
        .filter_map(|(path, server)| {
            if !local_servers::alive(server.pid) {
                let _ = std::fs::remove_file(&path);
                return None;
            }
            answers(&server.url, deadline).then_some(server)
        })
        .collect();
    newest_first(&mut running);
    running
}

fn newest_first(servers: &mut [LocalServer]) {
    servers.sort_by(|a, b| b.started_at_ms.cmp(&a.started_at_ms));
}

fn uses(server: &LocalServer, running: usize) -> String {
    let id = server
        .vault_id
        .as_deref()
        .map(|id| format!(" {}", id.chars().take(12).collect::<String>()))
        .unwrap_or_default();
    let newest = if running > 1 {
        format!(", the newest of {running} running")
    } else {
        String::new()
    };
    format!(
        "Oneiron: this session uses your local vault{id} at {} ({}){newest}.",
        server.url,
        server.state_dir.display()
    )
}

/// Step 4: starts `serve` from the config every command reads when none is
/// named, on loopback, in a process group of its own, and waits for it to
/// answer until `deadline`. It runs on after the hook exits; the next
/// session finds it by its runtime file.
fn start(oneiron: &Path, deadline: Instant) -> Bound {
    let Some(config) = local_servers::config_file(&ServeArgs::default()) else {
        return Bound::none(NO_VAULT.to_owned());
    };
    let log = local_servers::run_dir().map(|dir| dir.join(SERVE_LOG));
    let output = log.as_deref().and_then(|log| {
        local_servers::ensure_run_dir().ok()?;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(log)
            .ok()
    });
    let (stdout, stderr) = match output.and_then(|file| Some((file.try_clone().ok()?, file))) {
        Some((stdout, stderr)) => (Stdio::from(stdout), Stdio::from(stderr)),
        None => (Stdio::null(), Stdio::null()),
    };
    let spawned = oneiron_spawn::command(oneiron)
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .args(["--host", "127.0.0.1"])
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .process_group(0)
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            return Bound::none(format!(
                "Oneiron: no vault bound; the local vault in {} did not start: {error}.",
                config.display()
            ));
        }
    };
    loop {
        if let Some(server) = local_servers::listed()
            .into_iter()
            .map(|(_, server)| server)
            .find(|server| server.pid == child.id())
            && answers(&server.url, deadline)
        {
            return Bound {
                lines: vec![format!(
                    "{} Started for this session from {}.",
                    uses(&server, 1),
                    config.display()
                )],
                url: Some(server.url),
            };
        }
        if matches!(child.try_wait(), Ok(Some(_))) {
            let log = log
                .as_deref()
                .map_or_else(String::new, |log| format!(" (its log: {})", log.display()));
            return Bound::none(format!(
                "Oneiron: no vault bound; the local vault in {} did not start{log}.",
                config.display()
            ));
        }
        if Instant::now() >= deadline {
            return Bound::none(format!(
                "Oneiron: no vault bound yet; the local vault in {} is starting and the next \
                 session will find it.",
                config.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Whether an Oneiron server answers at `url`: `GET /.well-known/oneiron`
/// returns its pairing descriptor. The route needs no credential, so a
/// probe sends none.
fn answers(url: &str, deadline: Instant) -> bool {
    let timeout = deadline
        .saturating_duration_since(Instant::now())
        .min(PROBE_TIMEOUT);
    if timeout.is_zero() {
        return false;
    }
    let Ok(base) = reqwest::Url::parse(url) else {
        return false;
    };
    let Ok(probe) = base.join("/.well-known/oneiron") else {
        return false;
    };
    let loopback = base.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    let mut client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    // A local server is never reached through a proxy.
    if loopback {
        client = client.no_proxy();
    }
    let Ok(response) = client.build().and_then(|client| client.get(probe).send()) else {
        return false;
    };
    if !response.status().is_success() {
        return false;
    }
    let mut body = Vec::new();
    if response
        .take(MAX_READ_BYTES)
        .read_to_end(&mut body)
        .is_err()
    {
        return false;
    }
    serde_json::from_slice::<PairingDescriptor>(&body)
        .is_ok_and(|descriptor| descriptor.protocol == PairingDescriptor::default().protocol)
}
