//! Which vault a session binds (ARCH-0028 `#plugin-first-run`, owner ruling
//! PLUGIN-FIRSTRUN = D), the first that applies:
//!
//! 1. a pin: the hook's `--url`, else `ONEIRON_URL`, else `url` in
//!    `hook.toml` in the per-user oneiron folder;
//! 2. a running local vault: a runtime file ([`local_servers`]) whose pid
//!    lives and whose server answers `GET /.well-known/oneiron`, the newest
//!    when several do;
//! 3. the hosted vault the person's cloud login selected ([`HostedDiscovery`]).
//!    No authenticated hosted-login discovery is integrated yet, so the step
//!    answers [`HostedDiscovery::Unavailable`]: that binds nothing and is not
//!    proof of no login, and a session that starts local because of it says
//!    so in one line naming the pins ([`HOSTED_DISCOVERY_UNAVAILABLE`]);
//! 4. a local server, started from the config every command reads when none
//!    is named, with the hook's `--settings-file` over it. With no config
//!    there is no vault to start, and the line names the setup step.
//!
//! The session's first line names the vault bound. A prompt takes steps 1 to
//! 3 exactly as a session does ([`choose`]), so it never recalls from a vault
//! the session would not have bound.

use std::io::Read as _;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use oneiron::authority::PairingDescriptor;
use serde::Deserialize;

use crate::commands::ConfigFiles;
use crate::commands::local_servers::{self, LocalServer};
use crate::config::{ServeArgs, resolve_serve_config};

/// The pin, in the per-user oneiron folder.
const PIN_FILE: &str = "hook.toml";
/// What a started server logs to, in the run folder.
const SERVE_LOG: &str = "serve.log";
/// The store file every initialized vault folder holds.
const STORE_FILE: &str = "data.mdb";
/// The longest one probe waits.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// How long after a started `serve` exits the hook waits for whoever holds
/// the vault to name itself: the lease writes its pid just after it is taken.
const HOLDER_GRACE: Duration = Duration::from_millis(500);
/// A pin or a descriptor is a few hundred bytes; a larger one is not read.
const MAX_READ_BYTES: u64 = 64 * 1024;
const NO_VAULT: &str = "Oneiron: no vault bound; set one up with `oneiron init ~/.oneiron/default` \
                        (docs/ops/claude-code-hooks.md).";
/// The line a session that binds a local vault at step 4 prints, because
/// step 3 could not look for a hosted vault (H41). One constant, so the
/// adapter that integrates discovery changes one line.
const HOSTED_DISCOVERY_UNAVAILABLE: &str = "Oneiron: hosted login discovery is not integrated; \
                                            started local; pin a hosted vault with --url, \
                                            ONEIRON_URL or hook config.";

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

/// What step 3 found: the hosted vault the person's cloud login selected
/// (H41). An authenticated selection adapter (the host integration's seam)
/// would answer a selected vault with its origin and credential, or no login
/// or no selection; until one is integrated the only answer is
/// `Unavailable`, which is not proof of no login.
enum HostedDiscovery {
    /// No hosted-login discovery is integrated: no login store is read, no
    /// cloud URL guessed and no credential looked up.
    Unavailable,
}

/// Step 3, as both a session and a prompt ask it.
const fn hosted_discovery() -> HostedDiscovery {
    HostedDiscovery::Unavailable
}

/// Steps 1 to 3, the one choice a session and a prompt both take.
enum Choice {
    /// Step 1: the pin, and whether it answered one probe. A pin that does
    /// not answer binds nothing; it never falls back to local.
    Pinned { pin: Pin, answers: bool },
    /// Step 2: the newest running local vault that answers, and how many
    /// answer.
    Running { newest: LocalServer, count: usize },
    /// Step 3 bound no hosted vault, and why; a session goes on to step 4.
    NoHosted(HostedDiscovery),
}

fn choose(flag: Option<&str>, deadline: Instant) -> Choice {
    if let Some(pin) = pin(flag) {
        // One probe: a pin that does not answer would hold a prompt for the
        // whole recall budget.
        let answered = answers(&pin.url, deadline);
        return Choice::Pinned {
            pin,
            answers: answered,
        };
    }
    let running = running(deadline);
    let count = running.len();
    match running.into_iter().next() {
        Some(newest) => Choice::Running { newest, count },
        None => Choice::NoHosted(hosted_discovery()),
    }
}

/// Binds a vault for a session, in the order above. A server it starts
/// layers `settings_file` over its config.
pub(super) fn session(
    flag: Option<&str>,
    oneiron: &Path,
    settings_file: Option<&Path>,
    deadline: Instant,
) -> Bound {
    match choose(flag, deadline) {
        Choice::Pinned {
            pin,
            answers: false,
        } => Bound::none(format!(
            "Oneiron: the vault pinned by {} at {} is not answering; this session has no vault.",
            pin.by, pin.url
        )),
        Choice::Pinned { pin, answers: true } => Bound {
            lines: vec![format!(
                "Oneiron: this session uses the vault at {}, pinned by {}.",
                pin.url, pin.by
            )],
            url: Some(pin.url),
        },
        Choice::Running { newest, count } => {
            let mut lines = vec![uses(&newest, count)];
            if count > 1
                && let Some(pin) = pin_file()
            {
                lines.push(format!(
                    "Oneiron: to keep using this vault, pin it: echo 'url = \"{}\"' > '{}'",
                    newest.url,
                    pin.display()
                ));
            }
            Bound {
                url: Some(newest.url),
                lines,
            }
        }
        Choice::NoHosted(HostedDiscovery::Unavailable) => {
            // Local start stays; the session is told why it is local.
            let mut bound = start(oneiron, settings_file, deadline);
            if bound.url.is_some() {
                bound.lines.push(HOSTED_DISCOVERY_UNAVAILABLE.to_owned());
            }
            bound
        }
    }
}

/// The vault a prompt recalls from, by the session's own choice: the pin, if
/// one is set and it answers; with no pin, the newest running local vault.
/// A prompt never starts a server and prints no line of its own.
pub(super) fn quietly(flag: Option<&str>, deadline: Instant) -> Option<String> {
    match choose(flag, deadline) {
        Choice::Pinned { pin, answers } => answers.then_some(pin.url),
        Choice::Running { newest, .. } => Some(newest.url),
        Choice::NoHosted(HostedDiscovery::Unavailable) => None,
    }
}

/// The config of the running local vault a hand-over queues to: with a pin,
/// the one a runtime file names at the pin, and none when no runtime file
/// does (a pin is never swapped for another vault); with no pin, the newest.
/// Its config file and its settings file both come from that one server; a
/// settings file no longer there is dropped, and the hand-over goes on
/// without it. A hand-over only writes a file, so it asks no server.
pub(super) fn running_config() -> Option<ConfigFiles> {
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
    let chosen = chosen?;
    Some(ConfigFiles {
        config: chosen.config,
        settings_file: chosen.settings_file.filter(|path| path.is_file()),
    })
}

#[derive(Deserialize)]
struct PinFile {
    url: Option<String>,
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
    // Only a pin no one else can write: the session sends its credential
    // where the pin says.
    let path = pin_file()?;
    let mut body = String::new();
    local_servers::open_own(&path)?
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

/// The running local vaults, newest first, asked in that order so a slow
/// older one cannot spend the newest one's time. A runtime file whose pid is
/// gone is removed; one whose server does not answer is passed over, and
/// stays: its server may still be starting.
fn running(deadline: Instant) -> Vec<LocalServer> {
    let mut alive: Vec<LocalServer> = local_servers::listed()
        .into_iter()
        .filter_map(|(path, server)| {
            if local_servers::alive(server.pid) {
                return Some(server);
            }
            let _ = std::fs::remove_file(&path);
            None
        })
        .collect();
    newest_first(&mut alive);
    alive
        .into_iter()
        .filter(|server| answers(&server.url, deadline))
        .collect()
}

fn newest_first(servers: &mut [LocalServer]) {
    servers.sort_by_key(|server| std::cmp::Reverse(server.started_at_ms));
}

fn uses(server: &LocalServer, running: usize) -> String {
    let id = server.vault_id.as_deref().map_or_else(String::new, |id| {
        format!(" {}", id.chars().take(12).collect::<String>())
    });
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
/// named, with `settings_file` over it as the preflight reads them, on
/// loopback, in a process group of its own, and waits for it to answer
/// until `deadline`. It runs on after the hook exits; the next
/// session finds it by its runtime file. When it cannot open the vault
/// because another process holds it, the session binds the server there
/// once one answers.
fn start(oneiron: &Path, settings_file: Option<&Path>, deadline: Instant) -> Bound {
    let Some(config) = local_servers::config_file(&ServeArgs::default()) else {
        return Bound::none(NO_VAULT.to_owned());
    };
    // `serve` creates a vault that is not there; the hook only starts one
    // that is (no vault is made without `oneiron init`).
    let Some(vault) = resolve_serve_config(&ServeArgs {
        config: Some(config.clone()),
        settings_file: settings_file.map(Path::to_path_buf),
        ..ServeArgs::default()
    })
    .ok()
    .map(|serve| serve.vault_path)
    .filter(|vault| vault.join(STORE_FILE).is_file()) else {
        return Bound::none(NO_VAULT.to_owned());
    };
    if Instant::now() >= deadline {
        return Bound::none(format!(
            "Oneiron: no vault answered in time; the local vault in {} was not started.",
            config.display()
        ));
    }
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
    let mut command = oneiron_spawn::command(oneiron);
    command.arg("serve").arg("--config").arg(&config);
    if let Some(settings_file) = settings_file {
        command.arg("--settings-file").arg(settings_file);
    }
    let spawned = command
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
    let did_not_start = || {
        let log = log
            .as_deref()
            .map_or_else(String::new, |log| format!(" (its log: {})", log.display()));
        Bound::none(format!(
            "Oneiron: no vault bound; the local vault in {} did not start{log}.",
            config.display()
        ))
    };
    let mut exited_at = None;
    loop {
        if exited_at.is_none() && matches!(child.try_wait(), Ok(Some(_))) {
            exited_at = Some(Instant::now());
        }
        if let Some(exited) = exited_at {
            // Most often another session started a `serve` a moment before,
            // which holds the vault and is not ready yet, so this one could
            // not open it: bind the server that answers next.
            if !held_by_another(&vault, child.id()) && exited.elapsed() >= HOLDER_GRACE {
                return did_not_start();
            }
            let running = running(deadline);
            if let Some(newest) = running.first() {
                return Bound {
                    lines: vec![uses(newest, running.len())],
                    url: Some(newest.url.clone()),
                };
            }
        } else if let Some(server) = local_servers::listed()
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
        if Instant::now() >= deadline {
            if exited_at.is_some() {
                return did_not_start();
            }
            return Bound::none(format!(
                "Oneiron: no vault bound yet; the local vault in {} is starting and the next \
                 session will find it.",
                config.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Whether a live process other than `child` holds the vault's writer
/// lease, by the pid the lease's lock file records for whoever took it.
fn held_by_another(vault: &Path, child: u32) -> bool {
    // Neither a link nor a FIFO, which could hold the hook past its deadline.
    let Ok(file) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(vault.join(oneiron::VAULT_WRITER_LOCK_FILE))
    else {
        return false;
    };
    let mut pid = String::new();
    file.metadata().is_ok_and(|metadata| metadata.is_file())
        && file.take(32).read_to_string(&mut pid).is_ok()
        && pid
            .trim()
            .parse::<u32>()
            .is_ok_and(|pid| pid != child && local_servers::alive(pid))
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
