//! The shipped `oneiron-server` binary as a child process: `init`, `whoami`,
//! `token agent` on the stopped vault, then `serve` on loopback with a
//! sampler thread reading the child's `/proc` memory every 100 ms.
//!
//! The server stays in the bench's process group: Ctrl-C, or a signal to the
//! group, stops both. A signal to the bench alone skips its destructors and
//! leaves the server running.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::embedder::{MODEL_ID, MODEL_KEY, PassCount};

/// How the vault embeds: not at all, through the loopback stub, or with the
/// shipped local model.
pub(crate) enum Embedding {
    None,
    Stub { endpoint: String, dimensions: usize },
    Local,
}

/// A fresh vault with its config, issuer secret and owner principal.
pub(crate) struct Vault {
    pub(super) dir: PathBuf,
    pub(super) path: PathBuf,
    pub(crate) config: PathBuf,
    pub(super) secret: String,
    pub(super) owner: String,
}

/// One agent's paired credential: the slip token and its holder key seed.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct Credential {
    pub(super) token: String,
    pub(super) binding_key: String,
}

fn run(bin: &Path, args: &[&str], env: &[(&str, &str)]) -> Result<String, String> {
    let output = Command::new(bin)
        .args(args)
        .envs(env.iter().copied())
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("run {} {}: {e}", bin.display(), args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "{} {} exited {}: {}",
            bin.display(),
            args.first().copied().unwrap_or(""),
            output.status,
            tail(&String::from_utf8_lossy(&output.stderr), 2000)
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("non-UTF-8 output: {e}"))
}

/// The last `n` characters of `text`.
fn tail(text: &str, n: usize) -> &str {
    let skip = text.chars().count().saturating_sub(n);
    text.char_indices()
        .nth(skip)
        .map_or("", |(at, _)| &text[at..])
}

impl Vault {
    pub(crate) fn init(
        bin: &Path,
        dir: &Path,
        embedding: &Embedding,
        env: &[(String, String)],
    ) -> Result<Self, String> {
        fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let path = dir.join("vault");
        let config = dir.join("vault.toml");
        let vault_arg = path.to_string_lossy().into_owned();
        let config_arg = config.to_string_lossy().into_owned();
        let mut args = vec![
            "init",
            vault_arg.as_str(),
            "--config",
            config_arg.as_str(),
            "--embedder",
        ];
        let dimensions;
        match embedding {
            Embedding::None => args.push("none"),
            Embedding::Local => args.push("local"),
            Embedding::Stub {
                endpoint,
                dimensions: d,
            } => {
                dimensions = d.to_string();
                args.extend([
                    "endpoint",
                    "--embedder-endpoint",
                    endpoint.as_str(),
                    "--embedder-model-key",
                    MODEL_KEY,
                    "--embedder-model-id",
                    MODEL_ID,
                    "--dimensions",
                    dimensions.as_str(),
                ]);
            }
        }
        let env = env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect::<Vec<_>>();
        run(bin, &args, &env)?;
        let whoami: Value = serde_json::from_str(&run(
            bin,
            &["whoami", &vault_arg, "--config", &config_arg],
            &[],
        )?)
        .map_err(|e| format!("whoami output: {e}"))?;
        let owner = whoami["owner_principal"]
            .as_str()
            .ok_or("whoami printed no owner_principal")?
            .to_owned();
        Ok(Self {
            dir: dir.to_owned(),
            path,
            config,
            secret: oneiron::EntityId::now().to_hex(),
            owner,
        })
    }

    /// Reads the actual persisted switch through the shipped stopped-vault door.
    pub(super) fn secret_scan(&self, bin: &Path) -> Result<String, String> {
        let printed = run(
            bin,
            &[
                "secret-scan",
                "--config",
                &self.config.to_string_lossy(),
                "--vault-path",
                &self.path.to_string_lossy(),
            ],
            &[],
        )?;
        let value: Value =
            serde_json::from_str(&printed).map_err(|e| format!("secret-scan: {e}"))?;
        match value["mode"].as_str() {
            Some("on") => Ok("scan-on".into()),
            Some("off") => Ok("scan-off".into()),
            _ => Err("secret-scan returned no resolved mode".into()),
        }
    }

    /// Mints a full-access agent named `name` on the stopped vault.
    pub(super) fn mint_agent(&self, bin: &Path, name: &str) -> Result<Credential, String> {
        let vault_arg = self.path.to_string_lossy().into_owned();
        let config_arg = self.config.to_string_lossy().into_owned();
        let printed = run(
            bin,
            &[
                "token",
                "agent",
                "--name",
                name,
                "--tier",
                "full-access",
                "--config",
                &config_arg,
                "--vault-path",
                &vault_arg,
            ],
            &[("ONEIRON_AUTH_SECRET", &self.secret)],
        )?;
        serde_json::from_str(&printed).map_err(|e| format!("token agent output: {e}"))
    }

    /// The owner's first pairing link (`token bootstrap`) on the stopped
    /// vault, for a server that will listen at `origin`. Redeeming it gives
    /// an owner-grade credential, which a full-access agent token is not.
    pub(crate) fn bootstrap_owner(&self, bin: &Path, origin: &str) -> Result<String, String> {
        let vault_arg = self.path.to_string_lossy().into_owned();
        let config_arg = self.config.to_string_lossy().into_owned();
        let printed = run(
            bin,
            &[
                "token",
                "bootstrap",
                "--url",
                origin,
                "--config",
                &config_arg,
                "--vault-path",
                &vault_arg,
            ],
            &[("ONEIRON_AUTH_SECRET", &self.secret)],
        )?;
        let link = printed.trim();
        if link.is_empty() {
            return Err("token bootstrap printed no link".into());
        }
        Ok(link.to_owned())
    }

    /// Bytes on disk under the vault directory.
    pub(super) fn disk_bytes(&self) -> u64 {
        fn walk(path: &Path) -> u64 {
            fs::read_dir(path).map_or(0, |entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| match entry.metadata() {
                        Ok(meta) if meta.is_dir() => walk(&entry.path()),
                        Ok(meta) => meta.len(),
                        Err(_) => 0,
                    })
                    .sum()
            })
        }
        walk(&self.path)
    }
}

/// Process memory in MiB from `/proc/<pid>/status`.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub(super) struct Memory {
    pub(super) rss_mib: f64,
    pub(super) hwm_mib: f64,
    pub(super) anon_mib: f64,
    pub(super) file_mib: f64,
}

impl Memory {
    /// The larger of each field.
    pub(super) fn peak_with(self, other: Self) -> Self {
        Self {
            rss_mib: self.rss_mib.max(other.rss_mib),
            hwm_mib: self.hwm_mib.max(other.hwm_mib),
            anon_mib: self.anon_mib.max(other.anon_mib),
            file_mib: self.file_mib.max(other.file_mib),
        }
    }
}

fn read_memory(pid: u32) -> Option<Memory> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let field = |name: &str| {
        status
            .lines()
            .find(|line| line.starts_with(name))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|kb| kb.parse::<f64>().ok())
            .map_or(0.0, |kb| kb / 1024.0)
    };
    Some(Memory {
        rss_mib: field("VmRSS:"),
        hwm_mib: field("VmHWM:"),
        anon_mib: field("RssAnon:"),
        file_mib: field("RssFile:"),
    })
}

/// How many lines of the file at `log` contain `text`; 0 when it is unreadable.
fn count_lines(log: &Path, text: &str) -> usize {
    fs::read_to_string(log).map_or(0, |log| {
        log.lines().filter(|line| line.contains(text)).count()
    })
}

/// User + system CPU seconds the process has used, from `/proc/<pid>/stat`.
pub(super) fn cpu_seconds(pid: u32) -> Option<f64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.rsplit_once(')')?.1;
    let fields = rest.split_whitespace().collect::<Vec<_>>();
    let ticks = fields.get(11)?.parse::<f64>().ok()? + fields.get(12)?.parse::<f64>().ok()?;
    // USER_HZ is 100 on every Linux the fleet runs.
    Some(ticks / 100.0)
}

/// A running `serve`: its port, readiness time and memory peak.
pub(crate) struct Running {
    child: Child,
    log: PathBuf,
    pub(crate) pid: u32,
    pub(crate) base: String,
    pub(super) ready_ms: f64,
    peak: Arc<Mutex<Memory>>,
    stop: Arc<AtomicBool>,
    sampler: Option<JoinHandle<()>>,
}

pub(crate) fn free_port() -> Result<u16, String> {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("pick a port: {e}"))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|e| format!("pick a port: {e}"))
}

impl Running {
    pub(super) fn start(
        bin: &Path,
        vault: &Vault,
        env: &[(String, String)],
        log_name: &str,
        log_level: &str,
    ) -> Result<Self, String> {
        Self::start_on(bin, vault, env, log_name, log_level, free_port()?)
    }

    /// [`Self::start`] on a port the caller picked, for a pairing link that
    /// names the origin before the server is up.
    pub(crate) fn start_on(
        bin: &Path,
        vault: &Vault,
        env: &[(String, String)],
        log_name: &str,
        log_level: &str,
        port: u16,
    ) -> Result<Self, String> {
        let log_path = vault.dir.join(log_name);
        let log = fs::File::create(&log_path).map_err(|e| format!("server log: {e}"))?;
        let err = log.try_clone().map_err(|e| format!("server log: {e}"))?;
        let started = Instant::now();
        let child = Command::new(bin)
            .args(["serve", "--config"])
            .arg(&vault.config)
            .arg("--vault-path")
            .arg(&vault.path)
            .args(["--host", "127.0.0.1", "--port", &port.to_string()])
            .args(["--log-level", log_level])
            .env("ONEIRON_AUTH_SECRET", &vault.secret)
            .env("NO_COLOR", "1")
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            // The embedding worker's pass lines are the drain's evidence, so
            // they stay on under a caller's own `RUST_LOG`.
            .env(
                "RUST_LOG",
                format!(
                    "{},oneiron_server::server::embedding=info",
                    env.iter()
                        .rev()
                        .find(|(k, _)| k == "RUST_LOG")
                        .map_or(log_level, |(_, v)| v.as_str())
                ),
            )
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(err)
            .spawn()
            .map_err(|e| format!("spawn serve: {e}"))?;
        let pid = child.id();
        let peak = Arc::new(Mutex::new(Memory::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let sampler = {
            let (peak, stop) = (Arc::clone(&peak), Arc::clone(&stop));
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if let (Some(now), Ok(mut max)) = (read_memory(pid), peak.lock()) {
                        *max = max.peak_with(now);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            })
        };
        let mut running = Self {
            child,
            log: log_path,
            pid,
            base: format!("http://127.0.0.1:{port}"),
            ready_ms: 0.0,
            peak,
            stop,
            sampler: Some(sampler),
        };
        running.wait_ready(started)?;
        Ok(running)
    }

    fn wait_ready(&mut self, started: Instant) -> Result<(), String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|e| format!("health client: {e}"))?;
        let url = format!("{}/api/health", self.base);
        while started.elapsed() < Duration::from_secs(600) {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Err(format!("serve exited {status} before it was ready"));
            }
            if client
                .get(&url)
                .send()
                .is_ok_and(|r| r.status().is_success())
            {
                self.ready_ms = started.elapsed().as_secs_f64() * 1000.0;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Err("serve was not ready within 600 s".into())
    }

    /// The memory now, and the highest seen by the sampler since start.
    pub(super) fn memory(&self) -> (Memory, Memory) {
        let now = read_memory(self.pid).unwrap_or_default();
        let peak = self.peak.lock().map(|p| *p).unwrap_or_default();
        (now, peak)
    }

    /// Whether the server's log so far contains `text`.
    pub(super) fn logged(&self, text: &str) -> bool {
        self.log_count(text) > 0
    }

    /// How many lines of the server's log so far contain `text`.
    pub(super) fn log_count(&self, text: &str) -> usize {
        count_lines(&self.log, text)
    }

    /// [`Self::log_count`] as a function another thread can call.
    pub(super) fn log_counter(&self, text: &'static str) -> PassCount {
        let log = self.log.clone();
        Box::new(move || count_lines(&log, text))
    }

    /// Sends `signal` (a `kill -s` name such as `USR2`) to the server.
    pub(super) fn signal(&self, signal: &str) -> Result<(), String> {
        let status = Command::new("kill")
            .args(["-s", signal, &self.pid.to_string()])
            .status()
            .map_err(|e| format!("kill -s {signal}: {e}"))?;
        status
            .success()
            .then_some(())
            .ok_or_else(|| format!("kill -s {signal} {} failed", self.pid))
    }

    /// SIGTERM, then a wait of up to 120 s for a clean exit before SIGKILL;
    /// returns how the server exited.
    pub(crate) fn stop(mut self) -> String {
        let _ = self.signal("TERM");
        let deadline = Instant::now() + Duration::from_secs(120);
        let status = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => break status.to_string(),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                _ => {
                    let _ = self.child.kill();
                    break "killed after 120 s".to_owned();
                }
            }
        };
        self.stop.store(true, Ordering::Relaxed);
        if let Some(sampler) = self.sampler.take() {
            let _ = sampler.join();
        }
        status
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
