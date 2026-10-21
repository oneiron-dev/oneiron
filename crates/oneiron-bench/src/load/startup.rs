//! `load startup`: the server's memory while the shipped local embedding model
//! loads, which is where its startup peak lives. Each repeat starts a fresh
//! `serve` on one vault and waits for the model to report ready.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use super::server::{Embedding, Memory, Running, Vault};

#[derive(Debug, Serialize)]
struct Load {
    secret_scan: String,
    health_ms: f64,
    model_ready_ms: Option<f64>,
    at_ready: Memory,
    /// The sampler's peak and VmHWM from the start to 5 s after the model is ready.
    peak: Memory,
    idle: Memory,
}

#[derive(Debug, Serialize)]
struct StartupReport {
    bench: &'static str,
    label: Option<String>,
    started_unix: u64,
    hostname: String,
    loads: Vec<Load>,
}

struct Args {
    server: PathBuf,
    work: PathBuf,
    out: PathBuf,
    label: Option<String>,
    repeat: usize,
    env: Vec<(String, String)>,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut out = Args {
        server: PathBuf::new(),
        work: PathBuf::new(),
        out: PathBuf::new(),
        label: None,
        repeat: 3,
        env: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--server" => out.server = PathBuf::from(value),
            "--work" => out.work = PathBuf::from(value),
            "--out" => out.out = PathBuf::from(value),
            "--label" => out.label = Some(value.clone()),
            "--repeat" => out.repeat = value.parse().map_err(|_| "--repeat is a number")?,
            "--server-env" => {
                let (k, v) = value.split_once('=').ok_or("--server-env is KEY=VALUE")?;
                out.env.push((k.to_owned(), v.to_owned()));
            }
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    Ok(out)
}

/// Waits for the model-ready log line, returning milliseconds since `started`.
fn wait_model(log: &Path, started: Instant, cap: Duration) -> Option<f64> {
    while started.elapsed() < cap {
        if std::fs::read_to_string(log).is_ok_and(|text| text.contains("local embedder ready")) {
            return Some(started.elapsed().as_secs_f64() * 1000.0);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

pub(super) fn run(args: &[String]) -> Result<(), String> {
    let args = parse(args)?;
    let dir = args.work.join("startup-local");
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| format!("clear {}: {e}", dir.display()))?;
    }
    let vault = Vault::init(&args.server, &dir, &Embedding::Local, &args.env)?;
    let mut loads = Vec::new();
    for round in 0..args.repeat {
        let secret_scan = vault.secret_scan(&args.server)?;
        let log = format!("serve-startup-{round}.log");
        let started = Instant::now();
        let server = Running::start(&args.server, &vault, &args.env, &log, "info")?;
        let health_ms = server.ready_ms;
        let model_ready_ms = wait_model(&dir.join(&log), started, Duration::from_secs(900));
        let at_ready = server.memory().0;
        std::thread::sleep(Duration::from_secs(5));
        let (idle, sampled) = server.memory();
        loads.push(Load {
            secret_scan,
            health_ms,
            model_ready_ms,
            at_ready,
            peak: sampled.peak_with(idle),
            idle,
        });
        server.stop();
    }
    let report = StartupReport {
        bench: "oneiron-bench load startup v1",
        label: args.label,
        started_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        hostname: std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_default()
            .trim()
            .to_owned(),
        loads,
    };
    let text = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    std::fs::write(&args.out, text).map_err(|e| format!("{}: {e}", args.out.display()))
}
