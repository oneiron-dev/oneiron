//! Observations, raw latency samples and run provenance, never capacity targets.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use super::{Result, configuration::Plan};

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Metric {
    pub completed: usize,
    pub elapsed_seconds: f64,
    pub throughput_per_second: f64,
    pub p99_ms: f64,
    pub samples_ms: Vec<f64>,
}
impl Metric {
    pub(super) fn new(mut samples_ms: Vec<f64>, elapsed_seconds: f64) -> Result<Self> {
        if samples_ms.is_empty()
            || !elapsed_seconds.is_finite()
            || elapsed_seconds <= 0.0
            || samples_ms.iter().any(|s| !s.is_finite() || *s <= 0.0)
        {
            return Err("empty or invalid timing sample".into());
        }
        samples_ms.sort_by(f64::total_cmp);
        let completed = samples_ms.len();
        let p99_ms = samples_ms[(completed * 99).div_ceil(100) - 1];
        Ok(Self {
            completed,
            elapsed_seconds,
            throughput_per_second: completed as f64 / elapsed_seconds,
            p99_ms,
            samples_ms,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Host {
    pub os: String,
    pub arch: String,
    pub hostname: String,
    pub kernel: String,
    pub cpu: String,
    pub logical_cpus: usize,
    pub compiled_profile: String,
    pub compiled_opt_level: String,
    pub debug_assertions: bool,
    pub fd_limit: String,
}
impl Host {
    pub(super) fn capture() -> Result<Self> {
        let cpu = if cfg!(target_os = "linux") {
            std::fs::read_to_string("/proc/cpuinfo")?
                .lines()
                .find(|line| line.starts_with("model name"))
                .ok_or("CPU model unavailable")?
                .to_owned()
        } else if cfg!(target_os = "macos") {
            command("/usr/sbin/sysctl", &["-n", "machdep.cpu.brand_string"])?
        } else {
            return Err("fleet provenance supports Linux and macOS hosts".into());
        };
        Ok(Self {
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            hostname: command("uname", &["-n"])?,
            kernel: command("uname", &["-r"])?,
            cpu,
            logical_cpus: std::thread::available_parallelism()?.get(),
            compiled_profile: env!("ONEIRON_BENCH_COMPILED_PROFILE").into(),
            compiled_opt_level: env!("ONEIRON_BENCH_COMPILED_OPT_LEVEL").into(),
            debug_assertions: cfg!(debug_assertions),
            fd_limit: command("sh", &["-c", "ulimit -n"])?,
        })
    }
}

pub(super) fn command(program: &str, args: &[&str]) -> Result<String> {
    let output = std::process::Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(format!("{program} failed").into());
    }
    let text = String::from_utf8(output.stdout)?.trim().to_owned();
    if text.is_empty() {
        return Err(format!("{program} returned no provenance").into());
    }
    Ok(text)
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Receipt {
    pub schema: String,
    pub status: String,
    pub plan: Plan,
    pub host: Host,
    /// Checkout at measurement time, if this deployment includes Git metadata.
    pub revision: Option<String>,
    pub dirty: Option<bool>,
    pub binary_blake3: String,
    pub started_unix_ms: u128,
    pub metrics: BTreeMap<String, Metric>,
    pub held_sockets: usize,
    pub verified_writes: usize,
    pub verified_recalls: usize,
    pub hold_observed_ms: f64,
    pub optimization: Optimization,
}
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Optimization {
    pub route: String,
    pub equivalent_pairs: usize,
    pub result_blake3: String,
    pub incremental_speedup: f64,
    pub preparation_seconds: f64,
    pub preparation_included_speedup: f64,
}

pub(super) fn write_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn table(receipt: &Receipt) -> std::io::Result<()> {
    let mut output = std::io::stdout().lock();
    writeln!(
        output,
        "| verb / phase | completed | throughput / s | p99 ms |"
    )?;
    writeln!(output, "|---|---:|---:|---:|")?;
    for (name, metric) in &receipt.metrics {
        writeln!(
            output,
            "| {name} | {} | {:.3} | {:.3} |",
            metric.completed, metric.throughput_per_second, metric.p99_ms
        )?;
    }
    writeln!(
        output,
        "Held {} sockets for {:.3} ms; verified {} writes and {} recalls.",
        receipt.held_sockets,
        receipt.hold_observed_ms,
        receipt.verified_writes,
        receipt.verified_recalls
    )?;
    writeln!(
        output,
        "PPR resume speedup: {:.3}x incremental, {:.3}x including preparation ({} equal pairs).",
        receipt.optimization.incremental_speedup,
        receipt.optimization.preparation_included_speedup,
        receipt.optimization.equivalent_pairs
    )?;
    Ok(())
}
