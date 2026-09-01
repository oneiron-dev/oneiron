//! ONE-1579 axis 2: process spawn-to-ready wake latency.
//!
//! The measurement is the interval from immediately before the spawn to the
//! parent's COMPLETED TCP accept. No log line, stdout token or sleep stands in
//! for readiness anywhere on this path.
//!
//! After each sample the parent releases the child by closing the accepted
//! stream and then waits a bounded budget, terminating and reaping anything
//! still alive. Every sample records how its child left, so a caller-supplied
//! program that stays up after readiness is visible in the row instead of
//! hanging the run.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use super::axes::{CHILD_SHUTDOWN_RULE, READINESS_RULE, ReadinessSignal, WakeAxis};
use super::cells::{Cell, EvidenceKind, Percentiles};
use super::child_process::{
    ACCEPT_POLL_INTERVAL_US, ChildSettings, WakeProbe, child_command, child_shutdown_budget,
    describe_child, resolve_child_program, spawn_child, wait_bounded,
};

/// Axis 2: spawn-to-ready latency, sampled `settings.samples` times.
pub(crate) fn measure_wake(
    root: &Path,
    settings: &ChildSettings,
    evidence_kind: EvidenceKind,
) -> WakeAxis {
    let mut samples = Vec::with_capacity(settings.samples);
    let mut errors = Vec::new();
    let mut shutdown_outcomes: BTreeMap<String, usize> = BTreeMap::new();
    let mut description = None;
    // Defaulted, then overwritten by whatever the probe actually reported, so
    // the emitted signal is observed rather than asserted.
    let mut readiness_signal = ReadinessSignal::TcpAccept;
    let program = match resolve_child_program() {
        Ok(program) => Some(program),
        Err(reason) => {
            errors.push(reason);
            None
        }
    };
    if let Some(program) = program {
        for index in 0..settings.samples {
            let dir = root.join(format!("wake-{index}"));
            match wake_sample(&program, settings, &dir) {
                Ok(sample) => {
                    samples.push(sample.elapsed_ms);
                    readiness_signal = sample.signal;
                    *shutdown_outcomes.entry(sample.shutdown).or_insert(0) += 1;
                    description = Some(sample.child);
                }
                Err(reason) => errors.push(reason),
            }
        }
    }
    WakeAxis {
        readiness_signal,
        readiness_rule: READINESS_RULE,
        shutdown_rule: CHILD_SHUTDOWN_RULE,
        accept_poll_interval_us: ACCEPT_POLL_INTERVAL_US,
        samples: samples.len(),
        spawn_to_ready_ms: Cell::from_option(
            Percentiles::from_samples(&samples),
            "no child reached a completed TCP accept, so no wake latency was measured",
        ),
        child: Cell::from_option(description, "no ready child was spawned in this run"),
        shutdown_outcomes,
        errors,
        evidence_kind,
    }
}

/// One completed spawn-to-ready observation.
struct WakeSample {
    elapsed_ms: f64,
    signal: ReadinessSignal,
    child: String,
    shutdown: String,
}

fn wake_sample(
    program: &Path,
    settings: &ChildSettings,
    dir: &Path,
) -> Result<WakeSample, String> {
    std::fs::create_dir_all(dir)
        .map_err(|error| format!("wake child vault dir failed: {error}"))?;
    let probe = WakeProbe::bind()?;
    let addr = probe.addr()?;
    let (program, args) = child_command(
        settings.child.as_ref(),
        program,
        addr,
        dir,
        settings.hold_ms,
    );
    let child_line = describe_child(&program, &args);
    let started = Instant::now();
    let mut child = spawn_child(&program, &args)?;
    let ready = match probe.wait_ready(started, settings.accept_timeout()) {
        Ok(ready) => ready,
        Err(reason) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(reason);
        }
    };
    // Release the child by closing the accepted stream, then bound the wait:
    // a caller-supplied program is under no obligation to exit on that EOF.
    drop(ready.stream);
    let shutdown = wait_bounded(&mut child, child_shutdown_budget());
    Ok(WakeSample {
        elapsed_ms: ready.elapsed_ms,
        signal: ready.signal,
        child: child_line,
        shutdown: shutdown.as_str().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without a resolvable ready-child program the axis is explicitly
    /// not-ready and names why; it never reports a zero wake latency.
    #[test]
    fn a_wake_axis_without_a_child_program_is_not_ready() {
        let dir = tempfile::tempdir().expect("tempdir");
        let settings = ChildSettings {
            samples: 2,
            timeout_ms: 500,
            hold_ms: 5_500,
            child: None,
        };
        let axis = measure_wake(dir.path(), &settings, EvidenceKind::SyntheticSmoke);
        assert_eq!(axis.readiness_signal, ReadinessSignal::TcpAccept);
        assert_eq!(axis.readiness_rule, READINESS_RULE);
        assert_eq!(axis.shutdown_rule, CHILD_SHUTDOWN_RULE);
        if axis.samples == 0 {
            assert!(!axis.spawn_to_ready_ms.is_measured());
            assert!(!axis.child.is_measured());
            assert!(
                !axis.errors.is_empty(),
                "an unmeasured wake axis must say why"
            );
        }
        let rendered = serde_json::to_string(&axis).expect("axis renders");
        assert!(rendered.contains("shutdown_outcomes"), "{rendered}");
    }
}
