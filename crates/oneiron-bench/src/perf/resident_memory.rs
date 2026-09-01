//! ONE-1579 axis 4: resident memory across exactly ten READY child processes,
//! each holding its own open vault.
//!
//! The measurement is the ten children. The ARCH-0023b 50 MB per-vault budget
//! rides along as a comparison slot and is never the measurement.
//!
//! The ordering here is the whole point of the axis: every child must be
//! simultaneously ready when its RSS is read. The parent therefore spawns the
//! whole cohort, waits for exactly `required` completed accepts, PROVES every
//! child is still alive, and only then samples. A child that exited early — for
//! instance because its own hold expired while the parent was still accepting
//! its peers — fails the axis closed instead of quietly producing a smaller
//! sample. Plan admission keeps that from happening in the first place by
//! requiring `wake.hold_ms` to exceed the accept timeout by a sampling margin.
//!
//! Vault residency has a narrower proof boundary. The harness-owned
//! `perf wake-child` opens its vault before it connects, so its TCP readiness
//! also proves residency. A caller-supplied `wake.child` command is opaque: its
//! connect proves TCP readiness only, even if its arguments contain
//! `{vault_dir}`. Its RSS may be reported as a process diagnostic, but the axis
//! marks vault residency unproven and can never make that full run publishable.
//!
//! Release is parent-owned: the accepted streams are closed and every child is
//! then waited on under a bounded budget and terminated if it outlives it.

use std::collections::BTreeMap;
use std::net::TcpStream;
use std::path::Path;
use std::process::Child;
use std::time::Instant;

use super::axes::{ARCH_0023B_PER_VAULT_BUDGET_MB, CHILD_SHUTDOWN_RULE, ResidentMemoryAxis};
use super::cells::{Cell, EvidenceKind};
use super::child_process::{
    ChildSettings, WakeProbe, child_command, child_shutdown_budget, minimum_child_hold_ms,
    process_rss_bytes, resolve_child_program, spawn_child, wait_bounded,
};

const BUILTIN_VAULT_RESIDENCY_EVIDENCE: &str = "harness-owned perf wake-child opens the assigned vault before its TCP connect; a measured cohort therefore proves both readiness and vault residency";
const CUSTOM_VAULT_RESIDENCY_EVIDENCE: &str = "caller-supplied wake.child is opaque: its completed TCP connect proves readiness only; placeholder substitution does not prove that it opened or retained {vault_dir}, so this RSS is not per-vault residency evidence";
const UNMEASURED_VAULT_RESIDENCY_EVIDENCE: &str =
    "no complete child cohort was measured, so no process is claimed to hold an open vault";

/// One assembled, sampled and released cohort.
struct ReadyCohort {
    rss: Vec<u64>,
    shutdown_outcomes: BTreeMap<String, usize>,
}

/// Axis 4: resident memory with exactly `required` ready children, each
/// holding its own open vault.
pub(crate) fn measure_resident_memory(
    root: &Path,
    settings: &ChildSettings,
    required: usize,
    evidence_kind: EvidenceKind,
) -> ResidentMemoryAxis {
    let mut errors = Vec::new();
    let program = match resolve_child_program() {
        Ok(program) => program,
        Err(reason) => {
            errors.push(reason.clone());
            return not_ready(required, settings, errors, reason, evidence_kind);
        }
    };
    match hold_ready_children(&program, settings, root, required) {
        Ok(cohort) => measured(required, settings, cohort, errors, evidence_kind),
        Err(reason) => {
            errors.push(reason.clone());
            not_ready(required, settings, errors, reason, evidence_kind)
        }
    }
}

/// Spawns `required` children against ONE listener, waits for `required`
/// completed accepts, proves they are all still alive, and only then samples
/// each live child's RSS while every one of them is simultaneously ready.
fn hold_ready_children(
    program: &Path,
    settings: &ChildSettings,
    root: &Path,
    required: usize,
) -> Result<ReadyCohort, String> {
    let probe = WakeProbe::bind()?;
    let addr = probe.addr()?;
    let mut children = Vec::with_capacity(required);
    let started = Instant::now();
    for index in 0..required {
        let dir = root.join(format!("ready-{index}"));
        if let Err(error) = std::fs::create_dir_all(&dir) {
            kill_all(&mut children);
            return Err(format!("ready child vault dir failed: {error}"));
        }
        let (child_program, args) = child_command(
            settings.child.as_ref(),
            program,
            addr,
            &dir,
            settings.hold_ms,
        );
        match spawn_child(&child_program, &args) {
            Ok(child) => children.push(child),
            Err(reason) => {
                kill_all(&mut children);
                return Err(reason);
            }
        }
    }

    let streams = match accept_ready_cohort(&probe, required, started, settings) {
        Ok(streams) => streams,
        Err(reason) => {
            kill_all(&mut children);
            return Err(reason);
        }
    };

    let rss = match sample_live_cohort(&mut children, required) {
        Ok(rss) => rss,
        Err(reason) => {
            drop(streams);
            kill_all(&mut children);
            return Err(reason);
        }
    };

    // Sampling is done and every child was alive throughout it. Release them
    // by closing the accepted streams, then bound the wait on each.
    drop(streams);
    let mut shutdown_outcomes: BTreeMap<String, usize> = BTreeMap::new();
    for child in &mut children {
        let outcome = wait_bounded(child, child_shutdown_budget());
        *shutdown_outcomes
            .entry(outcome.as_str().to_owned())
            .or_insert(0) += 1;
    }
    Ok(ReadyCohort {
        rss,
        shutdown_outcomes,
    })
}

/// Waits for exactly `required` completed accepts, failing closed with how
/// many actually arrived.
///
/// The budget is ONE deadline for the whole cohort, not one per accept. That
/// is what makes [`minimum_child_hold_ms`] a real bound: the accept phase can
/// never outlast `wake.timeout_ms`, so a child whose hold exceeds that by the
/// sampling margin cannot expire before its peers are accepted and sampled.
fn cohort_deadline(started: Instant, settings: &ChildSettings) -> Result<Instant, String> {
    // `started` is captured before the first spawn. Child creation therefore
    // consumes this one advertised cohort budget; a new `Instant::now()` here
    // would silently add the entire spawn phase on top of it.
    started
        .checked_add(settings.accept_timeout())
        .ok_or_else(|| "the cohort readiness deadline overflowed Instant".to_owned())
}

fn accept_ready_cohort(
    probe: &WakeProbe,
    required: usize,
    started: Instant,
    settings: &ChildSettings,
) -> Result<Vec<TcpStream>, String> {
    let deadline = cohort_deadline(started, settings)?;
    let mut streams = Vec::with_capacity(required);
    for _ in 0..required {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        match probe.wait_ready(started, remaining) {
            Ok(ready) => streams.push(ready.stream),
            Err(reason) => {
                return Err(format!(
                    "only {} of {required} children reached a completed TCP accept within the \
                     {}ms cohort budget: {reason}",
                    streams.len(),
                    settings.timeout_ms
                ));
            }
        }
    }
    Ok(streams)
}

/// Reads every child's RSS, refusing to report a sample set unless all of them
/// were still alive when it was taken.
fn sample_live_cohort(children: &mut [Child], required: usize) -> Result<Vec<u64>, String> {
    let mut rss = Vec::with_capacity(required);
    for (index, child) in children.iter_mut().enumerate() {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!(
                "ready child {index} of {required} exited ({status}) before its resident memory \
                 was sampled, so the cohort was not simultaneously ready; a child's hold must \
                 outlast the parent's whole spawn, accept and sample phase"
            ));
        }
        match process_rss_bytes(child.id()) {
            Some(bytes) => rss.push(bytes),
            None => {
                return Err(
                    "per-process RSS is not readable on this platform, so the ten-ready-children \
                     measurement is unavailable"
                        .to_owned(),
                );
            }
        }
    }
    Ok(rss)
}

fn kill_all(children: &mut Vec<Child>) {
    for child in &mut *children {
        let _ = child.kill();
        let _ = child.wait();
    }
    children.clear();
}

fn measured(
    required: usize,
    settings: &ChildSettings,
    cohort: ReadyCohort,
    errors: Vec<String>,
    evidence_kind: EvidenceKind,
) -> ResidentMemoryAxis {
    let observed = cohort.rss.len();
    let total: u64 = cohort.rss.iter().sum();
    let mean = if observed == 0 {
        None
    } else {
        Some(total / observed as u64)
    };
    let budget_bytes = ARCH_0023B_PER_VAULT_BUDGET_MB * 1024 * 1024;
    let comparison = mean.map(|mean| {
        format!(
            "mean ready child RSS {mean} B vs the ARCH-0023b {ARCH_0023B_PER_VAULT_BUDGET_MB} MB \
             ({budget_bytes} B) per-vault budget slot"
        )
    });
    let builtin_child = settings.child.is_none();
    ResidentMemoryAxis {
        required_ready_children: required,
        ready_children_observed: observed,
        child_holds_open_vault: builtin_child && observed == required,
        vault_residency_evidence: if builtin_child {
            BUILTIN_VAULT_RESIDENCY_EVIDENCE
        } else {
            CUSTOM_VAULT_RESIDENCY_EVIDENCE
        },
        sampled_while_all_children_ready: observed == required,
        child_hold_ms: settings.hold_ms,
        minimum_child_hold_ms: minimum_child_hold_ms(settings.timeout_ms),
        per_child_rss_bytes: Cell::measured(cohort.rss),
        total_child_rss_bytes: Cell::measured(total),
        mean_child_rss_bytes: Cell::from_option(mean, "no ready child RSS sample was collected"),
        parent_rss_bytes: Cell::from_option(
            process_rss_bytes(std::process::id()),
            "the harness process RSS is not readable on this platform",
        ),
        arch_0023b_per_vault_budget_mb: ARCH_0023B_PER_VAULT_BUDGET_MB,
        budget_comparison: Cell::from_option(
            comparison,
            "no measured child RSS to compare against the budget slot",
        ),
        shutdown_rule: CHILD_SHUTDOWN_RULE,
        shutdown_outcomes: cohort.shutdown_outcomes,
        errors,
        evidence_kind,
    }
}

fn not_ready(
    required: usize,
    settings: &ChildSettings,
    errors: Vec<String>,
    reason: String,
    evidence_kind: EvidenceKind,
) -> ResidentMemoryAxis {
    ResidentMemoryAxis {
        required_ready_children: required,
        ready_children_observed: 0,
        child_holds_open_vault: false,
        vault_residency_evidence: UNMEASURED_VAULT_RESIDENCY_EVIDENCE,
        sampled_while_all_children_ready: false,
        child_hold_ms: settings.hold_ms,
        minimum_child_hold_ms: minimum_child_hold_ms(settings.timeout_ms),
        per_child_rss_bytes: Cell::not_ready(reason.clone()),
        total_child_rss_bytes: Cell::not_ready(reason.clone()),
        mean_child_rss_bytes: Cell::not_ready(reason.clone()),
        parent_rss_bytes: Cell::from_option(
            process_rss_bytes(std::process::id()),
            "the harness process RSS is not readable on this platform",
        ),
        arch_0023b_per_vault_budget_mb: ARCH_0023B_PER_VAULT_BUDGET_MB,
        budget_comparison: Cell::not_ready(reason),
        shutdown_rule: CHILD_SHUTDOWN_RULE,
        shutdown_outcomes: BTreeMap::new(),
        errors,
        evidence_kind,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::time::Duration;

    use super::*;

    fn settings(timeout_ms: u64) -> ChildSettings {
        ChildSettings {
            samples: 1,
            timeout_ms,
            hold_ms: minimum_child_hold_ms(timeout_ms),
            child: None,
        }
    }

    /// The parent must hold the WHOLE cohort connected at once: it accepts
    /// every child before it samples anything, and each stand-in stays
    /// connected across that window, leaving only when the parent releases it.
    #[test]
    fn the_whole_cohort_stays_connected_across_the_sampling_window() {
        let probe = WakeProbe::bind().expect("probe binds");
        let addr = probe.addr().expect("probe address");
        let required = 6;

        let stand_ins: Vec<std::thread::JoinHandle<bool>> = (0..required)
            .map(|_| {
                std::thread::spawn(move || {
                    let Ok(mut stream) = TcpStream::connect(addr) else {
                        return false;
                    };
                    // Stay ready until the parent closes the socket. A child
                    // that timed itself out here is exactly the failure the
                    // hold floor exists to prevent.
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                    let mut scratch = [0_u8; 1];
                    matches!(stream.read(&mut scratch), Ok(0))
                })
            })
            .collect();

        let started = Instant::now();
        let streams = accept_ready_cohort(&probe, required, started, &settings(20_000))
            .expect("the whole cohort is accepted");
        assert_eq!(
            streams.len(),
            required,
            "sampling may only start once every child is ready"
        );

        // The window a real run samples RSS in. Every stand-in must still be
        // connected here; none may have released itself.
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            stand_ins.iter().all(|handle| !handle.is_finished()),
            "no child may leave before the parent releases the cohort"
        );

        drop(streams);
        for stand_in in stand_ins {
            assert!(
                stand_in.join().expect("stand-in joins"),
                "each child leaves on the parent's EOF, not on its own timer"
            );
        }
    }

    /// The one readiness budget is armed before the first child spawn. Time
    /// spent creating children reduces the time left to accept them instead of
    /// receiving a fresh timeout after the loop.
    #[test]
    fn the_cohort_deadline_is_derived_from_the_pre_spawn_instant() {
        let settings = settings(20_000);
        let before_spawn = Instant::now();
        let deadline = cohort_deadline(before_spawn, &settings).expect("deadline");
        assert_eq!(
            deadline.checked_duration_since(before_spawn),
            Some(settings.accept_timeout())
        );

        let simulated_spawn_finish = before_spawn + Duration::from_secs(7);
        assert_eq!(
            deadline.checked_duration_since(simulated_spawn_finish),
            Some(Duration::from_secs(13)),
            "seven seconds spent spawning must consume seven seconds of the cohort budget"
        );
    }

    /// A cohort that does not assemble fails closed and says how many arrived.
    #[test]
    fn a_partial_cohort_fails_closed_naming_how_many_arrived() {
        let probe = WakeProbe::bind().expect("probe binds");
        let addr = probe.addr().expect("probe address");
        let arrived = 2;
        let stand_ins: Vec<TcpStream> = (0..arrived)
            .filter_map(|_| TcpStream::connect(addr).ok())
            .collect();
        assert_eq!(stand_ins.len(), arrived);
        assert!(
            stand_ins.iter().all(|stream| stream.peer_addr().is_ok()),
            "the arrived sockets stay connected through the accept window"
        );

        let error = accept_ready_cohort(&probe, 5, Instant::now(), &settings(200))
            .expect_err("a short cohort is refused");
        assert!(error.contains("only 2 of 5"), "{error}");
        drop(stand_ins);
    }

    /// Without a resolvable child program the axis is not-ready and still
    /// reports the hold floor it would have been held to.
    #[test]
    fn an_unavailable_child_program_reports_not_ready_with_its_hold_floor() {
        let settings = settings(20_000);
        let axis = not_ready(
            10,
            &settings,
            vec!["no child program".to_owned()],
            "no child program".to_owned(),
            EvidenceKind::SyntheticSmoke,
        );
        assert_eq!(axis.required_ready_children, 10);
        assert_eq!(axis.ready_children_observed, 0);
        assert!(!axis.sampled_while_all_children_ready);
        assert_eq!(axis.minimum_child_hold_ms, minimum_child_hold_ms(20_000));
        assert!(axis.child_hold_ms >= axis.minimum_child_hold_ms);
        assert!(matches!(axis.per_child_rss_bytes, Cell::NotReady { .. }));
        assert!(matches!(axis.total_child_rss_bytes, Cell::NotReady { .. }));
    }

    /// A custom command is opaque. Even when ten of its processes connect and
    /// have readable RSS, the TCP handshake does not prove they used
    /// `{vault_dir}` or retained an open vault.
    #[test]
    fn a_custom_child_cohort_never_claims_vault_residency() {
        let mut custom = settings(20_000);
        custom.child = Some(super::super::child_process::ChildCommandPlan {
            program: "/usr/bin/custom-child".to_owned(),
            args: vec![
                "--ready={ready_addr}".to_owned(),
                "--vault={vault_dir}".to_owned(),
            ],
        });
        let axis = measured(
            10,
            &custom,
            ReadyCohort {
                rss: vec![1_024; 10],
                shutdown_outcomes: BTreeMap::new(),
            },
            Vec::new(),
            EvidenceKind::MeasuredWallClock,
        );

        assert_eq!(axis.ready_children_observed, 10);
        assert!(axis.sampled_while_all_children_ready);
        assert!(axis.total_child_rss_bytes.is_measured());
        assert!(
            !axis.child_holds_open_vault,
            "a custom child's TCP connect proves readiness, not vault residency"
        );
        assert!(
            axis.vault_residency_evidence.contains("readiness only"),
            "{}",
            axis.vault_residency_evidence
        );
        assert!(
            axis.vault_residency_evidence.contains("does not prove"),
            "{}",
            axis.vault_residency_evidence
        );
    }

    /// A measured cohort records that every sample was taken while all the
    /// children were ready, plus how each of them left.
    #[test]
    fn a_measured_cohort_records_readiness_and_shutdown() {
        let settings = settings(20_000);
        let mut shutdown = BTreeMap::new();
        shutdown.insert("exited".to_owned(), 10_usize);
        let axis = measured(
            10,
            &settings,
            ReadyCohort {
                rss: vec![1_024_000; 10],
                shutdown_outcomes: shutdown,
            },
            Vec::new(),
            EvidenceKind::MeasuredWallClock,
        );
        assert_eq!(axis.ready_children_observed, 10);
        assert!(axis.sampled_while_all_children_ready);
        assert!(axis.child_holds_open_vault);
        assert!(
            axis.vault_residency_evidence
                .contains("opens the assigned vault")
        );
        assert_eq!(
            axis.total_child_rss_bytes.value().copied(),
            Some(10_240_000)
        );
        assert_eq!(axis.shutdown_outcomes.get("exited").copied(), Some(10));
        assert_eq!(axis.shutdown_rule, CHILD_SHUTDOWN_RULE);
    }
}
