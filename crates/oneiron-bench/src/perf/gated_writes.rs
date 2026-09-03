//! ONE-1579 axis 5: gated-write throughput through the public claim door.
//!
//! Engine boundary: writes are `ClaimCandidate` + `WriteEnvelope` through
//! `BatchBuilder::claim_candidate` and `commit`, and the gate ledger is read
//! back through `Vault::gate_decisions`. There is no raw LMDB write and no
//! engine-internal door anywhere on this path.
//!
//! Throughput is derived from SUCCESSFUL commits. A window in which some
//! commits failed did not achieve the attempt rate, and a window in which none
//! succeeded has no successful-commit rate at all — it is `not_ready`, never a
//! zero and never the attempt count divided by elapsed time. The attempt rate
//! is still reported, under its own name, so neither number can be read as the
//! other.
//!
//! The warmup floor is counted the same honest way: it counts successful
//! `ClaimCandidate` commits, not the number of loop iterations requested. A
//! transient gate or storage failure therefore cannot consume a warmup attempt
//! and still make the timed window claim that the successful warmup floor was
//! reached.

use std::collections::BTreeMap;
use std::time::Instant;

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

use super::axes::{
    COMMITS_PER_SECOND_NUMERATOR, FULL_RUN_MIN_GATED_WRITE_MEASURED,
    FULL_RUN_MIN_GATED_WRITE_WARMUP, GATED_WRITE_FLOOR_RULE, GATED_WRITE_PATH, GatedWriteAxis,
};
use super::cells::{Cell, EvidenceKind, Percentiles};
use super::corpus::BENCH_ENTITY_TYPE;

/// Predicate used by the gated-write axis. `profile.*` is an ordinary,
/// non-reserved namespace, so the write travels the public claim door.
pub(crate) const GATED_WRITE_PREDICATE: &str = "profile.bench_perf_gated_write";

/// Actor and subject fixtures for the gated-write axis.
fn gated_write_actors() -> Result<(EntityId, EntityId), String> {
    let actor = EntityId::from_bytes([0xA7; 16])
        .map_err(|error| format!("gated-write actor id failed: {error}"))?;
    let subject = EntityId::from_bytes([0x5B; 16])
        .map_err(|error| format!("gated-write subject id failed: {error}"))?;
    Ok((actor, subject))
}

fn gated_write_envelope(actor: EntityId) -> Result<WriteEnvelope, String> {
    let provenance = WriteProvenance::new(Value::Map(vec![
        (Value::from("harness"), Value::from("oneiron-bench perf")),
        (Value::from("ticket"), Value::from("ONE-1579")),
    ]))
    .map_err(|error| format!("gated-write provenance failed: {error}"))?;
    Ok(WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        provenance,
        ClaimApprovalStatus::Auto,
    ))
}

/// One commit carrying exactly one claim candidate, so a commit and a gate
/// decision stand in one-to-one correspondence.
fn commit_gated_claim(
    vault: &Vault,
    envelope: &WriteEnvelope,
    subject: EntityId,
    index: usize,
) -> Result<(), oneiron::Error> {
    let claim_id = EntityId::now();
    let now = 1_000_000 + index as u64;
    let candidate = ClaimCandidate::new(
        GATED_WRITE_PREDICATE,
        ClaimSubject::Entity(subject),
        Value::from(format!("perf-{index}")),
        1.0,
    )
    .with_scope(Value::Map(vec![(
        Value::from("sensitivity"),
        Value::from("public"),
    )]));
    vault
        .batch()
        .claim_candidate(
            &claim_id,
            candidate,
            envelope,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .commit()
}

/// The measured window, split by outcome so a failed attempt can never be
/// counted as successful throughput.
struct CommitWindow {
    commits_ok: usize,
    ok_latency_ms: Vec<f64>,
    failed_latency_ms: Vec<f64>,
    error_kinds: BTreeMap<String, usize>,
    wall_clock_ms: f64,
}

/// Untimed warmup outcomes. `commits_ok`, never `attempts`, is what may satisfy
/// the full-run warmup floor.
struct WarmupWindow {
    attempts: usize,
    commits_ok: usize,
    error_kinds: BTreeMap<String, usize>,
}

impl WarmupWindow {
    fn commit_errors(&self) -> usize {
        self.attempts.saturating_sub(self.commits_ok)
    }
}

/// Runs exactly `attempts` warmup operations and keeps their outcomes instead
/// of discarding every `Result`. The small generic seam gives the failure path
/// a deterministic regression without needing to make LMDB fail on demand.
fn measure_warmup<F>(attempts: usize, mut commit: F) -> WarmupWindow
where
    F: FnMut(usize) -> Result<(), String>,
{
    let mut commits_ok = 0_usize;
    let mut error_kinds = BTreeMap::new();
    for index in 0..attempts {
        match commit(index) {
            Ok(()) => commits_ok += 1,
            Err(kind) => *error_kinds.entry(kind).or_insert(0) += 1,
        }
    }
    WarmupWindow {
        attempts,
        commits_ok,
        error_kinds,
    }
}

/// Successful-commit throughput. A window in which NO commit succeeded has no
/// successful-commit rate to report, so it is explicitly `not_ready` rather
/// than a zero or the attempt rate wearing a successful-commit label.
fn successful_commits_per_second(
    commits_ok: usize,
    attempts: usize,
    wall_clock_ms: f64,
) -> Cell<f64> {
    if attempts == 0 || wall_clock_ms <= 0.0 {
        return Cell::not_ready("no measured gated-write commit window was opened");
    }
    if commits_ok == 0 {
        return Cell::not_ready(format!(
            "none of the {attempts} measured gated-write commits succeeded, so there is no \
             successful-commit throughput; see attempted_commits_per_second and error_kinds"
        ));
    }
    Cell::measured(commits_ok as f64 / (wall_clock_ms / 1e3))
}

/// The ATTEMPT rate, reported under its own name beside the successful rate.
fn attempted_commits_per_second(attempts: usize, wall_clock_ms: f64) -> Cell<f64> {
    if attempts == 0 || wall_clock_ms <= 0.0 {
        return Cell::not_ready("no measured gated-write commit window was opened");
    }
    Cell::measured(attempts as f64 / (wall_clock_ms / 1e3))
}

/// Axis 5: gated-write commits per second, error counts, and the gate ledger
/// read back to prove one decision was recorded per commit.
pub(crate) fn measure_gated_writes(
    vault: &Vault,
    warmup: usize,
    measured: usize,
    evidence_kind: EvidenceKind,
) -> Result<GatedWriteAxis, String> {
    let (actor, subject) = gated_write_actors()?;
    let envelope = gated_write_envelope(actor)?;
    for (id, label, entity_type) in [
        (actor, "actor", ENTITY_TYPE_PERSON),
        (subject, "subject", BENCH_ENTITY_TYPE),
    ] {
        vault
            .put_entity(
                &id,
                entity_type,
                TimeRange { start: 1, end: 1 },
                1,
                b"perf-gated-write",
            )
            .map_err(|error| format!("gated-write {label} seed failed: {error}"))?;
    }
    let warmup_window = measure_warmup(warmup, |index| {
        commit_gated_claim(vault, &envelope, subject, index)
            .map_err(|error| format!("{:?}", error.kind()))
    });

    let ledger_limit = warmup.saturating_add(measured).saturating_add(64);
    let baseline = vault
        .gate_decisions(ledger_limit)
        .map_err(|error| format!("gate ledger baseline read failed: {error}"))?
        .len();

    let window = measure_window(vault, &envelope, subject, warmup, measured);

    let decisions = vault
        .gate_decisions(ledger_limit)
        .map_err(|error| format!("gate ledger read failed: {error}"))?;
    let recorded = decisions.len().saturating_sub(baseline);
    let mut gate_outcomes: BTreeMap<String, usize> = BTreeMap::new();
    for decision in decisions.iter().take(recorded) {
        *gate_outcomes.entry(decision.outcome.clone()).or_insert(0) += 1;
    }

    let commit_errors = measured - window.commits_ok;
    let one_decision_per_commit = recorded == measured;
    let warmup_commits = warmup_window.commits_ok;
    let warmup_commit_errors = warmup_window.commit_errors();
    Ok(GatedWriteAxis {
        write_path: GATED_WRITE_PATH,
        warmup_attempts: warmup_window.attempts,
        warmup_commits,
        warmup_commit_errors,
        warmup_error_kinds: warmup_window.error_kinds,
        measured_commits: measured,
        commits_ok: window.commits_ok,
        commit_errors,
        error_kinds: window.error_kinds,
        wall_clock_ms: window.wall_clock_ms,
        commits_per_second: successful_commits_per_second(
            window.commits_ok,
            measured,
            window.wall_clock_ms,
        ),
        commits_per_second_numerator: COMMITS_PER_SECOND_NUMERATOR,
        attempted_commits_per_second: attempted_commits_per_second(measured, window.wall_clock_ms),
        commit_latency_ms: Cell::from_option(
            Percentiles::from_samples(&window.ok_latency_ms),
            "no gated-write commit SUCCEEDED, so no successful-commit latency was timed",
        ),
        failed_attempt_latency_ms: Cell::from_option(
            Percentiles::from_samples(&window.failed_latency_ms),
            "no gated-write commit failed in the measured window",
        ),
        gate_decisions_recorded: recorded,
        one_decision_per_commit,
        gate_enforcement_valid: commit_errors == 0 && one_decision_per_commit && measured > 0,
        gate_outcomes,
        meets_full_run_floor: warmup_commits >= FULL_RUN_MIN_GATED_WRITE_WARMUP
            && measured >= FULL_RUN_MIN_GATED_WRITE_MEASURED,
        floor: GATED_WRITE_FLOOR_RULE,
        evidence_kind,
    })
}

/// The timed window itself: one commit per iteration, each attributed to the
/// successful or the failed latency population.
fn measure_window(
    vault: &Vault,
    envelope: &WriteEnvelope,
    subject: EntityId,
    warmup: usize,
    measured: usize,
) -> CommitWindow {
    let mut window = CommitWindow {
        commits_ok: 0,
        ok_latency_ms: Vec::with_capacity(measured),
        failed_latency_ms: Vec::new(),
        error_kinds: BTreeMap::new(),
        wall_clock_ms: 0.0,
    };
    let started = Instant::now();
    for index in 0..measured {
        let step = Instant::now();
        let outcome = commit_gated_claim(vault, envelope, subject, warmup + index);
        let elapsed_ms = step.elapsed().as_secs_f64() * 1e3;
        match outcome {
            Ok(()) => {
                window.commits_ok += 1;
                window.ok_latency_ms.push(elapsed_ms);
            }
            Err(error) => {
                window.failed_latency_ms.push(elapsed_ms);
                let kind = error.kind();
                *window.error_kinds.entry(format!("{kind:?}")).or_insert(0) += 1;
            }
        }
    }
    window.wall_clock_ms = started.elapsed().as_secs_f64() * 1e3;
    window
}

#[cfg(test)]
mod tests {
    use super::super::corpus::perf_vault_config;
    use super::*;

    /// One commit carries exactly one claim candidate, so the gate ledger must
    /// grow by exactly one decision per commit — including for a commit the
    /// gate refuses, whose denial receipt is itself a decision.
    #[test]
    fn gated_write_fixture_records_one_decision_per_commit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), perf_vault_config(16, 2)).expect("vault opens");
        let commits = 5_usize;

        let axis = measure_gated_writes(&vault, 2, commits, EvidenceKind::SyntheticSmoke)
            .expect("gated-write axis measures");

        assert_eq!(axis.warmup_attempts, 2);
        assert_eq!(
            axis.warmup_commits + axis.warmup_commit_errors,
            axis.warmup_attempts,
            "every warmup attempt must be accounted for by outcome"
        );
        assert_eq!(
            axis.warmup_error_kinds.values().sum::<usize>(),
            axis.warmup_commit_errors
        );
        assert_eq!(axis.measured_commits, commits);
        assert_eq!(
            axis.gate_decisions_recorded, commits,
            "the gate ledger must record exactly one decision per measured commit (gate outcomes: \
             {:?}, commit errors: {:?})",
            axis.gate_outcomes, axis.error_kinds
        );
        assert!(axis.one_decision_per_commit);
        assert_eq!(
            axis.commits_ok + axis.commit_errors,
            commits,
            "every commit is accounted for as an ok or an error"
        );
        assert_eq!(
            axis.gate_outcomes.values().sum::<usize>(),
            commits,
            "every recorded decision is attributed to an outcome"
        );
        // The SUCCESSFUL-commit populations exist exactly when a commit
        // succeeded, and the failed-attempt population exactly when one did
        // not. Neither is allowed to stand in for the other.
        assert_eq!(
            axis.commit_latency_ms.is_measured(),
            axis.commits_ok > 0,
            "successful-commit latency exists exactly when a commit succeeded ({} ok, {} failed)",
            axis.commits_ok,
            axis.commit_errors
        );
        assert_eq!(
            axis.commits_per_second.is_measured(),
            axis.commits_ok > 0,
            "successful-commit throughput exists exactly when a commit succeeded"
        );
        assert_eq!(
            axis.failed_attempt_latency_ms.is_measured(),
            axis.commit_errors > 0,
            "failed-attempt latency exists exactly when an attempt failed"
        );
        assert!(
            axis.attempted_commits_per_second.is_measured(),
            "the attempt rate is reported whatever the outcomes were"
        );
        assert_eq!(axis.gate_enforcement_valid, axis.commit_errors == 0);
        assert!(
            !axis.meets_full_run_floor,
            "a five-commit fixture is deliberately below the full-run floor"
        );
        assert_eq!(axis.write_path, GATED_WRITE_PATH);
        assert_eq!(
            axis.commits_per_second_numerator,
            COMMITS_PER_SECOND_NUMERATOR
        );
    }

    /// Requested attempts are not warmup commits. Only successful
    /// ClaimCandidate commits count toward the floor, while every failure is
    /// retained by kind for the report.
    #[test]
    fn the_warmup_floor_counts_successful_commits_not_attempts() {
        let outcomes = measure_warmup(6, |index| match index {
            1 | 4 => Err("transient_storage".to_owned()),
            5 => Err("gate_refused".to_owned()),
            _ => Ok(()),
        });

        assert_eq!(outcomes.attempts, 6);
        assert_eq!(outcomes.commits_ok, 3);
        assert_eq!(outcomes.commit_errors(), 3);
        assert_eq!(outcomes.error_kinds.get("transient_storage"), Some(&2));
        assert_eq!(outcomes.error_kinds.get("gate_refused"), Some(&1));
        assert!(
            outcomes.commits_ok < outcomes.attempts,
            "failed loop iterations must not masquerade as warmup commits"
        );
    }

    /// The two rates must agree exactly when nothing failed, and must diverge
    /// the moment something does. Whichever way this fixture's gate decides,
    /// one of the two branches is exercised and both are load-bearing.
    #[test]
    fn the_successful_and_attempted_rates_agree_only_when_nothing_failed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), perf_vault_config(16, 2)).expect("vault opens");
        let axis = measure_gated_writes(&vault, 1, 4, EvidenceKind::SyntheticSmoke)
            .expect("gated-write axis measures");
        let attempted = axis
            .attempted_commits_per_second
            .measured_f64()
            .expect("the attempt rate is always reported");

        if axis.commit_errors == 0 {
            let successful = axis
                .commits_per_second
                .measured_f64()
                .expect("a clean window has a successful rate");
            assert!(
                (successful - attempted).abs() < 1e-9,
                "with no failures the two rates coincide: {successful} vs {attempted}"
            );
            assert!(axis.gate_enforcement_valid);
            assert!(
                !axis.failed_attempt_latency_ms.is_measured(),
                "nothing failed, so there is no failed-attempt latency population"
            );
        } else {
            assert!(
                !axis.gate_enforcement_valid,
                "a failed commit is failed gate enforcement"
            );
            assert!(axis.failed_attempt_latency_ms.is_measured());
            match axis.commits_per_second.measured_f64() {
                Some(successful) => assert!(
                    successful < attempted,
                    "a window with failures achieved LESS than it attempted: {successful} vs \
                     {attempted}"
                ),
                None => assert_eq!(
                    axis.commits_ok, 0,
                    "the successful rate is only absent when nothing succeeded"
                ),
            }
            assert!(
                !axis.error_kinds.is_empty(),
                "a failed commit must name its error kind"
            );
        }
    }

    /// Throughput counts SUCCESSFUL commits. A window with failures must not
    /// report the attempt rate under the successful-commit name, and a window
    /// with no success at all has no rate to report.
    #[test]
    fn throughput_is_derived_from_successful_commits_only() {
        // Ten attempts in one second: seven of them succeeded.
        let partial = successful_commits_per_second(7, 10, 1_000.0)
            .measured_f64()
            .expect("seven successes give a rate");
        assert!(
            (partial - 7.0).abs() < 1e-9,
            "the numerator is commits_ok, not the attempt count, got {partial}"
        );
        let attempted = attempted_commits_per_second(10, 1_000.0)
            .measured_f64()
            .expect("the attempt rate is still reported");
        assert!(
            (attempted - 10.0).abs() < 1e-9,
            "the attempt rate keeps its own name and value, got {attempted}"
        );
        assert!(
            partial < attempted,
            "a window with failures must report LESS successful throughput than attempts"
        );

        // Nothing succeeded: there is no successful-commit throughput.
        let none = successful_commits_per_second(0, 10, 1_000.0);
        assert!(
            !none.is_measured(),
            "a zero-success window has no successful-commit rate, not a zero one"
        );
        let rendered = serde_json::to_string(&none).expect("cell renders");
        assert!(rendered.contains("not_ready"), "{rendered}");
        assert!(
            rendered.contains("attempted_commits_per_second"),
            "{rendered}"
        );
        assert!(
            attempted_commits_per_second(10, 1_000.0).is_measured(),
            "the attempts still happened and are still reported"
        );

        // No window at all is not_ready on both counts.
        assert!(!successful_commits_per_second(0, 0, 0.0).is_measured());
        assert!(!attempted_commits_per_second(0, 0.0).is_measured());
    }
}
