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
