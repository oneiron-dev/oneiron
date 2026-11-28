//! The line's notices (design pass 32 r2, section 6): a fact about a lane-economy line, told to
//! the agents the line's lead Grants name, in the same write as the fact.
//!
//! - A notice goes to the actors of the line's current leads: each agent a lead Grant that
//!   stands now names, once. Whoever started the job is told nothing for having started it. A
//!   review overdue also goes to the vault's owners, and a line none of whose lead Grants stands
//!   tells its owners, so a fact is never told to no one.
//! - It is keyed by its fact: the claim for a unit's end or its unconfirmed job, the arm and rung
//!   for an overdue review, the machine and its boot for a returning machine. One row per
//!   recipient, whose id derives from the producer, that key and the recipient, so the same fact
//!   again writes nothing and a crash before the commit loses nothing (the inbox's replay).
//! - A notice is never a launch, a verdict, a refund or a source of elapsed time. The lane's wake
//!   tool reads them by cursor (LM-5); no session is resumed.
//!
//! Who writes which:
//! - a unit's end: [`super::settle_unit_in_txn`], for a fresh terminal only, in its own write;
//! - a unit unconfirmed and a review overdue: the clock makes them due, so the engine job
//!   [`LINE_NOTICES_JOB`] raises them at its cadence (`lines.notices.every`, hourly), for a vault
//!   no later write comes to;
//! - a machine that answers again: [`notify_machine_returned_in_txn`], which the issuer's guard
//!   calls on the machine's unreachable-to-answering transition (pass 33).

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::bytes_to_hex_lower;
use crate::experiment_arm::RungState;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::schedule::{
    ArmBy, Armed, JobPass, JobResult, JobSpec, Late, RETRY_FIRST_SECS, Ran, When,
};
use crate::{EntityId, Vault};

use super::claim::{ClaimKey, ClaimState, UnitClaim, UnitEnd, claims_in_txn};
use super::fold::GpuLine;
use super::store::line_in_txn;

/// A job's maximum plus this long with no end is unconfirmed (section 6).
const UNCONFIRMED_AFTER_MAXIMUM_MS: u64 = 3_600_000;

/// Which fact a line notice tells. Its producer is the notice's `source.producer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LineNoticeKind {
    /// A unit's claim ended `Settled`: its end cause, measured and charged seconds.
    UnitEnded,
    /// A unit's claim ended `Released`: the reason.
    UnitReleased,
    /// A unit's claim ended `BoxLost`: the machine and the run time last seen.
    UnitBoxLost,
    /// The owner wrote a unit's unconfirmed job off at zero: the machine.
    UnitWrittenOff,
    /// A started unit's job passed its maximum plus one hour with no end: the machine, since
    /// when.
    UnitUnconfirmed,
    /// A promoted rung waited the line's review bound for its review: the arm and the rung.
    /// Told to the vault's owners as well.
    ReviewOverdue,
    /// A machine with a unit lost on it answers again under a new boot: the machine, the boot.
    MachineReturned,
}

impl LineNoticeKind {
    /// The notice's `source.producer`.
    #[must_use]
    pub const fn producer(self) -> &'static str {
        match self {
            Self::UnitEnded => "line.unit_ended",
            Self::UnitReleased => "line.unit_released",
            Self::UnitBoxLost => "line.unit_box_lost",
            Self::UnitWrittenOff => "line.unit_written_off",
            Self::UnitUnconfirmed => "line.unit_unconfirmed",
            Self::ReviewOverdue => "line.review_overdue",
            Self::MachineReturned => "line.machine_returned",
        }
    }

    /// Whether the vault's owners are told beside the leads.
    const fn tells_owners(self) -> bool {
        matches!(self, Self::ReviewOverdue)
    }
}

/// The agents the line's lead Grants name, each once, for each Grant that stands now: a live
/// agent Grant, not withdrawn and not past its end.
fn standing_lead_agents_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    line: &GpuLine,
) -> crate::Result<BTreeSet<EntityId>> {
    let mut agents = BTreeSet::new();
    if line.leads.is_empty() {
        return Ok(agents);
    }
    let now = vault.grant_judgement_secs_in_txn(txn)?;
    for standing in vault.agent_grants_in_txn(txn)? {
        if line.leads.contains(&standing.id)
            && standing.stands_at(now)
            && !crate::authority::grant_known_withdrawn_in_txn(&vault.store, txn, standing.id)
        {
            agents.insert(standing.grant.member_ref);
        }
    }
    Ok(agents)
}

/// Tells `kind` about `subject` to the line's leads, and to the vault's owners for a review
/// overdue or when no lead Grant of the line stands, in the caller's write: one notice per
/// recipient, keyed by `key` and the recipient. Returns the notices this call wrote; the same
/// fact again writes none.
///
/// # Errors
///
/// A store failure.
pub(crate) fn notify_line_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    line: &GpuLine,
    kind: LineNoticeKind,
    key: &str,
    subject: &EntityId,
    detail: &str,
) -> crate::Result<Vec<EntityId>> {
    let mut recipients = standing_lead_agents_in_txn(vault, wtxn, line)?;
    if kind.tells_owners() || recipients.is_empty() {
        recipients.extend(crate::policy_model::owners_in_txn(vault, wtxn)?);
    }
    let created_at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let mut written = Vec::new();
    for recipient in recipients {
        let event = NotificationEvent {
            kind: NotificationKind::LineNotice,
            source: NotificationSource {
                producer: kind.producer().to_owned(),
                event: format!("{key}:{}", recipient.to_hex()),
                result: Some(subject.to_hex()),
                detail: Some(detail.to_owned()),
                ..NotificationSource::default()
            },
            subject_refs: Vec::new(),
            recipient: Some(recipient),
            created_at,
            origin_conversation: None,
        };
        let (id, fresh) = vault.stage_notification_in_txn(wtxn, &event)?;
        if fresh {
            written.push(id);
        }
    }
    Ok(written)
}

/// A claim's key as a notice key: its row key bytes, in lower hex.
fn claim_key_words(key: &ClaimKey) -> String {
    bytes_to_hex_lower(&key.key_bytes())
}

/// The unit a claim is, as notice words.
fn unit_words(claim: &UnitClaim) -> String {
    format!(
        "arm={} rung={} attempt={}",
        claim.arm.to_hex(),
        claim.rung,
        claim.attempt
    )
}

/// A machine as notice words: its id, or `unknown`.
fn machine_words(machine: Option<EntityId>) -> String {
    machine.map_or_else(|| "unknown".to_owned(), |machine| machine.to_hex())
}

/// Tells the end `claim` now holds to its line's leads, in the settle's own write: one notice
/// per terminal. [`super::settle_unit_in_txn`] calls it for a fresh terminal only, so a replayed
/// settle writes none. A claim that has not ended, or whose line is gone, tells nothing.
///
/// # Errors
///
/// A store failure.
pub(crate) fn notify_unit_end_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim: &UnitClaim,
) -> crate::Result<Vec<EntityId>> {
    let ClaimState::Ended(terminal) = &claim.state else {
        return Ok(Vec::new());
    };
    let Some(line) = line_in_txn(vault, wtxn, &claim.line)? else {
        return Ok(Vec::new());
    };
    let unit = unit_words(claim);
    let (kind, detail) = match &terminal.end {
        UnitEnd::Settled => (
            LineNoticeKind::UnitEnded,
            format!(
                "{unit} end={} measured_secs={} charged_secs={}",
                terminal.node_end.as_deref().unwrap_or("unknown"),
                terminal.measured_secs,
                terminal.charged_secs
            ),
        ),
        UnitEnd::Released(reason) => (
            LineNoticeKind::UnitReleased,
            format!("{unit} reason={reason}"),
        ),
        UnitEnd::BoxLost => (
            LineNoticeKind::UnitBoxLost,
            format!(
                "{unit} machine={} last_seen_secs={}",
                machine_words(terminal.machine),
                terminal.lost_secs
            ),
        ),
        // A write-off has no machine answer, so it names the machine the claim was pinned to,
        // as its `unit_unconfirmed` notice did.
        UnitEnd::WrittenOff { .. } => (
            LineNoticeKind::UnitWrittenOff,
            format!(
                "{unit} machine={}",
                machine_words(terminal.machine.or(claim.machine))
            ),
        ),
    };
    notify_line_in_txn(
        vault,
        wtxn,
        &line,
        kind,
        &claim_key_words(&claim.key()),
        &claim.id,
        &detail,
    )
}

/// When a started claim's job became unconfirmed: the job's start plus the claim's maximum plus
/// one hour (section 6). A started claim whose job row is missing counts from its reservation.
fn unconfirmed_from_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: &UnitClaim,
) -> crate::Result<u64> {
    let started_at_ms = vault
        .gpu_job_in_txn(txn, &claim.id)?
        .map_or(claim.reserved_at_ms, |job| job.created_at_ms);
    Ok(started_at_ms
        .saturating_add(claim.reserved_secs.saturating_mul(1_000))
        .saturating_add(UNCONFIRMED_AFTER_MAXIMUM_MS))
}

/// Raises the notices the clock has made due by `now_ms`, in the caller's write: each started
/// unit whose job passed its maximum plus one hour with no end (`unit_unconfirmed`, keyed by
/// its claim), and each promoted rung that has waited its line's `review_overdue_secs` since the
/// verdict (`review_overdue`, keyed by arm and rung, to the leads and the owners). Returns how
/// many notices it wrote; a fact told before writes none.
///
/// # Errors
///
/// A store failure.
pub(crate) fn raise_due_line_notices_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    now_ms: u64,
) -> crate::Result<u64> {
    let mut lines: BTreeMap<EntityId, Option<GpuLine>> = BTreeMap::new();
    let mut written = 0_usize;
    for claim in claims_in_txn(vault, wtxn)? {
        if claim.state != ClaimState::Started {
            continue;
        }
        let since = unconfirmed_from_in_txn(vault, wtxn, &claim)?;
        if since > now_ms {
            continue;
        }
        if !lines.contains_key(&claim.line) {
            lines.insert(claim.line, line_in_txn(vault, wtxn, &claim.line)?);
        }
        let Some(Some(line)) = lines.get(&claim.line) else {
            continue;
        };
        let detail = format!(
            "{} machine={} since_ms={since}",
            unit_words(&claim),
            machine_words(claim.machine)
        );
        written += notify_line_in_txn(
            vault,
            wtxn,
            line,
            LineNoticeKind::UnitUnconfirmed,
            &claim_key_words(&claim.key()),
            &claim.id,
            &detail,
        )?
        .len();
    }
    for arm in vault.experiment_arms_in_txn(wtxn)? {
        for rung in &arm.rungs {
            if rung.state != RungState::AwaitingReview {
                continue;
            }
            let Some(verdict) = &rung.verdict else {
                continue;
            };
            if !lines.contains_key(&arm.line) {
                lines.insert(arm.line, line_in_txn(vault, wtxn, &arm.line)?);
            }
            let Some(Some(line)) = lines.get(&arm.line) else {
                continue;
            };
            let due_at_ms = verdict
                .at_ms
                .saturating_add(line.budget.review_overdue_secs.saturating_mul(1_000));
            if due_at_ms > now_ms {
                continue;
            }
            let detail = format!(
                "arm={} rung={} waiting_since_ms={}",
                arm.id.to_hex(),
                rung.rung,
                verdict.at_ms
            );
            written += notify_line_in_txn(
                vault,
                wtxn,
                line,
                LineNoticeKind::ReviewOverdue,
                &format!("{}:{}", arm.id.to_hex(), rung.rung),
                &arm.id,
                &detail,
            )?
            .len();
        }
    }
    Ok(u64::try_from(written).unwrap_or(u64::MAX))
}

/// Tells the leads of each line with a unit lost on `machine` that it answers again under boot
/// `boot_id`, in the caller's write (section 6, `machine_returned`). A line counts when one of
/// its claims ended `BoxLost` on the machine within the line's `machine_returned_window_secs`
/// before `now_ms`, or is started on it (its pinned machine) and unconfirmed now, whatever its
/// age: a claim unconfirmed now was unconfirmed within the window. Keyed by machine
/// and boot: one notice per outage and recipient. The issuer's guard calls it on the machine's
/// unreachable-to-answering transition (pass 33, section 7). Returns the notices it wrote.
///
/// # Errors
///
/// A store failure.
pub fn notify_machine_returned_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    machine: &EntityId,
    boot_id: &str,
    now_ms: u64,
) -> crate::Result<Vec<EntityId>> {
    let mut told = BTreeSet::new();
    let mut written = Vec::new();
    let key = format!("{}:{boot_id}", machine.to_hex());
    let detail = format!("machine={} boot_id={boot_id}", machine.to_hex());
    for claim in claims_in_txn(vault, wtxn)? {
        if told.contains(&claim.line) {
            continue;
        }
        // The last moment the claim stood lost on the machine: a box-lost end's time, or now for
        // a started claim that is unconfirmed now.
        let last_lost_ms = match &claim.state {
            ClaimState::Ended(terminal)
                if terminal.end == UnitEnd::BoxLost && terminal.machine == Some(*machine) =>
            {
                Some(terminal.ended_at_ms)
            }
            ClaimState::Started if claim.machine == Some(*machine) => {
                let since = unconfirmed_from_in_txn(vault, wtxn, &claim)?;
                (since <= now_ms).then_some(now_ms)
            }
            _ => None,
        };
        let Some(last_lost_ms) = last_lost_ms else {
            continue;
        };
        let Some(line) = line_in_txn(vault, wtxn, &claim.line)? else {
            continue;
        };
        let window_ms = line
            .budget
            .machine_returned_window_secs
            .saturating_mul(1_000);
        if last_lost_ms.saturating_add(window_ms) < now_ms {
            continue;
        }
        told.insert(claim.line);
        written.extend(notify_line_in_txn(
            vault,
            wtxn,
            &line,
            LineNoticeKind::MachineReturned,
            &key,
            machine,
            &detail,
        )?);
    }
    Ok(written)
}

/// The line notices the clock makes due (`unit_unconfirmed`, `review_overdue`), raised at the
/// cadence `lines.notices.every` (hourly): the trigger for a vault no later write comes to. Each
/// is keyed by its fact, so a run that finds nothing new writes nothing.
pub(crate) static LINE_NOTICES_JOB: JobSpec = JobSpec {
    code: "lines.notices",
    when: When::Setting(&super::setting_keys::LINE_NOTICES_EVERY),
    arm_by: ArmBy::Engine,
    late: Late::Run,
    retry_first_secs: RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: false,
    at_open: false,
    once_per_pass: true,
    runs_here: |_vault, _txn| Ok(true),
    drive: crate::schedule::Drive::Runner,
    run: run_line_notices,
};

/// One run of [`LINE_NOTICES_JOB`]: the notices due by the vault's clock, in one write.
fn run_line_notices(
    vault: &Vault,
    _armed: &Armed,
    _pass: &JobPass<'_>,
) -> crate::Result<JobResult> {
    let now_ms = vault.now_recorded_ms();
    vault.with_write_txn(|wtxn| raise_due_line_notices_in_txn(vault, wtxn, now_ms))?;
    Ok(JobResult::of(Ran::Done))
}
