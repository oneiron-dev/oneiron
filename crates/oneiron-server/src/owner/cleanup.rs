//! Cleanup review (ARCH-0073): the archive proposals the cleanup job opened,
//! the digests of what cleanup archived, the runs that archived and what each
//! held before, the job's posture and the done-task retention dial, bringing
//! an archived record back, and reverting a whole run (OF-449). One open
//! proposal also reviews slot by slot, with each slot's evidence and full
//! content, and decides per item in one complete verdict (FIX 1758).
//!
//! The job proposes first while ARCH-0066's integrity teeth are open: nothing
//! is archived until the owner accepts, and the engine refuses the automatic
//! posture until those teeth close. Archive is the only verb; a record
//! restored here is the same record, never a copy, and the owner keeps it:
//! cleanup leaves it alone until it changes.

use oneiron::attempt_queue::AttemptId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{Memory, MemoryError};
use oneiron::vault_cleanup::{
    self, ArchivedEntity, CleanupDecideRequest, CleanupDecideView, CleanupDigest, CleanupKind,
    CleanupPosture, CleanupProposal, CleanupRevertEntry, CleanupRevertReason, CleanupReviewRequest,
    CleanupReviewView, CleanupRunRecord, CleanupRunRevert, CleanupRunRevertAnswer,
    CleanupSnapshotEntry,
};
use oneiron::{EntityId, ErrorKind, Vault};
use serde::{Deserialize, Serialize};

use super::stamp::rfc3339_secs;
use super::{OwnerError, OwnerResult, entity_id};

/// The `kind` of an archived record, as against a completed attempt.
const RECORD: &str = "record";

/// What an erased slot reads as, an id slot or a revert's outcome (FIX 7517).
const ERASED: &str = "erased";

/// Everything the owner reviews about cleanup.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct CleanupReview {
    /// `propose_first` or `auto_with_digest`.
    pub(crate) posture: &'static str,
    /// Done tasks and attempts older than this many days are archived; `0`
    /// turns that arm off.
    pub(crate) task_retention_days: u64,
    /// Open proposals, oldest first. Nothing in them is archived yet.
    pub(crate) proposals: Vec<Proposal>,
    /// What cleanup archived, one entry per run or accepted proposal.
    pub(crate) digests: Vec<Digest>,
    /// Everything cleanup archived that is still archived: records and
    /// completed attempts, one restorable view (ARCH-0073 §6).
    pub(crate) archived: Vec<Archived>,
    /// Every run that archived something, oldest first: each entry as it
    /// stood before the run archived it, and the run's revert once there is
    /// one. Send a run's `attempt` to `/cleanup/revert-run` to revert it.
    pub(crate) runs: Vec<Run>,
    /// Runs whose record does not read, by attempt; the rest of the review
    /// still answers.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) unreadable_runs: Vec<String>,
}

/// One cleanup run that archived something.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct Run {
    /// The run's attempt id: what `/cleanup/revert-run` takes.
    pub(crate) attempt: String,
    /// `auto_archived` or `proposal_accepted`.
    pub(crate) decision: &'static str,
    /// The digest that decision recorded.
    pub(crate) digest: String,
    pub(crate) archived_at: String,
    /// What the run archived, each entry as it stood just before.
    pub(crate) entries: Vec<Slot<RunEntry>>,
    /// The stored answer of the run's revert; null until it is reverted.
    pub(crate) reverted: Option<Reverted>,
}

/// One entry a run archived.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct RunEntry {
    pub(crate) entity: String,
    pub(crate) kind: &'static str,
    /// BLAKE3 of the stored bytes the run hid (64 hex). The archive keeps
    /// them; a revert lifts the mark and writes no body. Null when an erase
    /// scrubbed this binding: the attempt changed after the run, and the
    /// erase reached the bytes it named (FIX 7615).
    pub(crate) revision: Option<String>,
    /// The mark in force before the run, hex; null when there was none, or
    /// when an erase scrubbed it (FIX 7615).
    pub(crate) before: Option<String>,
    /// The exact mark the run wrote, hex; null when an erase scrubbed it, as
    /// `revision` (FIX 7615).
    pub(crate) after: Option<String>,
}

/// A run's revert, as stored.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct Reverted {
    pub(crate) at: String,
    pub(crate) entries: Vec<Slot<RevertEntry>>,
}

/// What reverting a whole run did.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct RunReverted {
    pub(crate) attempt: String,
    pub(crate) reverted_at: String,
    /// True when an earlier revert stored this answer; nothing changed now.
    pub(crate) repeated: bool,
    pub(crate) entries: Vec<Slot<RevertEntry>>,
}

/// What reverting a run did to one entry.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct RevertEntry {
    pub(crate) entity: String,
    pub(crate) kind: &'static str,
    /// `restored`, `already_restored`, `changed` or `unavailable`.
    pub(crate) outcome: &'static str,
    /// Why a `changed` or `unavailable` entry stayed as it is:
    /// `archived_again`, `unreadable`, `deleted` or `gone`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<&'static str>,
    /// Its stored bytes changed after the run archived them.
    pub(crate) edited: bool,
}

/// One slot of a listing: what it names, or its erased form once an erase
/// reached what it named (FIX 7517). The slot keeps its place, so each list
/// keeps its count.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(untagged)]
pub(crate) enum Slot<T> {
    Live(T),
    Erased(ErasedSlot),
}

/// An erased slot: `{"erased": true}`, with no id, kind, hash or mark. A
/// revert's entry also answers `"outcome": "erased"`: nothing was lifted.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct ErasedSlot {
    pub(crate) erased: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) outcome: Option<&'static str>,
}

impl<T> Slot<T> {
    fn of<S>(slot: Option<&S>, live: impl FnOnce(&S) -> T) -> Self {
        match slot {
            Some(slot) => Self::Live(live(slot)),
            None => Self::Erased(ErasedSlot {
                erased: true,
                outcome: None,
            }),
        }
    }
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct Proposal {
    pub(crate) id: String,
    pub(crate) attempt: String,
    pub(crate) created_at: String,
    pub(crate) candidates: Vec<Slot<Candidate>>,
    /// What accepting archives, by kind.
    pub(crate) impact: Impact,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct Candidate {
    pub(crate) entity: String,
    pub(crate) kind: &'static str,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct Impact {
    pub(crate) total: usize,
    pub(crate) claimless_persons: usize,
    pub(crate) empty_summaries: usize,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct Digest {
    pub(crate) id: String,
    pub(crate) attempt: Option<String>,
    pub(crate) proposal: Option<String>,
    /// `auto_archived` or `proposal_accepted`.
    pub(crate) decision: &'static str,
    pub(crate) posture: &'static str,
    pub(crate) at: String,
    /// Each archived id; `"erased"` once an erase reached it (FIX 7517).
    pub(crate) archived: Vec<String>,
    /// Candidates the accept found no longer empty, so left alone;
    /// `"erased"` as in `archived`.
    pub(crate) skipped: Vec<String>,
    /// Candidates the owner rejected in a per-item decision (FIX 1758):
    /// left alone and not pinned; `"erased"` as in `archived`. Absent when
    /// there were none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) rejected: Vec<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct Archived {
    /// Send this and `kind` to `/cleanup/restore` to bring it back.
    pub(crate) entity: String,
    /// `record`, or `completed_attempt` for a finished queue record.
    pub(crate) kind: &'static str,
    /// When it was archived; an attempt's time is its digest's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) archived_at: Option<String>,
}

/// What accepting a proposal did.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct Accepted {
    pub(crate) proposal: String,
    pub(crate) archived: Vec<String>,
    pub(crate) skipped: Vec<String>,
    /// Candidates an erase reached before the accept: they name no one, and
    /// nothing was archived for them (FIX 7517). Absent when there were none.
    #[serde(skip_serializing_if = "none_erased")]
    pub(crate) erased: usize,
    pub(crate) digest: String,
}

/// The owner's cleanup settings; an absent field is left as it is.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CleanupSettings {
    /// `propose_first` or `auto_with_digest`.
    #[serde(default)]
    pub(crate) posture: Option<String>,
    /// Days a done task or attempt stays in the working set; `0` turns the
    /// arm off.
    #[serde(default)]
    pub(crate) task_retention_days: Option<u32>,
}

pub(crate) fn review(vault: &Vault) -> OwnerResult<CleanupReview> {
    let digests = vault_cleanup::cleanup_digests(vault)?;
    let mut archived: Vec<Archived> = vault.archived_entities()?.iter().map(archived).collect();
    for attempt in vault.archived_attempts()? {
        archived.push(Archived {
            entity: attempt_hex(attempt),
            kind: CleanupKind::CompletedAttempt.as_str(),
            archived_at: digests
                .iter()
                .rev()
                .find(|row| {
                    row.archived
                        .iter()
                        .flatten()
                        .any(|id| id.as_bytes() == attempt.as_bytes())
                })
                .map(|row| rfc3339_secs(row.at)),
        });
    }
    let runs = vault_cleanup::cleanup_runs(vault)?;
    Ok(CleanupReview {
        posture: vault_cleanup::cleanup_posture(vault)?.as_str(),
        task_retention_days: vault.task_retention_days()?,
        proposals: vault_cleanup::cleanup_proposals(vault)?
            .iter()
            .map(proposal)
            .collect(),
        digests: digests.iter().map(digest).collect(),
        archived,
        runs: runs.runs.iter().map(run_view).collect(),
        unreadable_runs: runs.unreadable.into_iter().map(attempt_hex).collect(),
    })
}

pub(crate) fn accept(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    proposal: &str,
) -> OwnerResult<Accepted> {
    let id = entity_id("proposal", proposal)?;
    let outcome = vault
        .accept_cleanup_proposal_as(owner, &id)
        .map_err(|error| proposal_gone(error, proposal))?;
    Ok(Accepted {
        proposal: outcome.proposal.to_hex(),
        archived: hexes(&outcome.archived),
        skipped: hexes(&outcome.skipped),
        erased: outcome.erased,
        digest: outcome.digest.to_hex(),
    })
}

pub(crate) fn reject(vault: &Vault, owner: &AuthenticatedOwner, proposal: &str) -> OwnerResult<()> {
    let id = entity_id("proposal", proposal)?;
    vault
        .reject_cleanup_proposal_as(owner, &id)
        .map_err(|error| proposal_gone(error, proposal))
}

/// Reviews one open proposal slot by slot (FIX 1758): each slot's evidence,
/// state, revision and what accepting it does, and its full content through
/// `memory`, the owner's own reads.
pub(crate) fn review_proposal(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    request: &CleanupReviewRequest,
) -> OwnerResult<CleanupReviewView> {
    vault_cleanup::review_cleanup_proposal_as(memory, owner, request).map_err(per_item_refusal)
}

/// Decides one open proposal slot by slot in one complete verdict (FIX
/// 1758).
pub(crate) fn decide(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: &CleanupDecideRequest,
) -> OwnerResult<CleanupDecideView> {
    vault
        .decide_cleanup_proposal_as(owner, request)
        .map_err(per_item_refusal)
}

pub(crate) fn configure(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    settings: &CleanupSettings,
) -> OwnerResult<CleanupReview> {
    if let Some(posture) = settings.posture.as_deref() {
        let posture = CleanupPosture::parse(posture).ok_or_else(|| {
            OwnerError::Invalid("posture must be `propose_first` or `auto_with_digest`".to_owned())
        })?;
        vault
            .set_cleanup_posture_as(owner, posture)
            .map_err(|error| match error.kind() {
                ErrorKind::InvariantViolation => OwnerError::Refused(
                    "cleanup stays propose-first until the integrity checks it waits on close \
                     (ARCH-0066); accept or reject its proposals instead"
                        .to_owned(),
                ),
                _ => OwnerError::from(error),
            })?;
    }
    if let Some(days) = settings.task_retention_days {
        vault.set_task_retention_days_as(owner, Some(days))?;
    }
    review(vault)
}

/// Brings back one entry of the review's `archived` list, named by its
/// `entity` and `kind`: a record or a completed attempt, each through its own
/// owner-bound door. Records and attempts are separate tables, so the kind
/// says which one, never a guess.
pub(crate) fn restore(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    entity: &str,
    kind: Option<&str>,
) -> OwnerResult<()> {
    let id = entity_id("entity", entity)?;
    let restored = match kind.unwrap_or(RECORD) {
        RECORD => vault.restore_archived_as(owner, &id),
        kind if kind == CleanupKind::CompletedAttempt.as_str() => {
            vault.restore_archived_attempt_as(owner, AttemptId::from_bytes(id.as_bytes())?)
        }
        _ => {
            return Err(OwnerError::Invalid(
                "kind must be `record` or `completed_attempt`".to_owned(),
            ));
        }
    };
    restored.map_err(|error| match error.kind() {
        ErrorKind::VaultCleanupRestoreNotArchived => {
            OwnerError::Changed(format!("{entity} is not archived by cleanup"))
        }
        _ => OwnerError::from(error),
    })
}

/// Reverts one whole cleanup run, named by the `attempt` of a review `runs`
/// entry. Each entry answers for itself and a repeat answers as stored. A
/// run whose proposal still waits, or that ran before runs kept snapshots,
/// has nothing this door reverts.
pub(crate) fn revert_run(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    attempt: &str,
) -> OwnerResult<RunReverted> {
    let run = AttemptId::from_bytes(entity_id("attempt", attempt)?.as_bytes())?;
    match vault.revert_cleanup_run_as(owner, run)? {
        CleanupRunRevertAnswer::Reverted(revert) => Ok(run_reverted(&revert)),
        CleanupRunRevertAnswer::NoSuchRun => {
            Err(OwnerError::NotFound("cleanup run", attempt.to_owned()))
        }
        CleanupRunRevertAnswer::ProposalOpen(proposal) => Err(OwnerError::Changed(format!(
            "cleanup run {attempt} has archived nothing yet: its proposal {} waits for review; \
             reject it instead",
            proposal.to_hex()
        ))),
        CleanupRunRevertAnswer::Unrecorded => Err(OwnerError::Refused(format!(
            "cleanup run {attempt} ran before runs kept snapshots; restore its entries one by one"
        ))),
    }
}

/// A per-item door's typed answer, as the owner surface gives it: a verdict
/// that is not one choice per slot is invalid; a proposal no longer open, or
/// a review that changed since its revision, is changed; a read the owner's
/// lane refuses is refused; any other code (a storage fault) is the host's
/// failure, not a refusal (FIX 10504).
fn per_item_refusal(error: MemoryError) -> OwnerError {
    match error.code.as_str() {
        oneiron::memory::MEMORY_CODE_BAD_REQUEST => OwnerError::Invalid(error.message),
        oneiron::memory::MEMORY_CODE_INVALID_STATE | oneiron::memory::MEMORY_CODE_NOT_FOUND => {
            OwnerError::Changed(error.message)
        }
        oneiron::memory::MEMORY_CODE_FORBIDDEN => OwnerError::Refused(error.message),
        _ => OwnerError::Host(anyhow::anyhow!("cleanup review: {}", error.message)),
    }
}

fn proposal_gone(error: oneiron::Error, proposal: &str) -> OwnerError {
    match error.kind() {
        ErrorKind::VaultCleanupProposalNotFound => OwnerError::Changed(format!(
            "cleanup proposal {proposal} is no longer open; review again"
        )),
        _ => OwnerError::from(error),
    }
}

fn proposal(row: &CleanupProposal) -> Proposal {
    let impact = row.impact_preview();
    Proposal {
        id: row.id.to_hex(),
        attempt: attempt_hex(row.attempt),
        created_at: rfc3339_secs(row.created_at),
        candidates: row
            .candidates
            .iter()
            .map(|candidate| {
                Slot::of(candidate.as_ref(), |candidate| Candidate {
                    entity: candidate.entity.to_hex(),
                    kind: candidate.kind.as_str(),
                })
            })
            .collect(),
        impact: Impact {
            total: impact.total,
            claimless_persons: impact.claimless_persons,
            empty_summaries: impact.empty_summaries,
        },
    }
}

fn digest(row: &CleanupDigest) -> Digest {
    Digest {
        id: row.id.to_hex(),
        attempt: row.attempt.map(attempt_hex),
        proposal: row.proposal.map(|id| id.to_hex()),
        decision: row.decision.as_str(),
        posture: row.posture.as_str(),
        at: rfc3339_secs(row.at),
        archived: slot_hexes(&row.archived),
        skipped: slot_hexes(&row.skipped),
        rejected: slot_hexes(&row.rejected),
    }
}

fn archived(row: &ArchivedEntity) -> Archived {
    Archived {
        entity: row.entity.to_hex(),
        kind: RECORD,
        archived_at: Some(rfc3339_secs(row.archived_at)),
    }
}

fn run_view(row: &CleanupRunRecord) -> Run {
    Run {
        attempt: attempt_hex(row.attempt),
        decision: row.snapshot.decision.as_str(),
        digest: row.snapshot.digest.to_hex(),
        archived_at: rfc3339_secs(row.snapshot.at),
        entries: row
            .snapshot
            .entries
            .iter()
            .map(|entry| Slot::of(entry.as_ref(), run_entry))
            .collect(),
        reverted: row.revert.as_ref().map(|revert| Reverted {
            at: rfc3339_secs(revert.reverted_at),
            entries: revert_entries(revert),
        }),
    }
}

fn run_entry(entry: &CleanupSnapshotEntry) -> RunEntry {
    RunEntry {
        entity: entry.entity.to_hex(),
        kind: entry.kind.as_str(),
        revision: entry.revision.map(|revision| bytes_hex(&revision)),
        before: entry.before.as_deref().map(bytes_hex),
        after: entry.after.as_deref().map(bytes_hex),
    }
}

fn run_reverted(revert: &CleanupRunRevert) -> RunReverted {
    RunReverted {
        attempt: attempt_hex(revert.attempt),
        reverted_at: rfc3339_secs(revert.reverted_at),
        repeated: revert.repeated,
        entries: revert_entries(revert),
    }
}

/// A revert's answers, each entry an erase reached since answering
/// `erased`: nothing was lifted for it (FIX 7517).
fn revert_entries(revert: &CleanupRunRevert) -> Vec<Slot<RevertEntry>> {
    revert
        .entries
        .iter()
        .map(|entry| match entry {
            Some(entry) => Slot::Live(revert_entry(entry)),
            None => Slot::Erased(ErasedSlot {
                erased: true,
                outcome: Some(ERASED),
            }),
        })
        .collect()
}

fn revert_entry(entry: &CleanupRevertEntry) -> RevertEntry {
    RevertEntry {
        entity: entry.entity.to_hex(),
        kind: entry.kind.as_str(),
        outcome: entry.outcome.as_str(),
        reason: entry.outcome.reason().map(CleanupRevertReason::as_str),
        edited: entry.edited,
    }
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hexes(ids: &[EntityId]) -> Vec<String> {
    ids.iter().map(EntityId::to_hex).collect()
}

/// Each id as hex, an erased slot as `"erased"` (FIX 7517).
fn slot_hexes(ids: &[Option<EntityId>]) -> Vec<String> {
    ids.iter()
        .map(|id| {
            id.as_ref()
                .map_or_else(|| ERASED.to_owned(), EntityId::to_hex)
        })
        .collect()
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if hands the field by reference"
)]
fn none_erased(count: &usize) -> bool {
    *count == 0
}

fn attempt_hex(attempt: oneiron::attempt_queue::AttemptId) -> String {
    attempt
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
