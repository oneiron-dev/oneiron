//! Cleanup review (ARCH-0073): the archive proposals the cleanup job opened,
//! the digests of what cleanup archived, the job's posture and the done-task
//! retention dial, and bringing an archived record back.
//!
//! The job proposes first while ARCH-0066's integrity teeth are open: nothing
//! is archived until the owner accepts, and the engine refuses the automatic
//! posture until those teeth close. Archive is the only verb; a record
//! restored here is the same record, never a copy.

use oneiron::attempt_queue::AttemptId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::vault_cleanup::{
    self, ArchivedEntity, CleanupDigest, CleanupKind, CleanupPosture, CleanupProposal,
};
use oneiron::{EntityId, ErrorKind, Vault};
use serde::{Deserialize, Serialize};

use super::stamp::rfc3339_secs;
use super::{OwnerError, OwnerResult, entity_id};

/// Everything the owner reviews about cleanup.
#[derive(Debug, Serialize)]
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
}

#[derive(Debug, Serialize)]
pub(crate) struct Proposal {
    pub(crate) id: String,
    pub(crate) attempt: String,
    pub(crate) created_at: String,
    pub(crate) candidates: Vec<Candidate>,
    /// What accepting archives, by kind.
    pub(crate) impact: Impact,
}

#[derive(Debug, Serialize)]
pub(crate) struct Candidate {
    pub(crate) entity: String,
    pub(crate) kind: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct Impact {
    pub(crate) total: usize,
    pub(crate) claimless_persons: usize,
    pub(crate) empty_summaries: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct Digest {
    pub(crate) id: String,
    pub(crate) attempt: Option<String>,
    pub(crate) proposal: Option<String>,
    /// `auto_archived` or `proposal_accepted`.
    pub(crate) decision: &'static str,
    pub(crate) posture: &'static str,
    pub(crate) at: String,
    pub(crate) archived: Vec<String>,
    /// Candidates the accept found no longer empty, so left alone.
    pub(crate) skipped: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Archived {
    /// Send this to `/cleanup/restore` as `entity` to bring it back.
    pub(crate) entity: String,
    /// `record`, or `completed_attempt` for a finished queue record.
    pub(crate) kind: &'static str,
    /// When it was archived; an attempt's time is its digest's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) archived_at: Option<String>,
}

/// What accepting a proposal did.
#[derive(Debug, Serialize)]
pub(crate) struct Accepted {
    pub(crate) proposal: String,
    pub(crate) archived: Vec<String>,
    pub(crate) skipped: Vec<String>,
    pub(crate) digest: String,
}

/// The owner's cleanup settings; an absent field is left as it is.
#[derive(Debug, Default, Deserialize)]
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
        let id = EntityId::from_bytes_unchecked(*attempt.as_bytes());
        archived.push(Archived {
            entity: id.to_hex(),
            kind: CleanupKind::CompletedAttempt.as_str(),
            archived_at: digests
                .iter()
                .rev()
                .find(|row| row.archived.contains(&id))
                .map(|row| rfc3339_secs(row.at)),
        });
    }
    Ok(CleanupReview {
        posture: vault_cleanup::cleanup_posture(vault)?.as_str(),
        task_retention_days: vault.task_retention_days()?,
        proposals: vault_cleanup::cleanup_proposals(vault)?
            .iter()
            .map(proposal)
            .collect(),
        digests: digests.iter().map(digest).collect(),
        archived,
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
        digest: outcome.digest.to_hex(),
    })
}

pub(crate) fn reject(vault: &Vault, owner: &AuthenticatedOwner, proposal: &str) -> OwnerResult<()> {
    let id = entity_id("proposal", proposal)?;
    vault
        .reject_cleanup_proposal_as(owner, &id)
        .map_err(|error| proposal_gone(error, proposal))
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

/// Brings back what the review lists as archived: a record, or a completed
/// attempt, each through its own owner-bound door.
pub(crate) fn restore(vault: &Vault, owner: &AuthenticatedOwner, entity: &str) -> OwnerResult<()> {
    let id = entity_id("entity", entity)?;
    let attempt = AttemptId::from_bytes(id.as_bytes())?;
    let restored = if vault.archived_entity(&id)?.is_none() && vault.archived_attempt(attempt)? {
        vault.restore_archived_attempt_as(owner, attempt)
    } else {
        vault.restore_archived_as(owner, &id)
    };
    restored.map_err(|error| match error.kind() {
        ErrorKind::VaultCleanupRestoreNotArchived => {
            OwnerError::Changed(format!("{entity} is not archived by cleanup"))
        }
        _ => OwnerError::from(error),
    })
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
            .map(|candidate| Candidate {
                entity: candidate.entity.to_hex(),
                kind: candidate.kind.as_str(),
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
        archived: hexes(&row.archived),
        skipped: hexes(&row.skipped),
    }
}

fn archived(row: &ArchivedEntity) -> Archived {
    Archived {
        entity: row.entity.to_hex(),
        kind: "record",
        archived_at: Some(rfc3339_secs(row.archived_at)),
    }
}

fn hexes(ids: &[EntityId]) -> Vec<String> {
    ids.iter().map(EntityId::to_hex).collect()
}

fn attempt_hex(attempt: oneiron::attempt_queue::AttemptId) -> String {
    attempt
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
