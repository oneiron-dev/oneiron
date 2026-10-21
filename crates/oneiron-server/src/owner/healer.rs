//! The owner reads the self-healing loop (ARCH-0066): the three signed
//! oversight receipts the vault emits, and the custom-agent dispatches the
//! failure ladder ended, grouped by failure class, with a drill into one, and the
//! Coach's proposals still waiting for the owner, ordered by impact (OF-418 L4).

use oneiron::EntityId;
use oneiron::attempt_queue::{AttemptEvent, AttemptId, AttemptResultRef, AttemptState};
use oneiron::consent::AuthenticatedOwner;
use oneiron::failure_ladder::oversight::OversightCounts;
use oneiron::failure_ladder::{FailureSignalClass, HealResidue};
use serde::{Deserialize, Serialize};

use super::{OwnerResult, entity_id};

/// An attempt id in the lowercase hex its drill query takes back.
pub(crate) fn attempt_hex(id: &AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// One stored oversight receipt and whether it verifies against this vault
/// device's own key.
#[derive(Debug, Serialize)]
pub(crate) struct OversightRead {
    #[serde(flatten)]
    pub(crate) counts: OversightCounts,
    pub(crate) signer: String,
    pub(crate) verified: bool,
}

pub(crate) fn oversight(vault: &oneiron::Vault) -> OwnerResult<Vec<OversightRead>> {
    Ok(vault
        .healer_oversight_receipts()?
        .into_iter()
        .map(|(receipt, verified)| OversightRead {
            counts: receipt.counts,
            signer: receipt
                .signer
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            verified,
        })
        .collect())
}

/// Ended custom-agent dispatches of one failure class.
#[derive(Debug, Serialize)]
pub(crate) struct FailureGroup {
    pub(crate) class: FailureSignalClass,
    pub(crate) count: u64,
    pub(crate) attempts: Vec<String>,
}

pub(crate) fn failure_groups(vault: &oneiron::Vault) -> OwnerResult<Vec<FailureGroup>> {
    Ok(vault
        .custom_agent_failure_groups()?
        .into_iter()
        .map(|group| FailureGroup {
            class: group.class,
            count: group.count,
            attempts: group.member_refs.iter().map(attempt_hex).collect(),
        })
        .collect())
}

/// One source of the self-healing loop's human residue, in the engine's impact order
/// (OF-418 L4): what the Coach's proposals waiting for the owner were filed for, with the
/// identifiers and proof the order rests on, never cause text. The grouped failure counts
/// are their own read, unchanged.
#[derive(Debug, Serialize)]
pub(crate) struct HealResidueRead {
    /// `case`, `report`, `issue` or `unproved`.
    pub(crate) source_kind: &'static str,
    /// A case's ref, a report's receipt, an issue's id, or an unproved row's pending claim.
    pub(crate) source: String,
    pub(crate) proposals: Vec<HealProposalRead>,
    pub(crate) attempts: Vec<HealAttemptRead>,
    pub(crate) task: Option<String>,
    /// `unfinished`, a terminal disposition, or `unknown`.
    pub(crate) task_state: Option<&'static str>,
    pub(crate) stuck_since: Option<u64>,
    pub(crate) stuck_on: Vec<String>,
    /// Every distinct unfinished TASK that waits on the source, in walk order.
    pub(crate) dependents: Vec<String>,
    /// Every recorded `blocked_by` edge the walk read.
    pub(crate) edges: Vec<HealEdgeRead>,
    pub(crate) source_time: Option<u64>,
    pub(crate) score: HealScoreRead,
    /// Every part no record proves, with why it scores nothing.
    pub(crate) unknown: Vec<HealUnknownRead>,
}

/// One Coach proposal waiting in the owner's tray.
#[derive(Debug, Serialize)]
pub(crate) struct HealProposalRead {
    pub(crate) claim: String,
    pub(crate) decision: String,
    pub(crate) predicate: Option<String>,
    pub(crate) proposed_at: u64,
}

/// The attempt a source names, as its row stands now.
#[derive(Debug, Serialize)]
pub(crate) struct HealAttemptRead {
    pub(crate) attempt: String,
    pub(crate) state: AttemptState,
    pub(crate) updated_at: u64,
    pub(crate) task_ref: Option<String>,
    pub(crate) parked_at: Option<u64>,
    pub(crate) park_cause: Option<&'static str>,
}

/// One recorded `blocked_by` edge: `dependent` waits on `blocker`.
#[derive(Debug, Serialize)]
pub(crate) struct HealEdgeRead {
    pub(crate) dependent: String,
    pub(crate) blocker: String,
    pub(crate) recorded_at: u64,
    pub(crate) dependent_state: &'static str,
    pub(crate) blocker_state: &'static str,
}

/// What a row's records prove, in the order the engine compares it.
#[derive(Debug, Serialize)]
pub(crate) struct HealScoreRead {
    pub(crate) chain: bool,
    pub(crate) dependents: u64,
    pub(crate) parked_or_stuck: bool,
}

/// One unproved part of a row.
#[derive(Debug, Serialize)]
pub(crate) struct HealUnknownRead {
    pub(crate) marker: &'static str,
    pub(crate) about: String,
    pub(crate) explanation: &'static str,
}

pub(crate) fn residue(vault: &oneiron::Vault) -> OwnerResult<Vec<HealResidueRead>> {
    Ok(vault
        .healer_residue_by_impact()?
        .into_iter()
        .map(residue_read)
        .collect())
}

fn residue_read(row: HealResidue) -> HealResidueRead {
    let (stuck_since, stuck_on) = match row.stuck {
        Some((since, on)) => (Some(since), on.iter().map(EntityId::to_hex).collect()),
        None => (None, Vec::new()),
    };
    HealResidueRead {
        source_kind: row.source.kind(),
        source: row.source.id(),
        proposals: row
            .proposals
            .into_iter()
            .map(|proposal| HealProposalRead {
                claim: proposal.claim.to_hex(),
                decision: bytes_hex(&proposal.decision),
                predicate: proposal.predicate,
                proposed_at: proposal.proposed_at,
            })
            .collect(),
        attempts: row
            .attempts
            .into_iter()
            .map(|attempt| HealAttemptRead {
                attempt: attempt_hex(&attempt.attempt),
                state: attempt.state,
                updated_at: attempt.updated_at,
                task_ref: attempt.task_ref,
                parked_at: attempt.parked.map(|(at, _)| at),
                park_cause: attempt.parked.map(|(_, cause)| cause.as_str()),
            })
            .collect(),
        task: row.task.map(|(task, _)| task.to_hex()),
        task_state: row.task.map(|(_, state)| state.as_str()),
        stuck_since,
        stuck_on,
        dependents: row.dependents.iter().map(EntityId::to_hex).collect(),
        edges: row
            .edges
            .into_iter()
            .map(|edge| HealEdgeRead {
                dependent: edge.dependent.to_hex(),
                blocker: edge.blocker.to_hex(),
                recorded_at: edge.recorded_at,
                dependent_state: edge.dependent_state.as_str(),
                blocker_state: edge.blocker_state.as_str(),
            })
            .collect(),
        source_time: row.source_time,
        score: HealScoreRead {
            chain: row.score.chain,
            dependents: row.score.dependents,
            parked_or_stuck: row.score.parked_or_stuck,
        },
        unknown: row
            .unknown
            .into_iter()
            .map(|unknown| HealUnknownRead {
                marker: unknown.marker,
                about: unknown.about,
                explanation: unknown.explanation,
            })
            .collect(),
    }
}

/// Bytes in lowercase hex.
fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One member of a group, named by the class it was listed under.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DrillQuery {
    pub(crate) class: FailureSignalClass,
    pub(crate) attempt: String,
}

/// The ended attempt as the vault stores it, and the receipts its run left.
/// The output reference and the intervention trace are the evidence a review
/// reads; a drill is the only owner read of an attempt that has no run id.
#[derive(Debug, Serialize)]
pub(crate) struct FailureDrill {
    pub(crate) attempt: String,
    pub(crate) kind: String,
    pub(crate) state: AttemptState,
    pub(crate) tries: u32,
    pub(crate) last_error: Option<String>,
    pub(crate) task_ref: Option<String>,
    pub(crate) run_id: Option<String>,
    pub(crate) retry_of: Option<String>,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
    /// The artifact version the try's durable output lives in, if it left one.
    pub(crate) result_ref: Option<String>,
    /// Every interrupt, pause, resume, cancel and redirect, with its actor and
    /// note, in order.
    pub(crate) events: Vec<AttemptEvent>,
    pub(crate) receipt_refs: Vec<String>,
}

pub(crate) fn drill(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    query: DrillQuery,
) -> OwnerResult<FailureDrill> {
    let attempt = AttemptId::from_bytes(entity_id("attempt", &query.attempt)?.as_bytes())?;
    let drill = vault.drill_custom_agent_failure(owner, query.class, attempt)?;
    let trace = drill.trace;
    Ok(FailureDrill {
        attempt: attempt_hex(&trace.id),
        kind: trace.kind,
        state: trace.state,
        tries: trace.attempt_count,
        last_error: trace.last_error,
        task_ref: trace.task_ref,
        run_id: trace.run_id,
        retry_of: trace.retry_of.as_ref().map(attempt_hex),
        created_at: trace.created_at,
        updated_at: trace.updated_at,
        result_ref: trace.result_ref.map(AttemptResultRef::into_string),
        events: trace.events,
        receipt_refs: drill.receipt_refs,
    })
}
