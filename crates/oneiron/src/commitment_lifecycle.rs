//! Commitment fulfillment and gap-decay lifecycle (CMT-4, ONE-1541).
//!
//! CMT-1 ([`crate::commitment`]) owns the obligation record and its four status
//! verbs. CMT-2 ([`crate::commitment_schedule`]) owns the due index, the close
//! hook, and successor minting. This module is the sibling that decides WHEN a
//! status verb runs and repairs the seam between the two. It owns exactly four
//! things:
//!
//! 1. the typed dispatch that turns an EXPLICIT [`FulfillmentSource`] into
//!    CMT-1's [`Vault::fulfill_commitment`];
//! 2. the `brief --Fulfills--> commitment` traversal a completing task brief
//!    walks, plus the validated door that writes both ruled directions;
//! 3. the overdue-instance lapse sweep, batched all-or-nothing through CMT-1's
//!    lapse transition and CMT-2's status-unfiltered candidate feed;
//! 4. the Dreamer witness path, which writes a fulfillment PROPOSAL claim and
//!    never a status.
//!
//! Three rules shape everything here.
//!
//! * **Only `Open` takes a status effect.** A row that is already terminal is
//!   not an error and not a second transition: it is a torn write to REPAIR,
//!   and the repair re-runs only the close hook.
//! * **`closed_at` comes from the terminal claim header, never from retry
//!   time.** A repair at `t2` that passed `t2` would silently move the moment
//!   an obligation ended. The ONE exception is the lapse batch's own write,
//!   whose `learned_at` IS the transition it is performing.
//! * **The storage model does not move.** No second codec, no schedule schema
//!   change, no entity byte, no store table, no receipt ledger. Lifecycle
//!   receipts are projected from the terminal claim rows themselves.

use rmpv::Value;

use crate::batch::{EdgeValueFields, EntityMetadataHeader};
use crate::claim::{ClaimSource, ClaimSubject};
use crate::commitment::{CommitmentStatus, FulfillmentSource};
use crate::commitment_schedule::CommitmentInstanceOutcome;
use crate::dreamer_promotion::{
    DreamerRunContext, PromotionCandidate, PromotionOutcome, promote_consolidated_claims,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TASK};
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};

#[cfg(test)]
mod tests;

/// Engine-owned predicate for a Dreamer-witnessed fulfillment PROPOSAL.
///
/// Deliberately NOT `commitment.record`: a proposal is a separate fact about
/// the commitment, carries `supersedes = None`, and therefore cannot close the
/// live obligation. Approval-to-effect consumption is not invented here — the
/// explicit dispatch below stays the only status-effect path.
pub const PREDICATE_COMMITMENT_FULFILLMENT_PROPOSAL: &str = "commitment.fulfillment_proposal";

/// Value schema version of a fulfillment proposal.
pub const FULFILLMENT_PROPOSAL_SCHEMA_VERSION: u64 = 1;

/// The status a lifecycle close left on one commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentCloseResult {
    pub commitment_ref: EntityId,
    pub status: CommitmentStatus,
}

/// What completing one brief did to the commitments it discharges.
///
/// `repaired` is deliberately separate from `already_closed`: a target that was
/// already `Fulfilled` had its close hook re-run and its due rows cleared, while
/// an `already_closed` target ended some OTHER way and this brief did not close
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BriefFulfillmentReport {
    pub brief_ref: EntityId,
    pub fulfilled: Vec<EntityId>,
    pub repaired: Vec<EntityId>,
    pub already_closed: Vec<EntityId>,
}

/// What one gap-decay sweep did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LapseSweepReport {
    /// Instances this sweep transitioned `Open` → `Lapsed`.
    pub lapsed: Vec<EntityId>,
    /// Already-terminal instances whose close hook this sweep re-ran, using
    /// their committed terminal header time.
    pub repaired_close_hooks: Vec<EntityId>,
}

/// The committed close anchor of a terminal commitment: its claim row's current
/// `learned_at`.
///
/// A repair at `t2` reads the SAME `t1` the transition committed, which is what
/// makes the close hook idempotent in time as well as in effect.
fn commitment_terminal_learned_at(vault: &Vault, id: &EntityId) -> Result<u64> {
    let raw = vault.get_raw(id)?.ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("commitment claim header"))?;
    Ok(header.learned_at)
}

/// Writes both ruled directions of a brief fulfillment link, atomically.
///
/// The directions are `brief --Fulfills--> commitment` and
/// `commitment --DischargedBy--> brief`. The second is an INVERSE TRAVERSAL
/// edge, not a creation-causation claim: the brief closed the obligation, it
/// did not cause it to exist.
///
/// This is the validated door those reserved kinds exist for. Public raw edge
/// builders reject both with [`Error::ReservedEdgeKind`], so nothing else can
/// forge a link or write one direction without the other. It takes no
/// [`WriteEnvelope`] because edge rows carry no envelope evidence — it sits in
/// the same ungated `&Vault` trust class as every other commitment verb — and
/// it proves both endpoint classes BEFORE writing: the source must be a stored
/// `ENTITY_TYPE_TASK` brief, the target an OPEN `commitment.record`.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the source is missing or is not a task
/// brief, or when the target commitment is not open; [`Error::EntityNotFound`]
/// when the target does not exist.
pub fn link_brief_fulfillment(
    vault: &Vault,
    brief_ref: &EntityId,
    commitment_ref: &EntityId,
    linked_at: u64,
) -> Result<()> {
    let Some(raw_brief) = vault.get_raw(brief_ref)? else {
        return Err(Error::InvalidClaimBody(
            "fulfillment source is not a task brief",
        ));
    };
    let header = EntityMetadataHeader::parse(&raw_brief)
        .ok_or(Error::CorruptedIndex("task brief header"))?;
    if header.entity_type != ENTITY_TYPE_TASK {
        return Err(Error::InvalidClaimBody(
            "fulfillment source is not a task brief",
        ));
    }

    let Some(record) = vault.get_commitment_claim(commitment_ref)? else {
        return Err(Error::EntityNotFound);
    };
    if record.status != CommitmentStatus::Open {
        return Err(Error::InvalidClaimBody(
            "brief fulfillment link requires an open commitment",
        ));
    }

    // Structural rows: explicit weight, no VAD, no provenance hot flags. The
    // kinds carry no default prior precisely so this door states the weight.
    let edge_value = EdgeValueFields {
        weight: 1.0,
        created_at: linked_at,
        vad: crate::affect::Vad::NEUTRAL,
        provenance: None,
    };
    vault
        .batch()
        .edge_with_value_fields(brief_ref, EdgeKind::Fulfills, commitment_ref, edge_value)
        .edge_with_value_fields(
            commitment_ref,
            EdgeKind::DischargedBy,
            brief_ref,
            edge_value,
        )
        .commit()
}

/// The single explicit status-effect dispatcher.
///
/// `Open` runs CMT-1's fulfill verb; an already-`Fulfilled` row skips the
/// second status write and retries ONLY the close hook, with the terminal
/// header's committed time. Anything else is a typed refusal — a released,
/// lapsed or superseded obligation is closed history.
///
/// A [`FulfillmentSource::BriefCompletion`] must present a real `Fulfills`
/// edge, so a caller cannot discharge an arbitrary commitment by naming an
/// unrelated brief.
///
/// [`FulfillmentSource::ChecklistTick`] is accepted as a typed source and has
/// no producer in the engine.
pub fn fulfill_commitment_from(
    vault: &Vault,
    commitment_ref: &EntityId,
    source: FulfillmentSource,
    envelope: &WriteEnvelope,
    learned_at: u64,
) -> Result<CommitmentCloseResult> {
    if let FulfillmentSource::BriefCompletion { brief_ref } = source
        && !vault.edge_exists(&brief_ref, EdgeKind::Fulfills, commitment_ref)?
    {
        return Err(Error::InvalidClaimBody("brief does not fulfill commitment"));
    }

    let record = vault
        .get_commitment_claim(commitment_ref)?
        .ok_or(Error::EntityNotFound)?;
    match record.status {
        CommitmentStatus::Open => {
            vault.fulfill_commitment(commitment_ref, envelope, learned_at)?;
        }
        // Repair a prior status-commit / close-hook tear without emitting a
        // second status transition or lifecycle receipt.
        CommitmentStatus::Fulfilled => {}
        _ => {
            return Err(Error::InvalidClaimBody(
                "fulfillment requires an open or already-fulfilled commitment",
            ));
        }
    }
    // The terminal claim header is the committed close anchor. A repair at t2
    // must not substitute retry time for the status transition's t1.
    let closed_at = commitment_terminal_learned_at(vault, commitment_ref)?;
    // CMT-2 answers `Ok(vec![])` for a plain commitment that is not a scheduled
    // INSTANCE, so explicit fulfillment is not schedule-coupled.
    vault.on_instance_closed(
        commitment_ref,
        CommitmentInstanceOutcome::Fulfilled,
        envelope,
        closed_at,
    )?;
    Ok(CommitmentCloseResult {
        commitment_ref: *commitment_ref,
        status: CommitmentStatus::Fulfilled,
    })
}

/// Discharges every commitment a completing brief `Fulfills`.
///
/// The traversal is the stored reserved edge and nothing else — no new
/// adjacency index. A `Fulfills` target that does not decode as a commitment is
/// [`Error::CorruptedIndex`], not caller input: the validated door checked the
/// target's class at write time, so a bad target means the stored index moved
/// underneath it.
pub fn fulfill_commitments_for_brief(
    vault: &Vault,
    brief_ref: &EntityId,
    envelope: &WriteEnvelope,
    completed_at: u64,
) -> Result<BriefFulfillmentReport> {
    let mut fulfilled = Vec::new();
    let mut repaired = Vec::new();
    let mut already_closed = Vec::new();
    let mut targets = vault.targets(brief_ref, EdgeKind::Fulfills, Some(ENTITY_TYPE_CLAIM))?;
    targets.sort_unstable();
    targets.dedup();

    for commitment_ref in targets {
        let record = match vault.get_commitment_claim(&commitment_ref) {
            Ok(Some(record)) => record,
            Ok(None) | Err(Error::InvalidClaimBody(_)) => {
                return Err(Error::CorruptedIndex("brief fulfills non-commitment claim"));
            }
            Err(other) => return Err(other),
        };
        let source = FulfillmentSource::BriefCompletion {
            brief_ref: *brief_ref,
        };
        match record.status {
            CommitmentStatus::Open => {
                fulfill_commitment_from(vault, &commitment_ref, source, envelope, completed_at)?;
                fulfilled.push(commitment_ref);
            }
            // Already fulfilled: the close hook is re-run at the committed t1,
            // and the report says `repaired` rather than `already_closed`.
            CommitmentStatus::Fulfilled => {
                fulfill_commitment_from(vault, &commitment_ref, source, envelope, completed_at)?;
                repaired.push(commitment_ref);
            }
            CommitmentStatus::Released
            | CommitmentStatus::Lapsed
            | CommitmentStatus::Superseded => already_closed.push(commitment_ref),
        }
    }

    Ok(BriefFulfillmentReport {
        brief_ref: *brief_ref,
        fulfilled,
        repaired,
        already_closed,
    })
}

/// Lapses every overdue OPEN instance and repairs every overdue terminal one.
///
/// The candidate feed is CMT-2's [`Vault::overdue_commitment_instances`], which
/// applies the strict `LifecycleDue.at < now` boundary and does NOT filter by
/// status — the rows that most need attention are exactly the ones whose status
/// write already landed but whose due rows did not move.
///
/// Classification happens HERE, before any write: `Open` enters the
/// all-or-nothing lapse batch, and each terminal status repairs its close hook
/// with the matching outcome and its OWN committed header time.
///
/// This is a batch operation, not a scheduler. Nothing here polls, sleeps, or
/// owns a thread; the caller decides when a sweep runs.
pub fn lapse_overdue_commitments(
    vault: &Vault,
    now: u64,
    envelope: &WriteEnvelope,
) -> Result<LapseSweepReport> {
    let candidates = vault.overdue_commitment_instances(now)?;
    let mut to_lapse = Vec::new();
    let mut repairs = Vec::new();
    for instance_ref in candidates {
        let Some(record) = vault.get_commitment_claim(&instance_ref)? else {
            return Err(Error::CorruptedIndex("commitment due index"));
        };
        match record.status {
            CommitmentStatus::Open => to_lapse.push(instance_ref),
            CommitmentStatus::Lapsed
            | CommitmentStatus::Fulfilled
            | CommitmentStatus::Released
            | CommitmentStatus::Superseded => {
                let outcome = match record.status {
                    CommitmentStatus::Lapsed => CommitmentInstanceOutcome::Lapsed,
                    CommitmentStatus::Fulfilled => CommitmentInstanceOutcome::Fulfilled,
                    CommitmentStatus::Released => CommitmentInstanceOutcome::Released,
                    CommitmentStatus::Superseded => CommitmentInstanceOutcome::Superseded,
                    CommitmentStatus::Open => {
                        return Err(Error::InvariantViolation(
                            "open commitment reached the terminal repair arm",
                        ));
                    }
                };
                let closed_at = commitment_terminal_learned_at(vault, &instance_ref)?;
                repairs.push((instance_ref, outcome, closed_at));
            }
        }
    }

    if !to_lapse.is_empty() {
        // One transaction for the whole selection: a stale or gate-refused
        // member leaves every sibling open rather than half-lapsing the sweep.
        vault
            .batch()
            .commitment_gap_decay(&to_lapse, envelope, now)
            .commit()?;
    }

    for instance_ref in &to_lapse {
        // `now` for THIS write only: the batch above is the transition, so its
        // committed header time is the close anchor rather than a substitute
        // for one.
        let closed_at = commitment_terminal_learned_at(vault, instance_ref)?;
        vault.on_instance_closed(
            instance_ref,
            CommitmentInstanceOutcome::Lapsed,
            envelope,
            closed_at,
        )?;
    }
    for (instance_ref, outcome, closed_at) in &repairs {
        vault.on_instance_closed(instance_ref, *outcome, envelope, *closed_at)?;
    }

    Ok(LapseSweepReport {
        lapsed: to_lapse,
        repaired_close_hooks: repairs.into_iter().map(|(id, _, _)| id).collect(),
    })
}

/// Explicit release plus schedule close-hook repair.
///
/// `Open` runs CMT-1's release verb; an already-`Released` row skips the
/// duplicate status write. Both then close the schedule seam at the terminal
/// header time. A plain (non-INSTANCE) commitment is a successful no-op there.
pub fn release_commitment_with_close(
    vault: &Vault,
    commitment_ref: &EntityId,
    envelope: &WriteEnvelope,
    learned_at: u64,
) -> Result<CommitmentCloseResult> {
    close_with_hook(
        vault,
        commitment_ref,
        envelope,
        learned_at,
        CommitmentInstanceOutcome::Released,
        "release requires an open or already-released commitment",
    )
}

/// Explicit supersede plus schedule close-hook repair.
///
/// The symmetric twin of [`release_commitment_with_close`]. Superseding a
/// SCHEDULED instance through this door removes its due rows immediately;
/// CMT-1's raw [`Vault::supersede_commitment`] leaves them until the next
/// status-unfiltered sweep repairs them at the committed `t1`.
pub fn supersede_commitment_with_close(
    vault: &Vault,
    commitment_ref: &EntityId,
    envelope: &WriteEnvelope,
    learned_at: u64,
) -> Result<CommitmentCloseResult> {
    close_with_hook(
        vault,
        commitment_ref,
        envelope,
        learned_at,
        CommitmentInstanceOutcome::Superseded,
        "supersede requires an open or already-superseded commitment",
    )
}

/// The shared Open-or-already-terminal close shape behind the release and
/// supersede wrappers. One body because they differ only in outcome and in the
/// sentence they refuse with.
fn close_with_hook(
    vault: &Vault,
    commitment_ref: &EntityId,
    envelope: &WriteEnvelope,
    learned_at: u64,
    outcome: CommitmentInstanceOutcome,
    mismatch: &'static str,
) -> Result<CommitmentCloseResult> {
    let record = vault
        .get_commitment_claim(commitment_ref)?
        .ok_or(Error::EntityNotFound)?;
    let target = outcome.status();
    if record.status == CommitmentStatus::Open {
        match outcome {
            CommitmentInstanceOutcome::Released => {
                vault.release_commitment(commitment_ref, envelope, learned_at)?;
            }
            CommitmentInstanceOutcome::Superseded => {
                vault.supersede_commitment(commitment_ref, envelope, learned_at)?;
            }
            CommitmentInstanceOutcome::Fulfilled | CommitmentInstanceOutcome::Lapsed => {
                return Err(Error::InvariantViolation(
                    "close wrapper covers release and supersede only",
                ));
            }
        }
    } else if record.status != target {
        return Err(Error::InvalidClaimBody(mismatch));
    }
    let closed_at = commitment_terminal_learned_at(vault, commitment_ref)?;
    vault.on_instance_closed(commitment_ref, outcome, envelope, closed_at)?;
    Ok(CommitmentCloseResult {
        commitment_ref: *commitment_ref,
        status: target,
    })
}

/// Writes a Dreamer-witnessed fulfillment PROPOSAL — never a status.
///
/// This is the whole point of the path: a Dreamer that believes an obligation
/// was met records a durable, gated, machine-readable proposal against the
/// commitment and leaves the obligation OPEN. `supersedes` is `None`, so the
/// proposal structurally cannot close the live commitment, and no
/// `fulfill_commitment` call happens anywhere in this function. The explicit
/// dispatch above remains the only status-effect path.
///
/// The admissible witness TURN refs ride
/// [`PromotionCandidate::evidence_turn_refs`] and are consumed by the promotion
/// writer's GATE-11 admission; a candidate with no surviving evidence is
/// rejected there rather than written.
///
/// The Dreamer consolidation host is the expected producer. Wiring it is not
/// part of this ticket.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the target is missing;
/// [`Error::InvalidClaimBody`] when the target does not decode as a commitment,
/// or when it is already terminal.
pub fn propose_commitment_fulfilled(
    vault: &Vault,
    run: &DreamerRunContext,
    proposal_ref: EntityId,
    commitment_ref: EntityId,
    evidence_turn_refs: Vec<EntityId>,
    proposed_at: u64,
) -> Result<PromotionOutcome> {
    let target = vault
        .get_commitment_claim(&commitment_ref)?
        .ok_or(Error::EntityNotFound)?;
    if target.status != CommitmentStatus::Open {
        return Err(Error::InvalidClaimBody(
            "fulfillment proposal target is not an open commitment",
        ));
    }

    let value = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(FULFILLMENT_PROPOSAL_SCHEMA_VERSION),
        ),
        (Value::from("proposed_status"), Value::from("fulfilled")),
        (Value::from("proposed_at"), Value::from(proposed_at)),
    ]);
    let candidate = ClaimCandidate::new(
        PREDICATE_COMMITMENT_FULFILLMENT_PROPOSAL,
        ClaimSubject::Entity(commitment_ref),
        value,
        1.0,
    );
    promote_consolidated_claims(
        vault,
        run,
        vec![PromotionCandidate {
            claim_id: proposal_ref,
            candidate,
            evidence_turn_refs,
            // No external chain: the witness evidence is the TURN refs above.
            provenance_chain: Vec::new(),
            // A proposal never replaces the live commitment head.
            supersedes: None,
            evidence_meet: ClaimSource::Generated,
            occurred: TimeRange {
                start: proposed_at,
                end: proposed_at,
            },
            learned_at: proposed_at,
        }],
    )
}
