//! The receipted post-hoc review of automatic topology (FIX 7817, ARCH-0055
//! §8 "sampled post-hoc audit replaces 100% pre-check for reversible auto
//! classes"; Engine 19:59 = A on every fork).
//!
//! The producer is the apply door's successful local `Auto` merge, split or
//! facet, and nothing else: an approved ruling, a proposal, an undo, a
//! repair record and a replicated event declare no review. In the decision's
//! own writer it keeps one durable candidate, a [`TopologyAuditIntent`], and
//! queues the Coach's deduplicated `coach.topology_audit` job, so a decision
//! that lands always has its candidate and a rolled-back one has none. No
//! model and no sampler runs in that writer.
//!
//! The Coach's job drains the pending candidates. For each, a revision-pinned
//! topology-audit recipe the host runs selects in context, from the decision,
//! its evidence and its scope's audit and undo history; there is no fixed
//! probability, count or rate, and no owner setup. The pinned recipe, its
//! revision and the first selection persist before any review, so a retry
//! never selects again. A selected candidate is reviewed over the decision
//! read whole and its evidence under the Coach's own scoped read, and its
//! [`TopologyAuditResult`] is append-only. A candidate the recipe cannot be
//! asked about now stays pending; one it cannot judge is `Unknown`, never a
//! pass. A decision already undone or superseded is `Obsolete`, never
//! reviewed.
//!
//! A result is local review evidence: never a seal, an owner ruling, a
//! graduation input or a permission. A `Concern` on a decision still current
//! makes the Coach's receipted correction through the existing undo door,
//! with that door's authority and revision checks, unless the owner made the
//! decision: an owner's own decision is never undone by a review. The
//! catastrophe floor and every ordinary pre-check stay as they are.
//!
//! A recipe's answer is a declared model judgment, its scorer in the
//! decision receipt and its prompt in the recipe revision (L08-A 20:15).
//! Nothing here feeds a feedback, attribution or learning lane: a pass
//! invents no positive, a missing or abstaining review no loss, and an
//! unknown stays unknown without holding up the drain or the apply. A
//! correction the Coach made is its own receipted act, never the reviewed
//! decision's verified failure.
//!
//! The three tables are local side tables, never replicated authority, in the
//! canonical checkpoint tier: they restore as content, an erase of any record
//! a candidate names drops it, each declares the actor scrub an actor's erase
//! runs, and a home move carries them (the `home` submodule).

use serde::{Deserialize, Serialize};

use crate::claim::ClaimApprovalStatus;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideCodec, SideTable};
use crate::store::Store;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

use super::stored_event::{StoredIdentityOpAction, StoredIdentityOpEvent};

#[cfg(feature = "sync")]
mod home;
mod receipts;
mod run;

#[cfg(feature = "sync")]
pub(crate) use home::CoachTopologyAuditRows;
pub(crate) use receipts::topology_audit_receipts;
pub use run::{
    TopologyAuditAnswer, TopologyAuditCase, TopologyAuditRecipe, TopologyAuditReport,
    TopologyAuditReviewer,
};

/// The version of the rows this module writes.
const TOPOLOGY_AUDIT_SCHEMA_VERSION: u16 = 1;

/// The domain an audit's id derives under.
const AUDIT_ID_DOMAIN: &[u8] = b"oneiron/identity-topology/post-hoc-audit/v1";

#[doc(hidden)]
use oneiron_records::identity_topology::post_hoc_review::SELECTION_DIGEST_DOMAIN;
#[doc(hidden)]
pub use oneiron_records::identity_topology::post_hoc_review::{
    TopologyAuditCorrection, TopologyAuditDecider, TopologyAuditEvidence, TopologyAuditIntent,
    TopologyAuditOutcome, TopologyAuditResult, TopologyAuditScope, TopologyAuditSelection,
};

/// One durable candidate per eligible decision. Key: the audit id.
const INTENTS: SideTable<[u8; 32], TopologyAuditIntent, Named> =
    SideTable::new(&side_table::COACH_TOPOLOGY_AUDIT_INTENT);
/// The first selection of each candidate. Key: the audit id.
const SELECTIONS: SideTable<[u8; 32], TopologyAuditSelection, Named> =
    SideTable::new(&side_table::COACH_TOPOLOGY_AUDIT_SELECTION);
/// The one result of each reviewed candidate, append-only. Key: the audit id.
const RESULTS: SideTable<[u8; 32], TopologyAuditResult, Named> =
    SideTable::new(&side_table::COACH_TOPOLOGY_AUDIT_RESULT);

/// One eligible decision as its writer holds it.
pub(super) struct AuditDeclaration<'a> {
    pub(super) event: EntityId,
    pub(super) disposition: EntityId,
    /// The stored record its seal binds: a manifest for a decision in parts.
    pub(super) stored: &'a StoredIdentityOpEvent,
    /// The decision read whole.
    pub(super) record: &'a StoredIdentityOpEvent,
    pub(super) actor: Option<WriteActor>,
    pub(super) decided_by: TopologyAuditDecider,
}

/// Whether the apply door's decision is one this review covers: a local
/// `Auto` merge, split or facet.
pub(super) fn eligible(approval: ClaimApprovalStatus, action: &StoredIdentityOpAction) -> bool {
    approval == ClaimApprovalStatus::Auto
        && matches!(
            action,
            StoredIdentityOpAction::Merge { .. }
                | StoredIdentityOpAction::Split { .. }
                | StoredIdentityOpAction::Facet { .. }
        )
}

/// The audit id of `event` at `core_digest`.
fn audit_id(event: &EntityId, core_digest: &[u8; 32]) -> [u8; 32] {
    *blake3::Hasher::new()
        .update(AUDIT_ID_DOMAIN)
        .update(event.as_bytes())
        .update(core_digest)
        .finalize()
        .as_bytes()
}

/// Every record the decision `record` (read whole) of `event` names, each
/// once, in this order: its participants (a merge's sources and survivor, a
/// split's entity and heads, a facet's entity and masks); each claim its
/// reassignment map routes, or an edge item's two endpoints; each fork a
/// facet birthed; then its evidence refs. A review reads all of them, or
/// judges nothing.
///
/// # Errors
///
/// Never in practice: a fork id derives from a fixed domain.
fn decision_records(event: &EntityId, record: &StoredIdentityOpEvent) -> Result<Vec<EntityId>> {
    let mut records = Vec::new();
    match &record.action {
        StoredIdentityOpAction::Merge { sources, survivor } => {
            records.extend(sources.iter().copied());
            records.push(*survivor);
        }
        StoredIdentityOpAction::Split {
            entity,
            heads,
            reassignment,
            ..
        } => {
            records.push(*entity);
            records.extend(heads.iter().copied());
            records.extend(reassigned(reassignment));
        }
        StoredIdentityOpAction::Facet {
            entity,
            facets,
            reassignment,
            forked,
            ..
        } => {
            records.push(*entity);
            records.extend(facets.iter().copied());
            records.extend(reassigned(reassignment));
            for origin in forked {
                records.push(super::op_apply::facet_fork_id(event, origin)?);
            }
        }
        _ => {}
    }
    if let Some(evidence) = &record.evidence {
        records.extend(evidence.refs.iter().copied());
    }
    let mut seen = std::collections::BTreeSet::new();
    records.retain(|id| seen.insert(*id));
    Ok(records)
}

/// The records a reassignment map routes: each claim item, and each edge
/// item's two endpoints.
fn reassigned(map: &super::ReassignmentMap) -> impl Iterator<Item = EntityId> + '_ {
    map.entries.iter().flat_map(|entry| match entry.item {
        crate::claim::ClaimSubject::Entity(id) => vec![id],
        crate::claim::ClaimSubject::Edge { source, target, .. } => vec![source, target],
    })
}

/// The primary target of a merge (its survivor), split or facet (its entity).
fn primary_target(action: &StoredIdentityOpAction) -> Option<EntityId> {
    match action {
        StoredIdentityOpAction::Merge { survivor, .. } => Some(*survivor),
        StoredIdentityOpAction::Split { entity, .. }
        | StoredIdentityOpAction::Facet { entity, .. } => Some(*entity),
        _ => None,
    }
}

/// Keeps one eligible decision's review candidate and queues the Coach's
/// deduplicated job, in the decision's own writer. A replayed writer finds
/// the candidate it kept and the job it queued. A node that froze its home
/// state for a move declares nothing: its audit rows are history.
pub(super) fn declare_topology_audit_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    declaration: &AuditDeclaration<'_>,
    now: u64,
) -> Result<()> {
    #[cfg(feature = "sync")]
    if !keeps_audit_rows_in_txn(vault, &*txn)? {
        return Ok(());
    }
    let core_digest = super::core_digest(declaration.stored)?;
    let audit_id = audit_id(&declaration.event, &core_digest);
    if INTENTS.contains(&vault.store, &*txn, &audit_id)? {
        return Ok(());
    }
    let action = &declaration.record.action;
    let target = primary_target(action).ok_or(Error::InvariantViolation(
        "a topology audit covers a merge, split or facet only",
    ))?;
    // The registry class name, as a proposal's scope names it; a type the
    // registry does not name keeps its code, so a class name never refuses
    // the decision it describes.
    let target_class = match vault.get_entity_type_in_txn(&*txn, &target)? {
        Some(code) => crate::registry::entity_type_registry_entry(code)
            .map_or_else(|| format!("type:{code}"), |entry| entry.kind.to_owned()),
        None => "unknown".to_owned(),
    };
    let actor = super::proposer_scope::proposal_seal_scope_actor_in_txn(
        &vault.store,
        txn,
        declaration.actor.map(WriteActor::entity_ref),
    )?;
    let subjects = decision_records(&declaration.event, declaration.record)?;
    let intent = TopologyAuditIntent {
        schema_version: TOPOLOGY_AUDIT_SCHEMA_VERSION,
        audit_id,
        event: declaration.event,
        core_digest,
        disposition: declaration.disposition,
        scope: TopologyAuditScope {
            op_kind: action.kind_str().to_owned(),
            target_class,
            actor,
        },
        decided_by: declaration.decided_by,
        subjects,
        origin_attempt: declaration.actor.and_then(WriteActor::run_attempt),
        created_at: now,
    };
    INTENTS.put(&vault.store, txn, &audit_id, &intent)?;
    enqueue_drain_in_txn(vault, txn, now)
}

/// Queues the Coach's drain of pending candidates under its one fixed key:
/// a queued or running drain absorbs the request.
fn enqueue_drain_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>, now: u64) -> Result<()> {
    DreamerRunnerStore::new(vault).enqueue_coach_topology_audit_in_txn(txn, now)?;
    Ok(())
}

/// Whether this node still keeps the Coach's audit rows (FIX 5661, C1): not
/// once it froze its home state for a move and adopted none since. Its rows
/// are then history, the move carried them and the new home reviews them,
/// so this node writes no candidate, selection or result more; a move that
/// chains back here replaces them whole.
#[cfg(feature = "sync")]
fn keeps_audit_rows_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    crate::sync::home_handoff::takes_home_write_in_txn(
        vault,
        txn,
        crate::sync::home_handoff::HomeWrite::Settle,
    )
}

/// Drops every candidate that names the erased `id`, as its decision, as
/// one of its subjects or as a record its review read, with its selection
/// and result: the review of a decision about an erased record is not kept.
/// A no-op for an id none names.
pub(crate) fn erase_topology_audit_sources_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let mut named: Vec<[u8; 32]> = INTENTS
        .scan(store, &*txn)?
        .into_iter()
        .filter(|(_, intent)| {
            intent.event == *id || intent.disposition == *id || intent.subjects.contains(id)
        })
        .map(|(audit, _)| audit)
        .collect();
    named.extend(
        RESULTS
            .scan(store, &*txn)?
            .into_iter()
            .filter(|(_, result)| result.evidence_refs.contains(id))
            .map(|(audit, _)| audit),
    );
    for audit in named {
        INTENTS.delete(store, txn, &audit)?;
        SELECTIONS.delete(store, txn, &audit)?;
        RESULTS.delete(store, txn, &audit)?;
    }
    Ok(())
}

/// The actor scrub the three tables declare (FIX 3520, FIX 7817), run in
/// an actor's erase. A candidate whose decision names the erased actor among
/// its subjects goes with its selection and result, as an entity erase takes
/// it. A remaining result the actor reviewed keeps its outcome with no
/// reviewer, and a selection or result whose decision receipt names the
/// actor (its principal, a provider pin or an evidence version) keeps no
/// receipt. The scope's opaque handle stays: the handle map forgets the
/// actor in the same erase (FIX 10189), so it names no one.
pub(crate) fn erase_topology_audit_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::ports::names_no_actor_in_txn(&vault.store, &*txn, actor)? {
        return Ok(());
    }
    erase_topology_audit_sources_in_txn(&vault.store, txn, actor)?;
    let named = |receipt: &Option<String>| {
        receipt
            .as_deref()
            .is_some_and(|receipt| receipt.contains(&actor.to_hex()))
    };
    for (audit, mut selection) in SELECTIONS.scan(&vault.store, &*txn)? {
        if named(&selection.decision_receipt) {
            selection.decision_receipt = None;
            SELECTIONS.put(&vault.store, txn, &audit, &selection)?;
        }
    }
    for (audit, mut result) in RESULTS.scan(&vault.store, &*txn)? {
        if result.reviewer == Some(*actor) || named(&result.decision_receipt) {
            if result.reviewer == Some(*actor) {
                result.reviewer = None;
            }
            if named(&result.decision_receipt) {
                result.decision_receipt = None;
            }
            RESULTS.put(&vault.store, txn, &audit, &result)?;
        }
    }
    Ok(())
}
