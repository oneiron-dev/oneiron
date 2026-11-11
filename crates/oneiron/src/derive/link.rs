//! Identity links (kind 4, decision C-4): they land as proposals. A SameAs
//! between two claims lands as its proposed coreference status claim, and an
//! identity-topology judgment as a parked proposal event; an edge is applied,
//! or a topology event takes effect, only where a grant of today already
//! allows it: the owner's standing nightly-link grant for a SameAs, the
//! agent's own `topology_seal` Grant for a judgment. The status claim takes
//! the source's exposure, and a reader is served it only beside both claims.

use rmpv::Value;

use super::batch::{DerivedSameAs, DerivedTopology};
use super::claim::{StagedClaim, stage_candidate_in_txn};
use super::commit::{ItemContext, ItemOutcome, allowance_receipt_in_txn, refusal_receipt_in_txn};
use crate::authority::{ActAuthority, OwnerActKind};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::{Error, Result};
use crate::gate::{DeriveCapability, derive_verdict_in_txn};
use crate::identity_topology::{IdentityOpOutcome, IdentityOpWrite, TopologySeal};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::{ClaimCandidate, EntityId, Vault};

/// The refusal of a SameAs whose endpoints are not two claims the actor
/// reads.
pub const SAME_AS_NOT_CLAIMS: &str = "gate.deny.derive.same_as_not_claims";

/// The refusal of a topology judgment by an actor that names no live
/// `topology_seal` Grant of its own.
pub const TOPOLOGY_NEEDS_GRANT: &str = "gate.deny.derive.topology_needs_grant";

/// The refusal of a topology judgment naming a row the actor does not read.
pub const TOPOLOGY_UNREAD: &str = "gate.deny.derive.topology_unread";

/// The refusal of a topology judgment the topology ledger's transition
/// table or seal refuses.
pub const TOPOLOGY_REJECTED: &str = "gate.deny.derive.topology_rejected";

/// The reason a landed topology judgment's receipt names.
const TOPOLOGY_ALLOWED: &str = "gate.allow.derive.topology";

/// Stages a SameAs: the verdict is asked with no target because a proposal
/// changes neither claim. The actor's own read decides both ends, then the
/// proposed coreference status claim goes through the claim gate as the
/// caller. When the owner's standing nightly-link grant names this actor,
/// the SameAs edge is applied in a savepoint of its own; an edge the writer
/// refuses leaves the link proposed. The status claim takes the source's
/// exposure, and a reader is served it only beside both claims.
///
/// # Errors
///
/// Storage errors: each aborts the whole commit.
pub(super) fn stage_same_as_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    item: &DerivedSameAs,
) -> Result<ItemOutcome> {
    let source = context.resolve(&item.source)?;
    let target = context.resolve(&item.target)?;
    if let Err(refusal) = derive_verdict_in_txn(
        &vault.store,
        txn,
        context.stamp.actor,
        DeriveCapability::Derive,
        None,
    )? {
        return refuse(vault, txn, context, source, refusal.token());
    }
    let read = super::actor_read(vault, context.stamp.actor)?;
    let rows = read.get_entities_parts_in_txn(txn, &[source, target])?;
    let mut bodies = Vec::with_capacity(2);
    for row in rows {
        let Some((ENTITY_TYPE_CLAIM, _, body)) = row else {
            return refuse(vault, txn, context, source, SAME_AS_NOT_CLAIMS);
        };
        let Ok(body) = crate::claim::decode_claim_body(&body, true) else {
            return refuse(vault, txn, context, source, SAME_AS_NOT_CLAIMS);
        };
        bodies.push(body);
    }
    if source == target {
        return refuse(vault, txn, context, source, SAME_AS_NOT_CLAIMS);
    }
    // As the Dreamer's nightly SameAs drafts it: under the source's own
    // exposure, its refs the pair, its taint the pair's meet. The refs ride
    // the typed evidence envelope, as a derived claim's do: the derivation
    // floor (GATE-12) reads no other shape, and a bare `refs` map is no
    // evidence to it.
    let meet = bodies.iter().fold(ClaimSource::Generated, |meet, body| {
        crate::dreamer_consolidation::source_meet(
            meet,
            crate::claim::claim_evidence_taint(body)
                .or(body.source)
                .unwrap_or(ClaimSource::Generated),
        )
    });
    let anchor = &bodies[0];
    let mut candidate = ClaimCandidate::new(
        crate::claim::PREDICATE_COREFERENCE_STATUS,
        ClaimSubject::Edge {
            source,
            kind: EdgeKind::SameAs,
            target,
        },
        Value::from(crate::claim::COREFERENCE_STATUS_PROPOSED),
        1.0,
    )
    .with_scope_stamps(anchor.scope_facet, anchor.scope_project)
    .with_evidence(crate::dreamer_consolidation::encode_consolidation_evidence(
        &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
            refs: vec![source, target],
            chain: Vec::new(),
            source_meet: meet,
        },
    ));
    if let Some(world) = anchor.world {
        candidate = candidate.with_world(world);
    }
    candidate = candidate.with_relationships(anchor.rel.clone());
    if let Some(scope) = crate::claim::without_initial_weight(anchor.scope.clone()) {
        candidate = candidate.with_scope(scope);
    }
    let candidate = candidate.with_evidence_taint(meet)?;
    let status_claim = EntityId::now();
    // Both claims were read under the actor's own read above. The status
    // claim keeps the unbound lane: the gate's reference check admits an
    // edge subject only once its edge is live, and a proposed link has none
    // yet.
    let outcome = stage_candidate_in_txn(
        vault,
        txn,
        context,
        &StagedClaim {
            local: &item.local,
            id: status_claim,
            candidate: &candidate,
            source: ClaimSource::Generated,
        },
        crate::core_write::CoreWriteLaneRef::Unbound,
    )?;
    if !matches!(outcome, ItemOutcome::Landed { .. }) {
        return Ok(outcome);
    }
    let actor = context.stamp.actor;
    if actor_fits_in_txn(vault, txn, actor)?
        && let Some(grant_ref) =
            crate::dreamer_consolidation::resources::require_nightly_link_write(vault, txn, actor)?
    {
        let link = crate::federation::ConsolidatedSameAs {
            actor,
            source,
            target,
            status_claim,
            grant_ref: &grant_ref,
        };
        let mut savepoint = vault.store.env.nested_write_txn(txn)?;
        match crate::federation::put_consolidated_same_as_in_txn(vault, &mut savepoint, &link) {
            Ok(()) => savepoint.commit()?,
            Err(error @ (Error::Storage(_) | Error::Io(_) | Error::MapFull)) => return Err(error),
            Err(_) => savepoint.abort(),
        }
    }
    Ok(outcome)
}

/// The coreference writer's actor check, in `txn`: the actor's row fits its
/// class.
fn actor_fits_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: crate::write_envelope::WriteActor,
) -> Result<bool> {
    use crate::ports::EntityStoreRead;
    let Some(raw) = vault.store.port_entity_record(txn, &actor.entity_ref())? else {
        return Ok(false);
    };
    Ok(crate::provenance::validate_actor_class(raw.entity_type, actor.actor_class()).is_ok())
}

/// Stages a topology judgment: the derive verdict with no target, the
/// actor's own live `topology_seal` Grant, and every row read by the actor;
/// then the judgment through the topology ledger under that Grant's seal,
/// in a savepoint of `txn`: a parked proposal, or an applied event when the
/// item asks for one.
///
/// # Errors
///
/// Storage errors: each aborts the whole commit.
pub(super) fn stage_topology_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    item: &DerivedTopology,
) -> Result<ItemOutcome> {
    let participants = item.op.participants();
    let about = participants.first().copied();
    let actor = context.stamp.actor;
    let allowance =
        match derive_verdict_in_txn(&vault.store, txn, actor, DeriveCapability::Derive, None)? {
            Ok(allowance) => allowance,
            Err(refusal) => return refuse_about(vault, txn, context, about, refusal.token()),
        };
    if participants.is_empty() {
        return refuse_about(vault, txn, context, about, TOPOLOGY_UNREAD);
    }
    if actor.actor_class() != EdgeActorClass::Agent {
        return refuse_about(vault, txn, context, about, TOPOLOGY_NEEDS_GRANT);
    }
    let Ok(granted) = vault.granted_act_in_txn(
        txn,
        actor.entity_ref(),
        item.grant,
        OwnerActKind::TopologySeal,
    ) else {
        return refuse_about(vault, txn, context, about, TOPOLOGY_NEEDS_GRANT);
    };
    let read = super::actor_read(vault, actor)?;
    if read
        .get_entities_parts_in_txn(txn, &participants)?
        .iter()
        .any(Option::is_none)
    {
        return refuse_about(vault, txn, context, about, TOPOLOGY_UNREAD);
    }
    let seal = TopologySeal::decision(ActAuthority::Agent(granted));
    let write = IdentityOpWrite {
        source: ClaimSource::Generated,
        approval: if item.apply {
            ClaimApprovalStatus::Auto
        } else {
            ClaimApprovalStatus::Proposed
        },
        confidence: 1.0,
        actor: Some(actor),
    };
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    let event = match vault.apply_identity_topology_op_as_in_txn(
        &mut savepoint,
        &item.op,
        &write,
        &seal,
        context.now,
    ) {
        Ok(IdentityOpOutcome::Applied { event, .. } | IdentityOpOutcome::Parked { event }) => {
            savepoint.commit()?;
            event
        }
        Ok(IdentityOpOutcome::Noop) => {
            savepoint.abort();
            return refuse_about(vault, txn, context, about, TOPOLOGY_REJECTED);
        }
        Err(error @ (Error::Storage(_) | Error::Io(_) | Error::MapFull)) => return Err(error),
        Err(_) => {
            savepoint.abort();
            return refuse_about(vault, txn, context, about, TOPOLOGY_REJECTED);
        }
    };
    let receipt = allowance_receipt_in_txn(
        vault,
        txn,
        context,
        Some(event),
        &[TOPOLOGY_ALLOWED.to_owned()],
        &allowance,
    )?;
    Ok(ItemOutcome::Landed {
        rows: vec![event],
        approval: Some(write.approval),
        receipt: Some(receipt),
    })
}

fn refuse(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    row: EntityId,
    reason: &str,
) -> Result<ItemOutcome> {
    refuse_about(vault, txn, context, Some(row), reason)
}

fn refuse_about(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    row: Option<EntityId>,
    reason: &str,
) -> Result<ItemOutcome> {
    let reasons = vec![reason.to_owned()];
    let receipt = refusal_receipt_in_txn(vault, txn, context, row, &reasons)?;
    Ok(ItemOutcome::Refused { reasons, receipt })
}
