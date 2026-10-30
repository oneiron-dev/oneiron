//! Generic claim-door and batch writes of the projector-only `comm.*`
//! classes, routed through the projector.
//!
//! The projector alone authors `comm.last_touch`, `comm.thread_member` and
//! the STOP heads of `comm.opt_out`: it mints each head at an id derived from
//! its source event, behind its compare-and-set write and its slot rules (the
//! newest touch supersedes the rest; one live membership per thread; a STOP
//! consumes its slot's clear gates). A generic write of these classes is not
//! refused. It is recorded as the source event the projector reads, and the
//! projector projects that event in the same write, so the head stands when
//! the write commits. The projector's own writes, the typed doors and
//! replication land through `apply_ops` and never come here.

use std::collections::{BTreeSet, HashMap};

use super::claims::{
    CommClaim, CommClaimValue, CommError, PREDICATE_COMM_LAST_TOUCH, PREDICATE_COMM_OPT_OUT,
    PREDICATE_COMM_THREAD_MEMBER,
};
use super::consent::OPT_OUT_REASON_STOP;
use super::descriptor::claim_class_descriptor_in_txn;
use super::projector::{RecordedEventProjection, put_source_event_in_txn};
use super::records::CommEventKind;
use crate::Vault;
use crate::batch::BatchOp;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, encode_claim_body};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};

/// The classes a generic write routes, while their descriptor says
/// `projector_only`.
const ROUTED_PREDICATES: [&str; 3] = [
    PREDICATE_COMM_LAST_TOUCH,
    PREDICATE_COMM_THREAD_MEMBER,
    PREDICATE_COMM_OPT_OUT,
];

/// Where one generic put of a routed class goes.
enum CommPutRoute {
    /// The door writes it as before.
    Door,
    /// The projector took it: recorded and projected, or a replay.
    Projector,
    /// It names a party this write does not hold.
    PartyMissing,
}

/// Routes one generic claim-door write of a projector-only `comm.*` class
/// through the projector, in the caller's write. Returns `true` when the
/// write was routed, so the door writes nothing more, and `false` when the
/// door writes it as before.
///
/// A class routes while its descriptor (the synced row, else the compiled
/// one) says `projector_only`. The body is validated as the door validates
/// it, so a body the door refuses is refused alike. A body byte-identical to
/// the claim already at `id` is a replay and records nothing. Otherwise the
/// fact the body states becomes a source event on the party it names: a live
/// touch an asserted touch, a live membership a join, a closed membership a
/// leave at its close, and a live STOP opt-out on one channel class an
/// inbound STOP, whose send hold starts in this write. The projector then
/// projects the event in this write and mints the head at its derived id, so
/// `id` stays free; an event the projector's pass would leave waiting stays
/// pending for that pass. A body that states no fact the projector authors (a
/// proposed, rejected or stale head, a closed touch, a closed opt-out, a
/// party-wide one or one for another reason) and a subject that is not a
/// PERSON party are left to the door.
///
/// # Errors
/// A body the door refuses, a subject that is not there, or a storage
/// failure.
pub fn route_projector_only_comm_put_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<bool> {
    if !ROUTED_PREDICATES.contains(&body.predicate.as_str()) {
        return Ok(false);
    }
    let data = encode_claim_body(body)?;
    let mut projection = RecordedEventProjection::default();
    match route_comm_put_in_txn(vault, wtxn, id, &body.predicate, &data, &mut projection)? {
        CommPutRoute::Door => Ok(false),
        CommPutRoute::Projector => Ok(true),
        CommPutRoute::PartyMissing => Err(Error::EntityNotFound),
    }
}

/// Routes a batch's generic puts of the projector-only `comm.*` classes
/// through the projector, in the batch's own write, before any op stages.
///
/// A put routes as [`route_projector_only_comm_put_in_txn`] routes one, when
/// it is a CLAIM put with every admit flag closed (so no replicated,
/// engine-history or reserved-door put) whose body decodes to a routed class.
/// A routed put leaves `ops`, with each ClaimOf edge the batch writes from
/// its id; its events project in op order against one pass index. A put
/// stays with the door, as before, when another op of the batch names its
/// id, or when the party it names is not stored yet (the batch may put it).
///
/// # Errors
/// A routed body the door refuses, or a storage failure.
pub(crate) fn route_projector_only_batch_puts_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    ops: &mut Vec<BatchOp>,
) -> Result<()> {
    let candidates: Vec<(usize, String)> = ops
        .iter()
        .enumerate()
        .filter_map(|(index, op)| {
            let BatchOp::Put {
                entity_type: ENTITY_TYPE_CLAIM,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
                ..
            } = op
            else {
                return None;
            };
            let predicate = crate::claim::decode_claim_body(data, false).ok()?.predicate;
            ROUTED_PREDICATES
                .contains(&predicate.as_str())
                .then_some((index, predicate))
        })
        .collect();
    if candidates.is_empty() {
        return Ok(());
    }
    let mut mentions: HashMap<EntityId, usize> = HashMap::new();
    for op in ops.iter() {
        note_named_ids(op, |id| *mentions.entry(id).or_default() += 1);
    }
    let mut projection = RecordedEventProjection::default();
    let mut routed = BTreeSet::new();
    for (index, predicate) in candidates {
        let BatchOp::Put { id, data, .. } = &ops[index] else {
            continue;
        };
        if mentions.get(id) != Some(&1) {
            continue;
        }
        if matches!(
            route_comm_put_in_txn(vault, wtxn, id, &predicate, data, &mut projection)?,
            CommPutRoute::Projector
        ) {
            routed.insert(*id);
        }
    }
    if !routed.is_empty() {
        ops.retain(|op| !leaves_with_routed_put(op, &routed));
    }
    Ok(())
}

/// Routes one generic put of `data`, a body of the routed class `predicate`,
/// at `id`, as [`route_projector_only_comm_put_in_txn`] says.
fn route_comm_put_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    predicate: &str,
    data: &[u8],
    projection: &mut RecordedEventProjection,
) -> Result<CommPutRoute> {
    if !claim_class_descriptor_in_txn(&vault.store, wtxn, predicate)?
        .is_some_and(|descriptor| descriptor.projector_only)
    {
        return Ok(CommPutRoute::Door);
    }
    let body =
        crate::claim::validate_claim_body_and_decode_in_txn(&vault.store, wtxn, data, false)?;
    if let Some(resident) = vault.store.port_entity_record(&*wtxn, id)?
        && resident.entity_type == ENTITY_TYPE_CLAIM
        && resident.body == data[..]
    {
        return Ok(CommPutRoute::Projector);
    }
    let claim = CommClaim::from_claim_body(&body)?;
    let stated = matches!(
        claim.approval,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
    ) && !claim.stale;
    let live = stated && claim.lifecycle == ClaimLifecycleStatus::Active;
    let (party_ref, kind, channel_class, thread_ref, occurred_at) = match claim.value {
        CommClaimValue::LastTouch {
            party_ref,
            channel_class,
            occurred_at,
        } if live => (
            party_ref,
            CommEventKind::TouchAsserted,
            Some(channel_class),
            None,
            occurred_at,
        ),
        CommClaimValue::ThreadMember {
            party_ref,
            thread_ref,
            occurred_at,
        } if live => (
            party_ref,
            CommEventKind::ThreadJoined,
            None,
            Some(thread_ref),
            occurred_at,
        ),
        CommClaimValue::OptOut {
            party_ref,
            channel_class: Some(channel_class),
            reason,
            occurred_at,
        } if live && reason == OPT_OUT_REASON_STOP => (
            party_ref,
            CommEventKind::InboundStop,
            Some(channel_class),
            None,
            occurred_at,
        ),
        CommClaimValue::ThreadMember {
            party_ref,
            thread_ref,
            occurred_at,
        } if stated => (
            party_ref,
            CommEventKind::ThreadLeft,
            None,
            Some(thread_ref),
            claim.valid_to.unwrap_or(occurred_at),
        ),
        _ => return Ok(CommPutRoute::Door),
    };
    match vault.store.port_entity_record(&*wtxn, &party_ref)? {
        None => return Ok(CommPutRoute::PartyMissing),
        // The projector writes a comm head only on a PERSON party.
        Some(party) if party.entity_type != ENTITY_TYPE_PERSON => {
            return Ok(CommPutRoute::Door);
        }
        Some(_) => {}
    }
    let event_id = put_source_event_in_txn(
        vault,
        wtxn,
        party_ref,
        kind,
        channel_class.as_deref(),
        thread_ref.as_deref(),
        occurred_at,
    )
    .map_err(source_event_error)?;
    projection
        .project_in_txn(vault, wtxn, event_id, kind)
        .map_err(source_event_error)?;
    Ok(CommPutRoute::Projector)
}

fn source_event_error(error: CommError) -> Error {
    match error {
        CommError::Engine(error) => error,
        _ => Error::InvalidClaimBody("comm source event refused"),
    }
}

/// Calls `note` with each id `op` names, except the source of a ClaimOf edge
/// it writes: that edge leaves with its claim's routed put.
fn note_named_ids(op: &BatchOp, mut note: impl FnMut(EntityId)) {
    match op {
        BatchOp::Put { id, .. }
        | BatchOp::ClaimCandidate { id, .. }
        | BatchOp::Vector { id, .. }
        | BatchOp::Text { id, .. }
        | BatchOp::MediaVector { id, .. }
        | BatchOp::Phonetic { id, .. }
        | BatchOp::Delete { id } => note(*id),
        BatchOp::Edge { src, kind, tgt, .. }
        | BatchOp::PublicEdgeWithCreatedAt { src, kind, tgt, .. }
        | BatchOp::EdgeWithCreatedAt { src, kind, tgt, .. } => {
            if !matches!(kind, EdgeKind::ClaimOf) {
                note(*src);
            }
            note(*tgt);
        }
        BatchOp::SetEdgeWeight { src, tgt, .. }
        | BatchOp::SetEdgeVad { src, tgt, .. }
        | BatchOp::DeleteEdge { src, tgt, .. } => {
            note(*src);
            note(*tgt);
        }
        BatchOp::ReconcileLexicalQueryHints { source, keep } => {
            note(*source);
            keep.iter().copied().for_each(note);
        }
        BatchOp::CommitmentGapDecay { ids, .. } => ids.iter().copied().for_each(note),
    }
}

/// Whether `op` is a routed put, or a ClaimOf edge the batch writes from a
/// routed put's id.
fn leaves_with_routed_put(op: &BatchOp, routed: &BTreeSet<EntityId>) -> bool {
    match op {
        BatchOp::Put { id, .. } => routed.contains(id),
        BatchOp::Edge {
            src,
            kind: EdgeKind::ClaimOf,
            ..
        }
        | BatchOp::PublicEdgeWithCreatedAt {
            src,
            kind: EdgeKind::ClaimOf,
            ..
        }
        | BatchOp::EdgeWithCreatedAt {
            src,
            kind: EdgeKind::ClaimOf,
            ..
        } => routed.contains(src),
        _ => false,
    }
}
