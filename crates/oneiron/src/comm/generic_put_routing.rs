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
    /// The projector takes it: the source event it records, or `None` for a
    /// replay, which records nothing.
    Projector(Option<CommSourceEvent>),
    /// It names a party this write does not hold.
    PartyMissing,
}

/// The source event a routed put records on its party, for the projector.
struct CommSourceEvent {
    party_ref: EntityId,
    kind: CommEventKind,
    channel_class: Option<String>,
    thread_ref: Option<String>,
    occurred_at: u64,
}

impl CommSourceEvent {
    /// Records this event in `wtxn` and projects it there through
    /// `projection`, which notes the event and the heads its rule writes.
    fn record_in_txn(
        &self,
        vault: &Vault,
        wtxn: &mut heed::RwTxn<'_>,
        projection: &mut RecordedEventProjection,
    ) -> Result<()> {
        let event_id = put_source_event_in_txn(
            vault,
            wtxn,
            self.party_ref,
            self.kind,
            self.channel_class.as_deref(),
            self.thread_ref.as_deref(),
            self.occurred_at,
        )
        .map_err(source_event_error)?;
        projection
            .project_in_txn(vault, wtxn, event_id, self.kind)
            .map_err(source_event_error)
    }
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
    match comm_put_route_in_txn(vault, wtxn, id, &body.predicate, &data)? {
        CommPutRoute::Door => Ok(false),
        CommPutRoute::Projector(event) => {
            if let Some(event) = event {
                let mut projection = RecordedEventProjection::default();
                event.record_in_txn(vault, wtxn, &mut projection)?;
                // The source event and the rows its projection wrote go to
                // the live-window mirror when the caller's write commits.
                #[cfg(feature = "sync")]
                crate::batch::queue_committed_rows(vault, wtxn, projection.into_written());
                #[cfg(not(feature = "sync"))]
                drop(projection);
            }
            Ok(true)
        }
        CommPutRoute::PartyMissing => Err(Error::EntityNotFound),
    }
}

/// A batch's generic puts of the projector-only `comm.*` classes, taken out
/// of its ops for the projector: the source events they record, in op order.
pub(crate) struct RoutedBatchPuts {
    events: Vec<CommSourceEvent>,
}

impl RoutedBatchPuts {
    /// Records each routed put's source event in `wtxn` and projects it
    /// there, in op order against one pass index; an event the projector's
    /// pass would leave waiting stays pending for that pass. Returns the ids
    /// this wrote: the source events and the heads their projection wrote.
    ///
    /// # Errors
    /// A source event the projector refuses, or a storage failure.
    pub(crate) fn record_in_txn(
        self,
        vault: &Vault,
        wtxn: &mut heed::RwTxn<'_>,
    ) -> Result<BTreeSet<EntityId>> {
        let mut projection = RecordedEventProjection::default();
        for event in &self.events {
            event.record_in_txn(vault, wtxn, &mut projection)?;
        }
        Ok(projection.into_written())
    }
}

/// Routes a batch's generic puts of the projector-only `comm.*` classes
/// through the projector, in the batch's own write, before any op stages:
/// [`take_projector_only_batch_puts_in_txn`], then
/// [`RoutedBatchPuts::record_in_txn`]. Returns the ids the routing wrote:
/// the source events and the heads their projection wrote.
///
/// # Errors
/// As those two.
pub(crate) fn route_projector_only_batch_puts_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    ops: &mut Vec<BatchOp>,
) -> Result<BTreeSet<EntityId>> {
    match take_projector_only_batch_puts_in_txn(vault, wtxn, ops)? {
        Some(routed) => routed.record_in_txn(vault, wtxn),
        None => Ok(BTreeSet::new()),
    }
}

/// Takes a batch's generic puts of the projector-only `comm.*` classes out
/// of `ops` for the projector, reading `txn` and writing nothing. Returns
/// them, or `None` when no put leaves the batch.
///
/// A put routes as [`route_projector_only_comm_put_in_txn`] routes one, when
/// it is a CLAIM put with every admit flag closed (so no replicated,
/// engine-history or reserved-door put) whose body decodes to a routed class.
/// A routed put leaves `ops`, with each ClaimOf edge the batch writes from
/// its id. A put stays with the door, as before, when another op of the batch
/// names its id, or when the party it names is not stored yet (the batch may
/// put it).
///
/// # Errors
/// A routed body the door refuses, or a storage failure.
pub(crate) fn take_projector_only_batch_puts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ops: &mut Vec<BatchOp>,
) -> Result<Option<RoutedBatchPuts>> {
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
        return Ok(None);
    }
    let mut mentions: HashMap<EntityId, usize> = HashMap::new();
    for op in ops.iter() {
        note_named_ids(op, |id| *mentions.entry(id).or_default() += 1);
    }
    let mut events = Vec::new();
    let mut routed = BTreeSet::new();
    for (index, predicate) in candidates {
        let BatchOp::Put { id, data, .. } = &ops[index] else {
            continue;
        };
        if mentions.get(id) != Some(&1) {
            continue;
        }
        if let CommPutRoute::Projector(event) =
            comm_put_route_in_txn(vault, txn, id, &predicate, data)?
        {
            events.extend(event);
            routed.insert(*id);
        }
    }
    if routed.is_empty() {
        return Ok(None);
    }
    ops.retain(|op| !leaves_with_routed_put(op, &routed));
    Ok(Some(RoutedBatchPuts { events }))
}

/// Where one generic put of `data`, a body of the routed class `predicate`,
/// at `id` goes, as [`route_projector_only_comm_put_in_txn`] says, read in
/// `txn`.
fn comm_put_route_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    predicate: &str,
    data: &[u8],
) -> Result<CommPutRoute> {
    if !claim_class_descriptor_in_txn(&vault.store, txn, predicate)?
        .is_some_and(|descriptor| descriptor.projector_only)
    {
        return Ok(CommPutRoute::Door);
    }
    let body = crate::claim::validate_claim_body_and_decode_in_txn(&vault.store, txn, data, false)?;
    if let Some(resident) = vault.store.port_entity_record(txn, id)?
        && resident.entity_type == ENTITY_TYPE_CLAIM
        && resident.body == data[..]
    {
        return Ok(CommPutRoute::Projector(None));
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
    match vault.store.port_entity_record(txn, &party_ref)? {
        None => Ok(CommPutRoute::PartyMissing),
        // The projector writes a comm head only on a PERSON party.
        Some(party) if party.entity_type != ENTITY_TYPE_PERSON => Ok(CommPutRoute::Door),
        Some(_) => Ok(CommPutRoute::Projector(Some(CommSourceEvent {
            party_ref,
            kind,
            channel_class,
            thread_ref,
            occurred_at,
        }))),
    }
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
