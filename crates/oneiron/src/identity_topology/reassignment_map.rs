//! The ONE-1745 reassignment projection end to end: the typed map model, its
//! canonical wire codec, and the per-claim `vault_meta` rows the split and
//! facet apply doors record it as.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::batch::BatchOp;
use crate::claim::ClaimSubject;
use crate::edge::EdgeKind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;

use super::event_body_codec::{decode_id_bytes, decode_id_value, id_value, map_field};
use super::ledger_fold::IdentityTopologyFold;
use super::lifecycle_state::EntityLifecycleState;
use super::store_entity_helpers::{
    identity_topology_entity_type_for_store_in_txn, identity_topology_event_for_store_in_txn,
    topology_edge_weight,
};
use super::stored_event::StoredIdentityOpAction;
use super::wire_keys::{MAP_KEY_FACET, MAP_KEY_HEAD, MAP_KEY_ITEM};

/// One reassignment-map row: where an item of the split/facet entity goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReassignmentEntry {
    /// The claim (entity ref) or edge being reassigned.
    pub item: ClaimSubject,
    /// Destination head / facet, or explicit residue.
    pub target: ReassignmentTarget,
}

/// Destination of one reassignment-map row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReassignmentTarget {
    /// Assign to a split head (must be one of the op's `heads`).
    Head(EntityId),
    /// Assign to the facet minted from the op's `facets[index]` spec.
    Facet {
        /// Index into the facet op's `facets` list.
        index: u32,
    },
    /// Unattributable residue: stays on the original entity, marked
    /// ambiguous — never force-assigned (r2).
    Residue,
}

/// Evidence-guided reassignment map shared by split and facet (r2/r5).
///
/// The map is encoded CANONICALLY into the split event record (entries
/// normalized by item bytes) so ONE-1745 replays exactly what the decision
/// stated; MS-01 validates targets and records — application arms there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReassignmentMap {
    /// Per-item assignments. An item the map does not name is NOT residue —
    /// it is outside the decision entirely: it stays on the origin and reads
    /// back through [`Vault::claims_remaining_on_origin`](crate::Vault::claims_remaining_on_origin) (everything
    /// subject-bound to the origin minus what a split routed away).
    /// [`ReassignmentTarget::Residue`] is the stronger, r2-mandated
    /// statement — the decision LOOKED at the item and could not attribute
    /// it — and only those rows answer [`Vault::ambiguous_residue_claims`](crate::Vault::ambiguous_residue_claims),
    /// a subset of what remains. Collapsing the two would erase the
    /// "unattributable" judgment AND unbind the applied residue count from
    /// the map the event stores.
    pub entries: Vec<ReassignmentEntry>,
}

impl ReassignmentMap {
    /// r2 stats over the map: rows assigned to a head/facet vs rows left
    /// as explicit ambiguous residue.
    #[must_use]
    pub fn assigned_and_residue_counts(&self) -> (u64, u64) {
        let assigned = self
            .entries
            .iter()
            .filter(|entry| !matches!(entry.target, ReassignmentTarget::Residue))
            .count() as u64;
        let residue = self.entries.len() as u64 - assigned;
        (assigned, residue)
    }

    /// The canonical entry order the wire codec pins: sorted by encoded
    /// item bytes, then target shape — deterministic for any caller order.
    #[must_use]
    pub fn canonicalized(&self) -> Self {
        let mut entries = self.entries.clone();
        entries.sort_by_key(|entry| {
            (
                encode_reassignment_item(&entry.item),
                reassignment_target_rank(&entry.target),
            )
        });
        Self { entries }
    }
}

fn reassignment_target_rank(target: &ReassignmentTarget) -> (u8, Vec<u8>) {
    match target {
        ReassignmentTarget::Head(head) => (0, head.as_bytes().to_vec()),
        ReassignmentTarget::Facet { index } => (1, index.to_be_bytes().to_vec()),
        ReassignmentTarget::Residue => (2, Vec::new()),
    }
}

/// What `apply_reassignment_in_txn` recorded for one op (ARCH-0055 r2).
///
/// APPLIED counts, not declared ones: a map row naming an item this vault
/// holds no CLAIM for records nothing, so `assigned + residue` may be below
/// [`ReassignmentMap::assigned_and_residue_counts`]. The receipt projects
/// both, and the gap is the visible witness that a decision named something
/// the vault does not have.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReassignmentStats {
    /// Rows recorded against a concrete head or facet.
    pub assigned: usize,
    /// Rows recorded as explicit ambiguous residue on the origin.
    pub residue: usize,
}

/// The concrete destinations one op's reassignment rows resolve against —
/// the split's heads, or the facet op's freshly minted masks in spec order.
///
/// [`evaluate_transition`](super::evaluate_transition) has already refused the cross-shaped rows (a
/// facet target on a split, a head target on a facet, an out-of-range facet
/// index, a head the op does not name), so resolution here is total.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ReassignmentContext<'a> {
    /// Split heads: a [`ReassignmentTarget::Head`] row resolves to itself.
    Heads(&'a [EntityId]),
    /// Minted masks: a [`ReassignmentTarget::Facet`] row resolves by index.
    Facets(&'a [EntityId]),
}

impl ReassignmentContext<'_> {
    /// The entity one map row routes to, or `None` for ambiguous residue.
    ///
    /// A row whose target shape is foreign to the context is corruption,
    /// never caller error: the transition table rejects those shapes before
    /// any door reaches this code.
    fn resolve(self, target: &ReassignmentTarget) -> Result<Option<EntityId>> {
        let resolved = match (self, target) {
            (Self::Heads(heads), ReassignmentTarget::Head(head)) => {
                heads.iter().copied().find(|candidate| candidate == head)
            }
            (Self::Facets(facets), ReassignmentTarget::Facet { index }) => {
                facets.get(*index as usize).copied()
            }
            (_, ReassignmentTarget::Residue) => return Ok(None),
            _ => None,
        };
        resolved.map(Some).ok_or(Error::InvariantViolation(
            "identity topology reassignment target is not in the op's context",
        ))
    }
}

/// `vault_meta` key prefix of the SPLIT assignment index, keyed by ORIGIN:
/// prefix ++ origin(16) ++ event(16) ++ claim(16). The value is a
/// [`REASSIGNMENT_ROW_VERSION`]-tagged head id, or the bare version byte for
/// explicit ambiguous residue.
///
/// Keyed by event, not just by origin, so a row is owned by exactly the
/// ledger event that stated it: undo deletes its own rows and can never
/// clobber another event's.
///
/// This const lives with the family rather than in `store.rs` for the reason
/// [`IDENTITY_TOPOLOGY_SEQ_KEY`](super::IDENTITY_TOPOLOGY_SEQ_KEY) does — the family that owns the keyspace
/// owns its key shape, and `vault_meta` readers ignore unknown prefixes.
pub(crate) const REASSIGNMENT_ORIGIN_META_PREFIX: &[u8] = b"reassign:v1:o:";

/// `vault_meta` key prefix of the same index INVERTED by destination:
/// prefix ++ head(16) ++ event(16) ++ claim(16), value = the bare version
/// byte. [`Vault::claims_assigned_to`](crate::Vault::claims_assigned_to) is a prefix scan over this half; the
/// origin half alone would force a whole-table scan per query.
pub(crate) const REASSIGNMENT_TARGET_META_PREFIX: &[u8] = b"reassign:v1:t:";

/// Only accepted assignment-row version byte.
const REASSIGNMENT_ROW_VERSION: u8 = 1;

pub(super) fn encode_reassignment_item(item: &ClaimSubject) -> Vec<u8> {
    match item {
        ClaimSubject::Entity(id) => id.as_bytes().to_vec(),
        ClaimSubject::Edge {
            source,
            kind,
            target,
        } => {
            let mut bytes = Vec::with_capacity(ENTITY_ID_LEN * 2 + 1);
            bytes.extend_from_slice(source.as_bytes());
            bytes.push(*kind as u8);
            bytes.extend_from_slice(target.as_bytes());
            bytes
        }
    }
}

fn decode_reassignment_item(bytes: &[u8]) -> Result<ClaimSubject> {
    const ITEM_CONTEXT: &str = "identity topology event map item";
    match bytes.len() {
        ENTITY_ID_LEN => {
            let arr: [u8; ENTITY_ID_LEN] = bytes
                .try_into()
                .map_err(|_| Error::InvalidIdentityTopologyEventBody(ITEM_CONTEXT))?;
            EntityId::from_bytes(arr)
                .map(ClaimSubject::Entity)
                .map_err(|_| Error::InvalidIdentityTopologyEventBody(ITEM_CONTEXT))
        }
        len if len == ENTITY_ID_LEN * 2 + 1 => {
            let source = decode_id_bytes(&bytes[..ENTITY_ID_LEN], ITEM_CONTEXT)?;
            let kind = EdgeKind::try_from_u8(bytes[ENTITY_ID_LEN])
                .ok_or(Error::InvalidIdentityTopologyEventBody(ITEM_CONTEXT))?;
            let target = decode_id_bytes(&bytes[ENTITY_ID_LEN + 1..], ITEM_CONTEXT)?;
            Ok(ClaimSubject::Edge {
                source,
                kind,
                target,
            })
        }
        _ => Err(Error::InvalidIdentityTopologyEventBody(ITEM_CONTEXT)),
    }
}

pub(super) fn encode_reassignment_map(map: &ReassignmentMap) -> Value {
    let canonical = map.canonicalized();
    Value::Array(
        canonical
            .entries
            .iter()
            .map(|entry| {
                let mut fields = vec![(
                    Value::from(MAP_KEY_ITEM),
                    Value::Binary(encode_reassignment_item(&entry.item)),
                )];
                match entry.target {
                    ReassignmentTarget::Head(head) => {
                        fields.push((Value::from(MAP_KEY_HEAD), id_value(&head)));
                    }
                    ReassignmentTarget::Facet { index } => {
                        fields.push((Value::from(MAP_KEY_FACET), Value::from(index)));
                    }
                    ReassignmentTarget::Residue => {}
                }
                Value::Map(fields)
            })
            .collect(),
    )
}

pub(super) fn decode_reassignment_map(value: &Value) -> Result<ReassignmentMap> {
    const MAP_CONTEXT: &str = "identity topology event map";
    let Value::Array(rows) = value else {
        return Err(Error::InvalidIdentityTopologyEventBody(MAP_CONTEXT));
    };
    let mut entries = Vec::with_capacity(rows.len());
    let mut previous_item: Option<&[u8]> = None;
    for row in rows {
        let fields = row
            .as_map()
            .ok_or(Error::InvalidIdentityTopologyEventBody(MAP_CONTEXT))?;
        let item_bytes = map_field(fields, MAP_KEY_ITEM)
            .and_then(Value::as_slice)
            .ok_or(Error::InvalidIdentityTopologyEventBody(MAP_CONTEXT))?;
        // The pinned wire order is STRICTLY ascending encoded item bytes
        // (the `canonicalized()` sort key): equal items are the duplicate-
        // assignment shape (one claim must not carry two assignments), and
        // out-of-order rows would re-serialize to different bytes than
        // stored — breaking the on-disk == re-encoded identity the sync
        // divergence checks rely on. Fail closed on both.
        if previous_item.is_some_and(|previous| previous >= item_bytes) {
            return Err(Error::InvalidIdentityTopologyEventBody(MAP_CONTEXT));
        }
        previous_item = Some(item_bytes);
        let item = decode_reassignment_item(item_bytes)?;
        let head = map_field(fields, MAP_KEY_HEAD);
        let facet = map_field(fields, MAP_KEY_FACET);
        let target = match (head, facet) {
            (None, None) => ReassignmentTarget::Residue,
            (Some(head), None) => ReassignmentTarget::Head(decode_id_value(head, MAP_CONTEXT)?),
            (None, Some(index)) => ReassignmentTarget::Facet {
                index: index
                    .as_u64()
                    .and_then(|index| u32::try_from(index).ok())
                    .ok_or(Error::InvalidIdentityTopologyEventBody(MAP_CONTEXT))?,
            },
            (Some(_), Some(_)) => {
                return Err(Error::InvalidIdentityTopologyEventBody(MAP_CONTEXT));
            }
        };
        entries.push(ReassignmentEntry { item, target });
    }
    Ok(ReassignmentMap { entries })
}

/// The `vault_meta` key of one origin-side assignment row.
fn reassignment_origin_key(origin: &EntityId, event: &EntityId, claim: &EntityId) -> Vec<u8> {
    reassignment_key(REASSIGNMENT_ORIGIN_META_PREFIX, origin, event, claim)
}

/// The `vault_meta` key of one destination-side assignment row.
fn reassignment_target_key(target: &EntityId, event: &EntityId, claim: &EntityId) -> Vec<u8> {
    reassignment_key(REASSIGNMENT_TARGET_META_PREFIX, target, event, claim)
}

fn reassignment_key(
    prefix: &[u8],
    anchor: &EntityId,
    event: &EntityId,
    claim: &EntityId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + ENTITY_ID_LEN * 3);
    key.extend_from_slice(prefix);
    key.extend_from_slice(anchor.as_bytes());
    key.extend_from_slice(event.as_bytes());
    key.extend_from_slice(claim.as_bytes());
    key
}

/// Splits a stored assignment key back into `(event, claim)`. Both halves are
/// fixed-width tails, so this is exact for either prefix.
fn decode_reassignment_key(prefix: &[u8], key: &[u8]) -> Result<(EntityId, EntityId)> {
    let corrupt = || Error::CorruptedIndex("identity reassignment key");
    let tail = key
        .get(prefix.len() + ENTITY_ID_LEN..)
        .ok_or_else(corrupt)?;
    let (event, claim) = tail.split_at_checked(ENTITY_ID_LEN).ok_or_else(corrupt)?;
    let id = |bytes: &[u8]| {
        let bytes: [u8; ENTITY_ID_LEN] = bytes.try_into().map_err(|_| corrupt())?;
        EntityId::from_bytes(bytes).map_err(|_| corrupt())
    };
    Ok((id(event)?, id(claim)?))
}

/// Encodes an assignment row: a bare version byte is explicit ambiguous
/// residue, a version byte plus a head id is an assignment.
fn encode_reassignment_row(target: Option<&EntityId>) -> Vec<u8> {
    let mut row = vec![REASSIGNMENT_ROW_VERSION];
    if let Some(target) = target {
        row.extend_from_slice(target.as_bytes());
    }
    row
}

/// Decodes an assignment row, fail-closed on any shape the encoder cannot
/// produce.
fn decode_reassignment_row(row: &[u8]) -> Result<Option<EntityId>> {
    let corrupt = || Error::CorruptedIndex("identity reassignment row");
    let [REASSIGNMENT_ROW_VERSION, target @ ..] = row else {
        return Err(corrupt());
    };
    if target.is_empty() {
        return Ok(None);
    }
    let bytes: [u8; ENTITY_ID_LEN] = target.try_into().map_err(|_| corrupt())?;
    EntityId::from_bytes(bytes).map(Some).map_err(|_| corrupt())
}

/// Resolves a decision's reassignment map into the concrete rows a vault can
/// record: `(claim, Some(destination))` or `(claim, None)` for residue.
///
/// Three filters, all deliberate:
/// - only an [`ClaimSubject::Entity`] item that names a STORED CLAIM row
///   resolves. An edge item is a later surface (the map vocabulary admits
///   one, r2, but moving an edge is not claim assignment), and an item this
///   vault holds nothing for records nothing.
/// - the claim must be ONE OF `origin`'s. A `ReassignmentEntry` is "where an
///   item OF the split/facet entity goes", but nothing upstream enforces
///   that: [`evaluate_transition`](super::evaluate_transition) checks the map's TARGETS, never its
///   items' provenance, and the map replicates verbatim on a peer's event.
///   Without this filter a split of `A` files an unrelated `B`'s claim under
///   `A`'s head, and a facet of `A` stamps `B`'s claim `FacetOf` a mask `A`
///   owns — cross-identity contamination the two query surfaces would then
///   report as fact. Membership is read the way this family's own reader
///   reads it ([`Vault::claims_remaining_on_origin`](crate::Vault::claims_remaining_on_origin) → `claims_for_subject`):
///   the canonical `claim_of` edge, as a point lookup. A closure reading
///   (a claim inherited through a merge into `origin`) would have to move
///   BOTH readers together, so it stays one derivation.
/// - the destination comes from `targets`, so a row can only ever route
///   where the op itself said it could.
///
/// A dropped row is not an error on either door: the replicated door must
/// not let a planted body abort a reconcile, and the local door already
/// treats an unresolvable row this way. The gap between what the map
/// DECLARED and what this returns is exactly what [`ReassignmentStats`]
/// reports and the receipt projects.
fn resolve_reassignment_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    origin: &EntityId,
    map: &ReassignmentMap,
    targets: ReassignmentContext<'_>,
) -> Result<Vec<(EntityId, Option<EntityId>)>> {
    let mut rows = Vec::with_capacity(map.entries.len());
    for entry in &map.entries {
        let ClaimSubject::Entity(claim) = entry.item else {
            continue;
        };
        if identity_topology_entity_type_for_store_in_txn(store, rtxn, &claim)?
            != Some(ENTITY_TYPE_CLAIM)
        {
            continue;
        }
        if store
            .edges_out
            .get(
                rtxn,
                &Store::encode_edge_key(&claim, EdgeKind::ClaimOf, origin),
            )?
            .is_none()
        {
            continue;
        }
        rows.push((claim, targets.resolve(&entry.target)?));
    }
    Ok(rows)
}

/// Writes `rows` as `event`'s assignment rows for `origin`, both directions.
fn write_reassignment_rows_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    event: &EntityId,
    origin: &EntityId,
    rows: &[(EntityId, Option<EntityId>)],
) -> Result<()> {
    for (claim, target) in rows {
        store.vault_meta.put(
            wtxn,
            &reassignment_origin_key(origin, event, claim),
            &encode_reassignment_row(target.as_ref()),
        )?;
        if let Some(target) = target {
            store.vault_meta.put(
                wtxn,
                &reassignment_target_key(target, event, claim),
                &[REASSIGNMENT_ROW_VERSION],
            )?;
        }
    }
    Ok(())
}

/// Deletes every assignment row filed under `origin`, both directions.
///
/// `event` narrows the sweep to ONE ledger event's rows (the undo door, which
/// must not touch a sibling event's); `None` clears the origin outright (the
/// reconcile door, which re-derives the whole set from the fold).
pub(super) fn clear_reassignment_rows_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    origin: &EntityId,
    event: Option<&EntityId>,
) -> Result<()> {
    let mut prefix = Vec::with_capacity(REASSIGNMENT_ORIGIN_META_PREFIX.len() + ENTITY_ID_LEN * 2);
    prefix.extend_from_slice(REASSIGNMENT_ORIGIN_META_PREFIX);
    prefix.extend_from_slice(origin.as_bytes());
    if let Some(event) = event {
        prefix.extend_from_slice(event.as_bytes());
    }
    let mut stale: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
    for row in store.vault_meta.prefix_iter(&*wtxn, &prefix)? {
        let (key, value) = row?;
        let (event, claim) = decode_reassignment_key(REASSIGNMENT_ORIGIN_META_PREFIX, &key)?;
        let twin = decode_reassignment_row(value.as_ref())?
            .map(|target| reassignment_target_key(&target, &event, &claim));
        stale.push((key.to_vec(), twin));
    }
    for (key, twin) in stale {
        store.vault_meta.delete(wtxn, &key)?;
        if let Some(twin) = twin {
            store.vault_meta.delete(wtxn, &twin)?;
        }
    }
    Ok(())
}

/// Shared by `SplitOp` and `FacetOp` apply (ARCH-0055 r2/r5) — the ticket's
/// point is that ONE mechanism records both, never a per-op copy.
///
/// Records where each mapped claim went WITHOUT rewriting a single claim
/// subject (r6): the stored subject stays the id the writer stated, forever,
/// and assignment is a separate engine-authored record over it. Residue rows
/// are recorded as explicit ambiguous residue on the origin — never
/// force-assigned to a head the decision did not name.
///
/// The two arms differ only in WHERE the record lives, because they have
/// different canonical witnesses:
/// - a SPLIT assignment has none — no edge, no subject change — so the
///   `vault_meta` index IS the record, keyed by the event that stated it.
/// - a FACET assignment already has one: the canonical `facet_of` stamp
///   ([`EdgeKind::FacetOf`], ONE-1645's write-time type table), which the
///   local query filter and the federation selector both already read. A
///   second projection of it would be a stale twin, so the stamps are staged
///   into `stamps` and no index row is written.
///
/// `stamps` is applied by the caller's [`apply_ops`](crate::batch::apply_ops) batch AFTER the minted
/// FACET rows land in the same batch — a `facet_of` edge whose target has no
/// entity row fails closed at that table.
#[expect(
    clippy::too_many_arguments,
    reason = "one shared split/facet apply door over event + origin + map + targets, accumulating into the caller's effect batch"
)]
pub(crate) fn apply_reassignment_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    event: &EntityId,
    origin: &EntityId,
    map: &ReassignmentMap,
    targets: ReassignmentContext<'_>,
    stamps: &mut Vec<BatchOp>,
    now: u64,
) -> Result<ReassignmentStats> {
    let rows = resolve_reassignment_in_txn(store, &*wtxn, origin, map, targets)?;
    let assigned = rows.iter().filter(|(_, target)| target.is_some()).count();
    let stats = ReassignmentStats {
        assigned,
        residue: rows.len() - assigned,
    };
    match targets {
        ReassignmentContext::Heads(_) => {
            write_reassignment_rows_in_txn(store, wtxn, event, origin, &rows)?;
        }
        ReassignmentContext::Facets(_) => {
            let weight = topology_edge_weight(EdgeKind::FacetOf)?;
            for (claim, target) in rows {
                let Some(facet) = target else {
                    continue;
                };
                stamps.push(BatchOp::EdgeWithCreatedAt {
                    src: claim,
                    kind: EdgeKind::FacetOf,
                    tgt: facet,
                    weight,
                    created_at: now,
                    vad: crate::affect::Vad::NEUTRAL,
                    provenance: None,
                });
            }
        }
    }
    Ok(stats)
}

/// Re-derives the split assignment rows of exactly `sources` from the ledger
/// fold — the reconcile-door half of the projection, the twin of
/// [`crate::identity_redirect::maintain_redirect_projection_in_txn`].
///
/// The apply and undo doors maintain their own rows directly (they hold the
/// event and its map, so they need no fold — the ONE-1744 O(N²) lesson). This
/// path exists for the doors that DON'T: sync ingest of a replicated split,
/// and the ONE-1604-D1 post-eviction unwind, both of which change which
/// events are in force without ever running the apply door.
///
/// Memoryless by construction: every source is cleared and re-derived from
/// whichever split event the fold currently has in force, so an undone,
/// superseded, or evicted split loses its rows without anyone tracking that
/// it had them.
pub(super) fn maintain_split_reassignment_projection_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    sources: &BTreeSet<EntityId>,
    fold: &IdentityTopologyFold,
) -> Result<()> {
    for origin in sources {
        clear_reassignment_rows_in_txn(store, wtxn, origin, None)?;
        if fold.states.get(origin) != Some(&EntityLifecycleState::Split) {
            continue;
        }
        let Some(event) = fold.current_event.get(origin) else {
            continue;
        };
        let Some(record) = identity_topology_event_for_store_in_txn(store, &*wtxn, event)? else {
            continue;
        };
        let StoredIdentityOpAction::Split {
            heads,
            reassignment,
            ..
        } = &record.action
        else {
            continue;
        };
        let rows = resolve_reassignment_in_txn(
            store,
            &*wtxn,
            origin,
            reassignment,
            ReassignmentContext::Heads(heads),
        )?;
        write_reassignment_rows_in_txn(store, wtxn, event, origin, &rows)?;
    }
    Ok(())
}

/// Claim ids filed under one assignment-index prefix scan, deduplicated and
/// in ascending id order.
pub(super) fn reassignment_claims_for_prefix_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    index_prefix: &[u8],
    anchor: &EntityId,
    keep: impl Fn(Option<EntityId>) -> bool,
) -> Result<BTreeSet<EntityId>> {
    let mut prefix = Vec::with_capacity(index_prefix.len() + ENTITY_ID_LEN);
    prefix.extend_from_slice(index_prefix);
    prefix.extend_from_slice(anchor.as_bytes());
    let mut claims = BTreeSet::new();
    for row in store.vault_meta.prefix_iter(rtxn, &prefix)? {
        let (key, value) = row?;
        if !keep(decode_reassignment_row(value.as_ref())?) {
            continue;
        }
        claims.insert(decode_reassignment_key(index_prefix, &key)?.1);
    }
    Ok(claims)
}
