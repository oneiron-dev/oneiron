//! The working set a caller seeds a context pack with (CROSS-ARCH-0011
//! amendment "workingSet"; CROSS-ARCH-0002b #ep-6-2-3): the rows a host
//! carried across a compaction. They are admitted one ref at a time, outside
//! ranking, and lead the pack before the ranked fill.
//!
//! Each ref passes the gates a ranked row passes: the retrieval run's
//! candidate predicate
//! ([`crate::pipeline::PipelineBuilder::admit_named_rows_in`]) and the pack's
//! own row gates. A ref that fails any gate, or whose own row the pack cannot
//! use, is dropped, and the rest still seed: one dead or hidden ref never
//! cancels the others and is never served. One count,
//! [`PackWorkingSetStats::dropped`], covers every reason alike, so a hidden
//! row is neither named nor told apart from a dead one.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use heed::RoTxn;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ScopedRead;
use crate::disclosure::DisclosureContext;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::PolicyManifestResolution;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead, TombstoneStoreRead};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CLAIM, ENTITY_TYPE_SKILL};
use crate::store::StoreRead;
use crate::{ErrorKind, Vault};

use super::quarantine::PackQuarantineIndex;
use super::validation::disclosure_admits_target;
use super::world_partition::record_world_by_id;

/// The most refs one working set may name. A longer set is refused, never
/// cut short.
pub const MAX_WORKING_SET_REFS: usize = 64;

/// The most `Supersedes` hops a superseded CLAIM ref is followed forward to
/// its live successor. A longer chain drops the ref.
const MAX_SUPERSESSION_HOPS: usize = 32;

/// What a pack did with the working set its caller seeded
/// ([`super::ContextPackBuilder::working_set`]). Every field is zero for a
/// pack with no working set.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct PackWorkingSetStats {
    /// Refs the caller named, after duplicates were removed.
    pub asked: usize,
    /// The working-set rows the pack serves, in working-set order: the ones
    /// its rows still hold after its last cut (a response limit, a scoped
    /// read's filter, a serialized budget; a row inside a serialized pack's
    /// L2 base prefix is held there). A superseded CLAIM ref is served as its
    /// live successor.
    pub served: Vec<EntityId>,
    /// Refs the assembled pack does not serve: dead, hidden from the reader,
    /// erased, quarantined, clamped, unusable as a row, outside the pack's
    /// worlds, types or query, or cut by the world share. One count for every
    /// reason. A later cut counts where that cut counts its rows.
    pub dropped: usize,
    /// Working-set rows a serialized pack cut because the working set's
    /// rows passed half of the pack's token budget.
    pub over_cap: usize,
    /// Working-set rows the ranked fill also found. Each is served once, as
    /// a working-set row.
    pub overlap: usize,
}

impl PackWorkingSetStats {
    /// Whether the pack was seeded at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.asked == 0
    }

    /// Keeps in [`Self::served`] only the rows `held` says the pack still
    /// holds, in working-set order. Each cut that removes rows calls it.
    pub(crate) fn settle(&mut self, held: impl Fn(&EntityId) -> bool) {
        self.served.retain(|id| held(id));
    }
}

/// The caller's refs in order with duplicates removed, refused over
/// [`MAX_WORKING_SET_REFS`].
pub(super) fn dedupe_working_set(refs: &[EntityId]) -> Result<Vec<EntityId>> {
    let mut seen = HashSet::with_capacity(refs.len());
    let deduped: Vec<EntityId> = refs.iter().copied().filter(|id| seen.insert(*id)).collect();
    if deduped.len() > MAX_WORKING_SET_REFS {
        return Err(Error::InvalidConfig(format!(
            "a context pack working set names at most {MAX_WORKING_SET_REFS} refs; this one names {}",
            deduped.len()
        )));
    }
    Ok(deduped)
}

/// The pack-wide state every working-set ref is judged against, read once in
/// the pack's snapshot. The retrieval run's own selection (authority, types,
/// worlds, query restrictions) is judged after these gates, by
/// [`crate::pipeline::PipelineBuilder::admit_named_rows_in`].
pub(super) struct WorkingSetGates<'p, 'a> {
    pub(super) vault: &'a Vault,
    pub(super) read: &'p StoreRead<'a>,
    /// The lane a scoped pack reads for; `None` for an owner pack.
    pub(super) reader: Option<&'a ScopedRead<'a>>,
    pub(super) clamp: Option<&'p DisclosureContext>,
    /// Stale federated worlds the scope drops; `None` for a scope that keeps
    /// them.
    pub(super) stale_worlds: Option<&'p BTreeMap<EntityId, crate::federation::WorldStaleStamp>>,
    pub(super) device_local: Option<&'p BTreeSet<EntityId>>,
    pub(super) quarantine: &'p PackQuarantineIndex,
}

/// One admitted working-set row: the id the pack serves and its entity type.
#[derive(Debug, Clone, Copy)]
pub(super) struct AdmittedWorkingSetRow {
    pub(super) id: EntityId,
    pub(super) entity_type: u8,
}

/// Admits `refs` (already deduplicated) in order. Each ref resolves forward,
/// then passes every pack gate; the admitted rows keep the refs' order, and
/// two refs that resolve to one row admit it once. A ref whose own row the
/// pack cannot use ([`refuses_one_row`]) is dropped as a hidden one is; a
/// store or policy failure still fails the pack.
pub(super) fn admit_working_set(
    gates: &WorkingSetGates<'_, '_>,
    rtxn: &RoTxn<'_>,
    refs: &[EntityId],
) -> Result<Vec<AdmittedWorkingSetRow>> {
    let policy = match gates.reader {
        Some(reader) => Some(reader.live_policy_manifest_in(rtxn)?),
        None => None,
    };
    let mut admitted = Vec::with_capacity(refs.len());
    let mut admitted_ids = HashSet::with_capacity(refs.len());
    for named in refs {
        let row = match admit_one_ref(gates, rtxn, policy.as_ref(), named) {
            Ok(row) => row,
            Err(error) if refuses_one_row(&error) => None,
            Err(error) => return Err(error),
        };
        if let Some(row) = row
            && admitted_ids.insert(row.id)
        {
            admitted.push(row);
        }
    }
    Ok(admitted)
}

/// Whether `error` refuses one working-set row alone: an invalid reference
/// or payload the pack's validation finds, a body that does not decode, a
/// NOTE whose citation erasure is in flight, sealed custody. Its ref is
/// dropped and the rest still seed. Any other error (the store, a policy)
/// fails the pack, as it fails a ranked row.
pub(super) fn refuses_one_row(error: &Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::ContextPackValidation
            | ErrorKind::InvalidClaimBody
            | ErrorKind::InvalidNoteBody
            | ErrorKind::InvalidSecretCustodyBody
    )
}

/// The row `named` admits as, if any: its head
/// ([`resolve_forward_in_txn`]) when the reader reads both and every pack
/// gate admits the head.
fn admit_one_ref(
    gates: &WorkingSetGates<'_, '_>,
    rtxn: &RoTxn<'_>,
    policy: Option<&PolicyManifestResolution>,
    named: &EntityId,
) -> Result<Option<AdmittedWorkingSetRow>> {
    let Some(head) = resolve_forward_in_txn(gates.read, rtxn, *named)? else {
        return Ok(None);
    };
    if let (Some(reader), Some(policy)) = (gates.reader, policy) {
        // A lane learns nothing about a ref it cannot read, not even where
        // its supersession chain leads. It reads the named row as its record
        // reads read a closed claim, and the head as a live row.
        if head != *named && !reads_as_recorded(reader, rtxn, policy, named)? {
            return Ok(None);
        }
        if !reader.is_ref_readable_with_policy_in(rtxn, policy, &head)? {
            return Ok(None);
        }
    }
    Ok(
        admitted_entity_type(gates, rtxn, &head)?.map(|entity_type| AdmittedWorkingSetRow {
            id: head,
            entity_type,
        }),
    )
}

/// Whether `reader` reads `id` as its record reads do, with the claim's
/// status waived ([`ScopedRead::recorded_lane`]), as the lane's lifecycle
/// read judges a closed claim: a superseded claim it reads in every other
/// respect. A composed read (an audience, a peer, a room) has no record lane,
/// so a superseded ref it names is dropped.
fn reads_as_recorded(
    reader: &ScopedRead<'_>,
    rtxn: &RoTxn<'_>,
    policy: &PolicyManifestResolution,
    id: &EntityId,
) -> Result<bool> {
    match reader.recorded_lane() {
        Ok(lane) => lane.is_ref_readable_with_policy_in(rtxn, policy, id),
        Err(error) if error.kind() == ErrorKind::InvariantViolation => Ok(false),
        Err(error) => Err(error),
    }
}

/// The live successor a CLAIM ref resolves to (CROSS-ARCH-0011: "superseded
/// claims resolve forward"): the stored edge is `new ─Supersedes→ old`, so
/// each hop follows the one inbound `Supersedes` peer that is a CLAIM, as the
/// lane's lifecycle read follows a claim's successor. A ref no claim
/// supersedes is its own head, and so is a row that is no CLAIM: a NOTE
/// fork's `Supersedes` edge never moves a NOTE ref. `None` drops the ref: two
/// CLAIM successors (no principled choice), a cycle, or a chain longer than
/// [`MAX_SUPERSESSION_HOPS`].
pub(super) fn resolve_forward_in_txn(
    read: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    id: EntityId,
) -> Result<Option<EntityId>> {
    if !is_stored_claim(read, rtxn, &id)? {
        return Ok(Some(id));
    }
    let mut head = id;
    let mut visited = HashSet::from([head]);
    for _ in 0..=MAX_SUPERSESSION_HOPS {
        let mut successors = Vec::new();
        for successor in
            read.port_edge_peers(rtxn, &head, EdgeDirection::In, EdgeKind::Supersedes)?
        {
            let successor = successor?;
            if !is_stored_claim(read, rtxn, &successor)? {
                continue;
            }
            successors.push(successor);
            if successors.len() > 1 {
                return Ok(None);
            }
        }
        let Some(next) = successors.pop() else {
            return Ok(Some(head));
        };
        if !visited.insert(next) {
            return Ok(None);
        }
        head = next;
    }
    Ok(None)
}

/// Whether `id` is a stored CLAIM whose body decodes.
fn is_stored_claim(read: &StoreRead<'_>, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    let Some(raw) = read.port_entity_raw(rtxn, id)? else {
        return Ok(false);
    };
    Ok(EntityMetadataHeader::parse(&raw)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_CLAIM)
        && crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).is_ok())
}

/// The entity type of `id` when every pack gate admits it as a working-set
/// row, else `None`: the gates an edge-walk neighbor passes, plus the erase,
/// deletion and quarantine checks the pack's validation would otherwise fail
/// the whole pack on. The retrieval run's selection follows
/// ([`crate::pipeline::PipelineBuilder::admit_named_rows_in`]).
fn admitted_entity_type(
    gates: &WorkingSetGates<'_, '_>,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<u8>> {
    let Some(raw) = gates.read.port_entity_raw(rtxn, id)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    let deletion = gates.read.port_deletion_state(rtxn, id)?;
    if deletion.deleted
        || deletion.stale
        || gates.quarantine.contains_entity(id)
        || gates.vault.archive_tombstone_in_txn(rtxn, id)?.is_some()
        || !crate::note::ordinary_entity_visible(gates.read, rtxn, id)?
        || !disclosure_admits_target(gates.vault, gates.read, rtxn, gates.clamp, id)?
    {
        return Ok(None);
    }
    if let Some(stale) = gates.stale_worlds
        && record_world_by_id(gates.read, rtxn, id)?.is_some_and(|world| stale.contains_key(&world))
    {
        return Ok(None);
    }
    if let Some(flagged) = gates.device_local
        && crate::settings::device_local_keeps_among(gates.read, rtxn, flagged, id)?
    {
        return Ok(None);
    }
    // Skills and agent definitions surface as capability hits, never as
    // memory rows.
    if matches!(
        header.entity_type,
        ENTITY_TYPE_SKILL | ENTITY_TYPE_AGENT_DEF
    ) {
        return Ok(None);
    }
    Ok(Some(header.entity_type))
}

/// Puts the working-set rows first, in working-set order, within each run of
/// rows that share a world section, so a partitioned pack keeps its sections
/// in order. Every other row keeps its place among the rest.
pub(super) fn lead_with_working_set(
    results: &mut [crate::serialize::context_entity::ContextEntity],
    served: &[EntityId],
) {
    if served.is_empty() {
        return;
    }
    let position = |id: &EntityId| served.iter().position(|seed| seed == id);
    let section = |entity: &crate::serialize::context_entity::ContextEntity| {
        entity
            .fields
            .as_ref()
            .and_then(|fields| fields.get(super::WORLD_SECTION_FIELD))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let mut start = 0;
    while start < results.len() {
        let label = section(&results[start]);
        let mut end = start + 1;
        while end < results.len() && section(&results[end]) == label {
            end += 1;
        }
        results[start..end].sort_by_key(|entity| position(&entity.id).unwrap_or(usize::MAX));
        start = end;
    }
}
