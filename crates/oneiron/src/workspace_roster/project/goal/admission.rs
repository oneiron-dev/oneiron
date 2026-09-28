//! Vault-private, exact-byte admission for goal claims and project goal pointers.
//! Caller-stamped provenance and replicated bodies never mint these permits.
use super::{GoalRecord, PREDICATE, decode_goal_claim};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimBody, ClaimLifecycleStatus, ClaimSubject, decode_claim_body, encode_claim_body,
};
use crate::error::Result;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::Store;
use crate::{EntityId, Error};
use heed::{RoTxn, RwTxn};

/// Local admission marker of one goal claim. Key: id16 (goal claim).
const CLAIM_MARKERS: SideTable<EntityId, ClaimMarker, Raw> =
    SideTable::new(&side_table::PROJECT_GOAL_INTAKE_ADMISSION);
/// The one project-body write a goal-pointer change is permitted. Key: id16 (project).
const POINTER_PERMITS: SideTable<EntityId, PointerPermit, Raw> =
    SideTable::new(&side_table::PROJECT_GOAL_INTAKE_POINTER_WRITE);

/// What the locally armed slot of one goal claim admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimMarker {
    /// The stored claim body, by hash: `[1]` + hash32.
    Sealed([u8; 32]),
    /// An armed birth: `[2]` + project id16 + typed goal payload hash32.
    Birth {
        project: [u8; 16],
        payload: [u8; 32],
    },
    /// A supersession permit: `[3]` + current body hash32 + closed body hash32.
    Superseding { from: [u8; 32], to: [u8; 32] },
}

impl RawValue for ClaimMarker {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(match self {
            Self::Sealed(hash) => [&[1][..], hash].concat(),
            Self::Birth { project, payload } => [&[2][..], project, payload].concat(),
            Self::Superseding { from, to } => [&[3][..], from, to].concat(),
        })
    }

    /// Any other shape is the admission refusal, not a storage error.
    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(match bytes.split_first() {
            Some((1, hash)) if hash.len() == 32 => Self::Sealed(fixed(hash)?),
            Some((2, rest)) if rest.len() == 48 => Self::Birth {
                project: fixed(&rest[..16])?,
                payload: fixed(&rest[16..])?,
            },
            Some((3, rest)) if rest.len() == 64 => Self::Superseding {
                from: fixed(&rest[..32])?,
                to: fixed(&rest[32..])?,
            },
            _ => return Err(invalid().into()),
        })
    }
}

/// The one project body a goal-pointer change may write: the prior and next goal ids (zeros for
/// none), then the body's hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PointerPermit {
    old: [u8; 16],
    new: [u8; 16],
    body: [u8; 32],
}

impl PointerPermit {
    fn new(old: Option<EntityId>, new: Option<EntityId>, body: &[u8]) -> Self {
        let slot = |id: Option<EntityId>| id.map_or([0; 16], |id| *id.as_bytes());
        Self {
            old: slot(old),
            new: slot(new),
            body: *blake3::hash(body).as_bytes(),
        }
    }
}

impl RawValue for PointerPermit {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok([&self.old[..], &self.new, &self.body].concat())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        if bytes.len() != 64 {
            return Err(invalid().into());
        }
        Ok(Self {
            old: fixed(&bytes[..16])?,
            new: fixed(&bytes[16..32])?,
            body: fixed(&bytes[32..])?,
        })
    }
}

fn fixed<const N: usize>(part: &[u8]) -> Result<[u8; N]> {
    part.try_into().map_err(|_| invalid())
}

fn invalid() -> Error {
    crate::error::RecordError::InvalidProjectBody("goal intake admission missing or invalid").into()
}
fn current_claim(store: &Store, txn: &RoTxn<'_>, id: EntityId) -> Result<(ClaimBody, Vec<u8>)> {
    let raw = store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or_else(invalid)?;
    if EntityMetadataHeader::parse(&raw).is_none_or(|h| h.entity_type != ENTITY_TYPE_CLAIM) {
        return Err(invalid());
    }
    let data = raw.get(ENTITY_METADATA_HEADER_LEN..).ok_or_else(invalid)?;
    Ok((
        decode_claim_body(data, true).map_err(|_| invalid())?,
        data.to_vec(),
    ))
}

/// Called at the common put chokepoint for every local, raw and replicated write.
pub(crate) fn guard_claim_put(
    store: &Store,
    txn: &RoTxn<'_>,
    id: EntityId,
    incoming: Option<&ClaimBody>,
    bytes: &[u8],
    replicated: bool,
) -> Result<()> {
    let marker = CLAIM_MARKERS.get(store, txn, &id)?;
    if marker.is_none() && incoming.is_none_or(|body| body.predicate != PREDICATE) {
        return Ok(());
    }
    let marker = marker.ok_or_else(invalid)?;
    let body = incoming.ok_or_else(invalid)?;
    let ClaimSubject::Entity(project) = body.subject else {
        return Err(invalid());
    };
    // A closed prior claim retains the original typed payload and immutable axes.
    let mut active = body.clone();
    active.lifecycle = ClaimLifecycleStatus::Active;
    active.valid_to = None;
    decode_goal_claim(&active, project)?;
    let new_hash = blake3::hash(bytes);
    match marker {
        ClaimMarker::Birth {
            project: project_bytes,
            payload: payload_hash,
        } if !replicated => {
            let rmpv::Value::Binary(payload) = &body.value else {
                return Err(invalid());
            };
            if project_bytes != *project.as_bytes()
                || payload_hash != *blake3::hash(payload).as_bytes()
                || store.entities.get(txn, id.as_bytes())?.is_some()
                || body.lifecycle != ClaimLifecycleStatus::Active
            {
                return Err(invalid());
            }
        }
        ClaimMarker::Sealed(stored) => {
            let (_, prior) = current_claim(store, txn, id)?;
            if stored != *blake3::hash(&prior).as_bytes() || stored != *new_hash.as_bytes() {
                return Err(invalid());
            }
        }
        ClaimMarker::Superseding {
            from: old_hash,
            to: allowed_hash,
        } if !replicated => {
            let (_, prior) = current_claim(store, txn, id)?;
            if old_hash != *blake3::hash(&prior).as_bytes() || allowed_hash != *new_hash.as_bytes()
            {
                return Err(invalid());
            }
        }
        _ => return Err(invalid()),
    }
    Ok(())
}

/// The one graph exception for a CLAIM -> PROJECT `ClaimOf` edge. A caller's
/// predicate/subject alone is never enough: the locally armed slot must bind
/// the exact stored body (or its still-open birth/closure transaction).
pub(crate) fn admitted_claim_of_project(
    store: &impl crate::store::ManifestDbs,
    txn: &RoTxn<'_>,
    claim: EntityId,
    project: EntityId,
) -> Result<bool> {
    let Some(marker) = CLAIM_MARKERS.get(store, txn, &claim)? else {
        return Ok(false);
    };
    let raw = store
        .entities()
        .get(txn, claim.as_bytes())?
        .ok_or_else(invalid)?;
    if EntityMetadataHeader::parse(&raw).is_none_or(|h| h.entity_type != ENTITY_TYPE_CLAIM) {
        return Err(invalid());
    }
    let data = raw.get(ENTITY_METADATA_HEADER_LEN..).ok_or_else(invalid)?;
    let body = decode_claim_body(data, true).map_err(|_| invalid())?;
    let mut active = body.clone();
    active.lifecycle = ClaimLifecycleStatus::Active;
    active.valid_to = None;
    decode_goal_claim(&active, project)?;
    let digest = blake3::hash(data);
    let allowed = match marker {
        ClaimMarker::Sealed(stored) => stored == *digest.as_bytes(),
        ClaimMarker::Birth {
            project: project_bytes,
            payload: payload_hash,
        } if body.lifecycle == ClaimLifecycleStatus::Active => {
            project_bytes == *project.as_bytes()
                && matches!(&body.value, rmpv::Value::Binary(payload)
                    if payload_hash == *blake3::hash(payload).as_bytes())
        }
        ClaimMarker::Superseding { to, .. }
            if body.lifecycle == ClaimLifecycleStatus::Superseded =>
        {
            to == *digest.as_bytes()
        }
        _ => false,
    };
    if !allowed {
        return Err(invalid());
    }
    Ok(true)
}

/// Only the owner-authenticated intake transaction may arm an unoccupied slot.
pub(super) fn arm_birth(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: EntityId,
    project: EntityId,
    record: &GoalRecord,
) -> Result<()> {
    if CLAIM_MARKERS.contains(store, txn, &id)? {
        return Err(invalid());
    }
    let marker = ClaimMarker::Birth {
        project: *project.as_bytes(),
        payload: *blake3::hash(&super::super::encode(record)?).as_bytes(),
    };
    CLAIM_MARKERS.put(store, txn, &id, &marker)?;
    Ok(())
}

pub(super) fn seal_claim(store: &Store, txn: &mut RwTxn<'_>, id: EntityId) -> Result<()> {
    let (_, data) = current_claim(store, txn, id)?;
    let marker = ClaimMarker::Sealed(*blake3::hash(&data).as_bytes());
    CLAIM_MARKERS.put(store, txn, &id, &marker)?;
    Ok(())
}

pub(super) fn trusted_active_claim(
    store: &Store,
    txn: &RoTxn<'_>,
    id: EntityId,
    project: EntityId,
) -> Result<ClaimBody> {
    let (body, data) = current_claim(store, txn, id)?;
    decode_goal_claim(&body, project)?;
    let marker = CLAIM_MARKERS.get(store, txn, &id)?.ok_or_else(invalid)?;
    if marker != ClaimMarker::Sealed(*blake3::hash(&data).as_bytes()) {
        return Err(invalid());
    }
    Ok(body)
}

pub(super) fn arm_supersession(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: EntityId,
    prior: &ClaimBody,
    at: u64,
) -> Result<()> {
    let (_, current) = current_claim(store, txn, id)?;
    let marker = CLAIM_MARKERS.get(store, txn, &id)?.ok_or_else(invalid)?;
    let old_hash = *blake3::hash(&current).as_bytes();
    if marker != ClaimMarker::Sealed(old_hash) {
        return Err(invalid());
    }
    let mut closed = prior.clone();
    closed.lifecycle = ClaimLifecycleStatus::Superseded;
    closed.valid_to = Some(at);
    let permit = ClaimMarker::Superseding {
        from: old_hash,
        to: *blake3::hash(&encode_claim_body(&closed)?).as_bytes(),
    };
    CLAIM_MARKERS.put(store, txn, &id, &permit)?;
    Ok(())
}

/// Generic project edits are fine; a change to its goal pointer is not.
pub(crate) fn guard_pointer_put(
    store: &Store,
    txn: &RoTxn<'_>,
    id: EntityId,
    bytes: &[u8],
    replicated: bool,
) -> Result<()> {
    let next: super::super::ProjectRecord = super::super::decode(bytes)?;
    let previous: Option<super::super::ProjectRecord> = super::super::record(
        store,
        txn,
        id,
        super::super::project_type(store).ok_or_else(invalid)?,
    )?;
    if previous.as_ref().and_then(|p| p.goal.as_ref()) == next.goal.as_ref() {
        return Ok(());
    }
    let goal = next
        .goal
        .as_deref()
        .map(EntityId::from_hex)
        .transpose()
        .map_err(|_| invalid())?;
    if replicated {
        return Err(invalid());
    }
    let old = previous
        .as_ref()
        .and_then(|p| p.goal.as_deref())
        .map(EntityId::from_hex)
        .transpose()?;
    let expected = PointerPermit::new(old, goal, bytes);
    if POINTER_PERMITS.get(store, txn, &id)? != Some(expected) {
        return Err(invalid());
    }
    if let Some(goal) = goal {
        trusted_active_claim(store, txn, goal, id)?;
    } else {
        let old = previous
            .as_ref()
            .and_then(|p| p.goal.as_deref())
            .ok_or_else(invalid)
            .and_then(|s| EntityId::from_hex(s).map_err(|_| invalid()))?;
        if !CLAIM_MARKERS.contains(store, txn, &old)? {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(super) fn arm_pointer(
    store: &Store,
    txn: &mut RwTxn<'_>,
    project: EntityId,
    old: Option<EntityId>,
    new: EntityId,
    body: &[u8],
) -> Result<()> {
    POINTER_PERMITS.put(
        store,
        txn,
        &project,
        &PointerPermit::new(old, Some(new), body),
    )?;
    Ok(())
}
pub(super) fn disarm_pointer(store: &Store, txn: &mut RwTxn<'_>, project: EntityId) -> Result<()> {
    POINTER_PERMITS.delete(store, txn, &project)?;
    Ok(())
}

/// Before tombstone publication, ungated calls must refuse goal deletions.
/// The caller's `gated` proof is minted by the owner deletion facade; this
/// check is re-run with that facade's own authority recheck in the write txn.
pub(crate) fn precheck_delete(
    store: &Store,
    txn: &RoTxn<'_>,
    id: EntityId,
    gated: bool,
) -> Result<()> {
    if CLAIM_MARKERS.contains(store, txn, &id)? {
        if !gated {
            return Err(invalid());
        }
        let (body, bytes) = current_claim(store, txn, id)?;
        let marker = CLAIM_MARKERS.get(store, txn, &id)?.ok_or_else(invalid)?;
        if marker != ClaimMarker::Sealed(*blake3::hash(&bytes).as_bytes())
            || body.predicate != PREDICATE
        {
            return Err(invalid());
        }
    }
    if let Some(kind) = super::super::project_type(store)
        && store.entities.get(txn, id.as_bytes())?.is_some_and(|raw| {
            EntityMetadataHeader::parse(&raw).is_some_and(|header| header.entity_type == kind)
        })
        && let Some(project) =
            super::super::record::<super::super::ProjectRecord>(store, txn, id, kind)?
        && project.goal.is_some()
    {
        return Err(invalid());
    }
    Ok(())
}

/// Remove a goal's current pointer and admission marker as part of the SAME
/// destructive txn. The facade prechecked and revalidated owner authority
/// before publishing; replicated tombstones reuse the established delete rail.
pub(crate) fn retire_for_delete(
    vault: &crate::Vault,
    txn: &mut RwTxn<'_>,
    id: EntityId,
) -> Result<()> {
    let store = &vault.store;
    if !CLAIM_MARKERS.contains(store, txn, &id)? {
        return Ok(());
    }
    let (body, _) = current_claim(store, txn, id)?;
    let ClaimSubject::Entity(project_id) = body.subject else {
        return Err(invalid());
    };
    // A soft-erased claim keeps its shell; its hub edge cannot outlive the
    // admission marker. Hard purge also tolerates this already-removed edge.
    vault
        .batch_in()
        .delete_edge(&id, crate::edge::EdgeKind::ClaimOf, &project_id)
        .apply(txn)?;
    // An absent or soft-erased project has no pointer left to reconcile, and
    // is never recreated; the goal's own edge and marker still retire here.
    if let Some(mut project) = super::super::record::<super::super::ProjectRecord>(
        store,
        txn,
        project_id,
        vault.project_type_byte()?,
    )? && project.goal.as_deref() == Some(id.to_hex().as_str())
    {
        project.goal = None;
        let bytes = super::super::encode(&project)?;
        POINTER_PERMITS.put(
            store,
            txn,
            &project_id,
            &PointerPermit::new(Some(id), None, &bytes),
        )?;
        vault
            .batch_in()
            .put(
                &project_id,
                vault.project_type_byte()?,
                crate::TimeRange { start: 0, end: 0 },
                0,
                &bytes,
            )
            .apply(txn)?;
        POINTER_PERMITS.delete(store, txn, &project_id)?;
        super::interview::bump_generation(store, txn, project_id)?;
    }
    CLAIM_MARKERS.delete(store, txn, &id)?;
    Ok(())
}

/// Deletion is not a backdoor for dropping a protected goal or its project.
/// A future owner-delete flow must supply its own checked authorization.
pub(crate) fn guard_goal_delete(store: &Store, txn: &RoTxn<'_>, id: EntityId) -> Result<()> {
    if CLAIM_MARKERS.contains(store, txn, &id)? {
        return Err(invalid());
    }
    if let Some(kind) = super::super::project_type(store)
        && store.entities.get(txn, id.as_bytes())?.is_some_and(|raw| {
            EntityMetadataHeader::parse(&raw).is_some_and(|header| header.entity_type == kind)
        })
        && let Some(project) =
            super::super::record::<super::super::ProjectRecord>(store, txn, id, kind)?
        && project.goal.is_some()
    {
        return Err(invalid());
    }
    Ok(())
}
