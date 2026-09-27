//! Vault-private, exact-byte admission for goal claims and project goal pointers.
//! Caller-stamped provenance and replicated bodies never mint these permits.
use super::{GoalRecord, PREDICATE, decode_goal_claim};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimBody, ClaimLifecycleStatus, ClaimSubject, decode_claim_body, encode_claim_body,
};
use crate::error::Result;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use crate::{EntityId, Error};
use heed::{RoTxn, RwTxn};

const CLAIM_KEY: &[u8] = b"project.goal_intake.admission/";
const POINTER_KEY: &[u8] = b"project.goal_intake.pointer_write/";

fn invalid() -> Error {
    super::super::invalid()
}
fn key(prefix: &[u8], id: EntityId) -> Vec<u8> {
    [prefix, id.as_bytes()].concat()
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
    let marker = store.vault_meta.get(txn, &key(CLAIM_KEY, id))?;
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
    match marker.as_ref() {
        [2, rest @ ..] if !replicated && rest.len() == 48 => {
            let (project_bytes, payload_hash) = rest.split_at(16);
            let rmpv::Value::Binary(payload) = &body.value else {
                return Err(invalid());
            };
            if project_bytes != project.as_bytes()
                || payload_hash != blake3::hash(payload).as_bytes()
                || store.entities.get(txn, id.as_bytes())?.is_some()
                || body.lifecycle != ClaimLifecycleStatus::Active
            {
                return Err(invalid());
            }
        }
        [1, stored @ ..] if stored.len() == 32 => {
            let (_, prior) = current_claim(store, txn, id)?;
            if stored != blake3::hash(&prior).as_bytes() || stored != new_hash.as_bytes() {
                return Err(invalid());
            }
        }
        [3, rest @ ..] if !replicated && rest.len() == 64 => {
            let (old_hash, allowed_hash) = rest.split_at(32);
            let (_, prior) = current_claim(store, txn, id)?;
            if old_hash != blake3::hash(&prior).as_bytes() || allowed_hash != new_hash.as_bytes() {
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
    let Some(marker) = store.vault_meta().get(txn, &key(CLAIM_KEY, claim))? else {
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
    let allowed = match marker.as_ref() {
        [1, stored @ ..] if stored.len() == 32 => stored == digest.as_bytes(),
        [2, rest @ ..] if rest.len() == 48 && body.lifecycle == ClaimLifecycleStatus::Active => {
            let (project_bytes, payload_hash) = rest.split_at(16);
            project_bytes == project.as_bytes()
                && matches!(&body.value, rmpv::Value::Binary(payload)
                    if payload_hash == blake3::hash(payload).as_bytes())
        }
        [3, rest @ ..]
            if rest.len() == 64 && body.lifecycle == ClaimLifecycleStatus::Superseded =>
        {
            &rest[32..] == digest.as_bytes()
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
    if store.vault_meta.get(txn, &key(CLAIM_KEY, id))?.is_some() {
        return Err(invalid());
    }
    let mut marker = vec![2];
    marker.extend_from_slice(project.as_bytes());
    marker.extend_from_slice(blake3::hash(&super::super::encode(record)?).as_bytes());
    store.vault_meta.put(txn, &key(CLAIM_KEY, id), &marker)?;
    Ok(())
}

pub(super) fn seal_claim(store: &Store, txn: &mut RwTxn<'_>, id: EntityId) -> Result<()> {
    let (_, data) = current_claim(store, txn, id)?;
    let mut marker = vec![1];
    marker.extend_from_slice(blake3::hash(&data).as_bytes());
    store.vault_meta.put(txn, &key(CLAIM_KEY, id), &marker)?;
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
    let marker = store
        .vault_meta
        .get(txn, &key(CLAIM_KEY, id))?
        .ok_or_else(invalid)?;
    if marker.first() != Some(&1) || marker.get(1..) != Some(blake3::hash(&data).as_bytes()) {
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
    let marker = store
        .vault_meta
        .get(txn, &key(CLAIM_KEY, id))?
        .ok_or_else(invalid)?;
    let old_hash = blake3::hash(&current);
    if marker.first() != Some(&1) || marker.get(1..) != Some(old_hash.as_bytes()) {
        return Err(invalid());
    }
    let mut closed = prior.clone();
    closed.lifecycle = ClaimLifecycleStatus::Superseded;
    closed.valid_to = Some(at);
    let mut permit = vec![3];
    permit.extend_from_slice(old_hash.as_bytes());
    permit.extend_from_slice(blake3::hash(&encode_claim_body(&closed)?).as_bytes());
    store.vault_meta.put(txn, &key(CLAIM_KEY, id), &permit)?;
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
    let Some(new_ref) = next.goal.as_ref() else {
        return Err(invalid());
    };
    let goal = EntityId::from_hex(new_ref).map_err(|_| invalid())?;
    if replicated {
        return Err(invalid());
    }
    let mut expected = Vec::with_capacity(64);
    expected.extend_from_slice(
        previous
            .as_ref()
            .and_then(|p| p.goal.as_ref())
            .map(|s| EntityId::from_hex(s).map(|id| *id.as_bytes()))
            .transpose()?
            .unwrap_or([0; 16])
            .as_slice(),
    );
    expected.extend_from_slice(goal.as_bytes());
    expected.extend_from_slice(blake3::hash(bytes).as_bytes());
    if store.vault_meta.get(txn, &key(POINTER_KEY, id))?.as_deref() != Some(expected.as_slice()) {
        return Err(invalid());
    }
    trusted_active_claim(store, txn, goal, id)?;
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
    let mut marker = Vec::with_capacity(64);
    marker.extend_from_slice(old.map_or([0; 16], |id| *id.as_bytes()).as_slice());
    marker.extend_from_slice(new.as_bytes());
    marker.extend_from_slice(blake3::hash(body).as_bytes());
    store
        .vault_meta
        .put(txn, &key(POINTER_KEY, project), &marker)?;
    Ok(())
}
pub(super) fn disarm_pointer(store: &Store, txn: &mut RwTxn<'_>, project: EntityId) -> Result<()> {
    store.vault_meta.delete(txn, &key(POINTER_KEY, project))?;
    Ok(())
}

/// Deletion is not a backdoor for dropping a protected goal or its project.
/// A future owner-delete flow must supply its own checked authorization.
pub(crate) fn guard_goal_delete(store: &Store, txn: &RoTxn<'_>, id: EntityId) -> Result<()> {
    if store.vault_meta.get(txn, &key(CLAIM_KEY, id))?.is_some() {
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
