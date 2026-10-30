//! A typed body on its entity's document-key sync frame (FIX 2458, OF-505).
//!
//! An office body never left the machine that imported it, so two of the
//! owner's machines could not edit one live body together. A typed body now
//! rides its entity's document frame as its head's frontiers and its commit
//! log: after a fixed prefix, the body's schema, its birth, its head
//! frontier, its commit count and the schema owner's record of the body,
//! then the operations the requesting peer lacks. Nothing derived from the
//! body travels: the receiver reads the body back through the same lift a
//! local commit runs.
//!
//! The receiver joins the log through the schema owner's merge preflight,
//! never by taking the sender's frontier. Operations that pass land on the
//! head here; operations that do not open a fork that names no opener, for
//! the owner to merge or discard. A frame of a body born elsewhere than the
//! one held here stands apart, refused as a document of another birth is. A
//! frame for an entity that is not live here is dropped: no frame brings a
//! body back. An entity that holds no body here takes the frame's, born on
//! the sender, with its owner's record.

use heed::{RoTxn, RwTxn};
use loro::{ExportMode, Frontiers, LoroDoc, VersionVector};
use serde::{Deserialize, Serialize};

use super::{
    BodyActor, DOCS, FORK_DOCS, FORKS, HEADS, TypedBodyFork, TypedBodyHead, TypedForkState,
    invalid, load, require_live, snapshot,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::Store;

/// The prefix that marks a document frame's payload as a typed body's. A
/// Loro blob starts with its own magic, so no text frame reads as one.
const FRAME_PREFIX: &[u8] = b"oneiron.typed_body.frame.v1\0";

/// The context a carried fork's id is derived in.
const CARRIED_FORK_CONTEXT: &str = "oneiron.typed_body.carried_fork.v1";

/// Why a frame's head frontier does not read against its operations.
const FRONTIER: &str = "typed body frame frontier";

/// What a frame says of its body, before the body's operations.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameHead {
    schema: String,
    birth: Vec<u8>,
    frontier: Vec<u8>,
    commits: u64,
    /// The schema owner's record of the body (an office body's import
    /// facts); empty for none.
    record: Vec<u8>,
}

/// What the module that owns a body's schema reads and writes of its frames.
pub(crate) struct BodyOwner {
    /// Its record of an entity's body, which rides beside the body.
    pub(crate) record: fn(&Vault, &RoTxn<'_>, &EntityId) -> Result<Option<Vec<u8>>>,
    /// Installs a record a frame brought, beside a body of a schema born
    /// here from that frame.
    pub(crate) adopt: fn(&Vault, &mut RwTxn<'_>, &EntityId, &str, &[u8]) -> Result<()>,
    /// Its merge preflight for a body of a schema: `true` lands the carried
    /// operations on the head, `false` opens a fork the owner resolves.
    pub(crate) preflight: fn(&Vault, &str, &CarriedBody<'_>) -> Result<bool>,
}

/// A carried body beside the one held here, as a merge preflight reads it.
pub(crate) struct CarriedBody<'a> {
    /// The body at its head here.
    pub(crate) live: &'a LoroDoc,
    /// The body at the sender's head.
    pub(crate) theirs: &'a LoroDoc,
    /// Both, merged.
    pub(crate) merged: &'a LoroDoc,
    /// The frontier both hold.
    pub(crate) base: &'a [u8],
    /// The head's frontier here.
    pub(crate) head: &'a [u8],
}

/// `entity`'s body as a frame for a peer that holds `peer`: the operations
/// it lacks, after the head's frontiers and `owner`'s record. `None` when
/// `entity` has no typed body.
pub(crate) fn typed_body_frame_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    peer: &VersionVector,
    owner: &BodyOwner,
) -> Result<Option<Vec<u8>>> {
    let Some(head) = HEADS.get(&vault.store, txn, entity)? else {
        return Ok(None);
    };
    let doc = load(DOCS.get(&vault.store, txn, entity)?, Some(&head.frontier))?;
    let updates = doc
        .export(ExportMode::updates(peer))
        .map_err(|_| invalid("typed body frame export"))?;
    let frame = FrameHead {
        schema: head.schema,
        birth: head.birth,
        frontier: head.frontier,
        commits: head.commits,
        record: (owner.record)(vault, txn, entity)?.unwrap_or_default(),
    };
    let head = rmp_serde::to_vec_named(&frame).map_err(|_| invalid("typed body frame encode"))?;
    let len = u32::try_from(head.len()).map_err(|_| invalid("typed body frame encode"))?;
    Ok(Some(
        [FRAME_PREFIX, &len.to_be_bytes(), &head, &updates].concat(),
    ))
}

/// `entity`'s body's version vector, which a peer's request for its frame
/// names. `None` when `entity` has no typed body.
pub(crate) fn typed_body_vv_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    entity: &EntityId,
) -> Result<Option<VersionVector>> {
    let Some(head) = HEADS.get(store, txn, entity)? else {
        return Ok(None);
    };
    Ok(Some(
        load(DOCS.get(store, txn, entity)?, Some(&head.frontier))?.oplog_vv(),
    ))
}

/// Whether `entity` holds a typed body here: a document the owner lane
/// carries beside NOTEs.
pub(crate) fn has_typed_body_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    entity: &EntityId,
) -> Result<bool> {
    HEADS.contains(store, txn, entity)
}

/// Every entity that holds a typed body here.
pub(crate) fn typed_body_entities_in_txn(store: &Store, txn: &RoTxn<'_>) -> Result<Vec<EntityId>> {
    HEADS.scan_keys(store, txn, &[])
}

/// Joins `payload`, a typed body's frame, to `entity`'s body in the caller's
/// writer, through `owner`'s merge preflight. `None` when `payload` is no
/// typed body's frame; else whether the head moved, a body was taken or a
/// fork opened.
pub(crate) fn join_typed_body_frame_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    payload: &[u8],
    owner: &BodyOwner,
) -> Result<Option<bool>> {
    let Some((frame, updates)) = decode(payload)? else {
        return Ok(None);
    };
    match require_live(&vault.store, txn, entity) {
        Ok(()) => {}
        Err(Error::EntityNotFound) => return Ok(Some(false)),
        Err(error) => return Err(error),
    }
    let Some(head) = HEADS.get(&vault.store, txn, entity)? else {
        return birth_carried_in_txn(vault, txn, entity, &frame, updates, owner).map(Some);
    };
    if head.schema != frame.schema || head.birth != frame.birth {
        return Err(invalid("a typed body frame of another body birth"));
    }
    join_carried_in_txn(vault, txn, head, &frame, updates, owner).map(Some)
}

/// `payload` read as a typed body's frame: its head and its operations.
/// `None` when it is no typed body's frame; one that does not read refuses.
fn decode(payload: &[u8]) -> Result<Option<(FrameHead, &[u8])>> {
    let Some(rest) = payload.strip_prefix(FRAME_PREFIX) else {
        return Ok(None);
    };
    let malformed = || invalid("typed body frame head");
    let (len, rest) = rest.split_first_chunk::<4>().ok_or_else(malformed)?;
    let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| malformed())?;
    let (head, updates) = rest.split_at_checked(len).ok_or_else(malformed)?;
    let frame = rmp_serde::from_slice(head).map_err(|_| malformed())?;
    Ok(Some((frame, updates)))
}

/// Imports a frame's operations into `doc`. Every operation they build on
/// must be held, as a document frame's must.
fn import_frame(doc: &LoroDoc, updates: &[u8]) -> Result<()> {
    if updates.is_empty() {
        return Ok(());
    }
    let status = doc
        .import(updates)
        .map_err(|_| invalid("typed body frame operations"))?;
    if status.pending.is_some() {
        return Err(invalid(
            "typed body frame operations lack what they build on",
        ));
    }
    Ok(())
}

/// Takes `frame`'s body, born on the sender, as `entity`'s where this vault
/// holds none: the whole log, read through `owner`'s preflight and the
/// lift, with the owner's record. Whether it took one.
fn birth_carried_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    frame: &FrameHead,
    updates: &[u8],
    owner: &BodyOwner,
) -> Result<bool> {
    let schema = &frame.schema;
    if schema.is_empty() || schema.len() > 64 || !schema.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(invalid(
            "a typed body schema is 1 to 64 visible ASCII bytes",
        ));
    }
    let doc = LoroDoc::new();
    import_frame(&doc, updates)?;
    if doc.oplog_vv().is_empty() {
        return Ok(false);
    }
    let held = |frontier: &[u8]| {
        Frontiers::decode(frontier)
            .ok()
            .and_then(|frontier| doc.frontiers_to_vv(&frontier))
    };
    if held(&frame.frontier).as_ref() != Some(&doc.oplog_vv()) || held(&frame.birth).is_none() {
        return Err(invalid("a typed body frame does not hold its whole body"));
    }
    let frontier = doc.oplog_frontiers().encode();
    let carried = CarriedBody {
        live: &doc,
        theirs: &doc,
        merged: &doc,
        base: &frontier,
        head: &frontier,
    };
    if !(owner.preflight)(vault, schema, &carried)? {
        return Err(invalid("a typed body frame does not read as its schema"));
    }
    (owner.adopt)(vault, txn, entity, schema, &frame.record)?;
    super::lift::remark_typed_body_in_txn(vault, txn, entity, &doc)?;
    DOCS.put(&vault.store, txn, entity, &snapshot(&doc)?)?;
    let head = TypedBodyHead {
        entity: *entity,
        schema: schema.clone(),
        birth: frame.birth.clone(),
        frontier,
        commits: frame.commits,
    };
    HEADS.put(&vault.store, txn, entity, &head)?;
    Ok(true)
}

/// Joins `frame`'s operations to `head`'s body through `owner`'s preflight:
/// operations that pass land on the head, as a merged fork's do, and the
/// body is read back through the lift; others open a fork. Whether the head
/// moved or a fork opened.
fn join_carried_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    mut head: TypedBodyHead,
    frame: &FrameHead,
    updates: &[u8],
    owner: &BodyOwner,
) -> Result<bool> {
    let entity = head.entity;
    let live = load(DOCS.get(&vault.store, txn, &entity)?, Some(&head.frontier))?;
    let merged = live.fork();
    import_frame(&merged, updates)?;
    if merged.oplog_vv() == live.oplog_vv() {
        return Ok(false);
    }
    let frontier = Frontiers::decode(&frame.frontier).map_err(|_| invalid(FRONTIER))?;
    let theirs_vv = merged
        .frontiers_to_vv(&frontier)
        .ok_or_else(|| invalid(FRONTIER))?;
    let theirs = merged.fork_at(&frontier).map_err(|_| invalid(FRONTIER))?;
    let base = live
        .vv_to_frontiers(&live.oplog_vv().intersection(&theirs_vv))
        .encode();
    let added = merged.len_changes().saturating_sub(live.len_changes());
    let added = u64::try_from(added).unwrap_or(u64::MAX);
    let carried = CarriedBody {
        live: &live,
        theirs: &theirs,
        merged: &merged,
        base: &base,
        head: &head.frontier,
    };
    if !(owner.preflight)(vault, &head.schema, &carried)? {
        return open_carried_fork_in_txn(vault, txn, &entity, &theirs, &theirs_vv, base, added);
    }
    head.frontier = merged.oplog_frontiers().encode();
    head.commits += added;
    super::lift::remark_typed_body_in_txn(vault, txn, &entity, &merged)?;
    DOCS.put(&vault.store, txn, &entity, &snapshot(&merged)?)?;
    HEADS.put(&vault.store, txn, &entity, &head)?;
    Ok(true)
}

/// Opens a fork of `entity`'s body holding `theirs`, a carried head whose
/// operations the merge preflight did not land, for the owner to merge or
/// discard. It names no opener, so no one's lineage excludes a merger, and
/// each operation keeps its own peer. One carried head opens one fork,
/// however often its frame arrives. Whether it opened.
fn open_carried_fork_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    theirs: &LoroDoc,
    theirs_vv: &VersionVector,
    base: Vec<u8>,
    commits: u64,
) -> Result<bool> {
    let fork = carried_fork_id(entity, theirs_vv)?;
    let key = (*entity, fork);
    if FORKS.contains(&vault.store, txn, &key)? {
        return Ok(false);
    }
    let record = TypedBodyFork {
        entity: *entity,
        fork,
        opener: BodyActor::Erased,
        base,
        commits,
        opened_at: vault.now_recorded_at(),
        state: TypedForkState::Open,
    };
    FORK_DOCS.put(&vault.store, txn, &key, &snapshot(theirs)?)?;
    FORKS.put(&vault.store, txn, &key, &record)?;
    tracing::info!(
        entity = %entity.to_hex(),
        fork = %fork.to_hex(),
        "a carried typed body does not pass its merge preflight; a fork waits for the owner"
    );
    Ok(true)
}

/// The id of the fork a carried head opens on `entity`: derived from the
/// head's version vector, so the same head names the same fork.
fn carried_fork_id(entity: &EntityId, theirs: &VersionVector) -> Result<EntityId> {
    let mut ends: Vec<(u64, i32)> = theirs.iter().map(|(peer, end)| (*peer, *end)).collect();
    ends.sort_unstable();
    let mut hasher = blake3::Hasher::new_derive_key(CARRIED_FORK_CONTEXT);
    hasher.update(entity.as_bytes());
    for (peer, end) in ends {
        hasher.update(&peer.to_be_bytes());
        hasher.update(&end.to_be_bytes());
    }
    let mut id = [0_u8; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    EntityId::from_bytes(id)
}
