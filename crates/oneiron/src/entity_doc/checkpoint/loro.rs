//! The entity document's actor carriers in its Loro history (FIX 6072): its
//! birth's actor and every engine stamp's, split out and put back through
//! the shared projection ([`crate::store::checkpoint_payload::loro`]). Every
//! other operation of the document's schema (its body text and its metadata
//! map) names no one; an operation outside that schema, or a message that is
//! no engine stamp, keeps its whole group under the vault-wide seal. A birth
//! or stamp whose actor did not open reads as no one, never as an actor some
//! binding of its peer names (Engine R2).
//!
//! A fork snapshot is a group of its own. A shallow one, as the live writer
//! keeps every one, stays under the vault-wide seal (Engine R3), and so does
//! a pending fork's: its record goes when its opener does not open, so its
//! snapshot is never kept without it (Engine and lead pick).

use ::loro::{ContainerID, ContainerType, JsonOp, JsonOpContent, LoroValue};

use super::super::EntityDoc;
use super::super::doc_actor::DocActor;
use super::super::document::{BIRTH, BODY, Birth, META, cut_stamp, decode_frontier};
use super::super::forks::ForkStatus;
use super::hex_id;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::store::checkpoint_payload::loro::{
    self as shared, LoroActorCodec, OpenedRow, SHALLOW, Split, SplitRow, SplitValue,
};
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OwnerRef, RoundTripPolicy, TypedRow, Unresolved,
};

/// The round trip a full-history fork snapshot takes (Engine R1): the same
/// history, in a container Loro may encode anew. No row keeps a digest of a
/// fork snapshot's bytes, so its restore has none to derive again.
const FORK_ROUND_TRIP: RoundTripPolicy = RoundTripPolicy::HistoryEquivalent;

/// The path of a stamp's actor in its message.
const STAMP_ACTOR: &str = "actor";
/// The path of the birth's actor in its record.
const BIRTH_ACTOR: &str = "Birth.actor";

/// A commit message that is no engine stamp.
const NOT_A_STAMP: &str = "an entity document commit message that is no engine stamp";
/// A birth record that does not read, or does not spell its bytes back.
const BIRTH_UNREAD: &str = "an entity document birth that does not spell back";
/// An operation outside the entity document's body and metadata.
const OUTSIDE_SCHEMA: &str = "an entity document operation outside its body and metadata";
/// A pending fork's snapshot, whose record goes when its opener does not
/// open.
const PENDING_FORK: &str = "a pending fork's snapshot, whose record goes with its opener";

/// The entity document's actor carriers.
struct EntityDocActors;

impl LoroActorCodec for EntityDocActors {
    const FAMILY: &'static str = "entity_doc";

    fn split_message(&self, message: &str) -> Split<String> {
        let cut = cut_stamp(message).ok_or(NOT_A_STAMP)?;
        if cut.id == ERASED_CALL_IDENTITY {
            return Ok(SplitValue::kept(message.to_owned()));
        }
        let actor = hex_id(cut.id).ok_or(NOT_A_STAMP)?;
        Ok(SplitValue {
            no_one: format!("{}{ERASED_CALL_IDENTITY}{}", cut.head, cut.tail),
            actors: vec![(STAMP_ACTOR.to_owned(), actor)],
        })
    }

    fn fill_message(&self, no_one: &str, path: &str, actor: EntityId) -> Result<String> {
        let cut = cut_stamp(no_one).ok_or_else(rows::bad_part)?;
        if path != STAMP_ACTOR || cut.id != ERASED_CALL_IDENTITY {
            return Err(rows::bad_part());
        }
        Ok(format!("{}{}{}", cut.head, actor.to_hex(), cut.tail))
    }

    fn split_map_insert(
        &self,
        container: &ContainerID,
        key: &str,
        value: &LoroValue,
    ) -> Split<LoroValue> {
        if !is_root(container, META, ContainerType::Map) {
            return Err(OUTSIDE_SCHEMA);
        }
        if key != BIRTH {
            return Ok(SplitValue::kept(value.clone()));
        }
        let birth = stored_birth(value).ok_or(BIRTH_UNREAD)?;
        let Some(actor) = birth.actor.id() else {
            return Ok(SplitValue::kept(value.clone()));
        };
        let no_one = Birth {
            actor: DocActor::Erased,
            ..birth
        };
        let no_one = no_one.encode().map_err(|_| BIRTH_UNREAD)?;
        Ok(SplitValue {
            no_one: LoroValue::from(no_one),
            actors: vec![(BIRTH_ACTOR.to_owned(), actor)],
        })
    }

    fn fill_map_insert(
        &self,
        container: &ContainerID,
        key: &str,
        no_one: &LoroValue,
        path: &str,
        actor: EntityId,
    ) -> Result<LoroValue> {
        if !is_root(container, META, ContainerType::Map) || key != BIRTH || path != BIRTH_ACTOR {
            return Err(rows::bad_part());
        }
        let birth = stored_birth(no_one).filter(|birth| birth.actor == DocActor::Erased);
        let birth = birth.ok_or_else(rows::bad_part)?;
        let birth = Birth {
            actor: DocActor::Actor(actor),
            ..birth
        };
        Ok(LoroValue::from(birth.encode()?))
    }

    fn keep_op(&self, op: &JsonOp) -> std::result::Result<(), &'static str> {
        match &op.content {
            JsonOpContent::Text(_) if is_root(&op.container, BODY, ContainerType::Text) => Ok(()),
            JsonOpContent::Map(_) if is_root(&op.container, META, ContainerType::Map) => Ok(()),
            _ => Err(OUTSIDE_SCHEMA),
        }
    }
}

/// Whether `container` is the root container `name` of kind `kind`.
fn is_root(container: &ContainerID, name: &str, kind: ContainerType) -> bool {
    match container {
        ContainerID::Root {
            name: root,
            container_type,
        } => root.as_str() == name && *container_type == kind,
        ContainerID::Normal { .. } => false,
    }
}

/// A stored birth record, when it reads and spells its own bytes back.
fn stored_birth(value: &LoroValue) -> Option<Birth> {
    let LoroValue::Binary(bytes) = value else {
        return None;
    };
    let birth = Birth::decode(bytes.as_slice()).ok()?;
    let spelled = birth.encode().ok()?;
    (spelled.as_slice() == bytes.as_slice()).then_some(birth)
}

/// Splits one entity document group: its full snapshot, then its updates
/// in replay order.
pub(super) fn split(
    rows: &[&[u8]],
    policy: RoundTripPolicy,
) -> std::result::Result<Vec<SplitRow>, Unresolved> {
    shared::split_loro(rows, &EntityDocActors, policy)
}

/// Rebuilds one entity document group from its opened rows.
pub(super) fn join(rows: &[OpenedRow<'_>]) -> Result<Vec<Vec<u8>>> {
    Ok(shared::join_loro(rows, &EntityDocActors)?.rows)
}

/// Refuses `bytes` unless it is a full entity document snapshot whose birth
/// names `owner`, when an owner is given.
pub(super) fn check_snapshot(bytes: &[u8], owner: Option<&EntityId>) -> Result<()> {
    let doc = EntityDoc::from_snapshot(bytes)?;
    let owned = owner.is_none_or(|owner| doc.birth().entity == owner.to_hex());
    if doc.doc.is_shallow() || !owned {
        return Err(rows::bad_part());
    }
    Ok(())
}

/// Refuses `bytes` unless it is a Loro update blob.
pub(super) fn check_update(bytes: &[u8]) -> Result<()> {
    if shared::is_update(bytes) {
        Ok(())
    } else {
        Err(rows::bad_part())
    }
}

/// One fork snapshot, under its fork's entity: a settled fork's full
/// history splits as a group of its own; a shallow one and a pending fork's
/// stay under the vault-wide seal, named with that entity.
pub(super) fn capture_fork_snapshot(
    out: &mut Captured,
    entity: EntityId,
    status: ForkStatus,
    base: &[u8],
    row: TypedRow<String, Vec<u8>>,
) {
    let owner = OwnerRef::entity(&entity);
    let shape = fork_shape(&row.bytes, &entity, status, base);
    let outcome = shape.and_then(|()| split(&[row.bytes.as_slice()], FORK_ROUND_TRIP));
    match outcome.map(|mut split| split.pop()) {
        Ok(Some(split)) => shared::place(out, owner, row.at, split),
        Ok(None) => out.unclassified(row.at, Some(owner), Unresolved::Undecodable),
        Err(reason) => out.unclassified(row.at, Some(owner), reason),
    }
}

/// Whether a fork snapshot is one full history a split takes: not a shallow
/// one, not a pending fork's, and one whose birth names the fork's entity
/// and whose history holds the fork's base.
fn fork_shape(
    snapshot: &[u8],
    entity: &EntityId,
    status: ForkStatus,
    base: &[u8],
) -> std::result::Result<(), Unresolved> {
    let doc = EntityDoc::from_snapshot(snapshot).map_err(|_| Unresolved::Undecodable)?;
    if doc.doc.is_shallow() {
        return Err(Unresolved::ActorSplit(SHALLOW));
    }
    if status == ForkStatus::Pending {
        return Err(Unresolved::ActorSplit(PENDING_FORK));
    }
    if doc.birth().entity != entity.to_hex() {
        return Err(Unresolved::SharedOwners);
    }
    let base = decode_frontier(base).map_err(|_| Unresolved::Undecodable)?;
    if doc.doc.frontiers_to_vv(&base).is_none() {
        return Err(Unresolved::Undecodable);
    }
    Ok(())
}

/// A fork snapshot rebuilt from its content and the actors that opened; its
/// birth must name `owner`.
pub(super) fn join_fork_snapshot(
    owner: &EntityId,
    content: &[u8],
    parts: &[&ActorPart],
) -> Result<Vec<u8>> {
    let atoms = shared::opened_atoms(parts)?;
    let mut joined = join(&[OpenedRow { content, atoms }])?;
    let bytes = joined.pop().ok_or_else(rows::bad_part)?;
    check_snapshot(&bytes, Some(owner))?;
    Ok(bytes)
}
