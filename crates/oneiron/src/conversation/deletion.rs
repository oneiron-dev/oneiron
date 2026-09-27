//! Actor-bound room deletion and per-person erasure over the existing delete door.
use super::*;
use crate::conversation_dag::{actor_in_txn, conversation_of};
use crate::deletion::{DeleteEntityOutcome, DeleteReason, DeletionGateContext, GatedDeletion};
use crate::edge::EdgeKind;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use rmpv::Value;

/// A host-local erasure fence: a completed sweep cannot be followed by a new
/// locally authored turn from the erased PERSON in this room.
pub(crate) fn erasure_key(room: EntityId, person: EntityId) -> Vec<u8> {
    [
        b"conversation:erased_person:v1:".as_slice(),
        room.as_bytes(),
        person.as_bytes(),
    ]
    .concat()
}

fn record_author(body: &[u8]) -> Result<Option<EntityId>> {
    let mut bytes = body;
    let Value::Map(fields) =
        rmpv::decode::read_value(&mut bytes).map_err(|_| invalid("invalid room record"))?
    else {
        return Err(invalid("invalid room record"));
    };
    if !bytes.is_empty() {
        return Err(invalid("trailing room record bytes"));
    }
    let mut authors = fields.iter().filter(|(k, _)| k.as_str() == Some("actor"));
    let Some((_, value)) = authors.next() else {
        return Ok(None);
    };
    if authors.next().is_some() {
        return Err(invalid("duplicate room author"));
    }
    let author = value.as_str().ok_or(invalid("invalid room author"))?;
    EntityId::from_hex(author)
        .map(Some)
        .map_err(|_| invalid("invalid room author"))
}

fn author_in(vault: &Vault, txn: &heed::RoTxn<'_>, record: EntityId) -> Result<Option<EntityId>> {
    match crate::vault::live_entity_row_in_txn(&vault.store, txn, &record)? {
        crate::vault::LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            body,
        } => record_author(&body),
        crate::vault::LiveEntityRow::DeletedShell => Ok(
            crate::conversation_dag::redacted_record_pin(&vault.store, txn, &record)?
                .and_then(|pin| pin.author),
        ),
        _ => Err(Error::EntityNotFound),
    }
}

fn check_delete(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
    actor: WriteActor,
    reason: DeleteReason,
    subject: Option<EntityId>,
) -> Result<RoomRole> {
    actor_in_txn(&vault.store, txn, actor)?;
    if conversation_of(&vault.store, txn, &record)? != room {
        return Err(denied());
    }
    let author = author_in(vault, txn, record)?;
    match reason {
        DeleteReason::UserDelete | DeleteReason::UserHardDelete
            if author == Some(actor.entity_ref()) =>
        {
            authorize(vault, txn, actor)?;
            Ok(RoomRole::Member)
        }
        DeleteReason::PolicyDelete => {
            let role = roles::role_in(vault, txn, room, actor)?;
            if matches!(role, RoomRole::Owner | RoomRole::Admin) {
                Ok(role)
            } else {
                Err(denied())
            }
        }
        DeleteReason::GdprDelete if subject.is_some() && subject == author => {
            let role = if Some(actor.entity_ref()) == author {
                authorize(vault, txn, actor)?;
                RoomRole::Member
            } else {
                let role = roles::role_in(vault, txn, room, actor)?;
                if !matches!(role, RoomRole::Owner | RoomRole::Admin) {
                    return Err(denied());
                }
                role
            };
            Ok(role)
        }
        _ => Err(denied()),
    }
}

/// Re-prove authority against the current transaction, including the
/// content-free custody retained by an already soft-erased TURN.
fn reverify_record_delete(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
    actor: WriteActor,
    reason: DeleteReason,
    subject: Option<EntityId>,
) -> Result<()> {
    check_delete(vault, txn, room, record, actor, reason, subject).map(|_| ())
}

impl Vault {
    fn delete_room_record_as(
        &self,
        room: EntityId,
        record: EntityId,
        actor: WriteActor,
        reason: DeleteReason,
        subject: Option<EntityId>,
    ) -> Result<DeleteEntityOutcome> {
        let txn = self.store.env.read_txn()?;
        let role = check_delete(self, &txn, room, record, actor, reason, subject)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        let context = DeletionGateContext::new_room(
            actor.entity_ref(),
            actor.actor_class(),
            crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            policy.read_frontier_hash()?,
            room,
            role,
        );
        drop(txn);
        let reverify = |txn: &heed::RoTxn<'_>| {
            reverify_record_delete(self, txn, room, record, actor, reason, subject)
        };
        self.delete_entity_with_reason_gated(
            &record,
            reason,
            GatedDeletion::new(context, &reverify),
        )
    }

    /// Deletes a room record as its author, or as a room owner/admin for policy.
    /// The underlying receipt is correlated to the actor/role gate decision.
    pub fn delete_room_record(
        &self,
        room: EntityId,
        record: EntityId,
        actor: WriteActor,
        reason: DeleteReason,
    ) -> Result<DeleteEntityOutcome> {
        if !matches!(
            reason,
            DeleteReason::UserDelete | DeleteReason::UserHardDelete | DeleteReason::PolicyDelete
        ) {
            return Err(denied());
        }
        self.delete_room_record_as(room, record, actor, reason, None)
    }

    /// Hard-erases this PERSON's live and soft-erased records in keyset pages.
    /// The local append fence commits before any page, and every page rechecks
    /// authority. A retry starts at the beginning and skips completed purges.
    pub fn erase_room_person(
        &self,
        room: EntityId,
        person: EntityId,
        actor: WriteActor,
    ) -> Result<Vec<DeleteEntityOutcome>> {
        self.with_write_txn(|txn| {
            authorize_room_erasure(self, txn, room, person, actor)?;
            self.store
                .vault_meta
                .put(txn, &erasure_key(room, person), &[1])?;
            Ok(())
        })?;
        let mut cursor = None;
        let mut outcomes = Vec::new();
        loop {
            let txn = self.store.env.read_txn()?;
            authorize_room_erasure(self, &txn, room, person, actor)?;
            let ids: Vec<_> = self
                .store
                .port_edges(
                    &txn,
                    &room,
                    EdgeDirection::In,
                    Some(EdgeKind::ChildOf),
                    cursor,
                )?
                .take(ERASE_PAGE)
                .map(|edge| edge.map(|info| info.target))
                .collect::<Result<_>>()?;
            let targets = ids
                .iter()
                .copied()
                .filter_map(|id| match author_in(self, &txn, id) {
                    Ok(Some(author)) if author == person => Some(Ok(id)),
                    Ok(_) | Err(Error::EntityNotFound) => None,
                    Err(err) => Some(Err(err)),
                })
                .collect::<Result<Vec<_>>>()?;
            drop(txn);
            for record in targets {
                outcomes.push(self.delete_room_record_as(
                    room,
                    record,
                    actor,
                    DeleteReason::GdprDelete,
                    Some(person),
                )?);
            }
            if ids.len() < ERASE_PAGE {
                break;
            }
            cursor = ids.last().copied();
        }
        Ok(outcomes)
    }
}

#[cfg(test)]
const ERASE_PAGE: usize = 2;
#[cfg(not(test))]
const ERASE_PAGE: usize = 256;

fn authorize_room_erasure(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    person: EntityId,
    actor: WriteActor,
) -> Result<()> {
    require_kind(vault, txn, person, ENTITY_TYPE_PERSON)?;
    if person != actor.entity_ref() {
        let role = roles::role_in(vault, txn, room, actor)?;
        if !matches!(role, RoomRole::Owner | RoomRole::Admin) {
            return Err(denied());
        }
    } else {
        authorize(vault, txn, actor)?;
    }
    body::body_in(vault, txn, room)?;
    Ok(())
}
