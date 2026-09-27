//! Actor-bound room deletion and per-person erasure over the existing delete door.
use super::*;
use crate::conversation_dag::{actor_in_txn, conversation_of};
use crate::deletion::{DeleteEntityOutcome, DeleteReason, DeletionGateContext, GatedDeletion};
use crate::edge::EdgeKind;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN,
};
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

const MESSAGE_OWNER: &[u8] = b"conversation:message_owner:v1:";

fn message_owner_key(message: EntityId) -> Vec<u8> {
    key(MESSAGE_OWNER, message)
}

/// Durable room membership for a MESSAGE, including after incident edges
/// have been removed by the reason-aware purge of its TURN.
pub(crate) fn room_message_owner_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    message: EntityId,
) -> Result<Option<EntityId>> {
    let persisted = store
        .vault_meta
        .get(txn, &message_owner_key(message))?
        .map(|bytes| {
            EntityId::from_bytes(
                bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("room MESSAGE owner pin"))?,
            )
        })
        .transpose()?;
    if persisted.is_none()
        && store
            .entities
            .get(txn, message.as_bytes())?
            .is_none_or(|raw| raw.first() != Some(&ENTITY_TYPE_MESSAGE))
    {
        return Ok(None);
    }
    let owners =
        crate::conversation_dag::edge_ids(store, txn, &message, EdgeKind::BelongsTo, false, 2)?;
    if owners.len() > 1 {
        return Err(Error::CorruptedIndex("multiple MESSAGE rooms"));
    }
    if let Some(owner) = owners.first()
        && store
            .entities
            .get(txn, owner.as_bytes())?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_CONVERSATION))
    {
        if persisted.is_some_and(|stored| stored != *owner) {
            return Err(Error::CorruptedIndex("room MESSAGE owner pin mismatch"));
        }
        return Ok(Some(*owner));
    }
    Ok(persisted)
}

/// Called after each locally staged or replicated MESSAGE edge, in the same
/// batch transaction. The room pin cannot be re-targeted, and an erased
/// PERSON may not attach a fresh MESSAGE after the room erasure fence.
pub(crate) fn pin_room_message_edge(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    message: EntityId,
    kind: EdgeKind,
    target: EntityId,
) -> Result<()> {
    if store
        .entities
        .get(txn, message.as_bytes())?
        .is_none_or(|raw| raw.first() != Some(&ENTITY_TYPE_MESSAGE))
    {
        return Ok(());
    }
    if kind == EdgeKind::BelongsTo
        && store
            .entities
            .get(txn, target.as_bytes())?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_CONVERSATION))
    {
        if room_message_owner_in(store, txn, message)?.is_some_and(|room| room != target) {
            return Err(denied());
        }
        store
            .vault_meta
            .put(txn, &message_owner_key(message), target.as_bytes())?;
    }
    if matches!(kind, EdgeKind::BelongsTo | EdgeKind::AuthoredBy)
        && let Some(room) = room_message_owner_in(store, txn, message)?
    {
        let authors = crate::conversation_dag::edge_ids(
            store,
            txn,
            &message,
            EdgeKind::AuthoredBy,
            false,
            2,
        )?;
        if authors.len() > 1 {
            return Err(Error::CorruptedIndex("multiple MESSAGE authors"));
        }
        if let Some(person) = authors.first()
            && store
                .vault_meta
                .get(txn, &erasure_key(room, *person))?
                .is_some()
        {
            return Err(denied());
        }
    }
    Ok(())
}

/// Refuse public batch delete and edge removal without actor/reason.
pub(crate) fn guard_room_message_delete(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    message: EntityId,
) -> Result<()> {
    if room_message_owner_in(store, txn, message)?.is_some() {
        return Err(denied());
    }
    Ok(())
}

/// Resolve room MESSAGE custody from its structural bindings, not from the
/// TURN byline: later actors can add their own messages to an earlier TURN.
/// An absent author is allowed only for owner/admin policy deletion.
fn message_room_author(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    message: EntityId,
) -> Result<Option<(EntityId, Option<EntityId>)>> {
    let Some(raw) = vault.store.entities.get(txn, message.as_bytes())? else {
        return Ok(None);
    };
    if raw.first() != Some(&ENTITY_TYPE_MESSAGE) {
        return Ok(None);
    }
    let one = |kind| -> Result<Option<EntityId>> {
        let mut found = None;
        for edge in vault
            .store
            .port_edges(txn, &message, EdgeDirection::Out, Some(kind), None)?
        {
            if found.replace(edge?.target).is_some() {
                return Err(Error::CorruptedIndex("multiple room MESSAGE bindings"));
            }
        }
        Ok(found)
    };
    let part = one(EdgeKind::PartOf)?;
    let direct = one(EdgeKind::BelongsTo)?;
    let pin = room_message_owner_in(&vault.store, txn, message)?;
    let author = one(EdgeKind::AuthoredBy)?;
    if let Some(author) = author {
        require_kind(vault, txn, author, ENTITY_TYPE_PERSON)?;
    }
    let from_part = match part {
        Some(turn) => match crate::vault::live_entity_row_in_txn(&vault.store, txn, &turn)? {
            crate::vault::LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_CONVERSATION,
                ..
            } => Some(turn),
            crate::vault::LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_TURN,
                ..
            }
            | crate::vault::LiveEntityRow::DeletedShell
            | crate::vault::LiveEntityRow::Absent => {
                crate::conversation_dag::room_turn_owner(&vault.store, txn, &turn)?
            }
            _ => return Err(denied()),
        },
        None => None,
    };
    if direct.is_some_and(|room| from_part.is_some_and(|other| room != other)) {
        return Err(denied());
    }
    let room = direct.or(from_part).or(pin);
    if let Some(room) = room {
        require_kind(vault, txn, room, ENTITY_TYPE_CONVERSATION)?;
        if part.is_some() && from_part.is_none() {
            return Err(denied());
        }
        Ok(Some((room, author)))
    } else {
        Ok(None)
    }
}

fn messages_in_turn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
    after: Option<EntityId>,
) -> Result<Vec<EntityId>> {
    vault
        .store
        .port_edges(txn, &turn, EdgeDirection::In, Some(EdgeKind::PartOf), after)?
        .take(ERASE_PAGE)
        .map(|edge| edge.map(|info| info.target))
        .collect()
}

/// A receiving vault may hold MESSAGE children the deleting host never saw.
/// Replay erases those local payloads before their TURN loses PartOf edges;
/// each message gets its own local hard marker and carrier-sweep obligation.
pub(crate) fn replay_room_message_tombstone(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    turn: EntityId,
    raw_value: &[u8],
) -> Result<()> {
    let Some(raw) = vault.store.entities.get(txn, turn.as_bytes())? else {
        return Ok(());
    };
    if raw.first() != Some(&ENTITY_TYPE_TURN) {
        return Ok(());
    }
    let Some(room) = crate::conversation_dag::room_turn_owner(&vault.store, txn, &turn)? else {
        return Ok(());
    };
    let reason = crate::deletion::decode_tombstone_value(raw_value).reason;
    let author = if reason == Some(crate::deletion::TombstoneReason::PolicyDelete) {
        None
    } else {
        author_in(vault, txn, turn)?
    };
    let mut cursor = None;
    loop {
        let ids = messages_in_turn(vault, txn, turn, cursor)?;
        let mut selected = Vec::new();
        for id in &ids {
            match message_room_author(vault, txn, *id)? {
                Some((owner, _)) if owner != room => return Err(denied()),
                Some((_, byline))
                    if reason == Some(crate::deletion::TombstoneReason::PolicyDelete)
                        || (author.is_some() && byline == author) =>
                {
                    selected.push(*id);
                }
                _ => {}
            }
        }
        for message in selected {
            vault.apply_replayed_tombstone_in_txn(txn, &message, raw_value)?;
        }
        if ids.len() < ERASE_PAGE {
            break;
        }
        cursor = ids.last().copied();
    }
    Ok(())
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
    let author = if let Some((message_room, author)) = message_room_author(vault, txn, record)? {
        if message_room != room {
            return Err(denied());
        }
        author
    } else {
        if conversation_of(&vault.store, txn, &record)? != room {
            return Err(denied());
        }
        author_in(vault, txn, record)?
    };
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
        // Delete selected MESSAGE content before its TURN loses the PartOf
        // edge. A personal operation never purges a different actor's row.
        if self
            .get_raw_unsealed(&record)?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_TURN))
        {
            let mut cursor = None;
            loop {
                let txn = self.store.env.read_txn()?;
                let ids = messages_in_turn(self, &txn, record, cursor)?;
                let mut targets = Vec::new();
                for id in &ids {
                    match message_room_author(self, &txn, *id)? {
                        Some((owner, _)) if owner != room => return Err(denied()),
                        Some((_, author))
                            if reason == DeleteReason::PolicyDelete
                                || author == subject.or(Some(actor.entity_ref())) =>
                        {
                            targets.push(*id);
                        }
                        _ => {}
                    }
                }
                drop(txn);
                for message in targets {
                    self.delete_room_record_as(room, message, actor, reason, subject)?;
                }
                if ids.len() < ERASE_PAGE {
                    break;
                }
                cursor = ids.last().copied();
            }
        }
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
        let mut outcomes = Vec::new();
        // MESSAGE text is stored separately from its TURN. Scan the room's
        // direct BelongsTo index first: messages authored by this PERSON may
        // live inside another actor's TURN, or their TURN may already be gone.
        let mut message_cursor = None;
        loop {
            let txn = self.store.env.read_txn()?;
            authorize_room_erasure(self, &txn, room, person, actor)?;
            let ids: Vec<_> = self
                .store
                .port_edges(
                    &txn,
                    &room,
                    EdgeDirection::In,
                    Some(EdgeKind::BelongsTo),
                    message_cursor,
                )?
                .take(ERASE_PAGE)
                .map(|edge| edge.map(|info| info.target))
                .collect::<Result<_>>()?;
            let mut targets = Vec::new();
            for id in &ids {
                if let Some((owner, Some(author))) = message_room_author(self, &txn, *id)?
                    && owner == room
                    && author == person
                {
                    targets.push(*id);
                }
            }
            drop(txn);
            for message in targets {
                outcomes.push(self.delete_room_record_as(
                    room,
                    message,
                    actor,
                    DeleteReason::GdprDelete,
                    Some(person),
                )?);
            }
            if ids.len() < ERASE_PAGE {
                break;
            }
            message_cursor = ids.last().copied();
        }
        let mut cursor = None;
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
