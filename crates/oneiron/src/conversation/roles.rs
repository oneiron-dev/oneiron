//! Host-local room role grants. Replicated body metadata never mints authority.
use super::body::RoomRole;
use super::*;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use crate::side_table::{self, Named, Raw, SideTable};

/// A member's host-local room role grant, keyed by `(room, person)`.
pub(super) const ROLE_GRANTS: SideTable<(EntityId, EntityId), RoomRole, Named> =
    SideTable::new(&side_table::CONVERSATION_ROLE_GRANT);

/// The actor that created a room, keyed by room.
pub(super) const ROOM_CREATORS: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::CONVERSATION_CREATOR);

/// `[1]` while the role door rewrites a room body, keyed by room.
pub(super) const ROLE_UPDATES: SideTable<EntityId, [u8; 1], Raw> =
    SideTable::new(&side_table::CONVERSATION_ROLE_UPDATE);

pub(super) fn role_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: WriteActor,
) -> Result<RoomRole> {
    authorize(vault, txn, actor)?;
    let id = actor.entity_ref();
    require_kind(vault, txn, id, ENTITY_TYPE_PERSON)?;
    person_role_in(
        vault,
        txn,
        room,
        id,
        actor.actor_class() == crate::EdgeActorClass::Human,
    )
}

/// The role PERSON `id` holds in ordinary room `room`, read as [`role_in`]
/// reads it for that PERSON acting itself; `human` says whether it acts as
/// a human, the only class the vault owner's binding makes the room's owner.
/// The room pin doors read a delegate agent's pen PERSON through it, so the
/// agent never stands above that PERSON. Refused for a non-member.
pub(crate) fn person_role_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    id: EntityId,
    human: bool,
) -> Result<RoomRole> {
    let body = body::body_in(vault, txn, room)?;
    // The vault owner's active authority binding is the implicit owner role.
    // It is never inferred from untrusted replicated body metadata.
    // Compared as stored bytes: a damaged creator row matches no actor.
    let creator = ROOM_CREATORS.get_bytes(&vault.store, txn, &room)?;
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    if fold.vault_root_is_conflicted() {
        return Err(denied());
    }
    if (fold.vault_id.is_none()
        && (creator.as_deref() == Some(id.as_bytes().as_slice())
            || (human
                && id == crate::vault::embedded_owner_actor_id()?
                && crate::memory::embedded_owner_shortcut_holds_in_txn(vault, txn)?)))
        || (fold.vault_id.is_some()
            && human
            && crate::memory::verify_owner_actor_binding_in_txn(vault, txn, id).is_ok())
    {
        return Ok(RoomRole::Owner);
    }
    if !membership::is_member_in(&vault.store, txn, room, id)? {
        return Err(denied());
    }
    let Some(role) = ROLE_GRANTS.get(&vault.store, txn, &(room, id))? else {
        return Ok(RoomRole::Member);
    };
    if body.roles.get(&id.to_hex()) != Some(&role) {
        return Err(denied());
    }
    Ok(role)
}

/// Who may admit to a room (OF-531): its owner, or a member whose role the
/// room policy lets delegate.
/// The PERSONs who own `room`, read in `txn`, each acting as a human
/// ([`person_role_in`] answers Owner): of the vault's live owners, its
/// embedded owner, the room's creator and the PERSONs the role door seated
/// as Owner, those whose standing holds now. Sorted, once each; a closed room's ask asks them
/// (ARCH-0082 #closed-room).
pub(crate) fn room_owners_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> Result<Vec<EntityId>> {
    let body = body::body_in(vault, txn, room)?;
    let mut candidates: std::collections::BTreeSet<EntityId> =
        crate::policy_model::owners_in_txn(vault, txn)?
            .into_iter()
            .collect();
    let creator = ROOM_CREATORS
        .get_bytes(&vault.store, txn, &room)?
        .and_then(|bytes| <[u8; 16]>::try_from(bytes.as_slice()).ok())
        .and_then(|bytes| EntityId::from_bytes(bytes).ok());
    candidates.extend(creator);
    candidates.insert(crate::vault::embedded_owner_actor_id()?);
    candidates.extend(
        body.roles
            .iter()
            .filter(|(_, role)| **role == RoomRole::Owner)
            .filter_map(|(person, _)| EntityId::from_hex(person).ok()),
    );
    let mut owners = Vec::new();
    for id in candidates {
        match person_role_in(vault, txn, room, id, true) {
            Ok(RoomRole::Owner) => owners.push(id),
            Ok(_) | Err(Error::Record(crate::error::RecordError::ConversationDenied)) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(owners)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoomHost {
    Owner,
    Delegate,
}

/// `actor`'s host standing in `room`, read live. A non-PERSON actor, or one
/// [`role_in`] refuses, is no host: `None`, never an error, so a join decision
/// can name the host it still needs.
pub(crate) fn room_host_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: WriteActor,
) -> Result<Option<RoomHost>> {
    if vault.get_entity_type_in_txn(txn, &actor.entity_ref())? != Some(ENTITY_TYPE_PERSON) {
        return Ok(None);
    }
    let role = match role_in(vault, txn, room, actor) {
        Ok(role) => role,
        Err(Error::Record(crate::error::RecordError::ConversationDenied)) => return Ok(None),
        Err(error) => return Err(error),
    };
    host_of_role_in(vault, txn, room, role)
}

/// [`room_host_in_txn`] for PERSON `id`, acting as a human when `human`,
/// without the write-actor check [`role_in`] makes first: a federation
/// peer's room body is judged by it, the grant having authenticated its
/// sender (ROOM-BODY-REPLICA-SETTINGS). A non-member is no host.
#[cfg(feature = "sync")]
pub(crate) fn person_room_host_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    id: EntityId,
    human: bool,
) -> Result<Option<RoomHost>> {
    match person_role_in(vault, txn, room, id, human) {
        Ok(role) => host_of_role_in(vault, txn, room, role),
        Err(Error::Record(crate::error::RecordError::ConversationDenied)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Whether PERSON `id` may delegate room roles in `room`, as the role door
/// asks of its caller ([`Vault::set_room_role`]), without the write-actor
/// check: for a federation peer's room body (ROOM-BODY-REPLICA-SETTINGS).
#[cfg(feature = "sync")]
pub(crate) fn person_delegates_roles_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    id: EntityId,
    human: bool,
) -> Result<bool> {
    match person_role_in(vault, txn, room, id, human) {
        Ok(role) => role_delegates_in(vault, txn, room, role),
        Err(Error::Record(crate::error::RecordError::ConversationDenied)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// The host standing `role` gives in `room`: an owner hosts, and any other
/// role the room policy lets delegate.
fn host_of_role_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    role: RoomRole,
) -> Result<Option<RoomHost>> {
    if role == RoomRole::Owner {
        return Ok(Some(RoomHost::Owner));
    }
    Ok(role_delegates_in(vault, txn, room, role)?.then_some(RoomHost::Delegate))
}

/// Whether the room policy lets `role` delegate room roles in `room`.
fn role_delegates_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    role: RoomRole,
) -> Result<bool> {
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    Ok(crate::gate::room_policy_allows(
        &policy,
        room,
        crate::gate::RoomAction::Delegate,
        role,
    ))
}

impl Vault {
    /// Sets a current member's room role. Only the vault owner or a room owner
    /// may delegate; the local grant and body update commit together.
    pub fn set_room_role(
        &self,
        room: EntityId,
        person: EntityId,
        role: RoomRole,
        actor: WriteActor,
    ) -> Result<()> {
        self.set_room_role_recorded(room, person, role, actor)
            .map(drop)
    }

    /// [`Self::set_room_role`], returning the engine's recorded time of the
    /// write, read in the write's own transaction: the time the
    /// `vault.rooms.members.role.set` receipt names.
    pub(crate) fn set_room_role_recorded(
        &self,
        room: EntityId,
        person: EntityId,
        role: RoomRole,
        actor: WriteActor,
    ) -> Result<u64> {
        self.with_write_txn_grouped(|txn| {
            let actor_role = role_in(self, txn, room, actor)?;
            if !role_delegates_in(self, txn, room, actor_role)? {
                return Err(denied());
            }
            require_kind(self, txn, person, ENTITY_TYPE_PERSON)?;
            let mut body = body::body_in(self, txn, room)?;
            if !membership::is_member_in(&self.store, txn, room, person)? {
                return Err(denied());
            }
            body.roles.insert(person.to_hex(), role);
            let raw = require_kind(self, txn, room, ENTITY_TYPE_CONVERSATION)?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("conversation header"))?;
            ROLE_UPDATES.put(&self.store, txn, &room, &[1])?;
            self.batch_in()
                .put(
                    &room,
                    ENTITY_TYPE_CONVERSATION,
                    crate::TimeRange {
                        start: header.occurred_start,
                        end: header.occurred_end,
                    },
                    header.learned_at,
                    &body.to_bytes()?,
                )
                .apply(txn)?;
            ROLE_GRANTS.put(&self.store, txn, &(room, person), &role)?;
            ROLE_UPDATES.delete(&self.store, txn, &room)?;
            crate::ports::recorded_at_in_txn(&self.store, txn)
        })
    }
}
