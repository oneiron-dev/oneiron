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
            || (actor.actor_class() == crate::EdgeActorClass::Human
                && id == crate::vault::embedded_owner_actor_id()?)))
        || (fold.vault_id.is_some()
            && actor.actor_class() == crate::EdgeActorClass::Human
            && crate::memory::verify_owner_actor_binding_in_txn(vault, txn, id).is_ok())
    {
        return Ok(RoomRole::Owner);
    }
    let rows = membership::rows_in(&vault.store, txn, room)?;
    if !membership::members_at_rows(&rows, u64::MAX).contains(&id) {
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
        self.with_write_txn(|txn| {
            let actor_role = role_in(self, txn, room, actor)?;
            let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
            if !crate::gate::room_policy_allows(
                &policy,
                room,
                crate::gate::RoomAction::Delegate,
                actor_role,
            ) {
                return Err(denied());
            }
            require_kind(self, txn, person, ENTITY_TYPE_PERSON)?;
            let mut body = body::body_in(self, txn, room)?;
            if !membership::members_at_rows(&membership::rows_in(&self.store, txn, room)?, u64::MAX)
                .contains(&person)
            {
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
            Ok(())
        })
    }
}
