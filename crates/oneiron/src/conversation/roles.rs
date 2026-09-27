//! Host-local room role grants. Replicated body metadata never mints authority.
use super::body::RoomRole;
use super::*;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};

pub(super) fn grant_key(room: EntityId, person: EntityId) -> Vec<u8> {
    [
        b"conversation:role_grant:v1:".as_slice(),
        room.as_bytes(),
        person.as_bytes(),
    ]
    .concat()
}

pub(crate) fn role_in(
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
    let creator = vault
        .store
        .vault_meta
        .get(txn, &key(b"conversation:creator:v1:", room))?;
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    if actor.actor_class() == crate::EdgeActorClass::Human
        && ((fold.vault_id.is_none() && creator.as_deref() == Some(id.as_bytes().as_slice()))
            || (fold.vault_id.is_some()
                && crate::memory::verify_owner_actor_binding_in_txn(vault, txn, id).is_ok()))
    {
        return Ok(RoomRole::Owner);
    }
    let rows = membership::rows_in(&vault.store, txn, room)?;
    if !membership::members_at_rows(&rows, u64::MAX).contains(&id) {
        return Err(denied());
    }
    let Some(raw) = vault.store.vault_meta.get(txn, &grant_key(room, id))? else {
        return Ok(RoomRole::Member);
    };
    let role: RoomRole = decode(&raw)?;
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
            if role_in(self, txn, room, actor)? != RoomRole::Owner {
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
            let marker = key(b"conversation:role_update:", room);
            self.store.vault_meta.put(txn, &marker, &[1])?;
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
            self.store
                .vault_meta
                .put(txn, &grant_key(room, person), &encode(&role)?)?;
            self.store.vault_meta.delete(txn, &marker)?;
            Ok(())
        })
    }
}
