//! Room bodies, membership windows, session presence and audience visibility.
mod body;
mod deletion;
mod membership;
mod preview;
mod roles;
mod session;
mod visibility;

pub use body::{ConversationBody, ConversationKind, RoomRole};
pub(crate) use body::{fresh_id_in_txn, validate_put_in_txn};
#[cfg(test)]
pub(crate) use deletion::ROOM_ERASURES;
pub(crate) use deletion::{
    guard_room_message_delete, pin_room_message_edge, replay_room_message_tombstone,
    room_message_owner_in, room_person_write_allowed,
};
pub use membership::{HistoryChoice, MembershipAction, MembershipRow, MembershipWindow};
pub use session::{SessionMode, SessionPresence};
pub(crate) use visibility::AudienceCache;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{RecordError, Result};
use crate::{EntityId, Error, Vault, WriteActor};
use serde::{Serialize, de::DeserializeOwned};

fn invalid(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidConversationBody(reason))
}
fn state(reason: &'static str) -> Error {
    Error::Record(RecordError::ConversationState(reason))
}
fn denied() -> Error {
    Error::Record(RecordError::ConversationDenied)
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| invalid("body encode"))
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    rmp_serde::from_slice(bytes).map_err(|_| invalid("body decode"))
}
fn require_kind(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId, kind: u8) -> Result<Vec<u8>> {
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?.is_live() {
        return Err(Error::EntityNotFound);
    }
    let raw = vault
        .store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != kind {
        return Err(invalid("entity kind"));
    }
    if vault.archive_tombstone_in_txn(txn, &id)?.is_some() {
        return Err(Error::EntityNotFound);
    }
    Ok(raw.to_vec())
}
fn authorize(vault: &Vault, txn: &heed::RoTxn<'_>, actor: WriteActor) -> Result<()> {
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &actor.entity_ref())?.is_live() {
        return Err(denied());
    }
    crate::memory::verify_actor_binding_in_txn(vault, txn, actor.entity_ref(), actor.actor_class())
        .map_err(|_| denied())
}

#[cfg(test)]
mod tests;
