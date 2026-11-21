//! Moved from `crates/oneiron/src/calendar/connectors/literal.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

pub const CODEC: u8 = 1;

pub const GENERATION: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LiteralKind {
    Outbox,
    Cursor,
}

pub fn invalid() -> oneiron_base::error::Error {
    oneiron_base::error::Error::InvalidConfig(
        "calendar literal carrier does not match its operation".into(),
    )
}

pub fn encode<T: Serialize>(value: &T) -> oneiron_base::error::Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid())
}

pub fn reference(kind: LiteralKind, instance: &[u8; 16]) -> EntityId {
    let mut input = [0; 17];
    input[0] = match kind {
        LiteralKind::Outbox => 1,
        LiteralKind::Cursor => 2,
    };
    input[1..].copy_from_slice(instance);
    let key = blake3::derive_key("oneiron calendar literal custody v1", &input);
    EntityId::from_bytes(key[..16].try_into().expect("sixteen derived bytes"))
        .expect("derived calendar custody id")
}
