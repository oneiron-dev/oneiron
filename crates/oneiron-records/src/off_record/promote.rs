//! Moved from `crates/oneiron/src/off_record/promote.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `EntityId` carries no serde impls, so the receipt's closure travels as the
/// raw 16-byte ids the entity tables already key on.
mod entity_ids_as_bytes {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use oneiron_contracts::entity_id::EntityId;

    pub(super) fn serialize<S: Serializer>(
        ids: &[EntityId],
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        ids.iter()
            .map(EntityId::as_bytes)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Vec<EntityId>, D::Error> {
        Vec::<[u8; 16]>::deserialize(deserializer)?
            .into_iter()
            .map(|bytes| EntityId::from_bytes(bytes).map_err(D::Error::custom))
            .collect()
    }
}

/// What ONE promotion did (ARCH-0052 D4, ONE-1730).
///
/// `replayed` is the exact closure that entered base — for a witnessed turn
/// with no artifacts, the TURN, its MESSAGE, its SUMMARY, and the room's fresh
/// CONVERSATION shell. `short_id_mapping` pairs each in-room alias with the
/// canonical short id the ordinary apply allocated for the same entity, so a
/// caller holding a temporary handle can re-address the promoted row.
///
/// `PartialEq` is load-bearing: the retry contract is that a second promote of
/// the same turn returns THIS value, unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromoteOutcome {
    #[serde(with = "entity_ids_as_bytes")]
    pub replayed: Vec<EntityId>,
    pub short_id_mapping: Vec<(String, String)>,
}

/// Durable, user-initiated receipt minted by promote. It carries opaque ids
/// only and survives the in-process session record.
///
/// The initiator fields record WHO consented, from the proof the saving
/// transaction rechecked, never a literal a caller passes in.
///
/// The receipt is also the RETRY ANSWER: it stores the first call's complete
/// [`PromoteOutcome`], so a second promote of the same turn reads it back and
/// returns it unchanged rather than allocating a second short id, restamping
/// time, duplicating an edge, or emitting a second decision receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffRecordPromoteReceipt {
    pub version: u8,
    pub session_ref: String,
    pub turn: [u8; 16],
    pub promoted_at: u64,
    /// The consenting actor's entity id, as lower-case hex.
    pub initiator_ref: String,
    /// How they proved it: [`PROMOTE_INITIATOR_OWNER`],
    /// [`PROMOTE_INITIATOR_ROOM_OWNER`] or [`PROMOTE_INITIATOR_ROOM_HOLDER`].
    pub initiator_kind: String,
    pub outcome: PromoteOutcome,
}
