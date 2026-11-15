//! Purposes of the inbox (`crates/oneiron/src/inbox`).
//!
//! Each legacy purpose here is an id by the legacy material rule
//! (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then a u64
//! little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until
//! the launch reset (PLAN-UC-04 stage 9).

purposes! {}

legacy_purposes! {
    /// The row a producer's event lands under (`inbox::notification::notification_id`). Parts:
    /// the producer, the event.
    NOTIFICATION = (Blake3, HashedFirst, "oneiron:inbox-notification:v1");
}
