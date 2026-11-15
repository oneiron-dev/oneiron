//! Purposes of affect state inputs (`crates/oneiron/src/affect`).
//!
//! Each legacy purpose here is an id by the legacy material rule
//! (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then a u64
//! little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until
//! the launch reset (PLAN-UC-04 stage 9).

purposes! {}

legacy_purposes! {
    /// One measured signal's observed claim, keyed by its own bytes, so the same measurement
    /// twice is one claim (`affect::state_inputs::put_signal_in_txn`). Parts: the signal's bytes.
    STATE_INDEX_SIGNAL = (Blake3, HashedFirst, "oneiron:state-index-signal:v1");
}
