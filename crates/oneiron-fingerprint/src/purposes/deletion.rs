//! Purposes of deletion (`crates/oneiron/src/deletion`).
//!
//! The leave action's ask nonce (`deletion/coop_delivery/leave.rs`, L7-09) names each
//! queued ask (its request id) and travels in the signed ask to the peer, and a repeated
//! leave action finds its first ask by it: the queue refuses any other ask under it. It
//! was main's stored and sent bytes before it moved here, so it keeps its bytes (K, the
//! stored-hash guard).

purposes! {}

legacy_purposes! {
    /// The leave action's erase ask nonce (`coop_delivery::leave::leave_ask_nonce`):
    /// BLAKE3 derive-key with the tag as context, then the pact id's 32 bytes and the
    /// epoch cutoff as a u64 little-endian, with no length before either; the nonce is
    /// the digest's first 16 bytes.
    LEAVE_ASK_NONCE = (Blake3, DeriveKeyContext, "oneiron leave erase request nonce v1");
}
