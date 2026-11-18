//! Purposes of channel identities (`crates/oneiron/src/channel_identity`).

purposes! {}

legacy_purposes! {
    /// The key an assignment's two slots are kept under (`channel_identity::assignment`):
    /// plain BLAKE3, no tag, then the canonical channel and the address or handle, each a u64
    /// big-endian length and its bytes.
    ASSIGNMENT_INDEX_KEY = (Blake3, NotHashed, "oneiron.channel_identity.assignment_index_key.v1");
}
