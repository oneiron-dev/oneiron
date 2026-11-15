//! Purposes of the workspace roster (`crates/oneiron/src/workspace_roster`).

purposes! {}

legacy_purposes! {
    /// A workplace filing's idempotency key (`workspace_roster::workplace_join::intent_key`):
    /// plain BLAKE3, the tag's bytes, then the purpose's text, the room's id (16 bytes), the
    /// subject's kind (one byte: 1 a person, 2 an agent) and the subject's id (16 bytes), all
    /// unframed. The key is the purpose's text, `:`, and the digest's first 16 bytes as 32
    /// lowercase hex digits. Join receipts replicate it to the house's other machines.
    WORKPLACE_JOIN_INTENT_KEY = (Blake3, HashedFirst, "oneiron.workplace.join.v1");
}
