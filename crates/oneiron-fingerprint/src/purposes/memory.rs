//! Purposes of memory (`crates/oneiron/src/memory`).

purposes! {}

legacy_purposes! {
    /// An encoder input's hash (`memory::extraction::shadow::hash_input`): SHA-256 with no
    /// tag; the turn and each message's id unframed, each text as a u64-LE length and its
    /// bytes, then the context window, the language, the speaker roles and a conversation
    /// register's later turns, each after its NUL-led marker and only when the input
    /// carries it; written as 64 lowercase hex digits. A shadow trace and a tagging trace
    /// stamp it, and an encoder parity check compares it with a golden's
    /// (`data/encoder_shadow.v1.json` pins one).
    ENCODER_INPUT = (Sha256, NotHashed, "oneiron.memory.encoder_input.v1");
}
