//! Purposes of the AI host (`crates/oneiron-server/src/ai_host`).

purposes! {}

legacy_purposes! {
    /// The dedupe key of a lens card press (`ai_host::lens_callbacks::dedupe_key`): plain
    /// BLAKE3, no tag, then the credential, the card's render id and the idempotency key, each
    /// a u64 little-endian length and its bytes. The key is `lens-callback:` and the digest's
    /// 64 lowercase hex digits. The dreamer attempt row stores it; a repeated press under it
    /// replays the queued callback.
    LENS_CALLBACK_DEDUPE_KEY = (Blake3, NotHashed, "oneiron.ai_host.lens_callback_dedupe_key.v1");
}
