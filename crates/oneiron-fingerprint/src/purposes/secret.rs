//! Purposes of secret scanning (`crates/oneiron/src/batch/secret_scan`) and secret custody
//! (`secret_custody`).

purposes! {}

legacy_purposes! {
    /// The key one part of a split custody input is kept and relayed under
    /// (`secret_custody::control::input::part_key`): plain BLAKE3, the tag's bytes, then the
    /// input digest the request names (32 bytes) and the part's index (u32 big-endian). Sync
    /// sends the row to peers under `input:` and this key's hex; a peer recomputes it to file
    /// the row, and refuses a row filed under another key.
    CUSTODY_INPUT_PART_KEY = (Blake3, HashedFirst, "oneiron/custody-input-part-key/v1");

    /// The key one part of a custody input's witness is kept and relayed under
    /// (`secret_custody::control::input::witness`): plain BLAKE3, the tag's bytes, then the
    /// request's authority entry hash, the input digest and the witness commitment (32 bytes
    /// each) and the part's index (u32 big-endian). Sent to peers as for
    /// [`CUSTODY_INPUT_PART_KEY`], under `witness:`.
    CUSTODY_WITNESS_PART_KEY = (Blake3, HashedFirst, "oneiron/custody-input-witness-part-key/v1");
}
