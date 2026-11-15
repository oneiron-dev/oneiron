//! Purposes of secret scanning (`crates/oneiron/src/batch/secret_scan`) and secret custody
//! (`secret_custody`).

purposes! {}

legacy_purposes! {
    /// The commitment to a custody input's whole witness
    /// (`secret_custody::control::input::witness`): plain BLAKE3, the tag's bytes, then the
    /// witness's length (u64 big-endian) and its bytes. Every witness part's signed frame
    /// and every input row's signed reference carry it, and the holder checks the joined
    /// parts against it.
    CUSTODY_WITNESS_COMMITMENT = (Blake3, HashedFirst, "oneiron/custody-input-witness-commitment/v1");

    /// The digest of one witness part's fragment, framed as
    /// [`CUSTODY_WITNESS_COMMITMENT`]: the part's signature covers it.
    CUSTODY_WITNESS_FRAGMENT = (Blake3, HashedFirst, "oneiron/custody-input-witness-fragment/v1");

    /// The digest of an input row's envelope, framed as [`CUSTODY_WITNESS_COMMITMENT`]:
    /// the row's signed reference to its witness covers it.
    CUSTODY_WITNESS_ROW = (Blake3, HashedFirst, "oneiron/custody-input-witness-row/v1");
}
