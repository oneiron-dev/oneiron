//! Purposes of secret scanning (`crates/oneiron/src/batch/secret_scan`) and secret custody
//! (`secret_custody`).
//!
//! Each legacy purpose below is an id by the legacy material rule
//! (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then a u64
//! little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until
//! the launch reset (PLAN-UC-04 stage 9).

purposes! {
    /// The place a lifted carrier row's custody records name as where their keys were found
    /// (`batch::secret_scan::mask::carrier`). Parts: `placeable`, or the table and key.
    LIFT_CARRIER = "oneiron:secret-lift:carrier:v1";
}

legacy_purposes! {
    /// The one ask an agent's reads of a file file (`secret_custody::reveal::file::file_ask_id`).
    /// Parts: the agent, the artifact, the read's hash, the project's hex, the run, and the
    /// custody class when there is one.
    REVEAL_FILE_ASK = (Blake3, HashedFirst, "oneiron.secret_reveal.file_ask.v1");

    /// The next id in an ask's sequence, from the one before: where a read asks again once its
    /// ask was delivered or answered (FIX 6623, 6737; `secret_custody::reveal::file`). Parts: the
    /// ask before.
    REVEAL_FILE_REASK = (Blake3, HashedFirst, "oneiron.secret_reveal.file_reask.v1");
}
