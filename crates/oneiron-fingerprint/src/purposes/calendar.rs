//! Purposes of the calendar (`crates/oneiron/src/calendar`).
//!
//! Each legacy purpose here is an id by the legacy material rule
//! (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then a u64
//! little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until
//! the launch reset (PLAN-UC-04 stage 9).

purposes! {}

legacy_purposes! {
    /// An EVENT's check-in recording artifact
    /// (`calendar::outcome::check_in_recording_artifact_id`). Parts: the EVENT.
    CHECK_IN_RECORDING_ARTIFACT = (Blake3, HashedFirst, "oneiron:calendar-outcome-recording:v1");
}
