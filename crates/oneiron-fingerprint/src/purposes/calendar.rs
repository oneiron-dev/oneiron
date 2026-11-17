//! Purposes of the calendar (`crates/oneiron/src/calendar`).
//!
//! Each legacy purpose here is an id by the legacy material rule
//! (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then a u64
//! little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until
//! the launch reset (PLAN-UC-04 stage 9).
//!
//! Purposes of calendar ingest (`oneiron` `calendar::ingest`).
//!
//! An installed ICS feed's standing import consent (`calendar/ingest/consent.rs`, CAL-02)
//! stores the feed's configuration digest in each consent record and compares it on every
//! read, so a changed recipe would drop each feed's consent. The review ref is sent in the
//! feed's review view and compared at the owner's decision. Both were main's stored and
//! sent bytes before they moved here, so they keep their bytes (K, the stored-hash guard).

purposes! {}

legacy_purposes! {
    /// An EVENT's check-in recording artifact
    /// (`calendar::outcome::check_in_recording_artifact_id`). Parts: the EVENT.
    CHECK_IN_RECORDING_ARTIFACT = (Blake3, HashedFirst, "oneiron:calendar-outcome-recording:v1");

    /// An installed ICS feed's configuration digest (`consent::config_digest`). BLAKE3 of
    /// the feed's `IcsFeedPollConfig` as `serde_json` bytes, with no tag and no length;
    /// written as 64 lowercase hex digits. Stored in each ICS feed consent record.
    ICS_FEED_CONFIG_DIGEST = (Blake3, NotHashed, "oneiron.calendar.ics_feed_config_digest.v1");

    /// The ref of an installed ICS feed's first-poll review (`consent::review_ref`).
    /// BLAKE3 derive-key with the tag as context, over the `serde_json` bytes of the pair
    /// (configuration digest hex, the review's claim id hexes in admission order), with no
    /// length; written as 64 lowercase hex digits. Sent in the review view and compared at
    /// the owner's decision.
    ICS_FEED_REVIEW_REF = (Blake3, DeriveKeyContext, "oneiron calendar.ics.review v1");
}
