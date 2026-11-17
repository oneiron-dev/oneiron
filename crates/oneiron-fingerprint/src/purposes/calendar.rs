//! Purposes of the calendar (`crates/oneiron/src/calendar`).
//! Purposes of calendar ingest (`oneiron` `calendar::ingest`).
//!
//! An installed ICS feed's standing import consent (`calendar/ingest/consent.rs`, CAL-02)
//! stores the feed's configuration digest in each consent record and compares it on every
//! read, so a changed recipe would drop each feed's consent. The review ref is sent in the
//! feed's review view and compared at the owner's decision. Both were main's stored and
//! sent bytes before they moved here, so they keep their bytes (K, the stored-hash guard).

purposes! {}

legacy_purposes! {
    /// The digest of a calendar connector literal (`calendar::connectors::literal::digest`):
    /// plain BLAKE3 of the value's JSON encoding, no tag. A seat's literal scope and an
    /// outbox row's or a remote cursor's digest are sealed in the connector's custody
    /// envelope, and opening it refuses an envelope whose digests differ from the row's now.
    CONNECTOR_LITERAL = (Blake3, NotHashed, "oneiron.calendar.connector_literal.v1");
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
