//! Purposes of the Dreamer.
//!
//! A proactivity digest's locator is the key it is stored under, and the name every
//! notification and the board pointer carry; its content hash is stored in the digest and
//! compared on every read. A free-time policy's digest is stored as the next policy's
//! `prior` and signed into the authority log's policy setting act, a receipt that cites
//! it. So each keeps its bytes (K, PLAN-UC-04 6.2). Each is BLAKE3 of a value's JSON and
//! writes no tag: the names below are registry names only.

purposes! {}

legacy_purposes! {
    /// A proactivity digest's locator (`digest_id`): every field it shows, as assembled.
    PROACTIVITY_DIGEST_LOCATOR =
        (Blake3, NotHashed, "oneiron.dreamer.proactivity_digest_locator.v1");

    /// A proactivity digest's content hash (`content_hash`): its locator and every field it
    /// shows, as admitted.
    PROACTIVITY_DIGEST_CONTENT_HASH =
        (Blake3, NotHashed, "oneiron.dreamer.proactivity_digest_content_hash.v1");

    /// A free-time policy's digest (`policy_digest`): the policy as JSON, `null` for none.
    FREE_TIME_POLICY_DIGEST = (Blake3, NotHashed, "oneiron.dreamer.free_time_policy_digest.v1");
}
