//! Purposes of feedback (`crates/oneiron/src/feedback`).

purposes! {}

legacy_purposes! {
    /// A report's exact request (`feedback::report::disclosure`): plain BLAKE3, the tag's
    /// bytes (with its final NUL), then the named MessagePack of the `ReportRequest`,
    /// unframed. An issue's disclosure basis stores its hex, the owner's report views return
    /// it, and a fresh digest equal to the stored one keeps an approval.
    REPORT_REQUEST = (Blake3, HashedFirst, "oneiron.report.request_digest.v1\0");

    /// The settings digest of a publisher training offer's worlds
    /// (`feedback::conversation_training::release`): BLAKE3 derive-key with the tag as the
    /// context, then for each world, in the order of the offer's world set, its 16 id bytes
    /// and its 32-byte settings revision, with no length or count. An offer's custody row
    /// stores it, and a release compares it afresh, so an offer whose worlds' settings
    /// changed is withheld.
    TRAINING_POLICY_REVISION =
        (Blake3, DeriveKeyContext, "oneiron publisher training world policy revision v1");
}
