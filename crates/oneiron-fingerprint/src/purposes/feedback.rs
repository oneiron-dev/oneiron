//! Purposes of feedback (`crates/oneiron/src/feedback`).

purposes! {}

legacy_purposes! {
    /// The settings digest of a publisher training offer's worlds
    /// (`feedback::conversation_training::release`): BLAKE3 derive-key with the tag as the
    /// context, then for each world, in the order of the offer's world set, its 16 id bytes
    /// and its 32-byte settings revision, with no length or count. An offer's custody row
    /// stores it, and a release compares it afresh, so an offer whose worlds' settings
    /// changed is withheld.
    TRAINING_POLICY_REVISION =
        (Blake3, DeriveKeyContext, "oneiron publisher training world policy revision v1");

    /// An issue signature's content hash (`feedback::report::delivery::packet_signature`):
    /// plain BLAKE3 of a shipped subject's triage packet as sorted JSON (the engine's `llm`
    /// canonical form), with no tag or length; lowercase hex. The issue signature row stores
    /// it, and the row's id is derived from the signature's bytes.
    TRIAGE_PACKET = (Blake3, NotHashed, "oneiron.feedback.triage_packet.v1");
}
