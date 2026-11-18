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
}
