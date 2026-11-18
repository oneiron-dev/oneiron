//! Purposes of feedback (`crates/oneiron/src/feedback`).

purposes! {}

legacy_purposes! {
    /// A report's exact request (`feedback::report::disclosure`): plain BLAKE3, the tag's
    /// bytes (with its final NUL), then the named MessagePack of the `ReportRequest`,
    /// unframed. An issue's disclosure basis stores its hex, the owner's report views return
    /// it, and a fresh digest equal to the stored one keeps an approval.
    REPORT_REQUEST = (Blake3, HashedFirst, "oneiron.report.request_digest.v1\0");

    /// A triage part's digest on a long revision's work graph
    /// (`feedback::triage::work::digest`): plain BLAKE3, the tag's bytes and then the part's
    /// text, with no length between them; the graph holds it as lowercase hex, and a part's
    /// answer is checked against it.
    TRIAGE_PART = (Blake3, HashedFirst, "oneiron:feedback-triage:part:v1");

    /// The digest of a triaged item's whole text on its work graph
    /// (`feedback::triage::work::digest`): plain BLAKE3, the tag's bytes and then the text,
    /// with no length between them; held as lowercase hex.
    TRIAGE_ITEM = (Blake3, HashedFirst, "oneiron:feedback-triage:item:v1");

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
