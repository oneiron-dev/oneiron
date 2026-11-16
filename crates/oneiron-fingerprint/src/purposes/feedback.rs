//! Purposes of feedback (`crates/oneiron/src/feedback`).

purposes! {}

legacy_purposes! {
    /// An issue signature's content hash (`feedback::report::delivery::packet_signature`):
    /// plain BLAKE3 of a shipped subject's triage packet as sorted JSON (the engine's `llm`
    /// canonical form), with no tag or length; lowercase hex. The issue signature row stores
    /// it, and the row's id is derived from the signature's bytes.
    TRIAGE_PACKET = (Blake3, NotHashed, "oneiron.feedback.triage_packet.v1");
}
