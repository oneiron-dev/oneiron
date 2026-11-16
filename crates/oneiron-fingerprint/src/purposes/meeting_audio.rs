//! Purposes of native meeting transcription
//! (`crates/oneiron-server/src/commands/owner/meeting_audio.rs`).
//!
//! The command names its native host by a revision, which its offer route and the run
//! receipts the transcript keeps carry, and its ASR route by the digest of the selection
//! receipt, which the meeting-audio host compares with each request's route. Both are the
//! SHA-256 of sorted JSON (`llm::canonical_json_bytes`), and each keeps its bytes (K,
//! PLAN-UC-04 stage 6.4c).

purposes! {}

legacy_purposes! {
    /// A native audio host's revision: SHA-256 of the sorted JSON of its script, runtime
    /// component, profile and helper pins and its unit models, with no tag or length,
    /// written as 64 lowercase hex digits.
    HOST_REVISION = (Sha256, NotHashed, "oneiron.meeting_audio.host_revision.v1");

    /// An ASR selection receipt's digest, the route's receipt ref after `sha256:`: SHA-256
    /// of the receipt's sorted JSON, with no tag or length, written as 64 lowercase hex
    /// digits.
    ASR_SELECTION_RECEIPT = (Sha256, NotHashed, "oneiron.meeting_audio.asr_selection_receipt.v1");
}
