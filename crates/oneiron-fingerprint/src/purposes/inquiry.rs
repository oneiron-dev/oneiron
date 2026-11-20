//! Purposes of inquiries (`crates/oneiron/src/inquiry`).
//!
//! An inquiry's answer effect digest is stored in the pending check-in its ladder opens
//! and in the check-in receipt, and an answer or a consume compares it: an answer over any
//! other effect settles nothing. Callers also hand it to the check-in verbs as hex. So it
//! keeps its bytes (K, PLAN-UC-04 6.2).

purposes! {}

legacy_purposes! {
    /// An inquiry's answer effect (`inquiry::member::effect_digest`): plain BLAKE3, the
    /// tag's bytes (no NUL), the grant's 16 id bytes, then the inquiry's wire JSON, with no
    /// length between them.
    ANSWER_EFFECT = (Blake3, HashedFirst, "oneiron.inquiry.answer.v1");
}
