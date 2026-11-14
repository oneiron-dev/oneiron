//! Moved from `crates/oneiron/src/gate/dispatch_compliance/amendment.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// What an amendment does to the pack's strictness.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum ComplianceAmendmentClass {
    /// Provably stricter: rows added, dials tightened, nothing relaxed.
    Tightening,
    /// Policy semantics unchanged; only citations, verification dates, penalty
    /// notes, or the engine-version floor moved.
    MetadataRefresh,
    /// Anything that relaxes the pack, and anything the comparator cannot
    /// order. Free-text requirement edits live here: an unorderable change is
    /// not guessed safe.
    LooseningOrAmbiguous,
}
