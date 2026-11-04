//! Compliance amendment classification and outcome values.

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

/// What a proposal did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComplianceAmendmentOutcome {
    /// Activated immediately, with a durable notice.
    Applied {
        /// The now-active pack version.
        pack_version: u32,
        /// The notice persisted alongside the activation.
        notice: String,
    },
    /// Staged. Nothing changed until an owner stamps this exact hash.
    PendingOwnerStamp {
        /// Canonical hash binding the exact proposed rows and version.
        proposal_hash: [u8; 32],
    },
}
