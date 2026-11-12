//! Moved from `crates/oneiron/src/federation/coreference.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::claim::ClaimApprovalStatus;
use rmpv::Value;

// ---------------------------------------------------------------------------
// Cross-vault coreference (FED-07, ONE-1414).
//
// A `same_as` link says two PERSON entities are one person. It says NOTHING
// about their claims: `ppr::lambda_for_kind(SameAs)` is `None`, so no
// retrieval mass crosses the link in either direction, and no claim body,
// source, or world scope is ever rewritten. Identity and claim POOLING are
// deliberately different things, and only the first one ships here.
//
// The link is LOCAL BY DEFAULT. Nothing about it leaves this vault until the
// owner writes a `core.coreference.share_consent` claim naming ONE pact, and
// the export filter then honors that consent for that pact alone.
//
// This module is the OWNING WRITE DOOR. The link and its status claim are
// meaningless apart — a link with no status is an unattributed identity
// assertion, a status with no link is a statement about nothing — so they are
// written in ONE transaction or not at all, behind an actor gate.
// ---------------------------------------------------------------------------

/// Status of a cross-vault coreference link.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CoreferenceStatus {
    /// Asserted, not yet owner-confirmed. Written `Proposed`.
    Proposed,
    /// Owner-confirmed identity. Written `Approved`.
    Confirmed,
}

impl CoreferenceStatus {
    /// The `core.coreference.status` value string.
    const fn wire(self) -> &'static str {
        match self {
            Self::Proposed => {
                oneiron_store::write_envelope::claim_predicate::COREFERENCE_STATUS_PROPOSED
            }
            Self::Confirmed => {
                oneiron_store::write_envelope::claim_predicate::COREFERENCE_STATUS_CONFIRMED
            }
        }
    }

    /// The approval a status is written at.
    ///
    /// `Confirmed` means the owner ruled, and the claim validator enforces the
    /// same pairing at the write door — so the two cannot drift.
    const fn approval(self) -> ClaimApprovalStatus {
        match self {
            Self::Proposed => ClaimApprovalStatus::Proposed,
            Self::Confirmed => ClaimApprovalStatus::Approved,
        }
    }
}
