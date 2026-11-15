//! The three small claim status axes and their pinned on-disk strings:
//! approval (consent), lifecycle (currentness), and source (provenance).

use crate::register::Register;

/// Claim approval status (`appr`): the ARCH-0003 consent axis.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
    Register,
)]
#[serde(rename_all = "snake_case")]
#[register("claim.approval.status")]
pub enum ClaimApprovalStatus {
    Auto,
    Proposed,
    Approved,
    Rejected,
}

impl ClaimApprovalStatus {
    /// Engine seam: `pub` only so `oneiron` can call it across the crate split.
    #[doc(hidden)]
    pub fn parse(value: &str) -> Option<Self> {
        <Self as Register>::named(value)
    }
}

/// Claim lifecycle status (`life`): the ARCH-0003 currentness axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimLifecycleStatus {
    Active,
    Superseded,
    Retracted,
}

impl ClaimLifecycleStatus {
    /// The pinned on-disk string for this status.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Retracted => "retracted",
        }
    }

    /// Engine seam: `pub` only so `oneiron` can call it across the crate split.
    #[doc(hidden)]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "superseded" => Some(Self::Superseded),
            "retracted" => Some(Self::Retracted),
            _ => None,
        }
    }
}

/// Claim provenance source (`src`).
///
/// `PartialOrd`/`Ord` are MECHANICAL (ONE-1314): they exist so a source class
/// can be a `BTreeSet` member in `SourceLineage`. Declaration order carries no
/// trust meaning — the trust lattice is `claim_source_rank`/`source_meet`, and
/// the auto-permit question is `requires_explicit_auto_permit` below.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
    Register,
)]
#[serde(rename_all = "snake_case")]
#[register("claim.source")]
pub enum ClaimSource {
    UserStated,
    Observed,
    Inferred,
    Imported,
    ToolOutput,
    Generated,
}

impl ClaimSource {
    /// Engine seam: `pub` only so `oneiron` can call it across the crate split.
    #[doc(hidden)]
    pub fn parse(value: &str) -> Option<Self> {
        <Self as Register>::named(value)
    }

    /// Engine seam: `pub` only so `oneiron` can call it across the crate split.
    #[doc(hidden)]
    pub const fn requires_explicit_auto_permit(self) -> bool {
        matches!(self, Self::Imported | Self::ToolOutput | Self::Generated)
    }
}
