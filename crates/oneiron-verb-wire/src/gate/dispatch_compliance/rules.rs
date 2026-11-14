//! Moved from `crates/oneiron/src/gate/dispatch_compliance/rules.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

// ---------------------------------------------------------------------------
// Pack data
// ---------------------------------------------------------------------------

/// The ARCH-0059 §8 `rule_kind` axis.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceRuleKind {
    /// What lawful basis the send needs, and whether a B2B exemption exists.
    ConsentClass,
    /// The sender's identity must be present and never concealed.
    SenderId,
    /// A postal address must appear in the message.
    PhysicalAddress,
    /// A working opt-out mechanism must appear in the message.
    OptoutMechanism,
    /// How fast an opt-out must be honored. A POST-SEND obligation: no
    /// dispatch-time fact can witness it, so it never blocks a dispatch.
    OptoutDeadline,
    /// The commercial nature of the message must be identifiable.
    ContentMarking,
    /// What evidence must be retained. A POST-SEND obligation; see
    /// [`ComplianceRuleKind::OptoutDeadline`].
    Records,
    /// How the address entered the list.
    SourceHygiene,
}

impl ComplianceRuleKind {
    /// Whether a dispatch-time fact can witness this row.
    ///
    /// Retention and opt-out deadlines are obligations that begin AFTER the
    /// send; blocking a dispatch on them would deny every send forever while
    /// enforcing nothing. They ship as data because they are real law the
    /// surface and suppression paths read.
    pub const fn is_dispatch_enforced(self) -> bool {
        !matches!(self, Self::OptoutDeadline | Self::Records)
    }
}

/// Whether a row's requirement admits a business-recipient exemption.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum B2bExemption {
    /// The exemption applies unconditionally.
    Yes,
    /// No exemption exists.
    No,
    /// The exemption exists but depends on evidence the pack names.
    Conditional,
}

/// The primary source a row was verified against.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ComplianceSource {
    /// Human-readable citation, e.g. the article or regulation number.
    pub citation: String,
    /// Stable URL of the primary source.
    pub url: String,
}

/// What to do when the dispatch carries no trusted jurisdiction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnknownJurisdictionDefault {
    /// Evaluate under the pack's strictest seeded pole. Never an automatic
    /// deny: facts that satisfy the pole still allow.
    StrictPole,
}

/// The machine check a conditional exemption demands.
///
/// Two mechanical primitives, not two jurisdictions. Which jurisdiction demands
/// which is [`CompliancePack::conditional_exemption_evidence`] — a data row.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceExemptionEvidence {
    /// The recipient's legal form must be known.
    LegalForm,
    /// A publication-context record must prove all three of its facts.
    PublicationContext,
}

/// Binds one jurisdiction's conditional rows to the evidence they demand.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConditionalExemptionEvidence {
    /// The jurisdiction token this binding governs.
    pub jurisdiction: String,
    /// What a `conditional` row in that jurisdiction demands.
    pub evidence: ComplianceExemptionEvidence,
}
