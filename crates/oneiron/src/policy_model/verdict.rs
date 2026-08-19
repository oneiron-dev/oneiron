//! What a classify pass concluded.

use serde::{Deserialize, Serialize};

use super::binding::PolicyContentBinding;
use super::planes::PolicyPlane;
use super::request::PolicyModelConfig;

/// The four things a policy verdict can ask for. `Warn` is the only non-`Allow`
/// arm that still delivers the content, and it delivers it BYTE-IDENTICALLY —
/// there is deliberately no arm that returns rewritten content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyClassifyDecision {
    Allow,
    Warn,
    Block,
    RouteToHelp,
}

impl PolicyClassifyDecision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Block => "block",
            Self::RouteToHelp => "route-to-help",
        }
    }

    /// The ledger spelling, which is `snake_case` where [`Self::as_str`] is
    /// `kebab-case` (reason codes and outcomes never carry dashes).
    #[must_use]
    pub(crate) const fn ledger_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Block => "block",
            Self::RouteToHelp => "route_to_help",
        }
    }
}

/// Which plane the verdict came from, and enough of that plane's identity to
/// attribute it. An owner verdict names only the owner's row; a hosted-legal
/// verdict additionally names the jurisdiction and policy version it was
/// decided under, because the reader is owed the source of a rule they did
/// not write.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "category", content = "sub", rename_all = "snake_case")]
pub enum PolicyVerdictCategory {
    None,
    OwnerPolicy {
        row_ref: String,
    },
    HostedLegal {
        category: HostedLegalCategory,
        jurisdiction: String,
        policy_version: String,
        row_ref: String,
    },
}

/// The public vocabulary of the hosted legal plane. It belongs to that plane
/// alone: an owner-plane row expresses whatever concern its author wants in
/// its own prose, and never borrows one of these labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostedLegalCategory {
    MinorSexualization,
    Ncii,
    SeriousCrime,
    JurisdictionRule,
}

impl HostedLegalCategory {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MinorSexualization => "minor_sexualization",
            Self::Ncii => "ncii",
            Self::SeriousCrime => "serious_crime",
            Self::JurisdictionRule => "jurisdiction_rule",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "minor_sexualization" => Some(Self::MinorSexualization),
            "ncii" => Some(Self::Ncii),
            "serious_crime" => Some(Self::SeriousCrime),
            "jurisdiction_rule" => Some(Self::JurisdictionRule),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyHedgeBucket {
    Certain,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PolicyConfidence {
    pub calibrated: f32,
    pub hedge_bucket: PolicyHedgeBucket,
}

impl PolicyConfidence {
    pub(crate) const CERTAIN: Self = Self {
        calibrated: 1.0,
        hedge_bucket: PolicyHedgeBucket::Certain,
    };

    pub(crate) const HIGH: Self = Self {
        calibrated: 0.92,
        hedge_bucket: PolicyHedgeBucket::High,
    };

    pub(crate) const MEDIUM: Self = Self {
        calibrated: 0.75,
        hedge_bucket: PolicyHedgeBucket::Medium,
    };
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyClassifyVerdict {
    pub decision: PolicyClassifyDecision,
    pub category: PolicyVerdictCategory,
    pub confidence: PolicyConfidence,
    pub binding: PolicyContentBinding,
    pub safeguard_binding: String,
}

impl PolicyClassifyVerdict {
    pub(crate) fn new(
        decision: PolicyClassifyDecision,
        category: PolicyVerdictCategory,
        confidence: PolicyConfidence,
        binding: PolicyContentBinding,
        config: &PolicyModelConfig,
    ) -> Self {
        Self {
            decision,
            category,
            confidence,
            binding,
            safeguard_binding: config.safeguard_binding.selector(),
        }
    }

    /// Nothing fired: the content is clean against whichever plane ran.
    pub(crate) fn clean_allow(binding: PolicyContentBinding, config: &PolicyModelConfig) -> Self {
        Self::new(
            PolicyClassifyDecision::Allow,
            PolicyVerdictCategory::None,
            PolicyConfidence::HIGH,
            binding,
            config,
        )
    }

    #[must_use]
    pub fn decision_str(&self) -> &'static str {
        self.decision.as_str()
    }

    /// The plane the verdict is attributed to, or `None` for a clean allow.
    #[must_use]
    pub fn plane(&self) -> Option<PolicyPlane> {
        match self.category {
            PolicyVerdictCategory::None => None,
            PolicyVerdictCategory::OwnerPolicy { .. } => Some(PolicyPlane::OwnerPolicy),
            PolicyVerdictCategory::HostedLegal { .. } => Some(PolicyPlane::HostedLegal),
        }
    }
}
