//! What a classify pass concluded.

use serde::{Deserialize, Serialize};

use super::binding::PolicyContentBinding;
use super::pattern::PolicyPatternRole;
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
    /// Every category, so a test can walk the set. Exhaustive by construction:
    /// a new variant that is not added here fails the round-trip pin.
    ///
    /// It is deliberately NOT what builds a response schema any more. A
    /// prompt's vocabulary is scoped to the rows the substrate owner's policy
    /// actually publishes, so a plane never teaches its model a label its own
    /// policy has no row for.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 4] = [
        Self::MinorSexualization,
        Self::Ncii,
        Self::SeriousCrime,
        Self::JurisdictionRule,
    ];

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

/// Evidence that the pass which produced a verdict ALSO evaluated a hosted
/// service's legal policy, and which published version of it.
///
/// A vault-side pass answers the owner's question; a relay needs to know
/// whether the hosted service's question was answered too. Content and policy
/// hashes cannot tell the two apart — they say what was judged, not against
/// which plane — so the hosted plane leaves its own mark here or the relay
/// treats it as never having run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HostedPlaneAttestation {
    /// Always [`PolicyPlane::HostedLegal`]. Carried explicitly so a verdict
    /// from another plane cannot be read as hosted evidence by omission.
    pub plane: PolicyPlane,
    pub policy_version: String,
    pub policy_hash: String,
}

/// Everything a pass learned on the way to its verdict, kept so the substrate
/// owner can improve the policy that produced it.
///
/// This is the loop the whole design turns on: patterns are unreliable, so the
/// engine records which ones fired and what the model said about them, and the
/// substrate owner reads that back. It carries IDS and the model's own words —
/// never a pattern's source text, and never the policy document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyPassAudit {
    /// Every substrate-owner pattern rule that matched, in rule order — even
    /// the ones the model went on to overrule.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_pattern_ids: Vec<String>,
    /// The role that governed once several rules matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acting_pattern_role: Option<PolicyPatternRole>,
    /// Rule ids the MODEL named, under a rationale-bearing output contract.
    /// These are the policy document's own ids, not the pattern rules'.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_rule_ids: Vec<String>,
    /// The model's own confidence word, as its policy document asked for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_confidence: Option<String>,
    /// The model's stated reason, bounded and otherwise untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_rationale: Option<String>,
}

impl PolicyPassAudit {
    /// Whether this audit says anything at all. An empty audit is dropped
    /// rather than carried, so a verdict that learned nothing says so by
    /// having none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.matched_pattern_ids.is_empty()
            && self.acting_pattern_role.is_none()
            && self.model_rule_ids.is_empty()
            && self.model_confidence.is_none()
            && self.model_rationale.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyClassifyVerdict {
    pub decision: PolicyClassifyDecision,
    pub category: PolicyVerdictCategory,
    pub confidence: PolicyConfidence,
    pub binding: PolicyContentBinding,
    pub safeguard_binding: String,
    /// What the pass learned. Boxed and absent-by-default for the same reason
    /// the hosted attestation is: most verdicts have nothing to say, and a
    /// verdict rides inside every relay pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<Box<PolicyPassAudit>>,
    /// Set only by a pass that evaluated a hosted legal policy. Absent on
    /// every owner-plane verdict, which is exactly what makes it evidence.
    ///
    /// Boxed because absent is the common case: a local vault's verdicts would
    /// otherwise carry the hosted plane's two strings around forever to say
    /// nothing, and a verdict rides inside every relay pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosted_attestation: Option<Box<HostedPlaneAttestation>>,
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
            audit: None,
            hosted_attestation: None,
        }
    }

    /// Attaches what the pass learned. An audit with nothing in it is dropped,
    /// so `audit.is_some()` means the pass actually learned something.
    #[must_use]
    pub fn with_audit(mut self, audit: PolicyPassAudit) -> Self {
        self.audit = (!audit.is_empty()).then(|| Box::new(audit));
        self
    }

    /// Marks this verdict as having been decided with `policy`'s hosted legal
    /// plane in play. The vault-side runner calls this so a relay can verify
    /// the hosted question was asked; nothing else may.
    #[must_use]
    pub fn attesting_hosted_plane(mut self, policy: &super::planes::HostedLegalPolicy) -> Self {
        self.hosted_attestation = Some(Box::new(HostedPlaneAttestation {
            plane: PolicyPlane::HostedLegal,
            policy_version: policy.version.clone(),
            policy_hash: policy.policy_hash.clone(),
        }));
        self
    }

    /// Whether this verdict carries evidence of a pass over exactly `policy`.
    /// Version AND hash must match: a version string alone would let an
    /// amended policy be attested by a receipt from the text it replaced.
    #[must_use]
    pub fn attests_hosted_plane(&self, policy: &super::planes::HostedLegalPolicy) -> bool {
        self.hosted_attestation.as_ref().is_some_and(|attestation| {
            attestation.plane == PolicyPlane::HostedLegal
                && attestation.policy_version == policy.version
                && attestation.policy_hash == policy.policy_hash
        })
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
