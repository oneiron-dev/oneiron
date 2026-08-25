//! What a classify pass concluded.

use serde::{Deserialize, Serialize};

use super::binding::PolicyContentBinding;
use super::pattern::PolicyPatternRole;
use super::planes::PolicyPlane;
use super::request::{PolicyModelConfig, RelayClassifierMode};

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
        /// The host's own category label, as its policy registered it. The
        /// engine publishes no vocabulary of its own here — see
        /// [`HostedLegalRow::category`].
        ///
        /// [`HostedLegalRow::category`]: super::planes::HostedLegalRow::category
        category: String,
        jurisdiction: String,
        policy_version: String,
        row_ref: String,
    },
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
    /// The HOSTED classifier dial the attested pass ran under.
    ///
    /// The version and hash say which POLICY was in force; they say nothing
    /// about how hard the pass was told to look at it. Flip
    /// `hosted_classifier_mode` and a receipt from the old setting still names
    /// the right policy — so without this the relay would keep trusting a pass
    /// the current configuration would not accept, and skip the hosted pass
    /// the new dial requires.
    ///
    /// `None` means the attestation predates this field and reads as NOT
    /// attesting, which sends the relay to run its own hosted pass. That is
    /// the safe direction for an old receipt: a redundant pass costs a model
    /// call, a wrongly trusted one costs the coverage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classifier_mode: Option<RelayClassifierMode>,
    /// The host's OUTAGE POSTURE at the moment the attested pass ran, and
    /// whether that pass needed it.
    ///
    /// Identity and dial say what was judged and how much of the traffic the
    /// instruction covered. Neither says what the host had agreed to do when
    /// the model did not answer — and under
    /// [`HostedOutagePolicy::ProceedReceipted`] a pass may PROCEED through an
    /// availability degrade. A receipt minted that way is not evidence for a
    /// vault now running `Halt`, whose whole posture is that an outage stops
    /// the relay: trusting it releases exactly what the current configuration
    /// exists to hold.
    ///
    /// `None` predates the field and does NOT attest, for the reason
    /// `classifier_mode` beside it does not: an attestation that cannot say
    /// which posture authorized it is not evidence about posture at all.
    ///
    /// [`HostedOutagePolicy::ProceedReceipted`]: super::request::HostedOutagePolicy::ProceedReceipted
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outage_policy: Option<super::request::HostedOutagePolicy>,
    /// Whether the attested pass PROCEEDED THROUGH A DEGRADE, which is the
    /// only case where the posture above is load-bearing.
    ///
    /// A pass the model answered is evidence on its own terms: the verdict it
    /// reached is the same verdict under either posture, because no outage was
    /// tolerated to reach it. Comparing postures for such a pass refuses a
    /// perfectly good attestation and forces a re-run — and a re-run under
    /// `ProceedReceipted` whose model is now unavailable degrades to a
    /// NON-HALTING allow, releasing content the attested verdict blocked.
    /// That is a strictly worse outcome than the staleness the comparison was
    /// added to prevent, which is why the comparison is gated on this.
    ///
    /// `None` predates the field and falls to the strict branch, where the
    /// absent `outage_policy` beside it refuses anyway. Same fail direction,
    /// no new trust by omission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded: Option<bool>,
}

/// Serde skip predicate: a pass that dropped nothing says so by omission.
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if hands the field by reference"
)]
fn is_zero(value: &usize) -> bool {
    *value == 0
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
    /// Rule ids the MODEL named, under a rationale-bearing output contract,
    /// deduped and cut down to the rules the plane actually resolved. These
    /// are the policy document's own ids, not the pattern rules'.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_rule_ids: Vec<String>,
    /// How many ids the model cited that named no rule the plane resolved.
    ///
    /// A count, not the ids. Recording the strings would let one answer put
    /// unboundedly many rows in one ledger entry — the flood the engine used
    /// to hold off with a fixed cap on the whole array, which also threw away
    /// perfectly good citations once a model got talkative. What survives now
    /// is bounded by the plane's own rows; this is how the rest stays visible.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub model_rule_ids_dropped: usize,
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
            && self.model_rule_ids_dropped == 0
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
    /// The classifier-mode dial of the plane that MINTED this verdict — the
    /// owner dial for an owner-plane verdict, the hosted dial for a hosted
    /// one. Never both: one plane's dial moving must not stale the other
    /// plane's verdicts.
    ///
    /// A verdict is only reusable while the configuration that produced it is
    /// still the configuration in force, and the dial is part of that. Without
    /// it recorded, a clean allow minted under `PatternGated` survives a flip
    /// to `ClassifyAll` and releases content the current config says a model
    /// must look at — and, worse in the other direction, a `Block` the model
    /// decided under `ClassifyAll` keeps blocking after the owner flips to
    /// `PatternGated` and nothing escalates, which is a rule the owner
    /// switched off still being enforced.
    ///
    /// `None` means the verdict predates this field. It reads STALE, never
    /// "probably the default": a compat gap that guesses is a compat gap that
    /// releases content, so the absent case fails closed and costs one
    /// re-derivation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classifier_mode: Option<RelayClassifierMode>,
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
    /// The plane that MINTED this verdict.
    ///
    /// Every other marker of provenance is incidental and each misses a case.
    /// The category is absent on a clean allow. The attestation is minted only
    /// on the cloud-vault verification path, so no locally minted hosted
    /// verdict carries one. The binding cannot tell the planes apart at all —
    /// `relay_policy_binding` derives it from the same `content_binding`
    /// against the same manifest as the owner path. Nor can the classifier
    /// dial, which is equal on both planes by default. So the plane is
    /// recorded outright rather than inferred from something that happens to
    /// correlate with it.
    ///
    /// `Option` and `serde(default)` because verdicts predating the field are
    /// already stored. `None` means "minted before the engine recorded this",
    /// which the owner enforcement door REFUSES rather than assumes — the
    /// F86/F98 fail direction: a refusal costs one re-derivation, and trusting
    /// a plane nobody wrote down costs the separation the door exists for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plane_minted: Option<PolicyPlane>,
}

impl PolicyClassifyVerdict {
    /// `plane` is the plane MINTING this verdict, and it is an argument rather
    /// than something inferred from `category` because a clean allow has no
    /// category to infer from — and a clean allow is exactly the verdict whose
    /// reuse the dial has to govern.
    pub(crate) fn new(
        decision: PolicyClassifyDecision,
        category: PolicyVerdictCategory,
        confidence: PolicyConfidence,
        binding: PolicyContentBinding,
        config: &PolicyModelConfig,
        plane: PolicyPlane,
    ) -> Self {
        Self {
            decision,
            category,
            confidence,
            binding,
            safeguard_binding: config.safeguard_binding.selector(),
            classifier_mode: Some(config.classifier_mode(plane)),
            audit: None,
            hosted_attestation: None,
            plane_minted: Some(plane),
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
    pub fn attesting_hosted_plane(
        mut self,
        policy: &super::planes::HostedLegalPolicy,
        config: &PolicyModelConfig,
        pass: &super::relay::RelayBoundaryPass,
    ) -> Self {
        self.hosted_attestation = Some(Box::new(HostedPlaneAttestation {
            plane: PolicyPlane::HostedLegal,
            policy_version: policy.version.clone(),
            policy_hash: policy.policy_hash.clone(),
            classifier_mode: Some(config.classifier_mode(PolicyPlane::HostedLegal)),
            outage_policy: Some(config.hosted_outage_policy),
            // DERIVED from the pass, never asserted by the caller. The first
            // version of this took a `bool`, which let a runner mark a
            // degraded pass as model-answered — by mistake or by losing the
            // marker somewhere upstream — and an attestation is only evidence
            // if it cannot be made to say something the pass did not do.
            degraded: Some(pass.degraded().is_some()),
        }));
        self
    }

    /// Whether this verdict carries evidence of a pass over exactly `policy`,
    /// run under the hosted configuration now in force.
    ///
    /// Version AND hash must match: a version string alone would let an
    /// amended policy be attested by a receipt from the text it replaced. The
    /// hosted DIAL must match too, for the same reason one layer up — the
    /// policy can be identical while the instruction about how much of the
    /// traffic to classify against it has changed, and a pass taken under the
    /// old instruction is not evidence for the new one. An attestation
    /// recording no dial predates the field and attests nothing.
    #[must_use]
    ///
    /// And the OUTAGE POSTURE — but ONLY for a pass that proceeded through a
    /// degrade. Under `ProceedReceipted` such a pass is not evidence for a
    /// vault now running `Halt`, whose posture is that an outage stops the
    /// relay. A pass the model ANSWERED is evidence on its own terms under
    /// either posture, and refusing it would force a re-run that can itself
    /// degrade to a non-halting allow — releasing what the attested verdict
    /// blocked, which is worse than the staleness being guarded against.
    pub fn attests_hosted_plane(
        &self,
        policy: &super::planes::HostedLegalPolicy,
        config: &PolicyModelConfig,
    ) -> bool {
        self.hosted_attestation.as_ref().is_some_and(|attestation| {
            attestation.plane == PolicyPlane::HostedLegal
                && attestation.policy_version == policy.version
                && attestation.policy_hash == policy.policy_hash
                && attestation.classifier_mode
                    == Some(config.classifier_mode(PolicyPlane::HostedLegal))
                && match attestation.degraded {
                    // The model answered. The verdict it reached is the same
                    // under either posture, so posture is not evidence about
                    // it and comparing them only costs a re-derivation the
                    // relay may not survive.
                    Some(false) => true,
                    // It proceeded through an outage. That is reusable only
                    // where proceeding was tolerated BOTH then and now.
                    //
                    // The `Halt` cases are not a posture mismatch, they are a
                    // pass that never yielded a reusable verdict at all: under
                    // `Halt` a degrade HALTS the relay. The persisted verdict
                    // is nonetheless a clean `Allow` — the halt lives on the
                    // pass, not in the verdict — so trusting it would convert
                    // a stopped pass into a `TrustedVaultSide` whose
                    // `must_halt_relay` is false, releasing content the
                    // original pass refused to release. Both postures must be
                    // `ProceedReceipted`, which is the only configuration
                    // under which that pass produced an allow anyone may
                    // reuse.
                    Some(true) => {
                        attestation.outage_policy
                            == Some(super::request::HostedOutagePolicy::ProceedReceipted)
                            && config.hosted_outage_policy
                                == super::request::HostedOutagePolicy::ProceedReceipted
                    }
                    // Predates the field and cannot say which it was. Not
                    // evidence about degradation, so not trusted.
                    None => false,
                }
        })
    }

    /// Whether this is the inert clean allow a plane that is OFF produces:
    /// nothing decided, nothing attributed, nothing learned.
    ///
    /// A disabled plane returns [`Self::clean_allow`] and can return nothing
    /// else — it never reaches a pattern, a row or a model. So a verdict that
    /// fails this was minted while the plane was ON, which is what makes the
    /// predicate usable as an "was this decided by a live plane" test.
    pub(crate) fn is_inert_clean_allow(&self) -> bool {
        self.decision == PolicyClassifyDecision::Allow
            && self.category == PolicyVerdictCategory::None
            && self.audit.is_none()
    }

    /// Nothing fired: the content is clean against whichever plane ran.
    pub(crate) fn clean_allow(
        binding: PolicyContentBinding,
        config: &PolicyModelConfig,
        plane: PolicyPlane,
    ) -> Self {
        Self::new(
            PolicyClassifyDecision::Allow,
            PolicyVerdictCategory::None,
            PolicyConfidence::HIGH,
            binding,
            config,
            plane,
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
