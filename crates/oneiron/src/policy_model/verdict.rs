//! What a classify pass concluded.

use serde::{Deserialize, Serialize};

use super::binding::PolicyContentBinding;
use super::planes::PolicyPlane;
use super::request::{PolicyModelConfig, RelayClassifierMode};

#[doc(hidden)]
pub use oneiron_records::policy_model::verdict::{
    PolicyClassifyDecision, PolicyConfidence, PolicyHedgeBucket, PolicyPassAudit, PolicyReadError,
    PolicyVerdictCategory,
};

#[doc(hidden)]
pub use oneiron_verb_wire::policy_model::verdict::PolicySkipReason;

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
    /// The hosted typed-ladder snapshot, when the host selected that path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_binding: Option<String>,
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
    /// The exact host-selected typed-ladder configuration, if one ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_binding: Option<String>,
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
            decision_binding: config.decision_binding(plane),
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
    /// the hosted question was asked; nothing else may. A `pass` that did not
    /// ask it, that asked it of another policy, or that halted leaves the
    /// verdict unattested.
    #[must_use]
    pub fn attesting_hosted_plane(
        mut self,
        policy: &super::planes::HostedLegalPolicy,
        config: &PolicyModelConfig,
        pass: &super::relay::RelayBoundaryPass,
    ) -> Self {
        // Evidence comes only from a pass that ran the hosted plane over a
        // hosted policy HERE. A BYO path, a trusted replay (either shape: a
        // replayed Allow or a replayed carrier the relay returns as
        // `VaultSideDecided`) and a pass with no hosted policy in play ran
        // nothing a relay could skip on their word. A replay re-minted as
        // evidence would also drop the degrade the receipt it replayed held.
        let super::relay::RelayBoundaryPass::Classified(ran) = pass else {
            self.hosted_attestation = None;
            return self;
        };
        let ran_here = match ran.resolution {
            super::relay::RelayResolution::PatternDecided
            | super::relay::RelayResolution::ModelDecided
            | super::relay::RelayResolution::PatternGatedAllow
            | super::relay::RelayResolution::LogOnly
            | super::relay::RelayResolution::Unresolved => true,
            super::relay::RelayResolution::NoPolicyInPlay
            | super::relay::RelayResolution::VaultSideDecided => false,
        };
        // A pass that HALTED left nothing anyone may reuse: a hosted Block,
        // RouteToHelp or Hold, or a degrade that stopped the relay (the
        // manifest moved, no output contract, an outage under `Halt`). The
        // attestation carries no hosted decision, so minting one onto this
        // verdict would let the carrier's own decision stand in for the
        // hosted one the pass reached. The halt is read from the pass, never
        // from the posture the caller hands in now. Unattested, a reuse runs
        // its own pass, which halts again.
        //
        // And the evidence is what the pass EXAMINED, stamped where it ran:
        // the policy it read, and the content, frontier and safeguard selector
        // this carrier is bound to. A `policy` argument naming another policy
        // (one registered after the pass, say), or a carrier for another
        // message, another frontier or another classifier, attests nothing,
        // because the pass is no evidence about it.
        let read_policy = ran.hosted_evidence.as_ref().filter(|read| {
            read.version == policy.version
                && read.policy_hash == policy.policy_hash
                && read.verify_content_hash == self.binding.content_hash
                && ran.verdict.binding.read_frontier_hash == self.binding.read_frontier_hash
                && ran.verdict.safeguard_binding == self.safeguard_binding
        });
        let Some(read_policy) = read_policy else {
            self.hosted_attestation = None;
            return self;
        };
        if !ran_here || !ran.hosted_policy_in_play || pass.must_halt_relay() {
            self.hosted_attestation = None;
            return self;
        }
        self.hosted_attestation = Some(Box::new(HostedPlaneAttestation {
            plane: PolicyPlane::HostedLegal,
            policy_version: read_policy.version.clone(),
            policy_hash: read_policy.policy_hash.clone(),
            // The dial the pass RAN under, never the caller's current one: a
            // pattern-gated pass is no evidence of a classify-all one.
            classifier_mode: ran.verdict.classifier_mode,
            decision_binding: ran.verdict.decision_binding.clone(),
            // A degraded pass that did not halt proceeded through an outage,
            // which only `ProceedReceipted` tolerates; the posture it records
            // is the one the pass ran under.
            outage_policy: Some(if ran.degraded.is_some() {
                super::request::HostedOutagePolicy::ProceedReceipted
            } else {
                config.hosted_outage_policy
            }),
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
                && attestation.decision_binding == config.decision_binding(PolicyPlane::HostedLegal)
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
    pub(super) fn is_inert_clean_allow(&self) -> bool {
        self.decision == PolicyClassifyDecision::Allow
            && self.category == PolicyVerdictCategory::None
            && self.audit.is_none()
    }

    /// Nothing fired: the content is clean against whichever plane ran.
    pub(super) fn clean_allow(
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

    /// The plane wanted a model answer and got none. The verdict carries no
    /// category and no confidence, and it is never an `Allow`.
    pub(super) fn skipped(
        reason: PolicySkipReason,
        binding: PolicyContentBinding,
        config: &PolicyModelConfig,
        plane: PolicyPlane,
    ) -> Self {
        Self::new(
            PolicyClassifyDecision::Skipped(reason),
            PolicyVerdictCategory::None,
            PolicyConfidence::UNEXAMINED,
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
