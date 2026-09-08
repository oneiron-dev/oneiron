//! Pass outcome vocabulary and the single degrade mint: boundary pass types, resolutions, verdict source, receipt-row helpers.

use std::collections::HashMap;

use serde::Serialize;

use crate::error::Result;
use crate::llm::{BudgetLease, LlmBackend};

use super::super::binding::PolicyContentBinding;
use super::super::pattern::{PatternEvaluation, PolicyPatternRole};
use super::super::planes::PolicyPlane;
use super::super::request::{HostedOutagePolicy, PolicyModelConfig};
use super::super::verdict::{PolicyClassifyDecision, PolicyClassifyVerdict, PolicyPassAudit};

/// Why a hosted relay pass could not put a usable safeguard-model answer
/// against the policy it ran under. A degraded pass fell back to whatever the
/// substrate owner's own `Decide` rules could conclude (never below it); the
/// marker keeps a degraded `Allow` distinguishable from a model-confirmed
/// `Allow` in receipts and logs.
///
/// Most variants name a missing ANSWER. The last names an answer that arrived
/// but could not be pinned to the policy state it was decided against, which
/// leaves the same hole: no verdict the pass can stand behind.
///
/// `non_exhaustive` on purpose: the variants name coverage gaps, and naming a
/// gap that was previously unnamed is the normal way this list grows. A
/// downstream exhaustive match would turn that into a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RelayBoundaryDegrade {
    /// The safeguard model was unavailable (transport/backend error).
    SafeguardModelUnavailable,
    /// The safeguard model responded but the answer was unusable —
    /// unreadable under the declared output contract, or naming a category the
    /// policy never published.
    SafeguardModelResponseUnusable,
    /// The pass required a model verdict and had no way to get one: no
    /// safeguard tier was supplied. Distinct from the two outage codes on
    /// purpose — no model failed here, the pass never had one.
    ///
    /// This is one form of the rule the engine has always held: a hosted
    /// policy's rows are prose only a model can read, so a pass without a
    /// model has answered nothing, whatever the patterns concluded.
    SafeguardModelTierAbsent,
    /// The pass had a model to ask but no declared output contract, so no
    /// answer it could get would be readable. Registration refuses a policy
    /// with no contract, so this names a policy that reached the relay without
    /// passing through the registry — the OTHER form of the same rule, and a
    /// different fault to chase than a missing tier.
    OutputContractUndeclared,
    /// The vault's policy state moved out from under the pass twice running,
    /// so no answer could be bound to the policy in force. Not a model fault:
    /// the model may well have answered both times. What is missing is a
    /// verdict this pass can attest, and the hosted plane does not relay
    /// content on a verdict it cannot attest.
    PolicyBindingMovedMidPass,
}

impl RelayBoundaryDegrade {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SafeguardModelUnavailable => "safeguard_model_unavailable",
            Self::SafeguardModelResponseUnusable => "safeguard_model_response_unusable",
            Self::SafeguardModelTierAbsent => "safeguard_model_tier_absent",
            Self::OutputContractUndeclared => "output_contract_undeclared",
            Self::PolicyBindingMovedMidPass => "policy_binding_moved_mid_pass",
        }
    }

    /// Whether this degrade is a MODEL-AVAILABILITY failure: the pass wanted
    /// an answer from a safeguard model and the model side could not supply
    /// one. That is the only class
    /// [`HostedOutagePolicy::ProceedReceipted`] applies to.
    ///
    /// The other two are excluded for reasons that are not about uptime.
    /// [`Self::OutputContractUndeclared`] means a policy reached the relay
    /// without passing registration, which no amount of model availability
    /// would fix. [`Self::PolicyBindingMovedMidPass`] means an answer arrived
    /// and could not be pinned to the policy state it was decided against —
    /// an unattestable verdict, which the hosted plane refuses to relay on
    /// whatever the host's outage posture is.
    #[must_use]
    pub const fn is_model_availability(self) -> bool {
        match self {
            Self::SafeguardModelUnavailable
            | Self::SafeguardModelResponseUnusable
            | Self::SafeguardModelTierAbsent => true,
            Self::OutputContractUndeclared | Self::PolicyBindingMovedMidPass => false,
        }
    }
}

/// How a pass reached its verdict. Every arm is a distinct receipt reason, so
/// a substrate owner reading the ledger can tell a pattern-decided block from
/// a model-decided one, and an allow the model examined from an allow the
/// patterns waved through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RelayResolution {
    /// A `Decide` pattern rule was the verdict; the model was never called.
    PatternDecided,
    /// The safeguard model answered and its answer governed.
    ModelDecided,
    /// `PatternGated` and nothing escalated: allowed with zero model calls.
    PatternGatedAllow,
    /// Only `Log` rules matched: recorded, never gated, zero model calls.
    LogOnly,
    /// Nothing to classify against — no hosted policy is bound to this
    /// identity.
    NoPolicyInPlay,
    /// A verified vault-side receipt carried the verdict, and the relay is
    /// returning it as it stands.
    ///
    /// It deliberately claims nothing about HOW the vault reached it. The
    /// receipt attests what was judged, not which machinery judged it: a
    /// vault-side pass may have been decided by one of the owner's `Decide`
    /// patterns with no model call at all, and with no hosted policy bound to
    /// the attested identity there is not even a hosted attestation to narrow
    /// it. Recording this as `ModelDecided` would put a claim in the ledger
    /// that no evidence supports.
    VaultSideDecided,
    /// The pass required a model verdict and did not get one, so it reached no
    /// resolution at all. The degrade marker beside it says why. Recorded as
    /// its own code rather than folded into `ModelDecided`, which would put a
    /// claim in the ledger that no model ever answered.
    Unresolved,
}

impl RelayResolution {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PatternDecided => "pattern_decided",
            Self::ModelDecided => "model_decided",
            Self::PatternGatedAllow => "pattern_gated_allow",
            Self::LogOnly => "log_only",
            Self::NoPolicyInPlay => "no_policy_in_play",
            Self::VaultSideDecided => "vault_side_decided",
            Self::Unresolved => "unresolved",
        }
    }
}

/// Outcome of a relay-boundary pass. Advisory only — this classifies, it does
/// not itself halt the relay; the caller must honor
/// [`RelayBoundaryPass::must_halt_relay`].
///
/// `Classified` is the only variant that ran a pass, and its verdict is
/// HOSTED-LEGAL ONLY — the owner plane is never assembled at the relay, so the
/// verdict category can never be [`PolicyVerdictCategory::OwnerPolicy`] unless
/// it came from a verified vault-side receipt.
///
/// Intentionally `Serialize` but NOT `Deserialize` (same reason as
/// [`RelayTrustDomain`]): a relay outcome is emitted for receipts/logs, never
/// reconstructed from untrusted bytes.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RelayBoundaryPass {
    /// Cloud vault: already classified vault-side and verified here; trusted.
    TrustedVaultSide,
    /// BYO connector: nothing transits our infra; nothing ran.
    NotRelayedByUs,
    /// OUR infra ran the hosted legal pass.
    ///
    /// Boxed because the two skip arms carry nothing: a pass that did not run
    /// should not pay for the verdict of one that did, and this outcome rides
    /// inside every relay call.
    Classified(Box<RelayClassifiedPass>),
}

/// What a relay pass that actually ran concluded.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RelayClassifiedPass {
    pub verdict: PolicyClassifyVerdict,
    /// Set when the pass could not get the model verdict it needed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded: Option<RelayBoundaryDegrade>,
    /// Whether [`Self::degraded`] stops the relay.
    ///
    /// Resolved where the degrade was RAISED, from the host's
    /// [`HostedOutagePolicy`] and the kind of degrade, because that is the one
    /// place holding both. Always `false` when nothing degraded — a pass with
    /// no degrade halts on its verdict alone.
    pub degrade_halts: bool,
    /// Whether a hosted legal policy was bound to the attested identity at
    /// all. A degrade means something different on each side of that line, so
    /// the fact travels with the pass rather than being re-derived.
    pub hosted_policy_in_play: bool,
    pub resolution: RelayResolution,
}

impl RelayBoundaryPass {
    /// A pass that reached a verdict. Every degrade in the crate is minted by
    /// [`degraded_hosted_pass`], which resolves the halt against the host's
    /// outage policy; this constructor is the non-degraded path, so it stays
    /// fail-closed by construction — any degrade arriving here halts.
    pub(in super::super) fn classified(
        verdict: PolicyClassifyVerdict,
        degraded: Option<RelayBoundaryDegrade>,
        hosted_policy_in_play: bool,
        resolution: RelayResolution,
    ) -> Self {
        Self::Classified(Box::new(RelayClassifiedPass {
            verdict,
            degrade_halts: degraded.is_some(),
            degraded,
            hosted_policy_in_play,
            resolution,
        }))
    }

    /// The verdict, present only when OUR infra ran a relay pass.
    #[must_use]
    pub fn boundary_verdict(&self) -> Option<&PolicyClassifyVerdict> {
        match self {
            Self::Classified(pass) => Some(&pass.verdict),
            Self::TrustedVaultSide | Self::NotRelayedByUs => None,
        }
    }

    /// Whether OUR infra ran a classify pass at the relay boundary. False for
    /// a trusted cloud vault and for BYO (never transits us).
    #[must_use]
    pub fn ran_relay_classify(&self) -> bool {
        matches!(self, Self::Classified(_))
    }

    /// The degradation marker, if the pass could not get the model verdict it
    /// needed.
    #[must_use]
    pub fn degraded(&self) -> Option<RelayBoundaryDegrade> {
        match self {
            Self::Classified(pass) => pass.degraded,
            Self::TrustedVaultSide | Self::NotRelayedByUs => None,
        }
    }

    /// How the pass reached its verdict, where it ran one.
    #[must_use]
    pub fn resolution(&self) -> Option<RelayResolution> {
        match self {
            Self::Classified(pass) => Some(pass.resolution),
            Self::TrustedVaultSide | Self::NotRelayedByUs => None,
        }
    }

    /// Whether a hosted legal policy was bound to the attested identity for
    /// this pass. A degrade raised AFTER the pass has to carry the same answer
    /// the pass had, or a fallback with no hosted policy comes back claiming a
    /// plane it never had — and [`Self::must_halt_relay`] reads exactly this
    /// flag, so it would halt on it too.
    #[must_use]
    pub fn hosted_policy_in_play(&self) -> bool {
        match self {
            Self::Classified(pass) => pass.hosted_policy_in_play,
            Self::TrustedVaultSide | Self::NotRelayedByUs => false,
        }
    }

    /// Whether the caller edge must NOT relay this content. `Block` and
    /// `RouteToHelp` halt; `Warn` does not — a warned relay still delivers the
    /// original content, with its notice alongside. A trusted cloud pass and
    /// an untouched BYO path never halt.
    ///
    /// A DEGRADED pass halts too, but only where a hosted legal policy was in
    /// play. The hosted plane is fail-closed and its rows are prose only the
    /// safeguard model can read, so a pass that never got a model verdict has
    /// zero coverage of them — whether the model was down, answered
    /// unreadably, was never supplied, or had no declared contract to answer
    /// under. Relaying anyway would answer a gap
    /// with an unexamined allow. The owner plane is sovereign and gets the
    /// opposite treatment: an owner-plane-only degrade never halts, because
    /// nothing sits beneath the owner's own policy to fall back to.
    ///
    /// That remains the DEFAULT and is what an unconfigured host gets. A host
    /// that chose [`HostedOutagePolicy::ProceedReceipted`] trades it for
    /// availability on model-availability degrades only, and the pass records
    /// that choice in [`RelayClassifiedPass::degrade_halts`] at the point the
    /// degrade was raised. A `Block` or `RouteToHelp` verdict halts either
    /// way: that is an answer, not an outage.
    #[must_use]
    pub fn must_halt_relay(&self) -> bool {
        match self {
            Self::Classified(pass) => {
                matches!(
                    pass.verdict.decision,
                    PolicyClassifyDecision::Block | PolicyClassifyDecision::RouteToHelp
                ) || (pass.degrade_halts && pass.hosted_policy_in_play)
            }
            Self::TrustedVaultSide | Self::NotRelayedByUs => false,
        }
    }
}

/// Both planes' answers about the same content, from one pass.
///
/// The two are kept apart on purpose. The relay's halt decision is the hosted
/// plane's business and the owner's verdict never feeds it; the owner's
/// enforcement is the vault's business and the hosted verdict never feeds
/// that. What they share is the content and the round trip.
#[derive(Debug, Clone, PartialEq)]
pub struct DualPlanePass {
    /// The vault owner's own verdict. A clean `Allow` when the owner's plane
    /// is off, has no document, or its model did not answer — that plane is
    /// sovereign and fails open.
    pub owner: PolicyClassifyVerdict,
    /// The hosted relay boundary's pass, which is what decides whether the
    /// relay may proceed.
    pub relay: RelayBoundaryPass,
    /// The owner plane wanted a model verdict and did not get one. Never halts
    /// anything; the caller is simply owed the fact.
    pub owner_model_skipped: bool,
}

/// Narrow read-only port for vault-side receipts owned by our relay VM.
pub trait VaultSideVerdictSource {
    /// The latest verdict recorded for this content at the relay boundary. The
    /// key is the locally recomputed, identity-free verification hash.
    fn latest_boundary_verdict(
        &self,
        verify_content_hash: &[u8; 32],
    ) -> Result<Option<PolicyClassifyVerdict>>;
}

/// Process-local vault-side verdict adapter keyed by the verification hash.
///
/// This is deliberately an adapter only: durable relay-store ownership belongs
/// to the connector edge that supplies this source.
#[derive(Debug, Default)]
pub struct InMemoryVaultSideVerdicts {
    verdicts: HashMap<[u8; 32], PolicyClassifyVerdict>,
}

impl InMemoryVaultSideVerdicts {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Associates a vault-side verdict with its identity-free verification key.
    pub fn insert(
        &mut self,
        verify_content_hash: [u8; 32],
        verdict: PolicyClassifyVerdict,
    ) -> Option<PolicyClassifyVerdict> {
        self.verdicts.insert(verify_content_hash, verdict)
    }
}

impl VaultSideVerdictSource for InMemoryVaultSideVerdicts {
    fn latest_boundary_verdict(
        &self,
        verify_content_hash: &[u8; 32],
    ) -> Result<Option<PolicyClassifyVerdict>> {
        Ok(self.verdicts.get(verify_content_hash).cloned())
    }
}

/// CloudVault verification either supplies its trusted pass or requires the
/// caller to run the hosted pass and audit the breach.
pub(super) enum CloudVaultPassOrFallback {
    Pass(RelayBoundaryPass),
    HostedFallback { receipt_breach: &'static str },
}

/// The safeguard model tier a pass may consult, with the lease it spends from.
/// Paired because the two are meaningless apart: a backend with no lease has no
/// budget to run under.
///
/// Public because the classifier is the SUBSTRATE OWNER's choice now. An
/// earlier design kept this crate-private on the theory that our relay
/// infrastructure had to pin its own classifier; the ruling this file
/// implements moves every moderation input — patterns, policy document, model
/// binding, generation parameters, classifier mode — to the substrate owner,
/// so there is nothing left for the engine to pin on their behalf.
#[derive(Clone, Copy)]
pub struct RelaySafeguardTier<'a> {
    pub backend: &'a dyn LlmBackend,
    pub lease: &'a BudgetLease,
}

impl std::fmt::Debug for RelaySafeguardTier<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelaySafeguardTier")
            .field("lease", &self.lease.id())
            .finish_non_exhaustive()
    }
}

/// What a pass learned on its way to a verdict, so a degrade raised AFTER the
/// pass ran does not throw the substrate owner's matched pattern ids away with
/// the verdict it replaces.
pub(super) fn pass_audit_of(pass: &RelayBoundaryPass) -> PolicyPassAudit {
    pass.boundary_verdict()
        .and_then(|verdict| verdict.audit.as_deref().cloned())
        .unwrap_or_default()
}

/// Whether the binding-checked receipt write leaves a row when the binding did
/// NOT move. A signalless clean allow writes none — that is the ledger's
/// existing contract — but it still has a pinned binding the relay is about to
/// act on, so it takes the check and writes only if the check finds something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::policy_model) enum RelayReceiptRow {
    /// Write the row whatever the check finds.
    Always,
    /// Write only the degrade row, and only if the binding moved.
    OnlyIfBindingMoved,
}

/// A pass that needed a model verdict and did not get one. The verdict falls
/// back to a clean allow — never below whatever a `Decide` rule already
/// concluded, because a `Decide` hit returns before this is reachable — and the
/// degrade marker is what makes the relay halt.
///
/// This is the ONLY place in the crate that raises a degrade, which is why it
/// is also where the halt is resolved: it holds both the degrade and the
/// host's [`HostedOutagePolicy`]. Under the default `Halt` every degrade
/// stops the relay, exactly as before. Under `ProceedReceipted` a
/// model-availability degrade does not — and nothing else changes about the
/// pass: the marker, the `Unresolved` resolution and the receipt row are all
/// still written, so the allow stays visibly one no model confirmed.
pub(super) fn degraded_hosted_pass(
    binding: PolicyContentBinding,
    config: &PolicyModelConfig,
    audit: PolicyPassAudit,
    degrade: RelayBoundaryDegrade,
    hosted_policy_in_play: bool,
) -> RelayBoundaryPass {
    let degrade_halts = match config.hosted_outage_policy {
        HostedOutagePolicy::Halt => true,
        HostedOutagePolicy::ProceedReceipted => !degrade.is_model_availability(),
    };
    RelayBoundaryPass::Classified(Box::new(RelayClassifiedPass {
        verdict: PolicyClassifyVerdict::clean_allow(binding, config, PolicyPlane::HostedLegal)
            .with_audit(audit),
        degraded: Some(degrade),
        degrade_halts,
        hosted_policy_in_play,
        resolution: RelayResolution::Unresolved,
    }))
}

/// Which zero-model allow this is: only `Log` rules matched, or the gate simply
/// found nothing to escalate.
pub(super) fn log_only_or_gated(evaluation: &PatternEvaluation<'_>) -> RelayResolution {
    if evaluation.acting_role() == Some(PolicyPatternRole::Log) {
        RelayResolution::LogOnly
    } else {
        RelayResolution::PatternGatedAllow
    }
}
