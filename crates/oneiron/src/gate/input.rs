use crate::claim::ClaimSource;
use crate::counterparty_contact::CounterpartyFirstTouch;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::outbound_consent::ScopedMcpCallContext;

use super::ceiling::{PolicyApprovalCeiling, PolicyCriticality};
use super::constants::POLICY_SCHEMA_VERSION;
use super::decision::GateReasonCode;

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateActor {
    pub(crate) actor_class: String,
    pub(crate) actor_ref: Option<String>,
    pub(crate) delegation_grant_ref: Option<String>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateContentKind {
    Claim,
    EdgeProvenanceClaim,
    PolicyManifest,
    ExternalEffect,
    /// ONE-1686 (RT-04): one witnessed MESSAGE envelope, gated at the shared
    /// `Memory::witness` write boundary. See `gate::witness_message`.
    WitnessMessage,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateContentKind {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::EdgeProvenanceClaim => "edge_provenance_claim",
            Self::PolicyManifest => "policy_manifest",
            Self::ExternalEffect => "external_effect",
            Self::WitnessMessage => "witness_message",
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GateProvenanceHandles {
    pub(crate) actor_entity_ref: Option<EntityId>,
    pub(crate) substrate_ref: Option<EntityId>,
    pub(crate) source_revision_ref: Option<[u8; ENTITY_ID_LEN]>,
    pub(crate) body_snapshot_ref: Option<[u8; ENTITY_ID_LEN]>,
    pub(crate) dreamer_run_id: Option<String>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateEvaluatorInput {
    pub(crate) actor: GateActor,
    pub(crate) source: Option<ClaimSource>,
    pub(crate) content_kind: GateContentKind,
    pub(crate) sensitivity_band: Option<u8>,
    pub(crate) criticality: PolicyCriticality,
    pub(crate) policy_manifest_version: String,
    pub(crate) provenance: GateProvenanceHandles,
    pub(crate) external_effect: Option<ExternalEffectGateContext>,
    /// The AGENT_DEF-authored ceiling bound resolved live for definition-bound
    /// actors ([`agent_definition_ceiling_for_actor`]); `None` = no definition
    /// bound (owner writes, connectors, non-definition agent actors) —
    /// preserves pre-AGENT-2 behavior at every existing construction site.
    pub(crate) agent_definition_ceiling: Option<PolicyApprovalCeiling>,
    /// The DEC-0006 consent context, when the caller composed one. `None` =
    /// this door has not been moved onto the unified consent path yet and
    /// keeps its pre-DEC-0006 criticality behaviour.
    pub(crate) consent: Option<ConsentGateContext>,
}

/// The DEC-0006 inputs the Gate needs to run the consent ladder.
///
/// The Gate does not compose these: `consent.rs` owns the evaluation, and this
/// carries its verdict plus the reason the verdict was reached, so the receipt
/// records WHY an op asked rather than only THAT it asked.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConsentGateContext {
    /// The consent evaluator's verdict for this operation.
    pub(crate) decision: crate::consent::ConsentDecision,
    /// Why the verdict was reached, when it was not Auto.
    pub(crate) reason: Option<ConsentPendingReason>,
}

/// Stable pending-reason codes for the DEC-0006 consent ladder.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsentPendingReason {
    /// Irreversible in effect, with no approve-once receipt or covering grant.
    IrreversibleEffect,
    /// A standing grant exists but the candidate exceeds its bound.
    BoundExceeded,
    /// The closed catastrophe floor matched — the only always-gate.
    CatastropheFloor,
    /// Required write facts were malformed or absent (invariant 8 fallback).
    WriteClassificationFailed,
}

impl ConsentGateContext {
    /// Runs the DEC-0006 evaluator and packages its verdict for the Gate.
    ///
    /// This is the ONE composer: `consent.rs` owns the decision, and the Gate
    /// only translates it into reason codes. Keeping the call here means a
    /// door opts into the unified consent path by composing a
    /// [`crate::consent::ComposedEffect`], never by re-implementing the ladder.
    pub(crate) fn evaluate(
        effect: &crate::consent::ComposedEffect,
        approve_once: Option<&crate::consent::ApproveOnceAuthorization>,
        grants: &[crate::consent::StandingConsentGrant],
    ) -> Self {
        let decision = crate::consent::evaluate_consent(effect, approve_once, grants);
        Self {
            decision,
            reason: (decision != crate::consent::ConsentDecision::Auto)
                .then(|| Self::pending_reason(effect, grants)),
        }
    }

    /// Why a non-Auto verdict was reached, in the evaluator's own precedence:
    /// catastrophe first, then a classification failure, then a bound a grant
    /// names but does not cover, else the plain irreversible case.
    fn pending_reason(
        effect: &crate::consent::ComposedEffect,
        grants: &[crate::consent::StandingConsentGrant],
    ) -> ConsentPendingReason {
        if effect.catastrophe().is_some() {
            return ConsentPendingReason::CatastropheFloor;
        }
        if crate::consent::classify_composed_effect(effect.facts()).is_err() {
            return ConsentPendingReason::WriteClassificationFailed;
        }
        if crate::consent::bound_exceeded(effect, grants) {
            return ConsentPendingReason::BoundExceeded;
        }
        ConsentPendingReason::IrreversibleEffect
    }
}

impl ConsentPendingReason {
    const fn reason_code(self) -> GateReasonCode {
        match self {
            Self::IrreversibleEffect => GateReasonCode::PendingConsentIrreversibleEffect,
            Self::BoundExceeded => GateReasonCode::PendingConsentBoundExceeded,
            Self::CatastropheFloor => GateReasonCode::PendingConsentCatastropheFloor,
            Self::WriteClassificationFailed => {
                GateReasonCode::PendingConsentWriteClassificationFailed
            }
        }
    }
}

/// Translates a consent verdict into Gate pending reasons.
///
/// `Auto` contributes nothing (the op runs). `Ask` and `Hide` both hold the
/// write — the difference between them is the SURFACE the host raises, which
/// is the domain fail-safe (invariant 8) and is carried by the reason, not by
/// a second Gate outcome.
/// The stable `gate.`-namespaced reason-code strings for one consent verdict.
///
/// Empty exactly when the verdict is Auto.
pub(crate) fn consent_gate_reason_codes(consent: &ConsentGateContext) -> Vec<String> {
    consent_ladder_reasons(Some(consent))
        .into_iter()
        .map(|code| code.as_str().to_owned())
        .collect()
}

pub(super) fn consent_ladder_reasons(consent: Option<&ConsentGateContext>) -> Vec<GateReasonCode> {
    let Some(consent) = consent else {
        return Vec::new();
    };
    match consent.decision {
        crate::consent::ConsentDecision::Auto => Vec::new(),
        crate::consent::ConsentDecision::Ask | crate::consent::ConsentDecision::Hide => {
            vec![
                consent
                    .reason
                    .unwrap_or(ConsentPendingReason::IrreversibleEffect)
                    .reason_code(),
            ]
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ExternalEffectPolicyRisk {
    #[default]
    Normal,
    HoldToProposal,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ExternalEffectPolicyRisk {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::HoldToProposal => "hold_to_proposal",
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalEffectGateContext {
    pub(crate) verb: String,
    pub(crate) channel: String,
    pub(crate) channel_identity_ref: Option<EntityId>,
    pub(crate) counterparty: Option<String>,
    pub(crate) brief_ref: Option<String>,
    pub(crate) send_ref: Option<String>,
    pub(crate) standing_grant_ref: Option<String>,
    pub(crate) scoped_mcp_call: Option<ScopedMcpCallContext>,
    pub(crate) scoped_mcp_grant_authorized: bool,
    pub(crate) counterparty_first_touch: Option<CounterpartyFirstTouch>,
    pub(crate) counterparty_opted_out: bool,
    pub(crate) counterparty_opt_out_receipt_reason: Option<&'static str>,
    pub(crate) has_opted_in: bool,
    pub(crate) has_permission: bool,
    pub(crate) policy_risk: ExternalEffectPolicyRisk,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalEffectGateInput {
    pub(crate) actor: GateActor,
    pub(crate) provenance: GateProvenanceHandles,
    pub(crate) verb: String,
    pub(crate) channel: String,
    pub(crate) channel_identity_ref: Option<EntityId>,
    pub(crate) counterparty: Option<String>,
    pub(crate) brief_ref: Option<String>,
    pub(crate) send_ref: Option<String>,
    pub(crate) standing_grant_ref: Option<String>,
    pub(crate) scoped_mcp_call: Option<ScopedMcpCallContext>,
    pub(crate) counterparty_first_touch: Option<CounterpartyFirstTouch>,
    pub(crate) counterparty_opted_out: bool,
    pub(crate) counterparty_opt_out_receipt_reason: Option<&'static str>,
    pub(crate) has_opted_in: bool,
    pub(crate) has_permission: bool,
    pub(crate) policy_risk: ExternalEffectPolicyRisk,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ExternalEffectGateInput {
    pub(super) fn gate_input(
        &self,
        agent_definition_ceiling: Option<PolicyApprovalCeiling>,
        consent: Option<ConsentGateContext>,
    ) -> GateEvaluatorInput {
        GateEvaluatorInput {
            actor: self.actor.clone(),
            source: None,
            content_kind: GateContentKind::ExternalEffect,
            sensitivity_band: None,
            criticality: PolicyCriticality::Normal,
            policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
            provenance: self.provenance.clone(),
            agent_definition_ceiling,
            consent,
            external_effect: Some(ExternalEffectGateContext {
                verb: self.verb.clone(),
                channel: self.channel.clone(),
                channel_identity_ref: self.channel_identity_ref,
                counterparty: self.counterparty.clone(),
                brief_ref: self.brief_ref.clone(),
                send_ref: self.send_ref.clone(),
                standing_grant_ref: self.standing_grant_ref.clone(),
                scoped_mcp_call: self.scoped_mcp_call.clone(),
                scoped_mcp_grant_authorized: false,
                counterparty_first_touch: self.counterparty_first_touch,
                counterparty_opted_out: self.counterparty_opted_out,
                counterparty_opt_out_receipt_reason: self.counterparty_opt_out_receipt_reason,
                has_opted_in: self.has_opted_in,
                has_permission: self.has_permission,
                policy_risk: self.policy_risk,
            }),
        }
    }
}
