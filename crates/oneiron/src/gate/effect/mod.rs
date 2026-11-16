mod admitted_approval;
mod approval_target;
mod effect_consent;
mod effect_contacts;
mod effect_grants;
mod effect_paced;
mod effect_pair;
mod evaluate;
mod evaluate_recipients;
mod preflight;
mod record;

pub(crate) use self::approval_target::{
    ApprovalTarget, BrowserSendTarget, CampaignLegFacts, ChannelIdentityLifecycleFacts,
    LinearMirrorFacts, OutboundSendFacts, ScopedMcpCallFacts,
};
pub(super) use self::effect_consent::{
    external_effect_action_requirement, external_effect_composed_effect,
    external_effect_consent_context, native_mail_cold_composed_effect,
};
pub(crate) use self::effect_contacts::{
    CounterpartyHydration, counterparty_send_override_in_txn, hydrate_external_effect_contact,
    hydrate_external_effect_contact_at,
};
pub(crate) use self::effect_grants::live_grant_covering_effect_in_txn;
use self::effect_grants::{
    channel_identity_envelope_admission_in_txn, record_standing_outbound_grant_use_in_txn,
    standing_outbound_grant_for_effect,
};
pub(crate) use self::effect_paced::{ExternalEffectCheck, check_external_effect_policy_paced};
pub(crate) use self::effect_pair::{PairAdmission, check_external_effect_policy_pair};
pub(crate) use self::evaluate::{evaluate_external_effect_policy, judge_external_effect_in_txn};
pub(crate) use self::preflight::{
    ExternalEffectPreflight, PreflightBudget, PreflightVerdict, preflight_answer_in_txn,
    preflight_words,
};
pub(crate) use self::record::{
    check_external_effect_policy, record_external_effect_policy, record_held_external_effect_policy,
};

use crate::connector_key::{
    self, ConnectorKeyStatus, EffectorBudgetCharge, EffectorBudgetChargeOutcome,
    EffectorBudgetOnExhaust,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::outbound_grant::StandingOutboundGrant;
use crate::store::{GateDecisionId, GateDecisionRecord, Store};

use super::decision::{GateDecision, GateOutcome, GateReasonCode, external_effect_receipt_reasons};
use super::definition_ceiling::agent_definition_ceiling_for_effect_actor;
use super::doors::{GateConsentBinding, gate_decision_matches_pending_candidate};
use super::grants::external_effect_grant_matches;
use super::input::{ConsentGateContext, ExternalEffectGateInput, GateEvaluatorInput};
use super::resolution::PolicyManifestResolution;

/// Connector-key target selected by governance. Accounting consumes this
/// value only after governance allows an effect.
pub(crate) struct ExternalEffectBudgetTarget {
    pub(crate) key_id: EntityId,
    pub(crate) key: connector_key::ConnectorKeyRecord,
    pub(crate) governing_connector: String,
}

/// Phase of one external-effect authorization at the ledger boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ApprovalContext {
    Observe,
    FirstAdmission,
    Retry(crate::consent::approval_proof::AdmittedApproval),
    /// The first admission of a held effect a code consent wait owns
    /// (DOOR-079 1a): its one-shot approval is the one the wait's answer
    /// minted under the wait's binding digest, which the admission writer
    /// proved from the rows. It removes only that consent ask.
    CodeWait([u8; 32]),
}

/// Uneffected external-policy decision. The chokepoint may debit the returned
/// target and adjust an exhaustion denial before this decision is recorded.
pub(crate) struct ExternalEffectGovernance {
    decision_id: GateDecisionId,
    decision: GateDecision,
    created_at: u64,
    input: GateEvaluatorInput,
    binding: GateConsentBinding,
    grant_ref: Option<String>,
    approve_once: Option<crate::consent::ApproveOnceAuthorization>,
    approval_context: ApprovalContext,
    ask_consent: Option<crate::llm::decision::AskConsent>,
    matched_grant: Option<StandingOutboundGrant>,
    /// Fix list row 17645: the standing grants that released the other
    /// recipients of one message to several, each once and none of them
    /// `matched_grant`; recorded as used when the message is admitted.
    recipient_grants: Vec<StandingOutboundGrant>,
    /// OF-374: the sender row's envelope slot covering this send, spent only
    /// when the decision is recorded as an admitting Allow.
    envelope_reservation: Option<crate::outbound_grant::ChannelIdentityGrantReservation>,
    /// FIX 7948: the place in its envelope's line a send meets at a full
    /// window when that envelope is all that covers it. The chokepoint keeps
    /// it in place of an admission; nothing records it as one.
    envelope_wait: Option<crate::outbound_grant::ChannelIdentityGrantRetention>,
    budget_target: Option<ExternalEffectBudgetTarget>,
    scoped_capability: Option<connector_key::ScopedCapabilityProvenance>,
}

/// The external-effect judgment before any decision id exists: what
/// [`evaluate_external_effect_policy`] decides, read-only (FIX 22102). A writer
/// turns it into [`ExternalEffectGovernance`] with [`Self::into_governance`]; a
/// preflight reads its outcome and drops it, which commits nothing.
pub(crate) struct ExternalEffectJudgment {
    decision: GateDecision,
    created_at: u64,
    /// The decision lacks external-effect authority that the owner's press
    /// on this one effect would supply (ARCH-0046 "a press per send").
    press_supplies_authority: bool,
    input: GateEvaluatorInput,
    binding: GateConsentBinding,
    grant_ref: Option<String>,
    approve_once: Option<crate::consent::ApproveOnceAuthorization>,
    approval_context: ApprovalContext,
    ask_consent: Option<crate::llm::decision::AskConsent>,
    matched_grant: Option<StandingOutboundGrant>,
    /// Fix list row 17645: the standing grants that released the other
    /// recipients of one message to several, each once and none of them
    /// `matched_grant`; carried into governance and recorded as used when the
    /// message is admitted.
    recipient_grants: Vec<StandingOutboundGrant>,
    /// OF-374: the sender row's envelope slot covering this send, spent only
    /// when the decision is recorded as an admitting Allow.
    envelope_reservation: Option<crate::outbound_grant::ChannelIdentityGrantReservation>,
    /// FIX 7948: the place in its envelope's line a send meets at a full
    /// window when that envelope is all that covers it. The chokepoint keeps
    /// it in place of an admission; nothing records it as one.
    envelope_wait: Option<crate::outbound_grant::ChannelIdentityGrantRetention>,
    budget_target: Option<ExternalEffectBudgetTarget>,
    scoped_capability: Option<connector_key::ScopedCapabilityProvenance>,
}

impl ExternalEffectJudgment {
    pub(crate) fn into_governance(self, decision_id: GateDecisionId) -> ExternalEffectGovernance {
        ExternalEffectGovernance {
            decision_id,
            decision: self.decision,
            created_at: self.created_at,
            input: self.input,
            binding: self.binding,
            grant_ref: self.grant_ref,
            approve_once: self.approve_once,
            approval_context: self.approval_context,
            ask_consent: self.ask_consent,
            matched_grant: self.matched_grant,
            recipient_grants: self.recipient_grants,
            envelope_reservation: self.envelope_reservation,
            envelope_wait: self.envelope_wait,
            budget_target: self.budget_target,
            scoped_capability: self.scoped_capability,
        }
    }

    #[must_use]
    pub(crate) fn outcome(&self) -> GateOutcome {
        self.decision.outcome()
    }

    pub(crate) fn decision(&self) -> &GateDecision {
        &self.decision
    }

    /// FIX 7948: the Gate allowed this send on an envelope whose window is
    /// full, so the send would keep its place in that envelope's line rather
    /// than go now, as
    /// [`ExternalEffectGovernance::retain_envelope_wait_in_txn`] keeps it.
    #[must_use]
    pub(crate) fn waits_for_envelope_window(&self) -> bool {
        self.decision.outcome() == GateOutcome::Allow && self.envelope_wait.is_some()
    }

    /// The decision lacks external-effect authority, and the owner's press on
    /// this one effect would supply it: the per-send mail press or the
    /// publish press (ARCH-0046 "a press per send").
    #[must_use]
    pub(crate) const fn press_supplies_authority(&self) -> bool {
        self.press_supplies_authority
    }

    /// The governing key an admitted effect would be charged to, if any;
    /// the judgment selects it and charges nothing.
    #[must_use]
    pub(crate) const fn budget_target(&self) -> Option<&ExternalEffectBudgetTarget> {
        self.budget_target.as_ref()
    }
}

impl ExternalEffectGovernance {
    #[must_use]
    pub(crate) fn outcome(&self) -> GateOutcome {
        self.decision.outcome()
    }

    /// The actual hydrated consent composition for a live scoped-MCP hold.
    /// It is metadata for an owner question, never admission authority.
    pub(crate) fn ask_consent(&self) -> Option<&crate::llm::decision::AskConsent> {
        self.ask_consent.as_ref()
    }

    /// The typed per-grant capability identity this governance verified, if the
    /// effect was admitted under a scoped-MCP grant. The chokepoint carries
    /// exactly this value into the durable intent row (ONE-1885).
    #[must_use]
    pub(crate) const fn scoped_capability(
        &self,
    ) -> Option<&connector_key::ScopedCapabilityProvenance> {
        self.scoped_capability.as_ref()
    }

    #[must_use]
    pub(crate) fn budget_target_mut(&mut self) -> Option<&mut ExternalEffectBudgetTarget> {
        self.budget_target.as_mut()
    }

    pub(crate) fn deny_budget_exhausted(&mut self) {
        self.decision = GateDecision::deny(GateReasonCode::DenyEffectorBudgetExhausted)
            .with_receipt_reasons(["effector_budget_exhausted"])
            .with_receipt_reasons(external_effect_receipt_reasons(
                self.input
                    .external_effect
                    .as_ref()
                    .expect("external effect input"),
            ));
    }
}

/// Same composer used by the Gate's approve-once lookup, so the owner
/// approves the exact effect the dispatcher later re-evaluates.
pub(crate) fn external_effect_approval_digest(
    effect: &ExternalEffectGateInput,
) -> Option<crate::consent::EffectDigest> {
    external_effect_composed_effect(effect).map(|composed| composed.digest())
}

/// The code-bound approval digest a code consent wait's answer mints and its
/// effect's gate looks up under [`ApprovalContext::CodeWait`]: one composer
/// for both (DOOR-079 1a).
pub(crate) fn code_wait_approval_digest(
    effect: &ExternalEffectGateInput,
    binding_digest: &[u8; 32],
) -> Option<crate::consent::EffectDigest> {
    effect_consent::code_wait_composed_effect(effect, binding_digest)
        .map(|composed| composed.digest())
}

/// The native action requirement offered by a consent-only code wait.
/// This is the same requirement the external-effect consent ladder judges.
pub(crate) fn code_wait_standing_bound(
    effect: &ExternalEffectGateInput,
) -> Option<crate::consent::GrantBound> {
    external_effect_action_requirement(effect)
}

/// The pack's one-send owner tap uses the same bound digest as the gate's
/// native-mail cold effect. A different target or send ref is a different tap.
pub(crate) fn native_mail_cold_approval_digest(
    effect: &ExternalEffectGateInput,
) -> Option<crate::consent::EffectDigest> {
    native_mail_cold_composed_effect(effect).map(|composed| composed.digest())
}

/// Debits the governance-selected connector key exactly once for an admitted
/// effect, mirroring the chokepoint `charge_once`: send-dimension rows debit
/// only for send-like effects, an exhausted suspend-class row suspends the key,
/// and the caller converts exhaustion into a denial. `pool` false leaves a
/// per-grant key's catalog pool to the key charged before it.
fn charge_admitted_external_effect(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    governance: &mut ExternalEffectGovernance,
    send_like: bool,
    pool: bool,
) -> Result<(Option<EffectorBudgetCharge>, bool)> {
    let mutation_recorded_at = crate::ports::recorded_at_in_txn(store, wtxn)?;
    let Some(target) = governance.budget_target_mut() else {
        return Ok((None, false));
    };
    // Budget windows advance on the engine's trusted clock, not a caller
    // timestamp, so the debit and any receipt echo share the same window.
    let budget_now = mutation_recorded_at;
    let outcome = connector_key::charge_effector_budgets_pooled(
        store,
        wtxn,
        &target.key_id,
        &mut target.key,
        &target.governing_connector,
        send_like,
        budget_now,
        pool,
    )?;
    let (mut charge, exhausted) = match outcome {
        EffectorBudgetChargeOutcome::NoRows(charge)
        | EffectorBudgetChargeOutcome::Charged(charge) => (charge, false),
        EffectorBudgetChargeOutcome::Exhausted {
            location,
            on_exhaust,
            mut charge,
        } => {
            if on_exhaust == EffectorBudgetOnExhaust::Suspend
                && let connector_key::SuspendAdmission::Suspended(suspended) =
                    connector_key::suspend_connector_key_in_txn(
                        store,
                        wtxn,
                        &target.key_id,
                        &target.key,
                        connector_key::SuspendCause::BudgetExhausted(&location),
                        budget_now,
                    )?
            {
                charge.read.status = suspended.status;
            }
            (charge, true)
        }
    };
    charge.matched_rows.sort_unstable();
    charge.matched_rows.dedup();
    Ok((Some(charge), exhausted))
}
