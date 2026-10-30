mod admitted_approval;
mod approval_target;
mod effect_consent;
mod effect_contacts;
mod effect_grants;
mod effect_paced;
mod effect_pair;
mod evaluate;
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
    counterparty_send_override_in_txn, hydrate_external_effect_contact,
};
pub(crate) use self::effect_grants::live_grant_covering_effect_in_txn;
use self::effect_grants::{
    channel_identity_envelope_admission_in_txn, standing_outbound_grant_for_effect,
    touch_standing_outbound_grant_in_txn,
};
pub(crate) use self::effect_paced::{ExternalEffectCheck, check_external_effect_policy_paced};
pub(crate) use self::effect_pair::{PairAdmission, check_external_effect_policy_pair};
pub(crate) use self::evaluate::evaluate_external_effect_policy;
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
    Retry(crate::outbound_intent_ledger::AdmittedApproval),
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
    matched_grant: Option<(EntityId, StandingOutboundGrant)>,
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

impl ExternalEffectGovernance {
    #[must_use]
    pub(crate) fn outcome(&self) -> GateOutcome {
        self.decision.outcome()
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
            if on_exhaust == EffectorBudgetOnExhaust::Suspend {
                connector_key::suspend_connector_key_in_txn(
                    store,
                    wtxn,
                    &target.key_id,
                    &target.key,
                    connector_key::budget_exhausted_reason(&location),
                    budget_now,
                )?;
                charge.read.status = ConnectorKeyStatus::Suspended;
            }
            (charge, true)
        }
    };
    charge.matched_rows.sort_unstable();
    charge.matched_rows.dedup();
    Ok((Some(charge), exhausted))
}
