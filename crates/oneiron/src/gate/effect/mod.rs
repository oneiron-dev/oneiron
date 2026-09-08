mod effect_consent;
mod effect_contacts;
mod effect_grants;

pub(super) use self::effect_consent::{
    external_effect_action_requirement, external_effect_composed_effect,
    external_effect_consent_context,
};
use self::effect_contacts::hydrate_external_effect_contact;
use self::effect_grants::{
    standing_outbound_grant_for_effect, touch_standing_outbound_grant_in_txn,
};

use crate::connector_key::{
    self, ConnectorKeyStatus, EffectorBudgetCharge, EffectorBudgetChargeOutcome,
    EffectorBudgetOnExhaust,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::outbound_grant::StandingOutboundGrant;
use crate::store::{GateDecisionId, GateDecisionRecord, Store};

use super::decision::{
    GateDecision, GateOutcome, GateReasonCode, external_effect_receipt_reasons,
    record_gate_decision_metrics,
};
use super::definition_ceiling::agent_definition_ceiling_for_effect_actor;
use super::doors::{GateConsentBinding, gate_decision_matches_pending_candidate};
use super::grants::external_effect_grant_matches;
use super::input::{ExternalEffectGateInput, GateEvaluatorInput};
use super::resolution::PolicyManifestResolution;

/// Connector-key target selected by governance. Accounting consumes this
/// value only after governance allows an effect.
pub(crate) struct ExternalEffectBudgetTarget {
    pub(crate) key_id: EntityId,
    pub(crate) key: connector_key::ConnectorKeyRecord,
    pub(crate) governing_connector: String,
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
    matched_grant: Option<(EntityId, StandingOutboundGrant)>,
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

/// Evaluates consent and connector governance without charging or recording.
/// The caller must either finalize the returned decision or abort its txn.
pub(crate) fn evaluate_external_effect_policy(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
    required_grant_id: Option<EntityId>,
) -> Result<ExternalEffectGovernance> {
    let (mut hydrated_effect, counterparty_send_override) =
        hydrate_external_effect_contact(store, &*wtxn, effect)?;
    hydrated_effect.standing_grant_ref = None;
    let mut scoped_mcp_grant_authorized = false;
    let matched_grant = standing_outbound_grant_for_effect(
        store,
        wtxn,
        &hydrated_effect,
        policy,
        required_grant_id,
    )?;
    if let Some((grant_id, grant)) = matched_grant.as_ref() {
        hydrated_effect.standing_grant_ref = Some(format!("grant:{}", grant_id.to_hex()));
        scoped_mcp_grant_authorized = grant.scope.scoped_mcp_grant().is_some();
    }
    // The effect door NEVER gates ceiling resolution on the caller-asserted
    // class alone: the resolver binds the identity pair, derives authority
    // from the governing entity's own type, and fails closed on unrecognized
    // class assertions.
    let agent_definition_ceiling = agent_definition_ceiling_for_effect_actor(
        store,
        &*wtxn,
        &hydrated_effect.actor.actor_class,
        hydrated_effect.actor.actor_ref.as_deref(),
        hydrated_effect.provenance.actor_entity_ref,
    );
    // DEC-0006: this door composes its consent context at the chokepoint, so
    // consent is evaluated by the one ladder rather than re-implemented per
    // call site. The coverage set folds three already-verified authorization
    // facts read on THIS write txn — the vault's ACTIVE consent grants, the
    // scope-matched `StandingOutboundGrant` (through the pinned adapter), and
    // any budget-free POLICY-scoped grant the compiler's four-axis matcher
    // accepts (echoed as a covering grant; see below) — so an effect already
    // authorized on remembered state is Auto on the consent axis exactly once,
    // honors revocation immediately, and an UNGRANTED irreversible effect is
    // the only one that enters the ask lane (invariant 1).
    let mut consent_grants = crate::consent::load_active_standing_grants(store, wtxn)?;
    let provisional = hydrated_effect.gate_input(agent_definition_ceiling, None);
    let requirement = external_effect_action_requirement(&hydrated_effect);
    if let (Some(requirement), Some(effect_ctx)) =
        (requirement, provisional.external_effect.as_ref())
    {
        let scoped_covers = policy.scoped_grants().iter().any(|grant| {
            grant.budget.is_none()
                && external_effect_grant_matches(grant, &provisional.actor, effect_ctx)
        });
        if scoped_covers && let Ok(grant) = crate::consent::ActionGrant::new(requirement.clone()) {
            consent_grants.push(crate::consent::StandingConsentGrant::Action(grant));
        }
        // A scope-matched `StandingOutboundGrant` resolved on this txn — the
        // matcher already enforced actor identity, channel/contact/verb-class
        // scope, and ACTIVE status — is folded as remembered coverage by
        // ECHOING the requirement as its covering grant. Dial vocabularies
        // differ per scope kind (channel/contact/brief/scoped-MCP), so the
        // adapter's normalized bound cannot be trusted to subset-match the
        // requirement's verb-shaped selectors; the door's own four-axis match
        // is the authority the echo records. Revocation is honored by the
        // matcher upstream: a revoked row never reaches this arm.
        if matched_grant.is_some()
            && let Ok(grant) = crate::consent::ActionGrant::new(requirement)
        {
            consent_grants.push(crate::consent::StandingConsentGrant::Action(grant));
        }
    }
    // A payload-aware scoped-MCP grant ALREADY authorized this effect at the
    // registry-match stage (`scoped_mcp_grant_authorized`) — the only safe MCP
    // auto path. Fold it: the effect is consent-covered, not re-asked.
    if scoped_mcp_grant_authorized
        && let Some(requirement) = external_effect_action_requirement(&hydrated_effect)
        && let Ok(grant) = crate::consent::ActionGrant::new(requirement)
    {
        consent_grants.push(crate::consent::StandingConsentGrant::Action(grant));
    }
    // The exact engine-computed digest is the only approve-once lookup key.
    // Reading it on THIS write transaction yields either no approval, one
    // unforgeable available authorization, or a typed spent-replay refusal.
    // The marker is changed to spent only when the final Gate decision is
    // recorded as Allow in this same transaction.
    let approve_once = external_effect_composed_effect(&hydrated_effect)
        .map(|effect| {
            crate::consent::approve_once_authorization_in_txn(store, &*wtxn, &effect.digest())
        })
        .transpose()?
        .flatten();
    let consent =
        external_effect_consent_context(&hydrated_effect, approve_once.as_ref(), &consent_grants);
    let mut input = hydrated_effect.gate_input(agent_definition_ceiling, consent);
    if let Some(effect) = input.external_effect.as_mut() {
        effect.scoped_mcp_grant_authorized = scoped_mcp_grant_authorized;
        // ONE-1752: the same post-conversion seam. Hydration cannot reach a
        // context that does not exist until `gate_input()` builds it, so the
        // override it resolved is written on here, once, before evaluation.
        effect.counterparty_send_override = counterparty_send_override;
    }
    let mut decision = policy.evaluate_gate(&input);
    let binding = GateConsentBinding::for_external_effect(&input, policy)?;
    let decision_id = GateDecisionId::now();
    let created_at = crate::unix_seconds_now();
    let grant_ref = input
        .external_effect
        .as_ref()
        .and_then(|effect| effect.standing_grant_ref.clone());

    // CA-06 campaign-compliance stage (ONE-1777). The evaluator hydrates its
    // own typed facts from the claim substrate on THIS txn and answers with a
    // pure verdict; the mapping to a decision stays here, where decisions are
    // constructed. It runs BEFORE the connector-key and budget stages — both
    // guarded on would-be-Allow — so a legal-row refusal never consumes budget,
    // exactly like the counterparty-opt-out wall. It converts a would-be Allow
    // AND a Pending: an owner approval must not be able to unlock a dispatch
    // the governing row forbids. It is enforcement, not a new approval step;
    // effects outside a campaign never reach the evaluator at all.
    if decision.outcome() != GateOutcome::Deny
        && let Some(crate::campaign::compliance::ComplianceVerdict::Block { reason, .. }) =
            crate::campaign::compliance::campaign_compliance_gate(
                store,
                &*wtxn,
                &hydrated_effect,
                created_at,
            )?
    {
        decision = GateDecision::deny(GateReasonCode::DenyCampaignCompliance)
            .with_receipt_reasons([reason.receipt_reason()])
            .with_receipt_reasons(external_effect_receipt_reasons(
                input
                    .external_effect
                    .as_ref()
                    .expect("external effect input"),
            ));
    }

    // GOV-01 connector-key stage (ONE-1416). Channel keys retain
    // unset-is-noop; synthetic scoped-MCP keys fail closed below. The status
    // wall and the budget stage are BOTH guarded on would-be-Allow (M1
    // resolution 2026-07-10): a law-class deny from `evaluate_gate` (e.g.
    // counterparty opt-out) keeps its reason code and never consumes budget.
    let normalized_channel = connector_key::normalize_connector_key(&hydrated_effect.channel);
    // The ONE typed per-grant capability identity in this scope. It is minted
    // only from the VERIFIED matched scoped-MCP grant and its admitted call's
    // safe canonical server — never from the effect's channel text — and it is
    // what the charter stage, the chokepoint, and the durable row all carry
    // (ONE-1885).
    let scoped_mcp_capability = matched_grant.as_ref().and_then(|(grant_id, grant)| {
        grant.scope.scoped_mcp_grant().and_then(|_| {
            hydrated_effect.scoped_mcp_call.as_ref().and_then(|call| {
                connector_key::ScopedCapabilityProvenance::mint(&call.server, grant_id)
            })
        })
    });
    let uses_scoped_mcp_governing_connector = matched_grant
        .as_ref()
        .is_some_and(|(_, grant)| grant.scope.scoped_mcp_grant().is_some())
        && hydrated_effect.scoped_mcp_call.is_some();
    let governing_connector = scoped_mcp_capability.as_ref().map_or_else(
        || normalized_channel.clone(),
        |capability| capability.connector().to_owned(),
    );
    let governing = connector_key::governing_connector_key(
        store,
        wtxn,
        &governing_connector,
        hydrated_effect.provenance.actor_entity_ref.as_ref(),
    )?;
    let budget_target = governing
        .as_ref()
        .map(|(key_id, key)| ExternalEffectBudgetTarget {
            key_id: *key_id,
            key: key.clone(),
            governing_connector: governing_connector.clone(),
        });
    if uses_scoped_mcp_governing_connector
        && decision.outcome() == GateOutcome::Allow
        && (scoped_mcp_capability.is_none() || governing.is_none())
    {
        // The real completion—registering each per-grant connector key through
        // the connector lifecycle—rides ONE-1794 with the live transport.
        // Until then, scoped MCP authority fails closed instead of inheriting
        // the channel unset-is-noop behavior. A matched scoped grant whose
        // server cannot produce the one safe canonical capability identity has
        // no per-grant key at all and fails closed on this same wall rather
        // than falling back to the ordinary channel key (ONE-1885).
        decision = GateDecision::pending(vec![GateReasonCode::PendingConnectorKeyUnregistered])
            .with_receipt_reasons(["connector_key_unregistered"])
            .with_receipt_reasons(external_effect_receipt_reasons(
                input
                    .external_effect
                    .as_ref()
                    .expect("external effect input"),
            ));
    }
    if let Some((_key_id, key)) = governing
        && decision.outcome() == GateOutcome::Allow
    {
        // GOV-10 charter stage (ONE-1417), between the status wall and the
        // budget stage: enforcement reads ONLY the compiled policy, never the
        // charter text. Drift degrades to proposed-only (Pending) until a
        // human re-stamps; a never-list match denies. Neither debits.
        let mut charter_wall = None;
        if key.status == ConnectorKeyStatus::Active
            && let Some(block) = key.charter.as_ref()
        {
            let effect_verb = hydrated_effect
                .scoped_mcp_call
                .as_ref()
                .map_or(hydrated_effect.verb.as_str(), |call| call.tool.as_str());
            // The two never-list modes are read separately and never confused.
            // A capability dispatch is measured against its typed identity by
            // the capability-only rules, and against the ORDINARY channel it
            // travels on (`mcp:{server}`, derived from that same typed value so
            // recovery reads the identical string) by the ordinary rules.
            let never_list_matches = || match scoped_mcp_capability.as_ref() {
                Some(capability) => {
                    connector_key::charter_never_list_matches_capability(block, capability)
                        || connector_key::charter_never_list_matches_scoped_channel(
                            block,
                            &capability.ordinary_channel(),
                            effect_verb,
                        )
                }
                None => connector_key::charter_never_list_matches(
                    block,
                    &governing_connector,
                    effect_verb,
                ),
            };
            if connector_key::charter_block_drifted(block)? {
                charter_wall = Some(
                    GateDecision::pending(vec![GateReasonCode::PendingCharterDrift])
                        .with_receipt_reasons(["charter_drift"]),
                );
            } else if never_list_matches() {
                charter_wall = Some(
                    GateDecision::deny(GateReasonCode::DenyCharterNeverList)
                        .with_receipt_reasons(["charter_never_list"]),
                );
            }
        }

        if key.status != ConnectorKeyStatus::Active {
            let status_reason = match key.status {
                ConnectorKeyStatus::Suspended => "connector_key_suspended",
                ConnectorKeyStatus::Revoked => "connector_key_revoked",
                ConnectorKeyStatus::Pending => "connector_key_pending",
                ConnectorKeyStatus::Active => unreachable!("guarded above"),
            };
            decision = GateDecision::deny(GateReasonCode::DenyConnectorKeySuspended)
                .with_receipt_reasons([status_reason])
                .with_receipt_reasons(external_effect_receipt_reasons(
                    input
                        .external_effect
                        .as_ref()
                        .expect("external effect input"),
                ));
        } else if let Some(wall) = charter_wall {
            // Charter drift / never-list are governance walls, not
            // accounting: they convert the decision whether or not the
            // pipeline will execute this dispatch.
            decision = wall.with_receipt_reasons(external_effect_receipt_reasons(
                input
                    .external_effect
                    .as_ref()
                    .expect("external effect input"),
            ));
        }
    }

    Ok(ExternalEffectGovernance {
        decision_id,
        decision,
        created_at,
        input,
        binding,
        grant_ref,
        approve_once,
        matched_grant,
        budget_target,
        scoped_capability: scoped_mcp_capability,
    })
}

pub(crate) fn record_external_effect_policy(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    governance: ExternalEffectGovernance,
) -> Result<(GateDecisionId, GateDecision)> {
    let ExternalEffectGovernance {
        decision_id,
        decision,
        created_at,
        input,
        binding,
        grant_ref,
        approve_once,
        matched_grant,
        budget_target: _,
        scoped_capability: _,
    } = governance;
    if decision.outcome() == GateOutcome::Allow
        && let Some(authorization) = approve_once.as_ref()
    {
        crate::consent::spend_approve_once_in_txn(store, wtxn, authorization)?;
    }
    let candidate = GateDecisionRecord {
        version: 0,
        decision_id,
        created_at,
        outcome: decision.outcome().as_str().to_owned(),
        reason_codes: decision
            .reason_codes()
            .iter()
            .map(|code| code.as_str().to_owned())
            .collect(),
        receipt_reasons: decision
            .receipt_reasons()
            .iter()
            .map(|reason| (*reason).to_owned())
            .collect(),
        system_notices: Vec::new(),
        actor_class: input.actor.actor_class.clone(),
        actor_ref: input.actor.actor_ref.clone(),
        content_kind: input.content_kind.as_str().to_owned(),
        policy_manifest_version: input.policy_manifest_version,
        claim_id: None,
        grant_ref,
        diff_handle: binding.diff_handle,
        read_frontier_hash: binding.read_frontier_hash,
        redacted_at: None,
    };
    if decision.outcome() == GateOutcome::Pending {
        // Read the caller's txn so retries also see its uncommitted appends.
        // Stop at the first match; the cursor is dropped before any write.
        let existing_id = store.find_gate_decision_id_in_txn(&*wtxn, |record| {
            gate_decision_matches_pending_candidate(record, &candidate)
        })?;
        if let Some(existing_id) = existing_id {
            record_gate_decision_metrics(&decision);
            return Ok((existing_id, decision));
        }
    }
    crate::off_record::FloorWrites::new(store).append_egress_gate_decision(wtxn, &candidate)?;
    if decision.outcome() == GateOutcome::Allow
        && let Some((grant_id, grant)) = matched_grant
    {
        touch_standing_outbound_grant_in_txn(store, wtxn, &grant_id, grant, created_at)?;
    }
    record_gate_decision_metrics(&decision);

    Ok((decision_id, decision))
}

/// Governance surface for external-effect callers that finalize the decision in
/// their own transaction. When `admit_for_execution` is set the caller applies
/// the effect immediately in this same txn (e.g. an identity lifecycle intent),
/// so the governing connector key is debited exactly once here and an exhausted
/// key flips the recorded decision to a budget-exhausted denial before the
/// effect is applied — one durable accounting event per genuinely-new effect
/// (design.out §2/§3). Governance-only callers pass `false` and never debit.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn check_external_effect_policy(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
    admit_for_execution: bool,
) -> Result<(GateDecisionId, GateDecision, Option<EffectorBudgetCharge>)> {
    let mut governance = evaluate_external_effect_policy(store, wtxn, effect, policy, None)?;
    let mut effector_charge = None;
    if admit_for_execution && governance.outcome() == GateOutcome::Allow {
        let (charge, exhausted) = charge_admitted_external_effect(
            store,
            wtxn,
            &mut governance,
            effect.send_ref.is_some(),
        )?;
        if exhausted {
            governance.deny_budget_exhausted();
        }
        effector_charge = charge;
    }
    let (decision_id, decision) = record_external_effect_policy(store, wtxn, governance)?;
    Ok((decision_id, decision, effector_charge))
}

/// Debits the governance-selected connector key exactly once for an admitted
/// effect, mirroring the chokepoint `charge_once`: send-dimension rows debit
/// only for send-like effects, an exhausted suspend-class row suspends the key,
/// and the caller converts exhaustion into a denial.
fn charge_admitted_external_effect(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    governance: &mut ExternalEffectGovernance,
    send_like: bool,
) -> Result<(Option<EffectorBudgetCharge>, bool)> {
    let Some(target) = governance.budget_target_mut() else {
        return Ok((None, false));
    };
    // Budget windows advance on the engine's trusted clock, not a caller
    // timestamp, so the debit and any receipt echo share the same window.
    let budget_now = crate::unix_seconds_now();
    let outcome = connector_key::charge_effector_budgets(
        store,
        wtxn,
        &target.key_id,
        &mut target.key,
        &target.governing_connector,
        send_like,
        budget_now,
    )?;
    let (mut charge, exhausted) = match outcome {
        EffectorBudgetChargeOutcome::NoRows(charge)
        | EffectorBudgetChargeOutcome::Charged(charge) => (charge, false),
        EffectorBudgetChargeOutcome::Exhausted {
            row_index,
            on_exhaust,
            mut charge,
        } => {
            if on_exhaust == EffectorBudgetOnExhaust::Suspend {
                connector_key::suspend_connector_key_in_txn(
                    store,
                    wtxn,
                    &target.key_id,
                    &target.key,
                    connector_key::budget_exhausted_reason(row_index),
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
