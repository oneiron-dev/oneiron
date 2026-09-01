use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::connector_key::{
    self, ConnectorKeyStatus, EffectorBudgetCharge, EffectorBudgetChargeOutcome,
    EffectorBudgetOnExhaust,
};
use crate::counterparty_contact::{
    CounterpartyContactRecord, CounterpartyFirstTouch, counterparty_contact_index_key,
    counterparty_contact_matches_channel_class, counterparty_contacts_by_party_channel,
    counterparty_contacts_by_party_full_scan, decode_counterparty_contact_index_value,
    normalize_channel_class, read_counterparty_contact_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::outbound_consent::{ScopedMcpConsentDecision, evaluate_scoped_mcp_call};
use crate::outbound_grant::{
    StandingOutboundGrant, decode_standing_outbound_grant_body,
    encode_standing_outbound_grant_body, standing_outbound_grant_principal_index_entity_id,
    standing_outbound_grant_principal_index_prefix,
};
use crate::registry::ENTITY_TYPE_OUTBOUND_GRANT;
use crate::store::{GateDecisionId, GateDecisionRecord, Store};

use super::decision::{
    GateDecision, GateOutcome, GateReasonCode, external_effect_receipt_reasons,
    record_gate_decision_metrics,
};
use super::definition_ceiling::agent_definition_ceiling_for_effect_actor;
use super::doors::GateConsentBinding;
use super::grants::external_effect_grant_matches;
use super::input::{
    ConsentGateContext, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateEvaluatorInput,
};
use super::resolution::PolicyManifestResolution;

/// Receipt reason for a deny whose only restrictive source is a CA-01
/// `comm.do_not_contact` head. Inside `store.rs`'s closed `counterparty_*`
/// receipt-reason family.
const COUNTERPARTY_OPT_OUT_DO_NOT_CONTACT_RECEIPT_REASON: &str =
    "counterparty_opt_out_do_not_contact";

/// Composes the DEC-0006 consent context for one external effect.
///
/// This is how the ONE production external-effect door
/// ([`evaluate_external_effect_policy`]) opts onto the unified consent path:
/// it maps the engine-observed effect facts into a [`crate::consent::ComposedEffect`]
/// and runs the ONE evaluator, so no caller re-implements the ladder or
/// smuggles a caller-chosen `reversible` verdict in (invariant 6 — every fact
/// here is host-observed: an outbound send is irreversible-in-effect by
/// construction, with external observers on the channel).
///
/// Returns `None` when the effect facts cannot be normalized into an honest
/// requirement pair (a verb or channel that fails the bound-ref rules) — the
/// door then keeps its pre-DEC-0006 criticality behaviour rather than
/// fabricate a bound no grant could ever cover or could always cover.
pub(super) fn external_effect_composed_effect(
    effect: &ExternalEffectGateInput,
) -> Option<crate::consent::ComposedEffect> {
    let facts = external_effect_facts(effect);
    let requirement = external_effect_action_requirement(effect)?;
    crate::consent::ComposedEffect::new(facts)
        .with_action_requirement(requirement)
        .ok()
}

pub(super) fn external_effect_consent_context(
    effect: &ExternalEffectGateInput,
    approve_once: Option<&crate::consent::ApproveOnceAuthorization>,
    grants: &[crate::consent::StandingConsentGrant],
) -> Option<ConsentGateContext> {
    let composed = external_effect_composed_effect(effect)?;
    Some(ConsentGateContext::evaluate(
        &composed,
        approve_once,
        grants,
    ))
}

/// The host-observed fact set for one external effect, in the consent
/// evaluator's vocabulary. An external send/deploy is irreversible-in-effect
/// and externally observable by definition; nothing here is caller-asserted.
fn external_effect_facts(effect: &ExternalEffectGateInput) -> crate::consent::EffectFacts {
    let operation_kind = if effect.verb.trim().is_empty() {
        format!("external:{}", effect.channel.trim())
    } else {
        format!("external:{}:{}", effect.channel.trim(), effect.verb.trim())
    };
    crate::consent::EffectFacts {
        operation_kind,
        // An outbound effect rides the transport's send hook chain.
        fires_hooks: true,
        // A dispatch leaves this vault: it is published to (observed by) the
        // channel's counterparties, so undo cannot retract it.
        triggers_publish: true,
        external_observers: true,
        undo_fidelity: crate::consent::UndoFidelity::None,
        blast_radius: 1,
        catastrophe: None,
    }
}

/// The action requirement one external effect must be covered by: acting actor
/// × its verb class × an envelope naming the verb selector.
///
/// The selector vocabulary mirrors the canonical
/// [`crate::consent::action_grant_from_standing_outbound_grant`] adapter
/// (`verb:<class>` / `channel:<channel>` / `contact:<ref>` / `brief:<ref>`),
/// so a legacy grant scope-matched onto this effect reads as consent-COVERING
/// it — the fold that closes the write-side residual without minting a second
/// rememberable lane. An effect whose verb class is not named by a grant's
/// dial is envelope-uncovered on the same axis, so it still asks (the DEC-0006
/// bound-exceeded path). The actor is NOT class-narrowed and the envelope is
/// NOT target-pinned: the adapter mints grants on `principal_ref` alone, and
/// the door's scope matcher already verified the channel/contact/brief axes on
/// this txn before this fold runs.
pub(super) fn external_effect_action_requirement(
    effect: &ExternalEffectGateInput,
) -> Option<crate::consent::GrantBound> {
    let actor_ref = effect
        .actor
        .actor_ref
        .clone()
        .or_else(|| effect.provenance.actor_entity_ref.map(|id| id.to_hex()))?;
    let verb_class = if effect.verb.trim().is_empty() {
        effect.channel.trim()
    } else {
        effect.verb.trim()
    };
    // The envelope's selectors name the verb axis exactly as the legacy
    // adapter mints it (`verb:<class>`), so a scope-matched grant's fold reads
    // as containing the effect. The channel axis rides the TARGET pin instead
    // of the selector set — the selectors must stay verb-shaped or a
    // verb-class grant (selector `[verb:send]`) would fail subset-containment
    // against a candidate that also names its channel. Target-pinning to the
    // channel mirrors the `Channel` dial's target arm, so `Channel{email}`
    // contains an email-send while a `BriefVerbClass{brief}` grant covers only
    // its own brief; a verb-class grant with NO target pin covers both.
    let mut envelope = crate::consent::ActionEnvelope::new([format!("verb:{verb_class}")]).ok()?;
    let target = effect
        .brief_ref
        .as_deref()
        .unwrap_or_else(|| effect.channel.trim());
    if !target.is_empty() {
        envelope = envelope.with_target(target).ok()?;
    }
    crate::consent::GrantBound::action(
        crate::consent::ActorBound::new(actor_ref).ok()?,
        crate::consent::ActionClass::new(verb_class).ok()?,
        envelope,
    )
    .ok()
}

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
}

impl ExternalEffectGovernance {
    #[must_use]
    pub(crate) fn outcome(&self) -> GateOutcome {
        self.decision.outcome()
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
    let mut hydrated_effect = hydrate_external_effect_contact(store, &*wtxn, effect)?;
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
    let scoped_mcp_governing_connector = matched_grant.as_ref().and_then(|(grant_id, grant)| {
        grant.scope.scoped_mcp_grant().and_then(|_| {
            hydrated_effect
                .scoped_mcp_call
                .as_ref()
                .map(|call| scoped_mcp_credential_connector_key(&call.server, grant_id))
        })
    });
    let uses_scoped_mcp_governing_connector = scoped_mcp_governing_connector.is_some();
    // The Option stays alive past this binding: it is the only VERIFIED
    // per-grant capability identity in this scope, and the charter never-list
    // stage below consults it. Consuming it here is what left that stage with a
    // full channel string it could not name (ONE-1885).
    let governing_connector = scoped_mcp_governing_connector
        .clone()
        .unwrap_or_else(|| normalized_channel.clone());
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
        && governing.is_none()
    {
        // The real completion—registering each per-grant connector key through
        // the connector lifecycle—rides ONE-1794 with the live transport.
        // Until then, scoped MCP authority fails closed instead of inheriting
        // the channel unset-is-noop behavior.
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
            if connector_key::charter_block_drifted(block)? {
                charter_wall = Some(
                    GateDecision::pending(vec![GateReasonCode::PendingCharterDrift])
                        .with_receipt_reasons(["charter_drift"]),
                );
            } else if connector_key::charter_never_list_matches_capability(
                block,
                &governing_connector,
                hydrated_effect
                    .scoped_mcp_call
                    .as_ref()
                    .map_or(hydrated_effect.verb.as_str(), |call| call.tool.as_str()),
                scoped_mcp_governing_connector.as_deref(),
            ) {
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
    } = governance;
    if decision.outcome() == GateOutcome::Allow
        && let Some(authorization) = approve_once.as_ref()
    {
        crate::consent::spend_approve_once_in_txn(store, wtxn, authorization)?;
    }
    crate::off_record::FloorWrites::new(store).append_egress_gate_decision(
        wtxn,
        &GateDecisionRecord {
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
        },
    )?;
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

fn standing_outbound_grant_for_effect(
    store: &Store,
    txn: &heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
    required_grant_id: Option<EntityId>,
) -> Result<Option<(EntityId, StandingOutboundGrant)>> {
    let current_policy_floor = policy.read_frontier_hash()?;
    let mut candidate_ids = if let Some(required_grant_id) = required_grant_id {
        vec![required_grant_id]
    } else {
        Vec::new()
    };
    if candidate_ids.is_empty() {
        let candidate_principals = if effect.scoped_mcp_call.is_some() {
            verified_standing_outbound_grant_principal(effect)
                .into_iter()
                .collect()
        } else {
            standing_outbound_grant_candidate_principals(effect)
        };
        for principal_ref in candidate_principals {
            let prefix = standing_outbound_grant_principal_index_prefix(&principal_ref)?;
            for entry in store.vault_meta.prefix_iter(txn, &prefix)? {
                let (key, _) = entry?;
                let id = standing_outbound_grant_principal_index_entity_id(&key, &principal_ref)?;
                if !candidate_ids.contains(&id) {
                    candidate_ids.push(id);
                }
            }
        }
    }
    for id in candidate_ids {
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            if required_grant_id == Some(id) {
                return Ok(None);
            }
            return Err(Error::CorruptedIndex("outbound grant entity row"));
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Err(Error::CorruptedIndex("outbound grant entity header"));
        };
        if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
            if required_grant_id == Some(id) {
                return Ok(None);
            }
            return Err(Error::CorruptedIndex("outbound grant entity type"));
        }
        let grant = decode_standing_outbound_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if !grant.is_active_under_policy(&current_policy_floor) {
            continue;
        }
        if !standing_outbound_grant_actor_matches(&grant, effect) {
            continue;
        }
        if let Some(call) = effect.scoped_mcp_call.as_ref() {
            if !is_mcp_effect_channel(&effect.channel) {
                continue;
            }
            if let Some(scoped_grant) = grant.scope.scoped_mcp_grant()
                && evaluate_scoped_mcp_call(scoped_grant, call.as_call())
                    == ScopedMcpConsentDecision::AutoFire
            {
                return Ok(Some((id, grant)));
            }
            continue;
        }
        if grant.scope.matches_effect(
            &effect.verb,
            &effect.channel,
            effect.counterparty.as_deref(),
            effect.brief_ref.as_deref(),
        ) {
            return Ok(Some((id, grant)));
        }
    }
    Ok(None)
}

pub(super) fn is_mcp_effect_channel(channel: &str) -> bool {
    channel
        .trim()
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("mcp:"))
}

pub(crate) fn scoped_mcp_credential_connector_key(server: &str, grant_id: &EntityId) -> String {
    connector_key::normalize_connector_key(&format!("mcp:{server}:grant:{}", grant_id.to_hex()))
}

/// Classifies a STORED connector as the synthetic per-grant capability key
/// shape [`scoped_mcp_credential_connector_key`] mints.
///
/// The gate never needs this: it holds the `Some` its verified matched live
/// scoped-MCP grant produced, so no caller-asserted string can become authority
/// there. Recovery re-enters after the grant match, holding only the connector
/// bytes the ledger's charged key stores, and this is the one discriminator that
/// gives those bytes the SAME capability identity the gate used — without which
/// a gate deny could still replay as an allow. It lives beside the producer so
/// the shape law has exactly one home; every other connector (including an
/// ordinary colon-bearing `mcp:calendar` channel key) stays a full channel with
/// no capability identity.
pub(crate) fn is_scoped_capability_connector_key(connector: &str) -> bool {
    if connector != connector_key::normalize_connector_key(connector) {
        return false;
    }
    let mut parts = connector.split(':');
    let (Some("mcp"), Some(server), Some("grant"), Some(grant_hex), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return false;
    };
    if server.is_empty() || server == "*" || server.contains('*') || server.as_bytes().contains(&0) {
        return false;
    }
    EntityId::from_hex(grant_hex)
        .ok()
        .is_some_and(|grant_id| grant_id.to_hex() == grant_hex)
}

fn standing_outbound_grant_candidate_principals(effect: &ExternalEffectGateInput) -> Vec<String> {
    let mut principals = Vec::with_capacity(2);
    if let Some(actor_ref) = effect.actor.actor_ref.as_deref()
        && !actor_ref.trim().is_empty()
    {
        principals.push(actor_ref.trim().to_owned());
    }
    if let Some(actor_entity_ref) = effect.provenance.actor_entity_ref {
        let actor_entity_ref = actor_entity_ref.to_hex();
        if !principals
            .iter()
            .any(|principal| principal == &actor_entity_ref)
        {
            principals.push(actor_entity_ref);
        }
    }
    principals
}

fn verified_standing_outbound_grant_principal(effect: &ExternalEffectGateInput) -> Option<String> {
    let actor_ref = effect
        .actor
        .actor_ref
        .as_deref()
        .map(str::trim)
        .filter(|actor_ref| !actor_ref.is_empty());
    match (actor_ref, effect.provenance.actor_entity_ref) {
        (Some(actor_ref), Some(actor_entity_ref)) => EntityId::from_hex(actor_ref)
            .ok()
            .filter(|actor_ref| *actor_ref == actor_entity_ref)
            .map(|_| actor_entity_ref.to_hex()),
        (Some(actor_ref), None) => Some(actor_ref.to_owned()),
        (None, Some(actor_entity_ref)) => Some(actor_entity_ref.to_hex()),
        (None, None) => None,
    }
}

fn standing_outbound_grant_actor_matches(
    grant: &StandingOutboundGrant,
    effect: &ExternalEffectGateInput,
) -> bool {
    effect
        .actor
        .actor_ref
        .as_deref()
        .is_some_and(|actor_ref| actor_ref == grant.principal_ref)
        || effect
            .provenance
            .actor_entity_ref
            .is_some_and(|actor_entity_ref| actor_entity_ref.to_hex() == grant.principal_ref)
}

fn touch_standing_outbound_grant_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    grant: StandingOutboundGrant,
    used_at: u64,
) -> Result<()> {
    let Some(raw) = store.entities.get(wtxn, id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("outbound grant entity header"));
    };
    if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
        return Err(Error::CorruptedIndex("outbound grant entity type"));
    }
    let touched = grant.touched(used_at)?;
    let body = encode_standing_outbound_grant_body(&touched)?;
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
    payload.push(ENTITY_TYPE_OUTBOUND_GRANT);
    payload.extend_from_slice(&header.occurred_start.to_be_bytes());
    payload.extend_from_slice(&header.occurred_end.to_be_bytes());
    payload.extend_from_slice(&header.learned_at.to_be_bytes());
    payload.extend_from_slice(&body);
    store.entities.put(wtxn, id.as_bytes(), &payload)?;
    Ok(())
}

/// Hydrates the counterparty consent facts the external-effect door decides on.
///
/// ONE-1868: `counterparty` is the ONLY required input. The lookup key is
/// `(party_ref, channel_class)` per ARCH-0057 §3, and `channel_identity_ref` is
/// ENRICHMENT that may add candidates — its absence can never return early,
/// because every shipping constructor leaves it `None` and the legal-class hard
/// deny below it was therefore unreachable.
///
/// Every restrictive source is OR-folded: COUNTERPARTY_CONTACT records AND CA-01's
/// `comm.do_not_contact` heads. No leg may clear suppression another leg
/// established.
fn hydrate_external_effect_contact(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
) -> Result<ExternalEffectGateInput> {
    let mut hydrated = effect.clone();
    let Some(party_ref) = effect.counterparty.as_deref() else {
        return Ok(hydrated);
    };

    let channel_class = normalize_channel_class(&effect.channel);
    for record in counterparty_contacts_for_send(
        store,
        txn,
        party_ref,
        &channel_class,
        effect.channel_identity_ref.as_ref(),
    )? {
        hydrated.counterparty_first_touch = hydrated
            .counterparty_first_touch
            .or(Some(record.first_touch));
        if record.first_touch == CounterpartyFirstTouch::Public
            && hydrated.policy_risk == ExternalEffectPolicyRisk::Normal
        {
            hydrated.policy_risk = ExternalEffectPolicyRisk::HoldToProposal;
        }
        hydrated.counterparty_opted_out |= record.is_opted_out();
        if record.is_opted_out() && hydrated.counterparty_opt_out_receipt_reason.is_none() {
            hydrated.counterparty_opt_out_receipt_reason = record
                .opt_out
                .map(crate::counterparty_contact::CounterpartyOptOut::receipt_reason);
        }
    }

    fold_matching_comm_do_not_contact_heads(store, txn, party_ref, &channel_class, &mut hydrated)?;
    Ok(hydrated)
}

/// Every contact record that participates in this send's restrictive aggregate.
///
/// Three CANDIDATE sources, de-duplicated by contact ref and ordered by it so
/// the folded first-touch and receipt reason are deterministic:
///
/// 1. the identity-independent `(party_ref, channel_class)` index;
/// 2. the legacy identity+counterparty index, when an identity is known — it may
///    only ADD candidates;
/// 3. an unbounded COUNTERPARTY_CONTACT scan, which is MANDATORY: the party-channel index
///    cannot prove its own completeness at HEAD, and a bounded fallback that
///    missed one opted-out row would answer a false "no".
///
/// Channel scope is then applied ONCE, here, to the merged set. Sources find
/// rows for the party; this predicate decides which are in scope for the class.
/// Keeping it at the single fold point is what makes `channel_identity_ref`
/// enrichment rather than a verdict input: source 2 is keyed by identity alone,
/// so a stale or explicitly-pinned cross-class identity would otherwise drag a
/// foreign-channel opt-out into the aggregate and let enrichment move the
/// verdict. A per-source predicate is one forgotten call from that bug; this is
/// zero.
fn counterparty_contacts_for_send(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party_ref: &str,
    channel_class: &str,
    channel_identity_ref: Option<&EntityId>,
) -> Result<Vec<CounterpartyContactRecord>> {
    let mut candidates =
        counterparty_contacts_by_party_channel(store, txn, party_ref, channel_class)?;
    if let Some(identity_ref) = channel_identity_ref
        && let Some(hit) =
            counterparty_contact_by_identity_index(store, txn, identity_ref, party_ref)?
    {
        candidates.push(hit);
    }
    candidates.extend(counterparty_contacts_by_party_full_scan(
        store, txn, party_ref,
    )?);

    candidates.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
    candidates.dedup_by(|(left, _), (right, _)| left == right);

    let mut records = Vec::with_capacity(candidates.len());
    for (_, record) in candidates {
        if counterparty_contact_matches_channel_class(store, txn, &record, channel_class)? {
            records.push(record);
        }
    }
    Ok(records)
}

/// Legacy identity+counterparty index hit, when a channel identity is known.
fn counterparty_contact_by_identity_index(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: &EntityId,
    counterparty: &str,
) -> Result<Option<(EntityId, CounterpartyContactRecord)>> {
    let key = counterparty_contact_index_key(identity_ref, counterparty)?;
    let Some(raw_id) = store.vault_meta.get(txn, &key)? else {
        return Ok(None);
    };
    let id = decode_counterparty_contact_index_value(&raw_id)?;
    let Some(record) = read_counterparty_contact_in_txn(store, txn, &id)? else {
        return Err(Error::CorruptedIndex(
            "counterparty contact lookup index entity row",
        ));
    };
    if !record.matches_counterparty(identity_ref, counterparty) {
        return Err(Error::CorruptedIndex(
            "counterparty contact lookup index assignment",
        ));
    }
    Ok(Some((id, record)))
}

/// OR-folds CA-01's `comm.do_not_contact` heads into the hydrated effect.
///
/// The predicate, the value codec, and the restrictive-wins semantics
/// (`Proposed` is effective; staleness never clears; only an authorized clear
/// stamp removes a head) are CA-01's — imported, never redefined here. The fold
/// is monotonic: it can only ADD suppression.
fn fold_matching_comm_do_not_contact_heads(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party_ref: &str,
    channel_class: &str,
    hydrated: &mut ExternalEffectGateInput,
) -> Result<()> {
    if !crate::campaign::claims::counterparty_do_not_contact_in_txn(
        store,
        txn,
        party_ref,
        Some(channel_class),
        &hydrated.verb,
    )? {
        return Ok(());
    }
    hydrated.counterparty_opted_out = true;
    // A COUNTERPARTY_CONTACT reason already folded above wins; otherwise the deny would
    // reach the receipt with no reason at all.
    if hydrated.counterparty_opt_out_receipt_reason.is_none() {
        hydrated.counterparty_opt_out_receipt_reason =
            Some(COUNTERPARTY_OPT_OUT_DO_NOT_CONTACT_RECEIPT_REASON);
    }
    Ok(())
}
