//! Scoped-call execution, post-effect decision, and result transport.

use std::fmt;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound_chokepoint::OutboundEffectResult;
use crate::outbound_grant::StandingOutboundGrant;
use crate::outbound_intent_ledger::{
    BudgetClass, FrozenOutboundCall, IntentDispatchResult, IntentEscalationReason,
    IntentLedgerError, IntentResolution, IntentState, OutboundSendOutcome, UnconfirmedDelivery,
};

use super::authority::{OutboundBindingAuthority, observed_freeze_events_since};
use super::connector_call::escalation_code;
use super::result_scrub::{OutboundResultSender, scrub_outbound_result};
use super::scope::{
    ScopedMcpCall, ScopedMcpCallContext, ScopedMcpConsentDecision, ScopedMcpEscalationReason,
    evaluate_scoped_mcp_call,
};
use super::tool_call::PreparedToolCall;

/// Counted output of one consent-bound durable dispatch.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopedMcpDispatchResult {
    pub decision: ScopedMcpConsentDecision,
    pub dispatch: Option<IntentDispatchResult>,
    pub freeze_events: usize,
    pub effectful_sends: usize,
    pub authorization_rejections: usize,
    pub scrubbable_result_fields: usize,
    pub scrubbed_result_fields: usize,
    checked_bytes: Vec<u8>,
    gate_decision_ref: Option<String>,
    gate_outcome: Option<String>,
    gate_reasons: Vec<String>,
    /// FIX 6424 part 3: the prepared request a Gate hold of this call named
    /// its approve-once digest for.
    held_ask: Option<super::approval::HeldConnectorAsk>,
    /// FIX 7351: the owner stopped the intent while its delivery stayed
    /// unresolved (it may have crossed the wire before the Stop).
    stop_unresolved: bool,
}

impl ScopedMcpDispatchResult {
    /// FIX 6424 part 3: the approve-once digest (64 lower-hex) the Gate
    /// decision that held this call names, copied from it: the owner's press
    /// on it releases exactly this prepared call. `None` for any other
    /// result.
    #[must_use]
    pub fn approval_digest(&self) -> Option<&str> {
        self.held_ask
            .as_ref()
            .map(|ask| ask.approval_digest.as_str())
    }

    /// The prepared request a Gate hold of this call asked about.
    pub(super) fn held_ask(&self) -> Option<&super::approval::HeldConnectorAsk> {
        self.held_ask.as_ref()
    }

    /// Whether the owner stopped the intent with its delivery unresolved: a
    /// send that may have gone out, never a definite non-delivery (FIX 7351).
    pub(super) fn owner_stopped_unresolved(&self) -> bool {
        self.stop_unresolved
    }

    /// The gate decision this dispatch recorded (`gate:<hex>`), when the
    /// gate ran on this call; a ledger replay records none.
    #[must_use]
    pub fn gate_decision_ref(&self) -> Option<&str> {
        self.gate_decision_ref.as_deref()
    }

    /// The gate's outcome (`allow`, `pending` or `deny`), or the hold a
    /// replay of an admitted row met (`pending`). `None` when neither ran.
    #[must_use]
    pub fn gate_outcome(&self) -> Option<&str> {
        self.gate_outcome.as_deref()
    }

    /// The gate's receipt reasons, then its reason codes, as recorded.
    #[must_use]
    pub fn gate_reasons(&self) -> &[String] {
        &self.gate_reasons
    }
}

impl fmt::Debug for ScopedMcpDispatchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedMcpDispatchResult")
            .field("decision", &self.decision)
            .field("dispatch", &self.dispatch)
            .field("freeze_events", &self.freeze_events)
            .field("effectful_sends", &self.effectful_sends)
            .field("authorization_rejections", &self.authorization_rejections)
            .field("scrubbable_result_fields", &self.scrubbable_result_fields)
            .field("scrubbed_result_fields", &self.scrubbed_result_fields)
            .field(
                "checked_bytes",
                &format_args!("[{} bytes redacted]", self.checked_bytes.len()),
            )
            .field("gate_decision_ref", &self.gate_decision_ref)
            .field("gate_outcome", &self.gate_outcome)
            .field("gate_reasons", &self.gate_reasons)
            .field("held_ask", &self.held_ask)
            .field("stop_unresolved", &self.stop_unresolved)
            .finish()
    }
}

/// Runs one scoped call through the intent ledger and authenticated result
/// sender. Scope-exceeds return without constructing a ledger request.
#[expect(clippy::too_many_arguments)]
pub(super) fn execute_scoped_mcp_outbound_call<S: OutboundResultSender>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    grant_id: EntityId,
    grant: &StandingOutboundGrant,
    principal_ref: &str,
    attempt_id: AttemptId,
    call_seq: u64,
    prepared_call: PreparedToolCall,
    now_ms: u64,
    sender: &mut S,
) -> std::result::Result<ScopedMcpDispatchResult, IntentLedgerError> {
    #[cfg(test)]
    let freeze_event_baseline = prepared_call.freeze_event_baseline();
    #[cfg(not(test))]
    let freeze_event_baseline = ();
    let _ = grant;
    let call = prepared_call.call().clone();
    // FIX 6424 part 3: the gate input pins this prepared call.
    let gate = super::approval::scoped_mcp_pinned_gate_input(
        principal_ref,
        grant_id,
        &prepared_call,
        attempt_id,
        call_seq,
    );
    let idempotency_supported = prepared_call.idempotency_supported();
    // The Send class follows the catalog entry (ONE-1794): only a
    // counterparty-communication connector's calls debit `Sends` rows.
    let budget_class = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        if crate::connector_key::scoped_server_debits_sends_in_txn(
            &vault.store,
            &txn,
            &call.server,
        )? {
            BudgetClass::Send
        } else {
            BudgetClass::Operation
        }
    };
    let prepared = crate::outbound_chokepoint::PreparedEffect {
        attempt_id,
        call_seq,
        server: call.server,
        tool: call.tool,
        payload: prepared_call.frozen_bytes().to_vec(),
        idempotency_supported,
        resolved_endpoint: Some(call.resolved_endpoint),
        gate,
        budget_class,
        authorization: crate::outbound_chokepoint::PreparedAuthorization::ScopedMcp {
            grant_id,
            principal_ref: principal_ref.to_owned(),
            prepared: Box::new(prepared_call.clone()),
        },
        verified_actor: None,
        owner_proof: None,
        dedupe_key: None,
        suppression_receipt: None,
        admission_ceiling: None,
        co_actor: None,
    };
    let mut transport = ScopedResultTransport::new(sender);
    let effect = crate::outbound_chokepoint::execute_outbound_effect(
        vault,
        authority,
        crate::outbound_chokepoint::OutboundEffectCommand::New(prepared),
        now_ms,
        &mut transport,
    )?;
    let decision =
        scoped_decision_after_effect(vault, grant_id, principal_ref, &prepared_call, &effect)?;
    let freeze_events = observed_freeze_events_since(freeze_event_baseline);
    let held_ask =
        super::approval::HeldConnectorAsk::of(effect.approval_digest.clone(), &prepared_call);
    let mut result = dispatch_result(effect, decision, transport, freeze_events);
    result.held_ask = held_ask;
    Ok(result)
}

/// The Gate input of one scoped call by `principal_ref` under `grant_id`:
/// the one place it is built, so a code consent wait's approval digest
/// (DOOR-079 1a) composes over the very input its effect's gate reads. FIX
/// 6424 part 3 pins the call's target beside it
/// (`approval::scoped_mcp_pinned_gate_input`), which the code-wait composer
/// never reads.
pub(super) fn scoped_mcp_gate_input(
    principal_ref: &str,
    grant_id: EntityId,
    call: &ScopedMcpCallContext,
) -> crate::gate::ExternalEffectGateInput {
    let actor_entity_ref = Some(EntityId::from_hex(principal_ref).unwrap_or(grant_id));
    crate::gate::ExternalEffectGateInput {
        actor: crate::gate::GateActor {
            actor_class: "first_party".to_owned(),
            actor_ref: Some(principal_ref.to_owned()),
            delegation_grant_ref: None,
        },
        provenance: crate::gate::GateProvenanceHandles {
            actor_entity_ref,
            ..crate::gate::GateProvenanceHandles::default()
        },
        verb: "send".to_owned(),
        channel: format!("mcp:{}", call.server),
        channel_identity_ref: None,
        counterparty: None,
        brief_ref: None,
        send_ref: None,
        standing_grant_ref: None,
        scoped_mcp_call: Some(call.clone()),
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: false,
        has_permission: false,
        policy_risk: crate::gate::ExternalEffectPolicyRisk::Normal,
        send_autonomy: None,
    }
}

/// Resumes one admitted scoped intent from its frozen ledger row, by id: the
/// ledger's own bytes, grant binding and endpoint, never a fresh
/// preparation. The frozen binding, key, manifest and charter checks still
/// run before transport and refuse or hold a call whose authority changed.
pub(super) fn resume_scoped_mcp_outbound_intent<S: OutboundResultSender>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    intent_id: [u8; 32],
    now_ms: u64,
    sender: &mut S,
) -> std::result::Result<ScopedMcpDispatchResult, IntentLedgerError> {
    let mut transport = ScopedResultTransport::new(sender);
    let effect = crate::outbound_chokepoint::execute_outbound_effect(
        vault,
        authority,
        crate::outbound_chokepoint::OutboundEffectCommand::Resume(intent_id),
        now_ms,
        &mut transport,
    )?;
    let decision = resumed_decision(&effect);
    Ok(dispatch_result(effect, decision, transport, 0))
}

/// Packs one effect and its transport's counters into the dispatch result.
fn dispatch_result<S>(
    effect: OutboundEffectResult,
    decision: ScopedMcpConsentDecision,
    transport: ScopedResultTransport<'_, S>,
    freeze_events: usize,
) -> ScopedMcpDispatchResult {
    let authorization_rejections = usize::from(
        effect.dispatch.state == Some(IntentState::Abandoned)
            || (effect.dispatch.state == Some(IntentState::Pending)
                && effect.dispatch.send_outcome.is_none()
                && effect.dispatch.replayed),
    );
    let dispatch = (effect.dispatch.state.is_some()
        || effect.dispatch.send_outcome.is_some()
        || effect.dispatch.replayed)
        .then_some(effect.dispatch);
    let stop_unresolved = matches!(
        effect.resolution,
        Some(IntentResolution::Stopped {
            delivery: UnconfirmedDelivery::Unresolved,
            reason: IntentEscalationReason::OwnerStopped,
        })
    );
    let gate_reasons = effect
        .gate_receipt_reasons
        .into_iter()
        .chain(effect.gate_reason_codes)
        .collect();
    ScopedMcpDispatchResult {
        decision,
        dispatch,
        freeze_events,
        effectful_sends: transport.effectful_sends,
        authorization_rejections,
        scrubbable_result_fields: transport.scrubbable_result_fields,
        scrubbed_result_fields: transport.scrubbed_result_fields,
        checked_bytes: transport.checked_bytes,
        gate_decision_ref: effect.gate_decision_id,
        gate_outcome: effect.gate_outcome,
        gate_reasons,
        held_ask: None,
        stop_unresolved,
    }
}

/// A frozen resume's consent decision. It has no live preparation to judge
/// against a grant's scope, so only what the replay itself met escalates:
/// connector governance in the receipt, a revoked connector, or a binding
/// the frozen check rejected.
fn resumed_decision(effect: &OutboundEffectResult) -> ScopedMcpConsentDecision {
    if let Some(reason) = connector_gate_reason(&effect.gate_receipt_reasons) {
        return ScopedMcpConsentDecision::Escalate(reason);
    }
    match effect
        .dispatch
        .escalation
        .map(|escalation| escalation.reason)
    {
        Some(IntentEscalationReason::ConnectorRevoked) => {
            ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::ConnectorKeyRevoked)
        }
        Some(IntentEscalationReason::BindingInvalid) => {
            ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::InvalidGrant)
        }
        _ => ScopedMcpConsentDecision::AutoFire,
    }
}

/// The connector governance a gate receipt reason names, if any.
fn connector_gate_reason(reasons: &[String]) -> Option<ScopedMcpEscalationReason> {
    reasons.iter().find_map(|reason| match reason.as_str() {
        "connector_key_unregistered" => Some(ScopedMcpEscalationReason::ConnectorKeyUnregistered),
        "connector_key_pending" => Some(ScopedMcpEscalationReason::ConnectorKeyPending),
        "connector_key_suspended" => Some(ScopedMcpEscalationReason::ConnectorKeySuspended),
        "connector_key_revoked" => Some(ScopedMcpEscalationReason::ConnectorKeyRevoked),
        "charter_drift" => Some(ScopedMcpEscalationReason::ConnectorKeyCharterDrift),
        "connector_manifest_drift" => Some(ScopedMcpEscalationReason::ConnectorManifestDrift),
        "charter_never_list" => Some(ScopedMcpEscalationReason::ConnectorKeyCharterNeverList),
        "effector_budget_exhausted" => Some(ScopedMcpEscalationReason::ConnectorKeyBudgetExhausted),
        _ => None,
    })
}

fn scoped_decision_after_effect(
    vault: &Vault,
    grant_id: EntityId,
    principal_ref: &str,
    prepared: &PreparedToolCall,
    effect: &OutboundEffectResult,
) -> std::result::Result<ScopedMcpConsentDecision, IntentLedgerError> {
    let connector_reason = connector_gate_reason(&effect.gate_receipt_reasons);
    if effect
        .gate_receipt_reasons
        .iter()
        .any(|reason| reason == "connector_manifest_stale")
    {
        let Some(identity) = crate::connector_key::ScopedCapabilityProvenance::mint(
            &prepared.call().server,
            &grant_id,
        ) else {
            return Ok(ScopedMcpConsentDecision::Escalate(
                ScopedMcpEscalationReason::ConnectorKeyUnregistered,
            ));
        };
        let actor = EntityId::from_hex(principal_ref).unwrap_or(grant_id);
        let Some((_, key)) = vault.connector_key_for(identity.connector(), Some(&actor))? else {
            return Ok(ScopedMcpConsentDecision::Escalate(
                ScopedMcpEscalationReason::ConnectorKeyUnregistered,
            ));
        };
        let Some(manifest) = key.retained_manifest.as_ref() else {
            return Ok(ScopedMcpConsentDecision::Escalate(
                ScopedMcpEscalationReason::ConnectorManifestDrift,
            ));
        };
        return Ok(ScopedMcpConsentDecision::Escalate(
            ScopedMcpEscalationReason::StaleConnectorManifest {
                current_manifest_hash: manifest.hash()?,
            },
        ));
    }
    if let Some(reason) = connector_reason {
        return Ok(ScopedMcpConsentDecision::Escalate(reason));
    }
    if effect
        .dispatch
        .escalation
        .as_ref()
        .is_some_and(|escalation| {
            escalation.reason
                == crate::outbound_intent_ledger::IntentEscalationReason::ConnectorRevoked
        })
    {
        return Ok(ScopedMcpConsentDecision::Escalate(
            ScopedMcpEscalationReason::ConnectorKeyRevoked,
        ));
    }
    if effect
        .dispatch
        .escalation
        .as_ref()
        .is_some_and(|escalation| {
            escalation.reason
                == crate::outbound_intent_ledger::IntentEscalationReason::BindingInvalid
        })
    {
        return Ok(ScopedMcpConsentDecision::Escalate(
            ScopedMcpEscalationReason::InvalidGrant,
        ));
    }
    if effect
        .gate_outcome
        .as_deref()
        .is_none_or(|outcome| outcome == "allow")
    {
        return Ok(ScopedMcpConsentDecision::AutoFire);
    }
    let Some(grant) = vault.get_standing_outbound_grant(&grant_id)? else {
        return Ok(ScopedMcpConsentDecision::Escalate(
            ScopedMcpEscalationReason::InvalidGrant,
        ));
    };
    if grant.principal_ref != principal_ref {
        return Ok(ScopedMcpConsentDecision::Escalate(
            ScopedMcpEscalationReason::WrongPrincipal,
        ));
    }
    let current_policy_floor = {
        let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
        crate::gate::resolve_policy_manifest(&vault.store, &rtxn)?.read_frontier_hash()?
    };
    if !grant.is_active_under_policy(&current_policy_floor) {
        return Ok(ScopedMcpConsentDecision::Escalate(
            ScopedMcpEscalationReason::InvalidGrant,
        ));
    }
    Ok(grant.scope.scoped_mcp_grant().map_or(
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::InvalidGrant),
        |scope| prepared.decision(scope),
    ))
}

pub(super) struct ScopedResultTransport<'a, S> {
    pub(super) inner: &'a mut S,
    pub(super) effectful_sends: usize,
    pub(super) scrubbable_result_fields: usize,
    pub(super) scrubbed_result_fields: usize,
    pub(super) checked_bytes: Vec<u8>,
    /// The body the last authorized send returned, handed on to that send's
    /// own terminal bridge only (DOOR-141 PR2), never counted or logged.
    settled_body: Option<Vec<u8>>,
}

impl<'a, S> ScopedResultTransport<'a, S> {
    pub(super) fn new(inner: &'a mut S) -> Self {
        Self {
            inner,
            effectful_sends: 0,
            scrubbable_result_fields: 0,
            scrubbed_result_fields: 0,
            checked_bytes: Vec::new(),
            settled_body: None,
        }
    }
}

impl<S: OutboundResultSender> crate::outbound_chokepoint::OutboundTransport
    for ScopedResultTransport<'_, S>
{
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.checked_bytes = call.payload().to_vec();
        let transport = self.inner.send(call);
        self.effectful_sends = self.effectful_sends.saturating_add(1);
        let scrubbable = transport.raw_result.scrubbable_field_count();
        self.settled_body = transport.raw_result.body().map(<[u8]>::to_vec);
        let scrubbed = scrub_outbound_result(transport.raw_result).scrubbed_field_count();
        self.scrubbable_result_fields = self.scrubbable_result_fields.saturating_add(scrubbable);
        self.scrubbed_result_fields = self.scrubbed_result_fields.saturating_add(scrubbed);
        transport.outcome
    }

    fn settled_result(&self) -> Option<&[u8]> {
        self.settled_body.as_deref()
    }
}

/// What one live connector question binds (ONE-2510): the original call's
/// principal, its exact standing grant, the governing key the call was
/// prepared against, the catalog name it called, and the server, tool and
/// endpoint the grant admitted. An answer is checked under exactly these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorElicitationBinding {
    /// The calling actor, hex.
    pub principal_ref: String,
    pub grant_id: EntityId,
    /// The governing connector key (`FrozenToolCallView::key_ref`).
    pub key_ref: EntityId,
    /// The catalog name the call named.
    pub name: String,
    pub server: String,
    pub tool: String,
    pub endpoint: String,
}

/// How one answer to a connector's question may go out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElicitationAnswerVerdict {
    /// Send the answer as given.
    Send,
    /// Ask the owner about this exact answer first.
    AskOwner,
    /// The original grant no longer covers the answer: the owner must
    /// change the grant. The question stays live, so a retry can land.
    Escalate(String),
    /// The answer may not go: the question is cancelled instead.
    Refuse(String),
}

impl Vault {
    /// Whether an answer to a live connector question may go out, under the
    /// original call's exact grant and principal (ONE-2510). A decline or a
    /// cancel carries no content and always goes. An accept needs that very
    /// grant (never another the principal holds) still active under the
    /// policy floor, still the principal's, and still admitting the original
    /// server, tool, endpoint and data class, on an active governing key;
    /// otherwise it escalates (a revoked key refuses). Then the key's
    /// elicitation setting, read now, decides: never allow refuses, always
    /// allow sends, always ask asks the owner, and auto takes rule 1 under
    /// the original grant. `answers_digest` names the frozen answer, for the
    /// record; it is never the answer's text.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn authorize_connector_elicitation_answer(
        &self,
        binding: &ConnectorElicitationBinding,
        answers_digest: [u8; 32],
        carries_content: bool,
    ) -> crate::Result<ElicitationAnswerVerdict> {
        let verdict = if carries_content {
            self.elicitation_answer_verdict(binding)?
        } else {
            ElicitationAnswerVerdict::Send
        };
        tracing::debug!(
            grant = %binding.grant_id.to_hex(),
            key = %binding.key_ref.to_hex(),
            answers = %crate::entity_id::bytes_to_hex_lower(&answers_digest),
            ?verdict,
            "connector elicitation answer authorized"
        );
        Ok(verdict)
    }

    /// The verdict on an answer that carries content.
    fn elicitation_answer_verdict(
        &self,
        binding: &ConnectorElicitationBinding,
    ) -> crate::Result<ElicitationAnswerVerdict> {
        let escalate = |reason: &str| -> crate::Result<ElicitationAnswerVerdict> {
            Ok(ElicitationAnswerVerdict::Escalate(reason.to_owned()))
        };
        let Some(grant) = self.get_standing_outbound_grant(&binding.grant_id)? else {
            return escalate(escalation_code(ScopedMcpEscalationReason::InvalidGrant));
        };
        if grant.principal_ref != binding.principal_ref {
            return escalate(escalation_code(ScopedMcpEscalationReason::WrongPrincipal));
        }
        let floor = {
            let txn = self.store.env.read_txn()?;
            crate::gate::resolve_policy_manifest(&self.store, &txn)?.read_frontier_hash()?
        };
        if !grant.is_active_under_policy(&floor) {
            return escalate(escalation_code(ScopedMcpEscalationReason::InvalidGrant));
        }
        let Some(scope) = grant.scope.scoped_mcp_grant() else {
            return escalate(escalation_code(ScopedMcpEscalationReason::InvalidGrant));
        };
        let Some(key) = self.get_connector_key(&binding.key_ref)? else {
            return escalate(escalation_code(
                ScopedMcpEscalationReason::ConnectorKeyUnregistered,
            ));
        };
        match key.status {
            crate::connector_key::ConnectorKeyStatus::Active => {}
            crate::connector_key::ConnectorKeyStatus::Revoked => {
                return Ok(ElicitationAnswerVerdict::Refuse(
                    escalation_code(ScopedMcpEscalationReason::ConnectorKeyRevoked).to_owned(),
                ));
            }
            crate::connector_key::ConnectorKeyStatus::Suspended => {
                return escalate(escalation_code(
                    ScopedMcpEscalationReason::ConnectorKeySuspended,
                ));
            }
            crate::connector_key::ConnectorKeyStatus::Pending => {
                return escalate(escalation_code(
                    ScopedMcpEscalationReason::ConnectorKeyPending,
                ));
            }
        }
        let Some(route) = self.route_connector_call(&binding.name)? else {
            return escalate("connector_not_routable");
        };
        // An elicitation answer is no connector.call answer: it lists none.
        let (payload_data_class, _, _) =
            self.connector_tool_class(&key, &route, &binding.tool, &mut Vec::new())?;
        let call = ScopedMcpCall {
            server: &binding.server,
            tool: &binding.tool,
            payload_data_class,
            resolved_endpoint: &binding.endpoint,
        };
        if let ScopedMcpConsentDecision::Escalate(reason) = evaluate_scoped_mcp_call(scope, call) {
            return escalate(escalation_code(reason));
        }
        Ok(
            match self.connector_elicitation_setting(&binding.key_ref)? {
                crate::connector_key::SlateDisposition::NeverAllow => {
                    ElicitationAnswerVerdict::Refuse("elicitation_never_allow".to_owned())
                }
                crate::connector_key::SlateDisposition::AlwaysAsk => {
                    ElicitationAnswerVerdict::AskOwner
                }
                // Rule 1 under the original grant: a reversible answer runs, and
                // an irreversible one runs because the standing grant checked
                // above covers it. Always allow folds in as that covering grant.
                crate::connector_key::SlateDisposition::Auto
                | crate::connector_key::SlateDisposition::AlwaysAllow => {
                    ElicitationAnswerVerdict::Send
                }
            },
        )
    }
}
