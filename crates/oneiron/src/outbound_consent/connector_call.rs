//! The generic connector call (ONE-2510): one tool on one catalogued
//! connector, through the scoped-MCP prepare → execute path.
//!
//! The engine owns the authority: the route, the caller's standing grant,
//! the approved schema on the governing key, the gate and the ledger. A
//! [`ConnectorCallHost`] owns what lives beneath the catalog name: the
//! installed transport and endpoint, and the credential, which it presents
//! only inside the send. A call the gate holds for consent or governance
//! keeps its exact request in one durable row, and
//! [`Vault::resume_connector_call`] re-enters it with the same logical
//! identity. The tool's own reply comes back to the caller as foreign data;
//! the ledger's scrub still keeps its raw bytes out of durable storage.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::connector_key::{
    ConnectorCallRoute, ConnectorKeyRecord, ConnectorKeyStatus, ScopedCapabilityProvenance,
    SlateDataClass, canonical_scoped_server_segment,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::Memory;
use crate::outbound_grant::StandingOutboundGrant;
use crate::outbound_intent_ledger::{
    IntentEscalationReason, IntentLedgerError, IntentState, OutboundSendOutcome,
    OutboundToolDescriptor,
};
use crate::side_table::{self, Named, SideTable};

use super::authority::OutboundBindingAuthority;
use super::execution::ScopedMcpDispatchResult;
use super::result_scrub::OutboundResultSender;
use super::scope::{
    DataClass, ScopedMcpCallContext, ScopedMcpConsentDecision, ScopedMcpEscalationReason,
};
use super::tool_call::{MutationIntent, ToolCallDescriptor};

/// The most bytes of one connector reply a host reads and keeps. One
/// constant, so a later ruling changes one line.
pub const CONNECTOR_REPLY_MAX_BYTES: usize = 1024 * 1024;

/// The held and pending-delivery calls, by call ref.
const PENDING_CALLS: SideTable<EntityId, PendingConnectorCall, Named> =
    SideTable::new(&side_table::OUTBOUND_CONNECTOR_CALL_PENDING);

/// One guest call: a catalog name, one of its tools, and the arguments. It
/// carries no endpoint, credential, schema, grant or principal: the engine
/// and the host resolve those beneath the name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorCallRequest {
    /// The connector's catalog name.
    pub name: String,
    /// The tool, as the connector's approved manifest names it.
    pub tool: String,
    /// The tool's arguments, a JSON object.
    #[serde(default = "empty_arguments")]
    pub arguments: Value,
    /// Preview (the default) or an explicit mutation.
    #[serde(default)]
    pub mutation: MutationIntent,
}

fn empty_arguments() -> Value {
    Value::Object(serde_json::Map::new())
}

/// The host's own identity for one call (a code-mode step, a job attempt).
/// The ledger keys one logical send by it, so the same step run again
/// replays instead of sending twice. Never taken from the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectorCallInvocation {
    pub attempt_id: AttemptId,
    pub call_seq: u64,
}

/// A connector's own reply to `tools/call`. Foreign data: the connector
/// wrote it, so it is untrusted, never instructions, and never stored in the
/// vault.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UntrustedToolResult {
    /// The MCP `content` blocks, as the connector sent them.
    pub content: Value,
    /// The MCP `structuredContent`, when the connector sent one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_content: Option<Value>,
    /// The connector's `isError`, or true when it answered with a JSON-RPC
    /// error instead of a result.
    pub is_error: bool,
    /// The JSON-RPC error object the connector answered with, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc_error: Option<Value>,
}

/// What one connector call came to.
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectorCallOutcome {
    /// The connector acknowledged the call. `result` is its reply when this
    /// send carried one; a replay of an already delivered call has none.
    Delivered {
        intent: Option<[u8; 32]>,
        result: Option<UntrustedToolResult>,
    },
    /// Held for consent or governance. Nothing was sent. Once the hold may
    /// have cleared, [`Vault::resume_connector_call`] re-enters it.
    Held {
        call_ref: EntityId,
        decision_ref: Option<String>,
        reasons: Vec<String>,
    },
    /// Not sent, and never will be under this request.
    Refused {
        decision_ref: Option<String>,
        reasons: Vec<String>,
    },
    /// The send's delivery is not settled. With a `call_ref`, resuming
    /// retries the same logical send; without one, the connector may or may
    /// not have received it and the ledger will not send it again.
    PendingDelivery {
        intent: [u8; 32],
        call_ref: Option<EntityId>,
        reasons: Vec<String>,
    },
}

/// The served side of the generic connector call: an
/// [`OutboundResultSender`] that also knows where each connector is
/// installed and keeps its own bounded copy of the last reply.
pub trait ConnectorCallHost: OutboundResultSender {
    /// The endpoint this host installed for the routed connector, or `None`
    /// when it has none. The grant's endpoint allowlist still gates it.
    fn tool_endpoint(&self, route: &ConnectorCallRoute) -> Option<String>;

    /// Takes the reply the last `send` read, kept before the ledger's scrub
    /// destroyed the raw bytes. `None` when that send read no reply.
    fn take_result(&mut self) -> Option<UntrustedToolResult>;
}

/// The exact request a held call re-enters with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingConnectorCall {
    name: String,
    tool: String,
    /// The guest's arguments as JSON text, exactly as first given.
    arguments: String,
    mutation: MutationIntent,
    /// The standing grant the last attempt ran under (hex), if one matched.
    grant_id: Option<String>,
    attempt_id: AttemptId,
    call_seq: u64,
    principal_ref: String,
    held_at_ms: u64,
}

/// What one pass came to, before the pending row is settled.
enum Step {
    Delivered {
        intent: Option<[u8; 32]>,
        result: Option<UntrustedToolResult>,
    },
    Held {
        decision_ref: Option<String>,
        reasons: Vec<String>,
    },
    Refused {
        decision_ref: Option<String>,
        reasons: Vec<String>,
    },
    Retryable {
        intent: [u8; 32],
        reasons: Vec<String>,
    },
    Unsettled {
        intent: [u8; 32],
        reasons: Vec<String>,
    },
}

fn held(reason: &str) -> Step {
    Step::Held {
        decision_ref: None,
        reasons: vec![reason.to_owned()],
    }
}

fn refused(reason: &str) -> Step {
    Step::Refused {
        decision_ref: None,
        reasons: vec![reason.to_owned()],
    }
}

impl Vault {
    /// Calls one tool on one catalogued connector for the caller `memory`
    /// is bound to. The principal is the verified actor of that scope; the
    /// grant, schema, endpoint and credential are never the guest's.
    pub fn call_connector<H: ConnectorCallHost>(
        &self,
        memory: &Memory<'_>,
        request: ConnectorCallRequest,
        invocation: Option<ConnectorCallInvocation>,
        host: &mut H,
    ) -> Result<ConnectorCallOutcome, IntentLedgerError> {
        if !std::ptr::eq(memory.vault(), self) {
            return Err(IntentLedgerError::InvalidInput(
                "the caller's scope is bound to another vault",
            ));
        }
        let invocation = invocation.unwrap_or_else(|| ConnectorCallInvocation {
            attempt_id: AttemptId::now(),
            call_seq: 0,
        });
        let arguments = serde_json::to_string(&request.arguments).map_err(|_| {
            IntentLedgerError::InvalidInput("connector call arguments are not JSON")
        })?;
        let pending = PendingConnectorCall {
            name: request.name,
            tool: request.tool,
            arguments,
            mutation: request.mutation,
            grant_id: None,
            attempt_id: invocation.attempt_id,
            call_seq: invocation.call_seq,
            principal_ref: memory.actor().to_hex(),
            held_at_ms: now_ms(),
        };
        self.drive_connector_call(None, pending, host)
    }

    /// Re-enters one held or pending-delivery call from its durable row:
    /// the same request, principal, attempt id and call seq, rechecked
    /// against live authority through prepare and execute. It takes no new
    /// arguments, and deletes the row once the call is delivered or refused.
    pub fn resume_connector_call<H: ConnectorCallHost>(
        &self,
        call_ref: &EntityId,
        host: &mut H,
    ) -> Result<ConnectorCallOutcome, IntentLedgerError> {
        let pending = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            PENDING_CALLS.get(&self.store, &txn, call_ref)?
        };
        let Some(pending) = pending else {
            return Ok(ConnectorCallOutcome::Refused {
                decision_ref: None,
                reasons: vec!["connector_call_not_held".to_owned()],
            });
        };
        self.drive_connector_call(Some(*call_ref), pending, host)
    }

    fn drive_connector_call<H: ConnectorCallHost>(
        &self,
        call_ref: Option<EntityId>,
        mut pending: PendingConnectorCall,
        host: &mut H,
    ) -> Result<ConnectorCallOutcome, IntentLedgerError> {
        let step = self.connector_call_step(&mut pending, host)?;
        let keep = |call_ref: Option<EntityId>, pending: &PendingConnectorCall| {
            let call_ref = call_ref.unwrap_or_else(EntityId::now);
            self.with_write_txn(|txn| PENDING_CALLS.put(&self.store, txn, &call_ref, pending))?;
            Ok::<_, IntentLedgerError>(call_ref)
        };
        let settle = |call_ref: Option<EntityId>| {
            if let Some(call_ref) = call_ref {
                self.with_write_txn(|txn| PENDING_CALLS.delete(&self.store, txn, &call_ref))?;
            }
            Ok::<_, IntentLedgerError>(())
        };
        Ok(match step {
            Step::Delivered { intent, result } => {
                settle(call_ref)?;
                ConnectorCallOutcome::Delivered { intent, result }
            }
            Step::Refused {
                decision_ref,
                reasons,
            } => {
                settle(call_ref)?;
                ConnectorCallOutcome::Refused {
                    decision_ref,
                    reasons,
                }
            }
            Step::Unsettled { intent, reasons } => {
                settle(call_ref)?;
                ConnectorCallOutcome::PendingDelivery {
                    intent,
                    call_ref: None,
                    reasons,
                }
            }
            Step::Held {
                decision_ref,
                reasons,
            } => ConnectorCallOutcome::Held {
                call_ref: keep(call_ref, &pending)?,
                decision_ref,
                reasons,
            },
            Step::Retryable { intent, reasons } => ConnectorCallOutcome::PendingDelivery {
                intent,
                call_ref: Some(keep(call_ref, &pending)?),
                reasons,
            },
        })
    }

    /// One pass: route, grant, governing key, approved schema, prepare,
    /// execute. Records the grant it ran under on `pending`.
    fn connector_call_step<H: ConnectorCallHost>(
        &self,
        pending: &mut PendingConnectorCall,
        host: &mut H,
    ) -> Result<Step, IntentLedgerError> {
        let Some(route) = self.route_connector_call(&pending.name)? else {
            return Ok(refused("connector_not_routable"));
        };
        let Some(server) = canonical_scoped_server_segment(&route.name) else {
            return Ok(refused("connector_name_not_scoped"));
        };
        let Some(endpoint) = host.tool_endpoint(&route) else {
            return Ok(refused("connector_endpoint_not_installed"));
        };
        let preferred = pending
            .grant_id
            .as_deref()
            .and_then(|hex| EntityId::from_hex(hex).ok());
        let Some((grant_id, grant)) =
            self.connector_call_grant(&pending.principal_ref, &server, &pending.tool, preferred)?
        else {
            return Ok(held("standing_grant_required"));
        };
        pending.grant_id = Some(grant_id.to_hex());
        // The gate binds the same actor from the same principal reference.
        let actor = EntityId::from_hex(&pending.principal_ref).unwrap_or(grant_id);
        let Some(capability) = ScopedCapabilityProvenance::mint(&server, &grant_id) else {
            return Ok(refused("connector_name_not_scoped"));
        };
        let Some((key_id, key)) = self.connector_key_for(capability.connector(), Some(&actor))?
        else {
            return Ok(held("connector_key_unregistered"));
        };
        match key.status {
            ConnectorKeyStatus::Active => {}
            ConnectorKeyStatus::Revoked => return Ok(refused("connector_key_revoked")),
            ConnectorKeyStatus::Suspended => return Ok(held("connector_key_suspended")),
            ConnectorKeyStatus::Pending => return Ok(held("connector_key_pending")),
        }
        let Some(manifest) = key.retained_manifest.as_ref() else {
            return Ok(held("connector_manifest_unapproved"));
        };
        let Some(schema) = manifest
            .tools()
            .iter()
            .find(|tool| tool.name == pending.tool)
            .map(|tool| tool.input_schema.clone())
        else {
            return Ok(if key.pending_manifest.is_some() {
                held("connector_manifest_drift")
            } else {
                refused("connector_tool_unknown")
            });
        };
        if key.tool_requires_confirmation(&pending.tool) {
            return Ok(held("connector_manifest_drift"));
        }
        if key.protocol_revision.is_none() {
            return Ok(held("connector_protocol_unpinned"));
        }
        let (payload_data_class, destructive_hint) =
            self.connector_tool_class(&key, &route, &pending.tool)?;
        let arguments: Value = serde_json::from_str(&pending.arguments)
            .map_err(|_| IntentLedgerError::InvalidRecord("held connector call arguments"))?;
        let call = ScopedMcpCallContext {
            server,
            tool: pending.tool.clone(),
            payload_data_class,
            resolved_endpoint: endpoint,
        };
        let descriptor = ToolCallDescriptor {
            schema: &schema,
            destructive_hint,
            // The approved manifest carries no replay annotations, so the
            // call is effectful and not idempotent.
            replay: OutboundToolDescriptor {
                read_only_hint: None,
                idempotency_supported_hint: None,
            },
        };
        let prepared = match self.prepare_connector_tool_call(
            &key_id,
            call,
            descriptor,
            &arguments,
            pending.mutation,
        ) {
            Ok(prepared) => prepared,
            Err(Error::InvalidConfig(_)) => return Ok(refused("connector_arguments_invalid")),
            Err(error) => return Err(error.into()),
        };
        let authority = OutboundBindingAuthority::for_vault(self)?;
        // A reply left from an earlier send is never this call's.
        drop(host.take_result());
        let dispatch = prepared.execute(
            self,
            &authority,
            grant_id,
            &grant,
            &pending.principal_ref,
            pending.attempt_id,
            pending.call_seq,
            now_ms(),
            &mut *host,
        )?;
        let reply = host.take_result();
        Ok(step_from_dispatch(&dispatch, reply))
    }

    /// The principal's live scoped grant for exactly this server and tool:
    /// the one the call last ran under when it still matches, else the first
    /// in index order.
    fn connector_call_grant(
        &self,
        principal_ref: &str,
        server: &str,
        tool: &str,
        preferred: Option<EntityId>,
    ) -> crate::Result<Option<(EntityId, StandingOutboundGrant)>> {
        let (ids, floor) = {
            let txn = self.store.env.read_txn()?;
            let floor =
                crate::gate::resolve_policy_manifest(&self.store, &txn)?.read_frontier_hash()?;
            let ids = crate::outbound_grant::standing_outbound_grant_ids_for_principal(
                &self.store,
                &txn,
                principal_ref,
            )?;
            (ids, floor)
        };
        let mut first = None;
        for id in ids {
            let Some(grant) = self.get_standing_outbound_grant(&id)? else {
                continue;
            };
            if grant.principal_ref != principal_ref || !grant.is_active_under_policy(&floor) {
                continue;
            }
            let Some(scope) = grant.scope.scoped_mcp_grant() else {
                continue;
            };
            if scope.server != server || scope.tool != tool {
                continue;
            }
            if preferred == Some(id) {
                return Ok(Some((id, grant)));
            }
            if first.is_none() {
                first = Some((id, grant));
            }
        }
        Ok(first)
    }

    /// The tool's payload class and destructive flag from its slate row on
    /// the governing key, else on the catalog key. A tool no slate names is
    /// Unclassified, which the grant check holds for the owner.
    fn connector_tool_class(
        &self,
        governing: &ConnectorKeyRecord,
        route: &ConnectorCallRoute,
        tool: &str,
    ) -> crate::Result<(DataClass, bool)> {
        let catalog_slate = self
            .get_connector_key(&route.key_ref)?
            .and_then(|key| key.slate_ref);
        for slate_id in [governing.slate_ref, catalog_slate].into_iter().flatten() {
            if let Some(slate) = self.connector_slate(slate_id)?
                && let Some(row) = slate.tool(tool)
            {
                let class = match row.data_class {
                    SlateDataClass::Public => DataClass::Public,
                    SlateDataClass::Personal => DataClass::Personal,
                    SlateDataClass::Secret => DataClass::Secret,
                    SlateDataClass::Header => DataClass::Unclassified,
                };
                return Ok((class, row.destroys));
            }
        }
        Ok((DataClass::Unclassified, false))
    }
}

/// Maps one execute onto a step. AutoFire alone proves nothing: only a Done
/// ledger row is delivery, and the gate's own outcome tells a hold from a
/// denial.
fn step_from_dispatch(
    dispatch: &ScopedMcpDispatchResult,
    reply: Option<UntrustedToolResult>,
) -> Step {
    let decision_ref = dispatch.gate_decision_ref().map(str::to_owned);
    let mut reasons: Vec<String> = Vec::new();
    for reason in dispatch.gate_reasons() {
        push_reason(&mut reasons, reason);
    }
    if let ScopedMcpConsentDecision::Escalate(reason) = dispatch.decision {
        push_reason(&mut reasons, escalation_code(reason));
    }
    let denied = dispatch.gate_outcome() == Some("deny");
    let hold_or_deny = |mut reasons: Vec<String>, decision_ref: Option<String>| {
        if denied {
            if reasons.is_empty() {
                reasons.push("gate_denied".to_owned());
            }
            Step::Refused {
                decision_ref,
                reasons,
            }
        } else {
            if reasons.is_empty() {
                reasons.push("gate_held".to_owned());
            }
            Step::Held {
                decision_ref,
                reasons,
            }
        }
    };
    let Some(ledger) = dispatch.dispatch.as_ref() else {
        return hold_or_deny(reasons, decision_ref);
    };
    let escalation = ledger.escalation.map(|escalation| escalation.reason);
    if let Some(reason) = escalation {
        push_reason(&mut reasons, intent_escalation_code(reason));
    }
    match (ledger.state, ledger.intent_id) {
        (Some(IntentState::Done), intent) => Step::Delivered {
            intent,
            result: reply,
        },
        (Some(IntentState::Abandoned), Some(intent))
            if matches!(
                escalation,
                Some(
                    IntentEscalationReason::NonIdempotentAmbiguous
                        | IntentEscalationReason::NonIdempotentPending
                )
            ) =>
        {
            Step::Unsettled { intent, reasons }
        }
        (Some(IntentState::Abandoned), _) => {
            if reasons.is_empty() {
                reasons.push("abandoned".to_owned());
            }
            Step::Refused {
                decision_ref,
                reasons,
            }
        }
        (Some(IntentState::Pending), Some(intent)) => match ledger.send_outcome {
            Some(OutboundSendOutcome::Failed(_)) => {
                push_reason(&mut reasons, "delivery_failed");
                Step::Retryable { intent, reasons }
            }
            Some(OutboundSendOutcome::Ambiguous | OutboundSendOutcome::Acked) => {
                push_reason(&mut reasons, "delivery_unconfirmed");
                Step::Retryable { intent, reasons }
            }
            None => hold_or_deny(reasons, decision_ref),
        },
        _ => hold_or_deny(reasons, decision_ref),
    }
}

fn push_reason(reasons: &mut Vec<String>, reason: &str) {
    if !reasons.iter().any(|known| known == reason) {
        reasons.push(reason.to_owned());
    }
}

fn escalation_code(reason: ScopedMcpEscalationReason) -> &'static str {
    match reason {
        ScopedMcpEscalationReason::InvalidGrant => "invalid_grant",
        ScopedMcpEscalationReason::ToolDataClassNotGranted => "tool_data_class_not_granted",
        ScopedMcpEscalationReason::WrongPrincipal => "wrong_principal",
        ScopedMcpEscalationReason::WrongServer => "wrong_server",
        ScopedMcpEscalationReason::WrongTool => "wrong_tool",
        ScopedMcpEscalationReason::EndpointNotAllowed => "endpoint_not_allowed",
        ScopedMcpEscalationReason::UnknownDataClass => "unknown_data_class",
        ScopedMcpEscalationReason::DataClassCeilingExceeded => "data_class_ceiling_exceeded",
        ScopedMcpEscalationReason::ConnectorKeyUnregistered => "connector_key_unregistered",
        ScopedMcpEscalationReason::ConnectorKeyPending => "connector_key_pending",
        ScopedMcpEscalationReason::ConnectorKeySuspended => "connector_key_suspended",
        ScopedMcpEscalationReason::ConnectorKeyRevoked => "connector_key_revoked",
        ScopedMcpEscalationReason::ConnectorKeyCharterDrift => "charter_drift",
        ScopedMcpEscalationReason::ConnectorManifestDrift => "connector_manifest_drift",
        ScopedMcpEscalationReason::StaleConnectorManifest { .. } => "connector_manifest_stale",
        ScopedMcpEscalationReason::ConnectorKeyCharterNeverList => "charter_never_list",
        ScopedMcpEscalationReason::ConnectorKeyBudgetExhausted => "effector_budget_exhausted",
    }
}

fn intent_escalation_code(reason: IntentEscalationReason) -> &'static str {
    match reason {
        IntentEscalationReason::NonIdempotentAmbiguous => "non_idempotent_ambiguous",
        IntentEscalationReason::NonIdempotentPending => "non_idempotent_pending",
        IntentEscalationReason::ConnectorRevoked => "connector_revoked",
        IntentEscalationReason::BindingInvalid => "binding_invalid",
        IntentEscalationReason::PreviouslyAbandoned => "previously_abandoned",
        IntentEscalationReason::CorruptLedgerRow => "corrupt_ledger_row",
        IntentEscalationReason::DedupeReservationReplaced => "dedupe_reservation_replaced",
        IntentEscalationReason::DedupeSuppressed => "dedupe_suppressed",
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
