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
//!
//! A host's identity for a call fixes its row's ref, so the same call run
//! again finds the call it held. Once a resume settles a held call, the row
//! keeps that outcome, without the reply, until a settler lists it
//! ([`Vault::pending_connector_calls`]), answers the wait the ref names and
//! acknowledges it ([`Vault::ack_connector_call_delivery`]).
//! [`Vault::connector_tool_schema`] reads a tool's approved schema through
//! the same resolution a call takes.
//!
//! A hold asks the owner once (`connector_call_asks`); the answer grants
//! nothing, the consent and key doors still do. A call nobody settles
//! expires a fixed time after it was first held (`connector_call_pending`).
//! A held call the ledger already admitted resumes from that frozen row by
//! its intent id (`connector_call_resume`), never from bytes prepared again.

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
pub(super) const PENDING_CALLS: SideTable<EntityId, PendingConnectorCall, Named> =
    SideTable::new(&side_table::OUTBOUND_CONNECTOR_CALL_PENDING);

/// The derivation domain of the call ref a host's own identity fixes, so the
/// same logical call finds its held row again instead of holding a second.
const CONNECTOR_CALL_REF_DOMAIN: &[u8] = b"oneiron:connector-call-ref:v1";

/// The reason a call gets when its host identity already names a held call
/// with another request.
const CONNECTOR_CALL_INVOCATION_CONFLICT: &str = "connector_call_invocation_conflict";

/// One guest call: a catalog name, one of its tools, and the arguments. It
/// carries no endpoint, credential, schema, grant or principal: the engine
/// and the host resolve those beneath the name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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
pub(super) struct PendingConnectorCall {
    pub(super) name: String,
    pub(super) tool: String,
    /// The guest's arguments as JSON text, exactly as first given.
    pub(super) arguments: String,
    pub(super) mutation: MutationIntent,
    /// The standing grant the last attempt ran under (hex), if one matched.
    pub(super) grant_id: Option<String>,
    pub(super) attempt_id: AttemptId,
    pub(super) call_seq: u64,
    pub(super) principal_ref: String,
    /// When the call was first held. Its expiry deadline counts from here,
    /// and no retry moves it.
    pub(super) held_at_ms: u64,
    /// What the call came to once a resume settled it. The row outlives its
    /// terminal outcome until the settler acknowledges the wait reply that
    /// carries it, so a crash before that reply commits strands no waiter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) settled: Option<SettledConnectorCall>,
    /// The hold reasons the owner's ask carried, kept once an ask was tried.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) held_reasons: Vec<String>,
    /// The arrival number of the owner's ask about this hold, once queued:
    /// the call asks once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) owner_ask_seq: Option<u64>,
}

impl PendingConnectorCall {
    /// Whether `other` asks for exactly this call: the same caller, tool,
    /// arguments and mutation.
    fn same_call(&self, other: &Self) -> bool {
        let arguments = |text: &str| serde_json::from_str::<Value>(text).ok();
        self.name == other.name
            && self.tool == other.tool
            && self.mutation == other.mutation
            && self.principal_ref == other.principal_ref
            && arguments(&self.arguments).is_some()
            && arguments(&self.arguments) == arguments(&other.arguments)
    }
}

/// A held call's terminal outcome, without the tool's reply: the ledger
/// never keeps a reply's bytes, so a recovery from this row is receipt-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SettledConnectorCall {
    Delivered {
        intent: Option<[u8; 32]>,
    },
    Refused {
        decision_ref: Option<String>,
        reasons: Vec<String>,
    },
    Unsettled {
        intent: [u8; 32],
        reasons: Vec<String>,
    },
}

impl SettledConnectorCall {
    pub(super) fn outcome(&self) -> ConnectorCallOutcome {
        match self.clone() {
            Self::Delivered { intent } => ConnectorCallOutcome::Delivered {
                intent,
                result: None,
            },
            Self::Refused {
                decision_ref,
                reasons,
            } => ConnectorCallOutcome::Refused {
                decision_ref,
                reasons,
            },
            Self::Unsettled { intent, reasons } => ConnectorCallOutcome::PendingDelivery {
                intent,
                call_ref: None,
                reasons,
            },
        }
    }
}

/// One held or pending-delivery call, as a settler lists it: its ref, the
/// catalog name and tool it calls, and whether a resume already settled it
/// (then its row waits only for [`Vault::ack_connector_call_delivery`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingConnectorCallRef {
    pub call_ref: EntityId,
    pub name: String,
    pub tool: String,
    pub settled: bool,
}

/// One tool's approved input schema, on the governing key the caller's own
/// grant resolves, or why there is none. Read-only and secret-free.
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectorToolSchema {
    Approved {
        input_schema: Value,
        destructive_hint: bool,
    },
    /// The hold or refusal a call of the tool would meet first.
    Unavailable { reasons: Vec<String> },
}

/// The tool beneath one grant, for a schema read: the governing key the
/// grant mints and the tool's approved schema there.
struct GoverningTool {
    key: ConnectorKeyRecord,
    schema: Value,
}

/// What one pass came to, before the pending row is settled.
pub(super) enum Step {
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

impl Step {
    /// The reasons a hold or a refusal carries.
    fn into_reasons(self) -> Vec<String> {
        match self {
            Self::Held { reasons, .. }
            | Self::Refused { reasons, .. }
            | Self::Retryable { reasons, .. }
            | Self::Unsettled { reasons, .. } => reasons,
            Self::Delivered { .. } => Vec::new(),
        }
    }
}

/// The call ref a host's identity fixes for one caller: the same caller's
/// same logical call always names the same held row.
fn connector_call_ref(
    principal_ref: &str,
    invocation: ConnectorCallInvocation,
) -> Result<EntityId, IntentLedgerError> {
    Ok(EntityId::derive(
        CONNECTOR_CALL_REF_DOMAIN,
        &[
            principal_ref.as_bytes(),
            invocation.attempt_id.as_bytes(),
            &invocation.call_seq.to_le_bytes(),
        ],
    )?)
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
        let named = invocation;
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
            settled: None,
            held_reasons: Vec::new(),
            owner_ask_seq: None,
        };
        let Some(named) = named else {
            return self.drive_connector_call(None, None, pending, host);
        };
        // The host's identity names one logical call: run again, it finds
        // the call it held instead of holding a second one.
        let call_ref = connector_call_ref(&pending.principal_ref, named)?;
        let held = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            PENDING_CALLS.get(&self.store, &txn, &call_ref)?
        };
        match held {
            None => self.drive_connector_call(None, Some(call_ref), pending, host),
            Some(held) if !held.same_call(&pending) => Ok(ConnectorCallOutcome::Refused {
                decision_ref: None,
                reasons: vec![CONNECTOR_CALL_INVOCATION_CONFLICT.to_owned()],
            }),
            Some(held) => {
                if let Some(settled) = &held.settled {
                    return Ok(settled.outcome());
                }
                if let Some(expired) =
                    self.expire_connector_call_if_due(&call_ref, &held, now_ms())?
                {
                    return Ok(expired);
                }
                self.drive_connector_call(Some(call_ref), None, held, host)
            }
        }
    }

    /// Re-enters one held or pending-delivery call from its durable row:
    /// the same request, principal, attempt id and call seq. A call the
    /// ledger already admitted resumes from that frozen row by intent id;
    /// one it never admitted is rechecked against live authority through
    /// prepare and execute. It takes no new arguments. A call past its
    /// expiry deadline settles as expired instead. Once the call is
    /// delivered or refused its row keeps that outcome, without the tool's
    /// reply, until [`Self::ack_connector_call_delivery`]; a resume of a
    /// settled row answers that receipt again and sends nothing.
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
        if let Some(settled) = &pending.settled {
            return Ok(settled.outcome());
        }
        if let Some(expired) = self.expire_connector_call_if_due(call_ref, &pending, now_ms())? {
            return Ok(expired);
        }
        self.drive_connector_call(Some(*call_ref), None, pending, host)
    }

    /// Every held or pending-delivery call's row, settled ones included, for
    /// a settler that resumes each and answers its wait.
    pub fn pending_connector_calls(
        &self,
    ) -> Result<Vec<PendingConnectorCallRef>, IntentLedgerError> {
        let txn = self.store.env.read_txn().map_err(Error::from)?;
        Ok(PENDING_CALLS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(call_ref, pending)| PendingConnectorCallRef {
                call_ref,
                name: pending.name,
                tool: pending.tool,
                settled: pending.settled.is_some(),
            })
            .collect())
    }

    /// Drops a settled call's row once the wait reply that carries its
    /// outcome has committed; `true` when it dropped one. A held or
    /// retryable row stays for its next resume.
    pub fn ack_connector_call_delivery(
        &self,
        call_ref: &EntityId,
    ) -> Result<bool, IntentLedgerError> {
        Ok(
            self.with_write_txn(|txn| match PENDING_CALLS.get(&self.store, txn, call_ref)? {
                Some(pending) if pending.settled.is_some() => {
                    PENDING_CALLS.delete(&self.store, txn, call_ref)
                }
                _ => Ok(false),
            })?,
        )
    }

    /// One tool's approved input schema for the caller `memory` is bound
    /// to, through the same route, grant and governing key a call of it
    /// takes. Reads only; nothing is held, sent or written.
    pub fn connector_tool_schema(
        &self,
        memory: &Memory<'_>,
        name: &str,
        tool: &str,
    ) -> Result<ConnectorToolSchema, IntentLedgerError> {
        if !std::ptr::eq(memory.vault(), self) {
            return Err(IntentLedgerError::InvalidInput(
                "the caller's scope is bound to another vault",
            ));
        }
        let unavailable = |stop: Step| ConnectorToolSchema::Unavailable {
            reasons: stop.into_reasons(),
        };
        let Some(route) = self.route_connector_call(name)? else {
            return Ok(unavailable(refused("connector_not_routable")));
        };
        let Some(server) = canonical_scoped_server_segment(&route.name) else {
            return Ok(unavailable(refused("connector_name_not_scoped")));
        };
        let governed = match self.governing_tool(&memory.actor().to_hex(), &server, tool)? {
            Ok(governed) => governed,
            Err(stop) => return Ok(unavailable(stop)),
        };
        let (_, destructive_hint, _) = self.connector_tool_class(&governed.key, &route, tool)?;
        Ok(ConnectorToolSchema::Approved {
            input_schema: governed.schema,
            destructive_hint,
        })
    }

    /// One pass and what it leaves durable. `call_ref` names the row the
    /// call already holds; `new_ref`, the ref a first hold takes (a fresh
    /// one when `None`). A terminal outcome of a call with a row keeps that
    /// row, settled, for the settler's acknowledgement; one with none
    /// writes nothing.
    fn drive_connector_call<H: ConnectorCallHost>(
        &self,
        call_ref: Option<EntityId>,
        new_ref: Option<EntityId>,
        mut pending: PendingConnectorCall,
        host: &mut H,
    ) -> Result<ConnectorCallOutcome, IntentLedgerError> {
        // A call its row already holds resumes through the ledger row it
        // admitted, if any; only a call with none resolves and prepares live.
        let resumed = match call_ref {
            Some(_) => self.resume_connector_call_intent(&pending, host)?,
            None => None,
        };
        let step = match resumed {
            Some(step) => step,
            None => self.connector_call_step(&mut pending, host)?,
        };
        let keep = |call_ref: Option<EntityId>, pending: &PendingConnectorCall| {
            let call_ref = call_ref.or(new_ref).unwrap_or_else(EntityId::now);
            self.with_write_txn(|txn| PENDING_CALLS.put(&self.store, txn, &call_ref, pending))?;
            Ok::<_, IntentLedgerError>(call_ref)
        };
        let settle = |call_ref: Option<EntityId>, settled: SettledConnectorCall| {
            if let Some(call_ref) = call_ref {
                let row = PendingConnectorCall {
                    settled: Some(settled),
                    ..pending.clone()
                };
                self.with_write_txn(|txn| PENDING_CALLS.put(&self.store, txn, &call_ref, &row))?;
            }
            Ok::<_, IntentLedgerError>(())
        };
        Ok(match step {
            Step::Delivered { intent, result } => {
                settle(call_ref, SettledConnectorCall::Delivered { intent })?;
                ConnectorCallOutcome::Delivered { intent, result }
            }
            Step::Refused {
                decision_ref,
                reasons,
            } => {
                settle(
                    call_ref,
                    SettledConnectorCall::Refused {
                        decision_ref: decision_ref.clone(),
                        reasons: reasons.clone(),
                    },
                )?;
                ConnectorCallOutcome::Refused {
                    decision_ref,
                    reasons,
                }
            }
            Step::Unsettled { intent, reasons } => {
                settle(
                    call_ref,
                    SettledConnectorCall::Unsettled {
                        intent,
                        reasons: reasons.clone(),
                    },
                )?;
                ConnectorCallOutcome::PendingDelivery {
                    intent,
                    call_ref: None,
                    reasons,
                }
            }
            Step::Held {
                decision_ref,
                reasons,
            } => {
                let call_ref = keep(call_ref, &pending)?;
                // The hold is durable: ask the owner about it, once. The
                // settler's pass repairs an ask that did not queue here.
                if let Err(error) = self.queue_connector_call_owner_ask(&call_ref, &reasons) {
                    tracing::warn!(
                        call_ref = %call_ref.to_hex(),
                        %error,
                        "connector call owner ask not queued"
                    );
                }
                ConnectorCallOutcome::Held {
                    call_ref,
                    decision_ref,
                    reasons,
                }
            }
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
        let (payload_data_class, destructive_hint, replay) =
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
            // The slate row's declared hints: a tool declared neither
            // read-only nor idempotent is effectful and not idempotent.
            replay,
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

    /// The principal's grant for `server` and `tool`, the governing key it
    /// mints and the tool's approved schema there, for a schema read. It
    /// follows `connector_call_step`'s resolution step for step (the same
    /// grant lookup, capability, governing key, status and manifest checks);
    /// a stop is the hold or refusal a call meets there.
    fn governing_tool(
        &self,
        principal_ref: &str,
        server: &str,
        tool: &str,
    ) -> Result<std::result::Result<GoverningTool, Step>, IntentLedgerError> {
        let Some((grant_id, _)) = self.connector_call_grant(principal_ref, server, tool, None)?
        else {
            return Ok(Err(held("standing_grant_required")));
        };
        // The gate binds the same actor from the same principal reference.
        let actor = EntityId::from_hex(principal_ref).unwrap_or(grant_id);
        let Some(capability) = ScopedCapabilityProvenance::mint(server, &grant_id) else {
            return Ok(Err(refused("connector_name_not_scoped")));
        };
        let Some((_, key)) = self.connector_key_for(capability.connector(), Some(&actor))? else {
            return Ok(Err(held("connector_key_unregistered")));
        };
        match key.status {
            ConnectorKeyStatus::Active => {}
            ConnectorKeyStatus::Revoked => return Ok(Err(refused("connector_key_revoked"))),
            ConnectorKeyStatus::Suspended => return Ok(Err(held("connector_key_suspended"))),
            ConnectorKeyStatus::Pending => return Ok(Err(held("connector_key_pending"))),
        }
        let Some(manifest) = key.retained_manifest.as_ref() else {
            return Ok(Err(held("connector_manifest_unapproved")));
        };
        let Some(schema) = manifest
            .tools()
            .iter()
            .find(|found| found.name == tool)
            .map(|found| found.input_schema.clone())
        else {
            return Ok(Err(if key.pending_manifest.is_some() {
                held("connector_manifest_drift")
            } else {
                refused("connector_tool_unknown")
            }));
        };
        Ok(Ok(GoverningTool { key, schema }))
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

    /// The tool's payload class, destructive flag and declared replay hints
    /// from its slate row on the governing key, else on the catalog key. A
    /// tool no slate names is Unclassified, which the grant check holds for
    /// the owner.
    fn connector_tool_class(
        &self,
        governing: &ConnectorKeyRecord,
        route: &ConnectorCallRoute,
        tool: &str,
    ) -> crate::Result<(DataClass, bool, OutboundToolDescriptor)> {
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
                let replay = OutboundToolDescriptor {
                    read_only_hint: Some(row.read_only),
                    idempotency_supported_hint: Some(row.idempotent),
                };
                return Ok((class, row.destroys, replay));
            }
        }
        let replay = OutboundToolDescriptor {
            read_only_hint: None,
            idempotency_supported_hint: None,
        };
        Ok((DataClass::Unclassified, false, replay))
    }
}

/// Maps one execute onto a step. AutoFire alone proves nothing: only a Done
/// ledger row is delivery, and the gate's own outcome tells a hold from a
/// denial.
pub(super) fn step_from_dispatch(
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

pub(super) fn intent_escalation_code(reason: IntentEscalationReason) -> &'static str {
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

pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// One held call's principal, connector name and tool, so the owner's
/// connector consent binds exactly the actor that will resume it. A row a
/// resume or an expiry already settled holds nothing, so it answers `None`.
pub(crate) fn held_connector_call_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    call_ref: &EntityId,
) -> crate::Result<Option<(String, String, String)>> {
    Ok(PENDING_CALLS
        .get(store, txn, call_ref)?
        .filter(|row| row.settled.is_none())
        .map(|row| (row.principal_ref, row.name, row.tool)))
}
