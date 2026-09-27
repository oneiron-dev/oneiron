//! Linear mutations through the vault's replay-first outbound dispatch door.

use std::path::PathBuf;

use oneiron::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchOutcome, OutboundDispatchRequest, OutboundExecutionOutcome,
    OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent, OutboundIntentDraft,
    OutboundIntentTrigger,
};
use oneiron::{LinearSyncResult, Vault};
use serde_json::Value;

use crate::egress::{CREATE, UPDATE};
use crate::journal::LinearResponseJournal;
use crate::{GraphQlCall, GraphQlExecutor, GraphQlTransportError, LinearOutboundDoor, invalid};

/// The credential-bearing host connector bound to the engine's ordinary
/// ExternalEffect gate, budget, intent ledger and receipt. A standalone HTTP
/// or callback-only path cannot implement `LinearOutboundDoor` in production.
pub struct VaultLinearOutboundDoor<'v, T> {
    vault: &'v Vault,
    journal: LinearResponseJournal<T>,
    actor: OutboundDispatchActor,
    gate: OutboundDispatchGate,
    now: u64,
}

impl<'v, T> VaultLinearOutboundDoor<'v, T> {
    /// Creates the host door. `actor` is the authenticated actor whose policy
    /// governs the effect; `gate` holds today's opt-in and permission facts.
    /// The directory is a host-private durable response store, not vault data.
    ///
    /// # Errors
    /// Refuses a missing response directory.
    pub fn new(
        vault: &'v Vault,
        transport: T,
        journal_dir: PathBuf,
        actor: OutboundDispatchActor,
        gate: OutboundDispatchGate,
        now: u64,
    ) -> LinearSyncResult<Self> {
        Ok(Self {
            vault,
            journal: LinearResponseJournal::new(transport, journal_dir)?,
            actor,
            gate,
            now,
        })
    }

    pub fn into_transport(self) -> T {
        self.journal.into_transport()
    }
}

struct LinearSink<'a, T> {
    journal: &'a mut LinearResponseJournal<T>,
    operation_id: [u8; 32],
    call: &'a GraphQlCall,
    intent_ref: &'a str,
}

impl<T: GraphQlExecutor> OutboundExecutionSink for LinearSink<'_, T> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        if request.intent_ref != self.intent_ref
            || request.intent.channel != "linear"
            || request.intent.content_ref.as_deref() != Some(self.call.body().to_string().as_str())
            || request.intent.idempotency_key.as_deref()
                != Some(blake3::Hash::from(self.operation_id).to_hex().as_str())
        {
            return OutboundExecutionOutcome::failed("linear frozen call mismatch");
        }
        match self.journal.dispatch(self.operation_id, self.call) {
            Ok(response) => {
                let key = if self.call.query == CREATE {
                    "issueCreate"
                } else {
                    "issueUpdate"
                };
                let provider = response["data"][key]["issue"]["id"]
                    .as_str()
                    .unwrap_or_default();
                OutboundExecutionOutcome::delivered_to_channel(provider)
            }
            Err(GraphQlTransportError::NotSent) => {
                OutboundExecutionOutcome::failed("linear transport not started")
            }
            Err(GraphQlTransportError::Uncertain) => {
                OutboundExecutionOutcome::failed("linear delivery uncertain")
                    .with_possible_delivery()
            }
        }
    }
}

impl<T: GraphQlExecutor> LinearOutboundDoor for VaultLinearOutboundDoor<'_, T> {
    fn dispatch(&mut self, operation_id: [u8; 32], call: &GraphQlCall) -> LinearSyncResult<Value> {
        let (verb, target) = if call.query == CREATE {
            ("create_issue", call.variables["input"]["teamId"].as_str())
        } else if call.query == UPDATE {
            ("update_issue", call.variables["id"].as_str())
        } else {
            return Err(invalid("unknown Linear mutation"));
        };
        let target = target
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| invalid("Linear mutation has no target"))?;
        let actor_ref = self
            .actor
            .actor_ref
            .as_deref()
            .ok_or_else(|| invalid("Linear outbound actor has no reference"))?;
        let digest = blake3::Hash::from(operation_id).to_hex().to_string();
        let intent_ref = format!("linear:{digest}");
        let intent = OutboundIntent::from_trigger(
            OutboundIntentDraft::new(actor_ref, verb, "linear", target)
                .content_ref(call.body().to_string())
                .idempotency_key(digest),
            OutboundIntentTrigger::agent_immediate(intent_ref.clone()),
        );
        let mut request = OutboundDispatchRequest::new(
            intent_ref.clone(),
            intent_ref.clone(),
            intent,
            self.actor.clone(),
            self.gate,
            self.now,
            OutboundDeliveryWindowDecision::DeliverNow,
        );
        request.ledger_identity_ref = Some(intent_ref.clone());
        let mut sink = LinearSink {
            journal: &mut self.journal,
            operation_id,
            call,
            intent_ref: &intent_ref,
        };
        let result = self
            .vault
            .dispatch_outbound_intent(request, &mut sink)
            .map_err(|_| invalid("Linear outbound dispatch failed"))?;
        if result.outcome != OutboundDispatchOutcome::DeliveredToChannel {
            return Err(invalid("Linear outbound dispatch did not deliver"));
        }
        self.journal
            .read_committed(&operation_id, call)
            .map_err(oneiron::LinearSyncError::from)?
            .ok_or_else(|| invalid("Linear delivered effect has no response receipt"))
    }
}
