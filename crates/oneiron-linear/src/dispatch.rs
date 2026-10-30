//! Linear mutations through the vault's replay-first outbound dispatch door.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::linear_sync::{
    LINEAR_RATE_WINDOW_REASON, LinearEffectHold, LinearEffectKind, LinearEffectRequest,
    LinearEffectRole, LinearRateTurn, LinearRoleApproval, LinearTaskStore, VaultLinearTaskStore,
};
use oneiron::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchOutcome, OutboundDispatchRequest, OutboundExecutionOutcome,
    OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent, OutboundIntentDraft,
    OutboundIntentTrigger,
};
use oneiron::{EntityId, LinearSyncError, LinearSyncResult, Vault};

use crate::egress::{CREATE, LinearMutation, UPDATE};
use crate::http::status_text;
use crate::journal::{LinearResponseJournal, request_ref};
use crate::{
    GraphQlCall, GraphQlExecutor, GraphQlTransportError, GraphQlValue, LinearBodyLine,
    LinearOutboundDoor, invalid,
};

/// The credential-bearing host connector bound to the engine's ordinary
/// ExternalEffect gate, budget, intent ledger and receipt. A standalone HTTP
/// or callback-only path cannot implement `LinearOutboundDoor` in production.
/// Each call is admitted for the door's actor (the host scheduler) and the
/// mirrored TASK revision's verified writer in ONE outbound admission, so a
/// remote mutation charges each distinct connector key once (OF-427).
pub struct VaultLinearOutboundDoor<'v, T> {
    vault: &'v Vault,
    journal: LinearResponseJournal<'v, T>,
    actor: OutboundDispatchActor,
    gate: OutboundDispatchGate,
    now: u64,
    /// How long a dispatch waits for a full Rate window (FIX 8788): none for
    /// a background pass.
    rate_wait: Duration,
}

impl<'v, T> VaultLinearOutboundDoor<'v, T> {
    /// Creates the host door. `actor` is the authenticated actor whose policy
    /// governs the effect; `gate` holds today's opt-in and permission facts.
    /// The directory keeps the host's content-free delivery state; the
    /// request and response bytes are the mirrored TASK's body custody in
    /// the vault (FIX 8609).
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
            journal: LinearResponseJournal::new(vault, transport, journal_dir)?,
            actor,
            gate,
            now,
            rate_wait: Duration::ZERO,
        })
    }

    /// This door, decoding each kept request and response on the host's
    /// memory `line` (FIX 8610).
    #[must_use]
    pub fn with_body_line(mut self, line: Arc<dyn LinearBodyLine>) -> Self {
        self.journal.set_body_line(line);
        self
    }

    /// This door, waiting up to `wait` for a full Rate window before each
    /// dispatch, at its fair turn among the verified writers waiting (FIX
    /// 8788). A door without one returns a full window at once as
    /// [`LinearSyncError::Waiting`].
    #[must_use]
    pub fn with_rate_wait(mut self, wait: Duration) -> Self {
        self.rate_wait = wait;
        self
    }

    pub fn into_transport(self) -> T {
        self.journal.into_transport()
    }

    /// Resolves a `content_ref` on an ordinary outbound receipt to the exact
    /// GraphQL request frozen before gate evaluation, while its TASK lives.
    ///
    /// # Errors
    /// Returns an error if the request cannot be read or decoded, or was
    /// erased with its TASK.
    pub fn request_by_ref(&self, reference: &str) -> LinearSyncResult<Option<GraphQlValue>> {
        self.journal.read_request(reference)
    }
}

/// The door's refusal of a call it did not deliver.
const DID_NOT_DELIVER: &str = "Linear outbound dispatch did not deliver";
/// What closes a refusal of a call the endpoint answered with a status (FIX
/// 9385): the status and its canonical reason, never a provider body.
const ANSWERED: &str = "; Linear answered HTTP ";

/// FIX 6824: the approve-once digest (64 lower-hex) and the role of the
/// actor whose press it names, read off a [`LinearSyncError::Held`] a
/// [`VaultLinearOutboundDoor`] returns when the Gate held the call for the
/// owner's press, or (FIX 6837) off the first held push a mirror pass's
/// [`LinearSyncError::PushFailed`] carries; `None` for every other error.
#[must_use]
pub fn held_approve_once(error: &LinearSyncError) -> Option<(&str, LinearEffectRole)> {
    match error {
        LinearSyncError::Held {
            role,
            approval_digest,
            ..
        } => Some((approval_digest, *role)),
        LinearSyncError::PushFailed(failures) => failures
            .iter()
            .find_map(|failure| held_approve_once(&failure.error)),
        _ => None,
    }
}

struct LinearSink<'a, 'v, T> {
    journal: &'a mut LinearResponseJournal<'v, T>,
    operation_id: [u8; 32],
    task: EntityId,
    call: &'a GraphQlCall,
    intent_ref: &'a str,
    content_ref: &'a str,
    /// The status the endpoint answered the call with, when it answered one
    /// that was not a success.
    status: &'a mut Option<u16>,
}

impl<T: GraphQlExecutor> OutboundExecutionSink for LinearSink<'_, '_, T> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        if request.intent_ref != self.intent_ref
            || request.intent.channel != "linear"
            || request.intent.content_ref.as_deref() != Some(self.content_ref)
            || request.intent.idempotency_key.as_deref()
                != Some(blake3::Hash::from(self.operation_id).to_hex().as_str())
        {
            return OutboundExecutionOutcome::failed("linear frozen call mismatch");
        }
        match self
            .journal
            .dispatch(self.operation_id, self.task, self.call)
        {
            Ok(issue) => OutboundExecutionOutcome::delivered_to_channel(issue),
            Err(GraphQlTransportError::NotSent) => {
                OutboundExecutionOutcome::failed("linear transport not started")
            }
            // FIX 8611: the endpoint refused the credential and ran nothing:
            // a definite non-delivery, kept with its status alone.
            Err(GraphQlTransportError::Rejected { status }) => {
                *self.status = Some(status);
                OutboundExecutionOutcome::failed("linear credential rejected")
                    .with_receipt_field("linear_http_status", status.to_string())
            }
            Err(GraphQlTransportError::Uncertain | GraphQlTransportError::Waiting) => {
                OutboundExecutionOutcome::failed("linear delivery uncertain")
                    .with_possible_delivery()
            }
            // FIX 9385: any other status may follow a run: uncertain, as
            // before, and kept with its status.
            Err(GraphQlTransportError::HttpStatus { status }) => {
                *self.status = Some(status);
                OutboundExecutionOutcome::failed("linear delivery uncertain")
                    .with_possible_delivery()
                    .with_receipt_field("linear_http_status", status.to_string())
            }
        }
    }

    /// FIX 9379: this exact operation's journal holds the endpoint's durable
    /// refusal of its credential, written before the ledger could record the
    /// definite non-delivery: nothing ran, so the engine retries it as one.
    /// Any other journal state proves nothing.
    fn known_non_delivery(&self, intent_ref: &str, idempotency_key: Option<&str>) -> bool {
        intent_ref == self.intent_ref
            && idempotency_key == Some(blake3::Hash::from(self.operation_id).to_hex().as_str())
            && self.journal.rejected(&self.operation_id)
    }
}

impl<T> VaultLinearOutboundDoor<'_, T> {
    /// The exact mirror mutation `call` sends, as the vault binds it to the
    /// TASK's current mirror operation, with the canonical verb and the
    /// transport target its dispatch names.
    fn mutation_effect<'c>(
        &self,
        mutation: &LinearMutation<'_>,
        call: &'c GraphQlCall,
    ) -> LinearSyncResult<(LinearEffectRequest, &'static str, &'c str)> {
        let operation_id = mutation.operation_id;
        let (verb, target, kind) = match mutation.issue {
            None if call.query == CREATE => (
                "create_issue",
                call.variables["input"]["teamId"].as_str(),
                LinearEffectKind::Create,
            ),
            Some(issue)
                if call.query == UPDATE
                    && call.variables["id"].as_str() == Some(issue.issue_id.as_str()) =>
            {
                (
                    "update_issue",
                    call.variables["id"].as_str(),
                    LinearEffectKind::Update,
                )
            }
            _ => return Err(invalid("unknown Linear mutation")),
        };
        let target = target
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| invalid("Linear mutation has no target"))?;
        self.actor
            .actor_ref
            .as_deref()
            .ok_or_else(|| invalid("Linear outbound actor has no reference"))?;
        let scheduler_actor = self
            .actor
            .actor_entity_ref
            .ok_or_else(|| invalid("Linear outbound actor has no entity"))?;
        let task_ref = match (mutation.task_ref, mutation.issue) {
            (Some(task_ref), _) => task_ref,
            (None, Some(issue)) => {
                VaultLinearTaskStore::new(self.vault)
                    .link_for_issue(issue)?
                    .ok_or(LinearSyncError::AuthorizationDenied)?
                    .task_ref
            }
            (None, None) => return Err(invalid("Linear create names no TASK")),
        };
        // The exact mutation the vault binds to the TASK's current mirror
        // operation and admits for both actors under the outbound writer.
        let effect = LinearEffectRequest {
            operation_id,
            task_ref,
            scheduler_actor,
            issue: mutation.issue.cloned(),
            kind,
            fields: mutation.fields.clone(),
        };
        Ok((effect, verb, target))
    }

    /// The outbound request this door dispatches `operation_id` under, with
    /// the staged request's `content_ref`, and its logical intent ref.
    fn door_request(
        &self,
        operation_id: [u8; 32],
        verb: &str,
        target: &str,
        content_ref: &str,
    ) -> (OutboundDispatchRequest, String) {
        let digest = blake3::Hash::from(operation_id).to_hex().to_string();
        let intent_ref = format!("linear:{digest}");
        let actor_ref = self.actor.actor_ref.as_deref().unwrap_or_default();
        let intent = OutboundIntent::from_trigger(
            OutboundIntentDraft::new(actor_ref, verb, "linear", target)
                .content_ref(content_ref.to_owned())
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
        (request, intent_ref)
    }

    /// FIX 6424 part 2a (CALLS `FIX 6424 Linear dual actor asks`): the
    /// approve-once digests this door's two asks on `call` name, scheduler
    /// first: the outbound dispatch's own `LinearDispatch` ask over the
    /// request this door dispatches the call under (its target, the content
    /// ref its staging names, its logical ref) with the mutation's mirror
    /// facts, and the TASK revision writer's `LinearMirror` ask
    /// ([`oneiron::Vault::linear_outbound_door_approval_digests`]). It stages,
    /// sends and records nothing.
    ///
    /// # Errors
    /// The door's own refusal of `call`, or the vault preview's.
    pub fn approval_digests(
        &self,
        mutation: &LinearMutation<'_>,
        call: &GraphQlCall,
    ) -> LinearSyncResult<[LinearRoleApproval; 2]> {
        let (effect, verb, target) = self.mutation_effect(mutation, call)?;
        let content_ref = request_ref(&effect.operation_id);
        let (request, _) = self.door_request(effect.operation_id, verb, target, &content_ref);
        self.vault
            .linear_outbound_door_approval_digests(&request, &effect)
    }
}

impl<T: GraphQlExecutor> LinearOutboundDoor for VaultLinearOutboundDoor<'_, T> {
    fn dispatch(
        &mut self,
        mutation: &LinearMutation<'_>,
        call: &GraphQlCall,
    ) -> LinearSyncResult<GraphQlValue> {
        let operation_id = mutation.operation_id;
        let (effect, verb, target) = self.mutation_effect(mutation, call)?;
        // FIX 6823: a retried send is rechecked over the request this door
        // dispatches it under, so its scheduler's kept press is read.
        let (recheck_request, _) =
            self.door_request(operation_id, verb, target, &request_ref(&operation_id));
        self.vault
            .recheck_admitted_linear_effect(&effect, &recheck_request)?;
        let content_ref = self
            .journal
            .stage_request(&operation_id, effect.task_ref, call)?;
        // FIX 8788: a full Rate window waits before each dispatch, up to the
        // door's wait, and a dispatch that met one at its admission waits
        // again; a door without a wait leaves it for a later pass.
        let now = Instant::now();
        let deadline = now.checked_add(self.rate_wait).unwrap_or(now);
        let mut turn = LinearRateTurn::default();
        let mut status = None;
        let result = loop {
            turn = self.vault.linear_rate_turn(&effect, deadline, turn)?;
            let (request, intent_ref) = self.door_request(operation_id, verb, target, &content_ref);
            let mut sink = LinearSink {
                journal: &mut self.journal,
                operation_id,
                task: effect.task_ref,
                call,
                intent_ref: &intent_ref,
                content_ref: &content_ref,
                status: &mut status,
            };
            let result = self
                .vault
                .dispatch_linear_outbound_intent_recorded(request, &effect, &mut sink)
                .map_err(|_| invalid("Linear outbound dispatch failed"))?;
            if result.outcome != OutboundDispatchOutcome::DeliveredToChannel
                && result
                    .gate_reason_codes
                    .iter()
                    .any(|code| code == LINEAR_RATE_WINDOW_REASON)
            {
                continue;
            }
            break result;
        };
        drop(turn);
        if result.outcome != OutboundDispatchOutcome::DeliveredToChannel {
            // FIX 6824: a hold for the owner's press is a typed hold naming
            // the blocking actor, its decision and its digest, copied from
            // the result.
            if let Some(hold) = LinearEffectHold::of_door_result(&result, &effect)
                && let Some(approval_digest) = hold.approval_digest
            {
                return Err(LinearSyncError::Held {
                    role: hold.role,
                    actor: hold.actor,
                    gate_decision_ref: hold.gate_decision_ref,
                    approval_digest,
                });
            }
            let mut refusal = DID_NOT_DELIVER.to_owned();
            if let Some(status) = status {
                refusal.push_str(&format!("{ANSWERED}{}", status_text(status)));
            }
            return Err(invalid(&refusal));
        }
        // The door's own admission is the push row's gate ref (OF-427 C9).
        if let Some(gate_ref) = result.gate_decision_id.as_deref() {
            self.vault.note_linear_outbound_gate(&effect, gate_ref)?;
        }
        self.journal
            .response(&operation_id, effect.task_ref)?
            .ok_or_else(|| invalid("Linear delivered effect has no response receipt"))
    }
}
