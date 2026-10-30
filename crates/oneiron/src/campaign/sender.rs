//! One campaign program step's send through the served channel transports
//! (FIX 11513). The enrollment leg freezes a typed JSON envelope as the
//! outbound payload; this sender decodes it, pre-checks the filed step
//! body, and executes the send on the served sink for the frozen channel
//! and verb. Slack and LINE ship here; email rides FIX 11641/11642.
//!
//! The envelope decode is strict: any other shape — including a program
//! written before the body filer, whose raw bytes carry no envelope —
//! fails as [`OutboundFailureKind::InvalidRequest`], never as a literal
//! fallback or a second send. The leg's `SenderTransport` drops this
//! sender's raw result (it forwards only the outcome, the remote task,
//! and the provider wait), so the raw result stays empty on every path.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Deserialize;

use crate::Vault;
use crate::entity_id::bytes_to_hex_lower;
use crate::outbound::{
    OutboundExecutionOutcomeKind, OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent,
    OutboundIntentDraft, OutboundIntentTrigger, OwnedServedChannelSink, outbound_verb_contract,
    provider_retry_after_secs,
};
use crate::outbound_consent::{OutboundResultSender, OutboundTransportResult, RawOutboundResult};
use crate::outbound_intent_ledger::{
    FrozenOutboundCall, OutboundFailureKind, OutboundSendFailure, OutboundSendOutcome,
    ProviderWait, RemoteTaskHandle,
};

/// The enrollment leg's frozen envelope, v1: the resolved target, the
/// pinned step-body ref, the member's party key (so erasing the person
/// stops the send), and the enrollment event's owner actor and ref. No
/// other keys; the leg emits exactly these five.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignOutboundEnvelope {
    target: String,
    content_ref: String,
    counterparty_ref: String,
    actor: String,
    trigger_ref: String,
}

/// A campaign send's result sender: the envelope decode, the filed-body
/// pre-check, and the served sink behind them.
pub struct CampaignChannelSender {
    vault: Arc<Vault>,
    sink: OwnedServedChannelSink,
    remote: Option<RemoteTaskHandle>,
    provider_wait: Option<ProviderWait>,
}

impl CampaignChannelSender {
    /// The sender on `vault`, whose LINE pushes count against
    /// `line_push_allowance` — the host's `[line]` monthly allowance, the
    /// same source the connector reply worker hands its sink.
    #[must_use]
    pub fn new(vault: Arc<Vault>, line_push_allowance: u32) -> Self {
        Self {
            vault: Arc::clone(&vault),
            sink: OwnedServedChannelSink::new(vault, line_push_allowance),
            remote: None,
            provider_wait: None,
        }
    }

    /// Certain non-delivery: the frozen call is not a sendable campaign
    /// envelope. Any stale remote handle and provider wait are dropped
    /// with it.
    fn invalid(&mut self) -> OutboundTransportResult {
        self.remote = None;
        self.provider_wait = None;
        OutboundTransportResult {
            outcome: OutboundSendOutcome::Failed(OutboundSendFailure {
                kind: OutboundFailureKind::InvalidRequest,
                code: None,
            }),
            raw_result: RawOutboundResult::new(None, None, None, None),
        }
    }
}

impl OutboundResultSender for CampaignChannelSender {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundTransportResult {
        let Ok(envelope) = serde_json::from_slice::<CampaignOutboundEnvelope>(call.payload())
        else {
            return self.invalid();
        };
        // K1: an unresolvable body is InvalidRequest, never the served
        // sink's literal fallback — the sink is never reached without one.
        let resolves = matches!(
            self.vault.campaign_step_body_text(&envelope.content_ref),
            Ok(Some(_))
        );
        if !resolves {
            return self.invalid();
        }
        let Ok(verb_contract) = outbound_verb_contract(call.server(), call.tool()) else {
            return self.invalid();
        };
        let Some(intent_id) = call.intent_id() else {
            return self.invalid();
        };
        let intent_id_hex = bytes_to_hex_lower(intent_id);
        let mut draft =
            OutboundIntentDraft::new(envelope.actor, call.tool(), call.server(), envelope.target)
                .content_ref(envelope.content_ref);
        if let Some(idempotency_key) = call.idempotency_key() {
            draft = draft.idempotency_key(idempotency_key);
        }
        let intent = OutboundIntent::from_trigger(
            draft,
            OutboundIntentTrigger::campaign(envelope.trigger_ref),
        );
        let request = OutboundExecutionRequest {
            intent_ref: &intent_id_hex,
            intent: &intent,
            // As the dispatch pipeline: only provider-native and
            // replace-safe verbs expose the frozen ledger key.
            idempotency_key: if call.idempotency_supported() {
                call.idempotency_key()
            } else {
                None
            },
            verb_contract,
            // The served sink ignores the sender identity; email sinks
            // need it (FIX 11641/11642).
            channel_identity_ref: None,
            space_posting: None,
            counterparty_ref: Some(envelope.counterparty_ref.as_str()),
            linkedin_sandbox_policy: None,
            // Email rows own hygiene headers (FIX 11641/11642).
            hygiene_headers: BTreeMap::new(),
            apns_interruption_level: None,
            calendar_invite: None,
        };
        let execution = self.sink.execute(&request);
        // The dispatch pipeline's mapping, verbatim: Delivered->Acked,
        // Deferred->Deferred, Failed+possible->Ambiguous,
        // Failed->Failed(TransportNotStarted).
        let outcome = match execution.kind {
            OutboundExecutionOutcomeKind::DeliveredToChannel => OutboundSendOutcome::Acked,
            OutboundExecutionOutcomeKind::Deferred => OutboundSendOutcome::Deferred,
            OutboundExecutionOutcomeKind::Failed if execution.delivery_may_have_occurred => {
                OutboundSendOutcome::Ambiguous
            }
            OutboundExecutionOutcomeKind::Failed => {
                OutboundSendOutcome::Failed(OutboundSendFailure {
                    kind: OutboundFailureKind::TransportNotStarted,
                    code: None,
                })
            }
        };
        // Only a Deferred send hands a handle on; any other outcome drops
        // the stale one, so `remote_task` never answers for an older send.
        self.remote = match execution.kind {
            OutboundExecutionOutcomeKind::Deferred => execution.remote_task.clone(),
            _ => None,
        };
        // Only a Failed definite non-delivery the provider refused for rate
        // or quota hands a wait on (the dispatch pipeline's FIX 8818
        // predicate, transport.rs); any other outcome drops the stale one,
        // so `provider_wait` never answers for an older send.
        self.provider_wait = match execution.kind {
            OutboundExecutionOutcomeKind::Failed if !execution.delivery_may_have_occurred => {
                execution.provider_wait.map(|kind| ProviderWait {
                    kind,
                    retry_after_secs: provider_retry_after_secs(&execution),
                })
            }
            _ => None,
        };
        OutboundTransportResult {
            outcome,
            raw_result: RawOutboundResult::new(None, None, None, None),
        }
    }

    fn remote_task(&self) -> Option<RemoteTaskHandle> {
        self.remote.clone()
    }

    fn provider_wait(&self) -> Option<ProviderWait> {
        self.provider_wait
    }
}
