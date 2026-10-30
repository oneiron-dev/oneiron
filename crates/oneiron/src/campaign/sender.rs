//! One campaign program step's send through the served channel transports
//! (FIX 11513). The enrollment leg freezes a typed JSON envelope as the
//! outbound payload; this sender decodes it, pre-checks the filed step
//! body, and executes the send on the served sink for the frozen channel
//! and verb. Slack, LINE, Gmail and native mail ship here (FIX 11641,
//! FIX 11642).
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
use crate::channel_identity_provider::EMAIL_CHANNEL;
use crate::channel_identity_provider::gmail::{
    GmailDelegatedAdapter, GmailSendPlan, GmailSendSink, HttpGmailSendWire,
};
use crate::channel_identity_provider::stalwart::{
    NativeMailMessage, StalwartClient, StalwartSendSink,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::outbound::{
    OutboundExecutionOutcome, OutboundExecutionOutcomeKind, OutboundExecutionRequest,
    OutboundExecutionSink, OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
    OutboundVerbContract, OwnedServedChannelSink, outbound_verb_contract,
    provider_retry_after_secs,
};
use crate::outbound_consent::{OutboundResultSender, OutboundTransportResult, RawOutboundResult};
use crate::outbound_intent_ledger::{
    FrozenOutboundCall, OutboundFailureKind, OutboundSendFailure, OutboundSendOutcome,
    ProviderWait, RemoteTaskHandle,
};

/// The enrollment leg's frozen envelope, v1: the resolved target, the
/// pinned step-body ref, the member's party key (so erasing the person
/// stops the send), and the enrollment event's owner actor and ref. Email
/// steps (FIX 11641) carry three more keys: the program subject, the
/// composition time, and the sticky sender. No other keys; a non-email
/// leg emits exactly the five base keys.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignOutboundEnvelope {
    target: String,
    content_ref: String,
    counterparty_ref: String,
    actor: String,
    trigger_ref: String,
    /// Email-only: the program row's subject.
    #[serde(default)]
    subject: Option<String>,
    /// Email-only: the enrollment event's detection time (Unix seconds),
    /// frozen as the mail `Date:`.
    #[serde(default)]
    composed_at: Option<u64>,
    /// Email-only: the step's sticky sender identity, entity hex.
    #[serde(default)]
    sender_ref: Option<String>,
}

/// The frozen email keys of one campaign send (FIX 11641), required iff
/// the frozen server is email.
struct EmailSendKeys {
    subject: String,
    composed_at: u64,
    sender_ref: EntityId,
}

/// A campaign send's result sender: the envelope decode, the filed-body
/// pre-check, and the served sink behind them.
pub struct CampaignChannelSender {
    vault: Arc<Vault>,
    sink: OwnedServedChannelSink,
    remote: Option<RemoteTaskHandle>,
    provider_wait: Option<ProviderWait>,
    stalwart: Option<StalwartClient>,
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
            stalwart: None,
        }
    }

    /// The host-owned Stalwart client the stalwart branch sends through
    /// (FIX 11642): the server builds one per send from its
    /// `[native_mail]` placement and the checked connection's credential
    /// and injects it here. Without it the stalwart branch fails closed.
    #[must_use]
    pub fn with_stalwart(mut self, client: StalwartClient) -> Self {
        self.stalwart = Some(client);
        self
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

    /// The gmail branch (FIX 11641): the frozen email keys name the sender
    /// row, whose delegated grant derives the member adapter; the frozen
    /// body, subject and composition time seal one send plan, which the
    /// gmail sink executes over the production send wire. The adapter, wire
    /// and sink are per-`send()` locals; no sender-struct fields needed.
    ///
    /// Sink-contract checklist (the campaign gmail send is the stack's
    /// first production consumer): channel `email` + verb `send` from the
    /// shared preamble's contract; `channel_identity_ref` is the sender
    /// row; `intent.content_ref` is the registered plan ref, never the
    /// step-body ref (K1 stays on the envelope ref); the intent target and
    /// the counterparty are both the plan's canonical recipient;
    /// `calendar_invite` is none; hygiene headers are empty.
    fn send_gmail(
        &mut self,
        call: &FrozenOutboundCall,
        envelope: &CampaignOutboundEnvelope,
        keys: &EmailSendKeys,
        verb_contract: &'static OutboundVerbContract,
        intent_id_hex: &str,
    ) -> OutboundTransportResult {
        let Ok(adapter) =
            GmailDelegatedAdapter::from_campaign_sender_row(&self.vault, keys.sender_ref)
        else {
            return self.invalid();
        };
        let Ok(Some(body_text)) = self.vault.campaign_step_body_text(&envelope.content_ref) else {
            return self.invalid();
        };
        let Ok(plan) = GmailSendPlan::new(
            &adapter,
            intent_id_hex,
            &envelope.target,
            &keys.subject,
            &body_text,
            None,
            keys.composed_at,
        ) else {
            return self.invalid();
        };
        // The sink binds the plan's canonical recipient to the intent
        // target and the counterparty alike (as the dispatch pipeline's
        // native-mail binding does): all three are the plan's recipient,
        // never the envelope's party key.
        let recipient = plan.recipient().to_owned();
        let plan_ref = plan.content_ref().to_owned();
        let Ok(wire) = HttpGmailSendWire::new() else {
            return self.invalid();
        };
        let mut sink = GmailSendSink::new(&self.vault, &adapter, keys.sender_ref, wire);
        sink.add_plan(plan);
        let mut draft = OutboundIntentDraft::new(
            envelope.actor.clone(),
            call.tool(),
            call.server(),
            recipient.clone(),
        )
        .content_ref(plan_ref);
        if let Some(idempotency_key) = call.idempotency_key() {
            draft = draft.idempotency_key(idempotency_key);
        }
        let intent = OutboundIntent::from_trigger(
            draft,
            OutboundIntentTrigger::campaign(envelope.trigger_ref.clone()),
        );
        let request = OutboundExecutionRequest {
            intent_ref: intent_id_hex,
            intent: &intent,
            // `email/send` never honors the ledger key
            // (NonIdempotentInterrupt); the sink ignores the key either way.
            idempotency_key: None,
            verb_contract,
            channel_identity_ref: Some(keys.sender_ref),
            space_posting: None,
            counterparty_ref: Some(recipient.as_str()),
            linkedin_sandbox_policy: None,
            hygiene_headers: BTreeMap::new(),
            apns_interruption_level: None,
            calendar_invite: None,
        };
        let execution = sink.execute(&request);
        self.settle_execution(execution)
    }

    /// The stalwart branch (FIX 11642): the frozen email keys name the
    /// sender row, which must already be provisioned as a native mailbox;
    /// the frozen body, subject and target seal one native message, which
    /// the stalwart sink submits over the injected host-owned client. The
    /// message and sink are per-`send()` locals; the client rides the
    /// sender struct because only the server can build it.
    ///
    /// Sink-contract checklist: channel `email` + verb `send`;
    /// `channel_identity_ref` is the sender row; `intent.content_ref` is
    /// the sealed message ref, never the step-body ref (K1 stays on the
    /// envelope ref); the intent target and the counterparty are both the
    /// message's canonical recipient; `calendar_invite` is none; hygiene
    /// headers are empty. The composed time stays frozen on the envelope
    /// but the wire ignores it: the Message-ID derives from the ledger
    /// key at send time.
    fn send_stalwart(
        &mut self,
        call: &FrozenOutboundCall,
        envelope: &CampaignOutboundEnvelope,
        keys: &EmailSendKeys,
        verb_contract: &'static OutboundVerbContract,
        intent_id_hex: &str,
    ) -> OutboundTransportResult {
        let Some(client) = self.stalwart.as_ref() else {
            return self.invalid();
        };
        let Ok(Some(body_text)) = self.vault.campaign_step_body_text(&envelope.content_ref) else {
            return self.invalid();
        };
        let Ok(message) = NativeMailMessage::new(
            &envelope.target,
            keys.subject.clone(),
            Some(body_text),
            None,
        ) else {
            return self.invalid();
        };
        // As the gmail branch: the intent target and the counterparty are
        // both the sealed canonical recipient, never the envelope's party
        // key.
        let recipient = message.to.clone();
        let Ok(message_ref) = message.content_ref() else {
            return self.invalid();
        };
        let execution = {
            let Ok(mut sink) = StalwartSendSink::new(client, &message) else {
                return self.invalid();
            };
            let mut draft = OutboundIntentDraft::new(
                envelope.actor.clone(),
                call.tool(),
                call.server(),
                recipient.clone(),
            )
            .content_ref(message_ref);
            if let Some(idempotency_key) = call.idempotency_key() {
                draft = draft.idempotency_key(idempotency_key);
            }
            let intent = OutboundIntent::from_trigger(
                draft,
                OutboundIntentTrigger::campaign(envelope.trigger_ref.clone()),
            );
            let request = OutboundExecutionRequest {
                intent_ref: intent_id_hex,
                intent: &intent,
                // `email/send` never honors the ledger key
                // (NonIdempotentInterrupt); the sink keys its draft on the
                // intent key-or-ref instead.
                idempotency_key: None,
                verb_contract,
                channel_identity_ref: Some(keys.sender_ref),
                space_posting: None,
                counterparty_ref: Some(recipient.as_str()),
                linkedin_sandbox_policy: None,
                hygiene_headers: BTreeMap::new(),
                apns_interruption_level: None,
                calendar_invite: None,
            };
            sink.execute(&request)
        };
        self.settle_execution(execution)
    }

    /// Settles one sink execution the dispatch pipeline's way, for the
    /// served, gmail and stalwart branches alike: Delivered hands Acked,
    /// Deferred hands its remote task on, a Failed that may have delivered
    /// is Ambiguous, and any other Failed is a definite non-delivery that
    /// hands its provider wait on. Stale handles never answer for an
    /// older send.
    fn settle_execution(&mut self, execution: OutboundExecutionOutcome) -> OutboundTransportResult {
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
        // FIX 11641: the leg freezes the email keys iff the step's channel
        // is email; the sender requires them iff the frozen server is
        // email, and refuses them otherwise, so slack/line envelopes stay
        // exactly the five base keys.
        let email_keys = match (
            call.server() == EMAIL_CHANNEL,
            envelope.subject.as_ref(),
            envelope.composed_at,
            envelope.sender_ref.as_ref(),
        ) {
            (true, Some(subject), Some(composed_at), Some(sender_ref)) => {
                let Ok(sender_ref) = EntityId::from_hex(sender_ref) else {
                    return self.invalid();
                };
                Some(EmailSendKeys {
                    subject: subject.clone(),
                    composed_at,
                    sender_ref,
                })
            }
            (false, None, None, None) => None,
            _ => return self.invalid(),
        };
        if let Some(keys) = &email_keys {
            // An email send routes on its sender row: a DelegatedGrant
            // sender is a member mailbox and sends through the gmail sink;
            // any other email sender is attempted through the stalwart
            // sink, whose mailbox binding answers for provisioned native
            // mailboxes and fails closed otherwise (FIX 11642). An
            // unreadable or absent sender row is not a sendable campaign
            // envelope.
            let gmail = match self.vault.get_channel_identity(&keys.sender_ref) {
                Ok(Some(row)) => row.grant().is_some(),
                _ => return self.invalid(),
            };
            if gmail {
                return self.send_gmail(call, &envelope, keys, verb_contract, &intent_id_hex);
            }
            return self.send_stalwart(call, &envelope, keys, verb_contract, &intent_id_hex);
        }
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
            // The served sink ignores the sender identity; each email
            // branch names it on its own request (FIX 11641, FIX 11642).
            channel_identity_ref: None,
            space_posting: None,
            counterparty_ref: Some(envelope.counterparty_ref.as_str()),
            linkedin_sandbox_policy: None,
            // Campaign sends freeze no hygiene headers: email ships empty
            // as slack/line do (FIX 11641, FIX 11642); the unsubscribe
            // minter is a follow-on.
            hygiene_headers: BTreeMap::new(),
            apns_interruption_level: None,
            calendar_invite: None,
        };
        let execution = self.sink.execute(&request);
        self.settle_execution(execution)
    }

    fn remote_task(&self) -> Option<RemoteTaskHandle> {
        self.remote.clone()
    }

    fn provider_wait(&self) -> Option<ProviderWait> {
        self.provider_wait
    }
}
