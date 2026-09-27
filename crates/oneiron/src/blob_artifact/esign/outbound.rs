//! SGN-02 uses the ordinary OF-327 gate and durable intent ledger.
use super::{
    ceremony::enqueue_seal,
    ledger::{append, state_in},
    model::*,
};
use crate::outbound::*;
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EsignOutboundVerb {
    SendForSignature,
    Remind,
    Void,
}
impl EsignOutboundVerb {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SendForSignature => "send_for_signature",
            Self::Remind => "remind",
            Self::Void => "void",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignOutboundCommand {
    pub document: String,
    /// Reviewed recipient count. Rechecked even on remind/resend.
    pub recipient_count: usize,
    pub verb: EsignOutboundVerb,
    pub reason: Option<String>,
}
struct EsignSink<'a> {
    vault: &'a Vault,
    command: &'a EsignOutboundCommand,
    actor: EsignAuditActor,
    automated: bool,
    now: u64,
    reminder: Option<(String, u32)>,
}
impl OutboundExecutionSink for EsignSink<'_> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        let result = self.vault.with_write_txn(|txn| {
            let id = EntityId::from_hex(&self.command.document)?;
            let marker = [
                b"esign.dispatch.v1/".as_slice(),
                blake3::hash(request.intent_ref.as_bytes()).as_bytes(),
            ]
            .concat();
            let binding = request
                .intent
                .content_ref
                .as_deref()
                .ok_or_else(|| invalid("missing command binding"))?;
            if let Some(prior) = self.vault.store.vault_meta.get(txn, &marker)? {
                if prior != binding.as_bytes() {
                    return Err(invalid("dispatch replay binding changed"));
                }
                return Ok(id);
            }
            if self.automated
                && !super::principals::automated_outbound_allowed(
                    self.vault,
                    txn,
                    request.intent.on_behalf_of.as_deref(),
                )?
            {
                return Err(invalid("autonomous send is outside the principal envelope"));
            }
            let mut state = state_in(self.vault, txn, id)?;
            if state.document.recipients.len() != self.command.recipient_count {
                return Err(invalid("recipient count changed"));
            }
            for item in &state.document.items {
                let item_id = EntityId::from_hex(&item.artifact_ref)?;
                let original =
                    super::super::read_blob_artifact_head_in_txn(&self.vault.store, txn, &item_id)?
                        .ok_or_else(|| invalid("missing original"))?;
                if original.version != item.original_version {
                    return Err(invalid("original PDF changed after admission"));
                }
            }
            let recipients = match self.command.verb {
                EsignOutboundVerb::SendForSignature => {
                    super::capability::require_recipient_capabilities(
                        self.vault, txn, id, &state, self.now,
                    )?;
                    state = append(
                        self.vault,
                        txn,
                        id,
                        EsignEvent::Sent,
                        self.actor.clone(),
                        self.now,
                    )?;
                    state
                        .document
                        .recipients
                        .iter()
                        .map(|r| r.id.clone())
                        .collect::<Vec<_>>()
                }
                EsignOutboundVerb::Remind => {
                    if state.status != DocumentStatus::Pending
                        || state.rejection.is_some()
                        || self.now >= state.document.expires_at
                    {
                        return Err(invalid("document cannot be reminded"));
                    }
                    if let Some((recipient, rung)) = &self.reminder {
                        if super::lifecycle::reminder_due(self.vault, txn, id, recipient, self.now)?
                            != Some(*rung)
                        {
                            return Err(invalid("reminder claim is no longer due"));
                        }
                        state = append(
                            self.vault,
                            txn,
                            id,
                            EsignEvent::Reminded {
                                recipient: recipient.clone(),
                                rung: *rung,
                            },
                            self.actor.clone(),
                            self.now,
                        )?;
                        vec![recipient.clone()]
                    } else {
                        if let Some(rules) = super::lifecycle::rules_in(self.vault, txn, id)? {
                            let sent = super::ledger::events_in(self.vault, txn, id)?
                                .into_iter()
                                .find(|row| matches!(row.event, EsignEvent::Sent))
                                .ok_or_else(|| invalid("pending document has no send claim"))?;
                            if self.now > sent.at.saturating_add(rules.reminder_cap_seconds) {
                                return Err(invalid("reminder cap elapsed"));
                            }
                        }
                        state
                            .document
                            .recipients
                            .iter()
                            .filter(|r| {
                                state.recipients[&r.id].signing == SigningStatus::Ready
                                    && self.now < state.recipients[&r.id].expires_at
                            })
                            .map(|r| r.id.clone())
                            .collect()
                    }
                }
                EsignOutboundVerb::Void => {
                    state = append(
                        self.vault,
                        txn,
                        id,
                        EsignEvent::Voided {
                            reason: self
                                .command
                                .reason
                                .clone()
                                .ok_or_else(|| invalid("void reason required"))?,
                        },
                        self.actor.clone(),
                        self.now,
                    )?;
                    let recipients = state
                        .document
                        .recipients
                        .iter()
                        .map(|r| r.id.clone())
                        .collect::<Vec<_>>();
                    super::lifecycle::notify(
                        self.vault,
                        txn,
                        id,
                        &state,
                        "void",
                        &recipients,
                        super::lifecycle::NoticeTrigger {
                            dispatch_ref: Some(request.intent_ref),
                            now: self.now,
                        },
                    )?;
                    self.vault
                        .store
                        .vault_meta
                        .put(txn, &marker, binding.as_bytes())?;
                    return Ok(id);
                }
            };
            let transition = if self.command.verb == EsignOutboundVerb::SendForSignature {
                "invite"
            } else {
                "reminder"
            };
            super::lifecycle::notify(
                self.vault,
                txn,
                id,
                &state,
                transition,
                &recipients,
                super::lifecycle::NoticeTrigger {
                    dispatch_ref: Some(request.intent_ref),
                    now: self.now,
                },
            )?;
            enqueue_seal(self.vault, txn, id, self.now)?;
            self.vault
                .store
                .vault_meta
                .put(txn, &marker, binding.as_bytes())?;
            Ok(id)
        });
        match result {
            Ok(id) => {
                OutboundExecutionOutcome::delivered_to_channel(format!("esign:{}", id.to_hex()))
                    .with_receipt_field(
                        "delivery_health",
                        if self.command.verb == EsignOutboundVerb::Void {
                            "local_terminal"
                        } else {
                            "enqueued"
                        },
                    )
            }
            Err(_) => OutboundExecutionOutcome::failed("esign_state_or_binding_changed"),
        }
    }
}
impl Vault {
    /// Only this adapter authors send/remind/void effects. The request retains
    /// normal gate, window, grant, rate-accounting and retry receipts.
    pub fn dispatch_esign(
        &self,
        request: OutboundDispatchRequest,
        command: &EsignOutboundCommand,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        self.dispatch_esign_inner(request, command, ip, user_agent, None)
    }
    pub(super) fn dispatch_esign_reminder(
        &self,
        request: OutboundDispatchRequest,
        command: &EsignOutboundCommand,
        recipient: &str,
        rung: u32,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        self.dispatch_esign_inner(
            request,
            command,
            None,
            None,
            Some((recipient.to_owned(), rung)),
        )
    }
    fn dispatch_esign_inner(
        &self,
        mut request: OutboundDispatchRequest,
        command: &EsignOutboundCommand,
        ip: Option<String>,
        user_agent: Option<String>,
        reminder: Option<(String, u32)>,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        let document = EntityId::from_hex(&command.document)?;
        if request.intent.channel != "esign"
            || request.intent.verb != command.verb.as_str()
            || request.intent.target != document.to_hex()
        {
            return Err(invalid("dispatch binding mismatch").into());
        }
        let state = self.esign_document(document)?;
        if state.document.recipients.len() != command.recipient_count {
            return Err(invalid("recipient count changed").into());
        }
        let bytes = serde_json::to_vec(&(command, &state.document, &reminder))
            .map_err(|_| invalid("command encoding"))?;
        request.intent.content_ref = Some(format!(
            "esign-command:{}",
            crate::entity_id::bytes_to_hex_lower(&Sha256::digest(&bytes))
        ));
        let actor = EsignAuditActor {
            actor: request.intent.actor.clone(),
            ip,
            user_agent,
        };
        let now = request.occurred_at;
        let automated = request.actor.actor_class != "human";
        OutboundDispatchPipeline.dispatch(
            self,
            request,
            &mut EsignSink {
                vault: self,
                command,
                actor,
                automated,
                now,
                reminder,
            },
        )
    }
    /// Expiry is an unsealed terminal and never queues a seal job.
    pub fn expire_esign_document(&self, document: EntityId, now: u64) -> Result<()> {
        self.sweep_esign_expiry(&[document], now).map(|_| ())
    }
}
