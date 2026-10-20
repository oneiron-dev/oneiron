//! SGN-02 uses the ordinary OF-327 gate and durable intent ledger.
use super::{
    ceremony::enqueue_seal,
    ledger::{append, state_in},
    model::*,
};
use crate::consent::AuthenticatedOwner;
use crate::outbound::*;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Esign outbound dispatch marker. Key: bytes32 (blake3 of the intent ref).
const DISPATCH_MARKER: SideTable<[u8; 32], DispatchMarker, Raw> =
    SideTable::new(&side_table::ESIGN_DISPATCH_MARKER);
/// One admitted e-sign act: the command binding it ran under and, when the
/// vault owner made it himself, his recorded act (FIX 5238). Stored as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DispatchMarker {
    /// The immutable command binding (`esign-command:<sha256>`).
    pub(super) binding: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) owner_act: Option<OwnerSendAct>,
}
/// The owner's own send, remind or void: his actor and the decision his
/// revalidated proof carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OwnerSendAct {
    pub(super) actor: String,
    pub(super) decision_ref: String,
}
impl RawValue for DispatchMarker {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        serde_json::to_vec(self).map_err(|_| invalid("dispatch marker encoding").into())
    }
    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        serde_json::from_slice(bytes).map_err(|_| invalid("dispatch marker schema").into())
    }
}
/// The marker of the act `intent_ref` admitted, if one ran.
pub(super) fn dispatch_marker_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    intent_ref: &str,
) -> Result<Option<DispatchMarker>> {
    DISPATCH_MARKER.get(
        &vault.store,
        txn,
        blake3::hash(intent_ref.as_bytes()).as_bytes(),
    )
}
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
    /// The vault owner's proof, when the act is his own.
    owner: Option<&'a AuthenticatedOwner>,
}
impl OutboundExecutionSink for EsignSink<'_> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        let result = self.vault.with_write_txn_grouped(|txn| {
            let id = EntityId::from_hex(&self.command.document)?;
            let marker = *blake3::hash(request.intent_ref.as_bytes()).as_bytes();
            let binding = request
                .intent
                .content_ref
                .as_deref()
                .ok_or_else(|| invalid("missing command binding"))?;
            if let Some(prior) = DISPATCH_MARKER.get(&self.vault.store, txn, &marker)? {
                if prior.binding != binding {
                    return Err(invalid("dispatch replay binding changed"));
                }

                return Ok(id);
            }
            // The owner's own act is recorded with his proof, revalidated
            // under this writer, so a delivery minted later can cite it.
            let owner_act = match self.owner {
                Some(owner) => {
                    let actor = super::principals::verify_owner(self.vault, txn, owner)?;
                    (request.intent.actor == actor.to_hex()).then(|| OwnerSendAct {
                        actor: actor.to_hex(),
                        decision_ref: owner.decision_id().to_hex(),
                    })
                }
                None => None,
            };
            let recorded = DispatchMarker {
                binding: binding.to_owned(),
                owner_act,
            };
            if self.automated
                && !super::principals::automated_outbound_allowed(
                    self.vault,
                    txn,
                    request.intent.on_behalf_of.as_deref(),
                )?
            {
                return Err(invalid("autonomous send is outside the principal envelope"));
            }
            let mut state = if self.command.verb == EsignOutboundVerb::Void {
                super::ledger::restrictive_state_in(self.vault, txn, id)?
            } else {
                state_in(self.vault, txn, id)?
            };
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
                    DISPATCH_MARKER.put(&self.vault.store, txn, &marker, &recorded)?;

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
            DISPATCH_MARKER.put(&self.vault.store, txn, &marker, &recorded)?;

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
        self.dispatch_esign_inner(request, command, (ip, user_agent), None, None)
    }
    /// [`Self::dispatch_esign`] for the vault owner's own act: admission
    /// rechecks his proof under its writer, and the act is recorded with it,
    /// so each delivery it queues mints its own signing link (FIX 5238).
    pub fn dispatch_esign_as_owner(
        &self,
        request: OutboundDispatchRequest,
        command: &EsignOutboundCommand,
        owner: &AuthenticatedOwner,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        self.dispatch_esign_inner(request, command, (None, None), None, Some(owner))
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
            (None, None),
            Some((recipient.to_owned(), rung)),
            None,
        )
    }
    fn dispatch_esign_inner(
        &self,
        mut request: OutboundDispatchRequest,
        command: &EsignOutboundCommand,
        (ip, user_agent): (Option<String>, Option<String>),
        reminder: Option<(String, u32)>,
        owner: Option<&AuthenticatedOwner>,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        let document = EntityId::from_hex(&command.document)?;
        if request.intent.channel != "esign"
            || request.intent.verb != command.verb.as_str()
            || request.intent.target != document.to_hex()
        {
            return Err(invalid("dispatch binding mismatch").into());
        }
        // A void narrows the document, so it is admitted on the whole chain.
        let state = if command.verb == EsignOutboundVerb::Void {
            let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
            super::ledger::restrictive_state_in(self, &txn, document)?
        } else {
            self.esign_document(document)?
        };
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
        let mut sink = EsignSink {
            vault: self,
            command,
            actor,
            automated,
            now,
            reminder,
            owner,
        };
        match owner {
            Some(owner) => self.dispatch_outbound_intent_as_owner(request, owner, &mut sink),
            None => OutboundDispatchPipeline.dispatch(self, request, &mut sink),
        }
    }
    /// Expiry is an unsealed terminal and never queues a seal job.
    pub fn expire_esign_document(&self, document: EntityId, now: u64) -> Result<()> {
        self.sweep_esign_expiry(&[document], now).map(|_| ())
    }
}
