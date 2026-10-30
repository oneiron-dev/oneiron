//! SGN-02 uses the ordinary OF-327 gate and durable intent ledger.
use super::{
    ceremony::enqueue_seal,
    ledger::{append, state_in},
    model::*,
};
use crate::consent::AuthenticatedOwner;
use crate::outbound::*;
use crate::side_table::classified::SideGet;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Esign outbound dispatch marker. Key: bytes32 (blake3 of the intent ref).
const DISPATCH_MARKER: SideTable<[u8; 32], DispatchMarker, Raw> =
    SideTable::new(&side_table::ESIGN_DISPATCH_MARKER);
/// One admitted e-sign act: the command binding it ran under and, when the
/// vault owner made it himself (FIX 5238) or pressed it through once
/// (FIX 6362), his recorded act. Stored as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DispatchMarker {
    /// The immutable command binding (`esign-command:<sha256>`).
    pub(super) binding: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) owner_act: Option<OwnerSendAct>,
    /// The act's ledger identity when its dispatch named one apart from its
    /// intent ref (FIX 6644): the ref its OF-327 row and its press are
    /// keyed by, which its deliveries look the admitted call up under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) ledger_identity_ref: Option<String>,
}
/// The vault owner's act an admitted e-sign act records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum OwnerSendAct {
    /// His own send, remind or void: his actor and the decision his
    /// revalidated proof carried.
    Direct { actor: String, decision_ref: String },
    /// His one-time press on an agent's send or reminder, as the gate spent
    /// it admitting this act: the ledger intent the press released and the
    /// effect digest it approved, both lower-hex (FIX 6362).
    Approved {
        intent_ref: String,
        effect_digest: String,
    },
}
impl RawValue for DispatchMarker {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        serde_json::to_vec(self).map_err(|_| invalid("dispatch marker encoding").into())
    }
    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        serde_json::from_slice(bytes).map_err(|_| invalid("dispatch marker schema").into())
    }
}
/// The owner's one-time press the gate spent admitting the e-sign act
/// `request` carries, as the ledger row that admission committed records it:
/// call 0 of the act's dispatch attempt, on the e-sign channel, for this
/// act's verb, target and command `binding`. `None` when no press released
/// it. The proof is the gate's alone; no caller supplies it. FIX 6644 (L10
/// 09:41, Engine 10:13): the row and the pinned send ref are the act's
/// `ledger_identity` when its dispatch named one, else its intent ref, as
/// the pin is `ledger_identity_ref.unwrap_or(intent_ref)`.
fn admitted_owner_press_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &OutboundExecutionRequest<'_>,
    binding: &str,
    ledger_identity: Option<&str>,
) -> Result<Option<OwnerSendAct>> {
    #[derive(Deserialize)]
    struct Bound {
        channel: String,
        verb: String,
        target: String,
        #[serde(default)]
        content_ref: Option<String>,
        #[serde(default)]
        approval_send_ref: Option<String>,
    }
    let identity = ledger_identity.unwrap_or(request.intent_ref);
    let attempt = crate::outbound::outbound_dispatch_attempt_id(identity)
        .map_err(|_| invalid("dispatch attempt id"))?;
    let record =
        crate::outbound_intent_ledger::read_intent_for_attempt_in_txn(vault, txn, attempt, 0)
            .map_err(|error| match error {
                crate::outbound_intent_ledger::IntentLedgerError::Engine(error) => error,
                _ => invalid("dispatch ledger row"),
            })?;
    let Some((record, proof)) =
        record.and_then(|record| record.admitted_approval.map(|proof| (record, proof)))
    else {
        return Ok(None);
    };
    let frozen: Bound =
        serde_json::from_slice(record.payload()).map_err(|_| invalid("dispatch frozen call"))?;
    let verb = request.intent.verb.as_str();
    if record.server != "esign"
        || record.tool != verb
        || frozen.channel != "esign"
        || frozen.verb != verb
        || frozen.target != request.intent.target
        || frozen.content_ref.as_deref() != Some(binding)
        // FIX 6424: the one send the press approved is this act's own.
        || frozen.approval_send_ref.as_deref() != Some(identity)
    {
        return Ok(None);
    }
    Ok(Some(OwnerSendAct::Approved {
        intent_ref: crate::entity_id::bytes_to_hex_lower(&proof.intent_id()),
        effect_digest: proof.effect_digest().to_hex(),
    }))
}
/// The marker of the act `intent_ref` admitted, if one ran: the store's own
/// failure (the outer error) apart from a marker that does not decode (the
/// inner one), which waits only the delivery that reads it (FIX 6482).
pub(super) fn dispatch_marker_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    intent_ref: &str,
) -> Result<Result<Option<DispatchMarker>>> {
    match DISPATCH_MARKER.get_classified(
        &vault.store,
        txn,
        blake3::hash(intent_ref.as_bytes()).as_bytes(),
    ) {
        SideGet::Missing => Ok(Ok(None)),
        SideGet::Decoded(marker) => Ok(Ok(Some(marker))),
        SideGet::DecodeError(unreadable) => Ok(Err(unreadable)),
        SideGet::StoreError(error) => Err(error),
    }
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
    /// A narrowed caller's ceiling (FIX 6403), judged in the writer that
    /// records the gate decision and again in the act's own write; `None`
    /// for every other act.
    scope: Option<EsignActScope<'a>>,
    /// A narrowed act's own store, writer or lane-read failure in its
    /// write: the dispatch's error, never a changed state (FIX 6403).
    error: Option<crate::Error>,
    /// The dispatch's ledger identity, when it names one (FIX 6644).
    ledger_identity: Option<String>,
}
/// A narrowed caller's ceiling on one outbound e-sign act (FIX 6403,
/// `lane_scope`).
pub(super) struct EsignActScope<'a> {
    /// The bound actor, whose content writer on the document lands the act.
    pub(super) writer: crate::WriteActor,
    /// Whether the caller's lane still reaches the document and every
    /// original its trail names, read in the snapshot given.
    pub(super) reaches: &'a dyn Fn(&heed::RoTxn<'_>) -> Result<bool>,
}
/// Why an act's write landed nothing.
enum NotApplied {
    /// The act's own refusal: its state or binding changed.
    Refused,
    /// A narrowed caller's lane no longer reaches the document or an
    /// original (FIX 6403).
    ScopeChanged,
    /// The store's, the writer's or the lane read's own failure (FIX 6403);
    /// an unrestricted act's store failure too (FIX 11863).
    Failed(crate::Error),
}
impl From<crate::Error> for NotApplied {
    /// The esign ledger's own refusal ([`super::model::invalid`]) inside the
    /// act is the act's refusal; every other error is a failure (FIX 11863).
    fn from(error: crate::Error) -> Self {
        match error {
            crate::Error::InvalidConfig(_) => Self::Refused,
            error => Self::Failed(error),
        }
    }
}
impl OutboundExecutionSink for EsignSink<'_> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        let act = |txn: &mut heed::RwTxn<'_>| -> std::result::Result<EntityId, NotApplied> {
            let id = EntityId::from_hex(&self.command.document)?;
            let marker = *blake3::hash(request.intent_ref.as_bytes()).as_bytes();
            let binding = request
                .intent
                .content_ref
                .as_deref()
                .ok_or(NotApplied::Refused)?;
            if let Some(prior) = DISPATCH_MARKER.get(&self.vault.store, txn, &marker)? {
                if prior.binding != binding {
                    return Err(NotApplied::Refused);
                }

                return Ok(id);
            }
            // The owner's own act is recorded with his proof, revalidated
            // under this writer, so a delivery minted later can cite it. An
            // agent's send or reminder records the owner's press the gate
            // spent admitting it, read off the row that admission committed.
            let owner_act = match self.owner {
                Some(owner) => {
                    let actor = super::principals::verify_owner(self.vault, txn, owner)?;
                    (request.intent.actor == actor.to_hex()).then(|| OwnerSendAct::Direct {
                        actor: actor.to_hex(),
                        decision_ref: owner.decision_id().to_hex(),
                    })
                }
                None if self.command.verb != EsignOutboundVerb::Void => admitted_owner_press_in(
                    self.vault,
                    txn,
                    request,
                    binding,
                    self.ledger_identity.as_deref(),
                )?,
                None => None,
            };
            let recorded = DispatchMarker {
                binding: binding.to_owned(),
                owner_act,
                ledger_identity_ref: self.ledger_identity.clone(),
            };
            if self.automated
                && !super::principals::automated_outbound_allowed(
                    self.vault,
                    txn,
                    request.intent.on_behalf_of.as_deref(),
                )?
            {
                return Err(NotApplied::Refused);
            }
            let mut state = if self.command.verb == EsignOutboundVerb::Void {
                super::ledger::restrictive_state_in(self.vault, txn, id)?
            } else {
                state_in(self.vault, txn, id)?
            };
            if state.document.recipients.len() != self.command.recipient_count {
                return Err(NotApplied::Refused);
            }
            for item in &state.document.items {
                let item_id = EntityId::from_hex(&item.artifact_ref)?;
                let original =
                    super::super::read_blob_artifact_head_in_txn(&self.vault.store, txn, &item_id)?
                        .ok_or(NotApplied::Refused)?;
                if original.version != item.original_version {
                    return Err(NotApplied::Refused);
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
                    // FIX 6219: the act its staged notices go out under.
                    super::notice_send_act::record_send_act_in_txn(
                        self.vault,
                        txn,
                        id,
                        request,
                        self.ledger_identity.as_deref(),
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
                        return Err(NotApplied::Refused);
                    }
                    if let Some((recipient, rung)) = &self.reminder {
                        if super::lifecycle::reminder_due(self.vault, txn, id, recipient, self.now)?
                            != Some(*rung)
                        {
                            return Err(NotApplied::Refused);
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
                                .ok_or(NotApplied::Refused)?;
                            if self.now > sent.at.saturating_add(rules.reminder_cap_seconds) {
                                return Err(NotApplied::Refused);
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
                            reason: self.command.reason.clone().ok_or(NotApplied::Refused)?,
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
        };
        // FIX 6403: a narrowed caller's act lands through its content writer
        // on the document (its Grant at the document's position in a shared
        // vault, never a whole-vault one), its lane judged again there first.
        // FIX 11863: the act tells its own refusal from the store's failure,
        // so a store failure reads `esign_not_applied` with its error, never
        // `esign_state_or_binding_changed`.
        let result = match &self.scope {
            None => self.vault.try_with_write_txn_grouped(act),
            Some(scope) => EntityId::from_hex(&self.command.document)
                .map_err(NotApplied::from)
                .and_then(|document| {
                    self.vault
                        .try_with_actor_content_write_txn(scope.writer, |content| {
                            content.update_artifact(document, |txn| {
                                if !(scope.reaches)(txn)? {
                                    return Err(NotApplied::ScopeChanged);
                                }
                                act(txn)
                            })
                        })
                }),
        };
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
            Err(NotApplied::Refused) => {
                OutboundExecutionOutcome::failed("esign_state_or_binding_changed")
            }
            Err(NotApplied::ScopeChanged) => {
                OutboundExecutionOutcome::failed("esign_scope_changed")
            }
            // Nothing landed: a definite non-delivery to OF-327, and the
            // error itself to the dispatch, which surfaces it.
            Err(NotApplied::Failed(error)) => {
                self.error = Some(error);
                OutboundExecutionOutcome::failed("esign_not_applied")
            }
        }
    }

    /// A narrowed caller's lane, judged in the writer that records the
    /// act's gate decision before it records one (FIX 6403): no decision is
    /// recorded for a document out of its reach, refused as the door
    /// refuses it. Every other act is not judged here.
    fn admit_in(&self, txn: &heed::RoTxn<'_>) -> Result<()> {
        match &self.scope {
            Some(scope) if !(scope.reaches)(txn)? => Err(super::lane_scope::unreached()),
            _ => Ok(()),
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
        self.dispatch_esign_inner(request, command, (ip, user_agent), None, None, None)
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
        self.dispatch_esign_inner(request, command, (None, None), None, Some(owner), None)
    }
    /// [`Self::dispatch_esign`], or [`Self::dispatch_esign_as_owner`] with
    /// `owner`, for a narrowed caller (FIX 6403): `scope` judges its lane in
    /// the writer that records the gate decision, where a document out of
    /// its reach records no decision and is refused as the door refuses it,
    /// and again in the act's own write, which lands through the caller's
    /// content writer on the document and is the failed outcome
    /// `esign_scope_changed` once the lane no longer reaches it. A store,
    /// writer or lane-read failure there is the dispatch's error.
    pub(super) fn dispatch_esign_in_scope(
        &self,
        request: OutboundDispatchRequest,
        command: &EsignOutboundCommand,
        owner: Option<&AuthenticatedOwner>,
        scope: EsignActScope<'_>,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        self.dispatch_esign_inner(request, command, (None, None), None, owner, Some(scope))
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
            None,
        )
    }
    /// FIX 6424 (Engine 10-20 20:4x): the approve-once digest an owner's
    /// one-time press must name to release the e-sign act `request` asks
    /// for with `command` once the Gate holds it: the act's command binding,
    /// as [`Self::dispatch_esign`] computes it, under
    /// [`crate::outbound::outbound_approve_once_digest`]. The press pins
    /// the document, that binding and the act's stable send ref (its
    /// `ledger_identity_ref` when it names one, else its intent ref), so only
    /// the act that keeps them spends it. A held act's dispatch result carries the same
    /// digest as `approval_digest`. It reads and records nothing else.
    /// `reminder` is the `(recipient, rung)` a reminder sweep binds
    /// ([`Self::sweep_esign_reminders`]), `None` for every other act.
    /// # Errors
    /// The refusals [`Self::dispatch_esign`] makes before its gate.
    pub fn esign_approve_once_digest(
        &self,
        request: &OutboundDispatchRequest,
        command: &EsignOutboundCommand,
        reminder: Option<(&str, u32)>,
    ) -> std::result::Result<Option<crate::consent::EffectDigest>, OutboundDispatchError> {
        let reminder = reminder.map(|(recipient, rung)| (recipient.to_owned(), rung));
        let mut request = request.clone();
        request.intent.content_ref =
            Some(self.esign_command_binding(&request, command, &reminder)?);
        crate::outbound::outbound_approve_once_digest(self, &request)
    }
    /// The immutable binding (`esign-command:<sha256>`) an e-sign act runs
    /// under: its command, the document as it stands and the reminder.
    fn esign_command_binding(
        &self,
        request: &OutboundDispatchRequest,
        command: &EsignOutboundCommand,
        reminder: &Option<(String, u32)>,
    ) -> std::result::Result<String, OutboundDispatchError> {
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
        let bytes = serde_json::to_vec(&(command, &state.document, reminder))
            .map_err(|_| invalid("command encoding"))?;
        Ok(format!(
            "esign-command:{}",
            crate::entity_id::bytes_to_hex_lower(&Sha256::digest(&bytes))
        ))
    }
    fn dispatch_esign_inner(
        &self,
        mut request: OutboundDispatchRequest,
        command: &EsignOutboundCommand,
        (ip, user_agent): (Option<String>, Option<String>),
        reminder: Option<(String, u32)>,
        owner: Option<&AuthenticatedOwner>,
        scope: Option<EsignActScope<'_>>,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        request.intent.content_ref =
            Some(self.esign_command_binding(&request, command, &reminder)?);
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
            scope,
            error: None,
            ledger_identity: request.ledger_identity_ref.clone(),
        };
        let result = match owner {
            Some(owner) => self.dispatch_outbound_intent_as_owner(request, owner, &mut sink),
            None => OutboundDispatchPipeline.dispatch(self, request, &mut sink),
        };
        // FIX 6403: a narrowed act's own write failure surfaces here.
        if let Some(error) = sink.error.take() {
            return Err(error.into());
        }
        result
    }
    /// Expiry is an unsealed terminal and never queues a seal job.
    pub fn expire_esign_document(&self, document: EntityId, now: u64) -> Result<()> {
        self.sweep_esign_expiry(&[document], now).map(|_| ())
    }
}
