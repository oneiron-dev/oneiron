//! The Gmail delegated adapter's send doors: send-token injection, approve-once
//! and batch approvals, and the recorded dispatch with its thread record.
//! Entry: `GmailDelegatedAdapter::dispatch_send_recorded`. Defines its own items.

use super::*;

impl GmailDelegatedAdapter {
    /// The SEND credential door: runs `apply` with the grant's token for a
    /// LIVE send-capable row this adapter speaks for.
    ///
    /// Three checks, all before the injection: the adapter's grant carries
    /// `mail.send`; the stored row is this adapter's ACTIVE row with that same
    /// scope set; and the custody record still proves the grant, including the
    /// provider's granted-send evidence. That last re-proof is the egress-time
    /// one: a member who narrowed their Google consent after the row went live
    /// leaves a host that re-registers custody without the evidence, and the
    /// next send refuses here rather than at Google.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a read-only grant or a mismatched/inactive
    /// row, plus the custody and SECRET-02 door arms.
    pub fn with_send_token_at_door(
        &self,
        vault: &Vault,
        identity_id: EntityId,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<DoorInjectionReceipt> {
        self.with_send_token_at_door_admitting(vault, identity_id, None, apply)
    }

    /// [`Self::with_send_token_at_door`] for a send that may carry files
    /// (fix list row 17645): `retained`, the holder of a frozen send with
    /// files, judges that send once more in the door's own writer, after
    /// the row and custody checks and before the token is copied out, so an
    /// erase or a clearance revocation that commits first stops it here. The
    /// writer is released before `apply` runs; an erase that commits after
    /// it finds the send already under way.
    ///
    /// # Errors
    ///
    /// As [`Self::with_send_token_at_door`], and the holder's refusal.
    pub(crate) fn with_send_token_at_door_admitting(
        &self,
        vault: &Vault,
        identity_id: EntityId,
        retained: Option<&dyn RetainedMailMessage>,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<DoorInjectionReceipt> {
        self.require_send_grant()?;
        // The row check, the custody re-proof and the token copy share one
        // write transaction, so a release or scope removal cannot commit
        // between them (FIX 9676, the FIX 6011 pattern); the door drops it
        // before `apply` runs.
        let wtxn = vault.store.env.write_txn()?;
        self.require_active_row_matches_adapter_in_txn(vault, &wtxn, &identity_id)?;
        self.verify_custody_grant_in_txn(vault, &wtxn)?;
        if let Some(retained) = retained {
            retained.admit_in(&wtxn)?;
        }
        vault.inject_secret_at_door_in_txn(
            wtxn,
            &self.config.custody_record_ref,
            super::super::GMAIL_CONNECTOR_EFFECTOR,
            apply,
        )
    }

    /// Owner approval for exactly one member send: "a press per send".
    ///
    /// Mints no standing authority. The envelope must name this adapter's live
    /// send-capable row, bound to the request's actor, and a frozen
    /// [`GmailSendPlan`] content ref; the digest is the canonical mail
    /// operation's, so a changed recipient, plan or send ref needs a new press.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for an envelope this adapter does not speak
    /// for, plus the approve-once door's owner checks.
    pub fn approve_send_once(
        &self,
        vault: &Vault,
        owner: &AuthenticatedOwner,
        request: &OutboundDispatchRequest,
    ) -> Result<ConsentReceipt> {
        let (identity_ref, actor) = self.require_send_envelope(vault, request)?;
        approve_canonical_mail_send_once(vault, owner, request, identity_ref, actor)
    }

    /// One owner press for a REVIEWED BATCH: exact approvals for exactly the
    /// enumerated sends, all minted in one transaction (ARCH-0046 "one press
    /// for a reviewed batch").
    ///
    /// `reviewed_send_refs` is what the owner saw: the card's
    /// `BundleExactSends` refs. The requests must be exactly those sends, one
    /// each, every one this adapter's member send with a frozen plan. Each
    /// gets its own canonical digest, so the press covers these sends and no
    /// other: it mints no standing authority and is never converted into the
    /// brief-wide grant the card's other scope choice would mint. Either every
    /// approval lands or none does; an already-pressed send refuses the batch.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the requests are not exactly the reviewed
    /// refs or any envelope is not this adapter's, plus the approve-once
    /// door's owner and replay checks.
    pub fn approve_send_batch(
        &self,
        vault: &Vault,
        owner: &AuthenticatedOwner,
        reviewed_send_refs: &[String],
        requests: &[OutboundDispatchRequest],
    ) -> Result<Vec<ConsentReceipt>> {
        let mut reviewed = reviewed_send_refs
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let mut requested = requests
            .iter()
            .map(|request| request.intent_ref.as_str())
            .collect::<Vec<_>>();
        reviewed.sort_unstable();
        requested.sort_unstable();
        if requests.is_empty()
            || reviewed != requested
            || requested.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(Error::InvalidConfig(
                "gmail batch approval must cover exactly the reviewed sends, once each".to_owned(),
            ));
        }
        let mut digests = Vec::with_capacity(requests.len());
        for request in requests {
            let (identity_ref, actor) = self.require_send_envelope(vault, request)?;
            digests.push(canonical_mail_send_digest(request, identity_ref, actor)?);
        }
        vault.with_write_txn_grouped(|wtxn| {
            digests
                .into_iter()
                .map(|digest| vault.approve_once_in_txn(wtxn, owner, digest))
                .collect()
        })
    }

    /// Dispatches one member send through the recorded dispatch door, then
    /// records its thread passport and comm touch on delivery.
    ///
    /// The envelope check is this adapter's; recipient binding, STOP, the Gate,
    /// the intent ledger, the outbound receipt and the transport's frozen-call
    /// checks are the common ones. A Held result is the owner's approval card:
    /// press [`Self::approve_send_once`] for the same request and dispatch it
    /// again. A retry after a crash or a projection error replays the ledger's
    /// stored outcome and re-projects the thread record without resending.
    ///
    /// # Errors
    ///
    /// The envelope refusal, the dispatch error, or a thread/comm projection
    /// failure after delivery (retry the same request to re-project).
    pub fn dispatch_send_recorded<W: GmailSendWire>(
        &self,
        vault: &Vault,
        request: OutboundDispatchRequest,
        sink: &mut GmailSendSink<'_, W>,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        let (identity_ref, actor) = self.require_send_envelope(vault, &request)?;
        if sink.identity_id != identity_ref
            || sink.adapter.config.mailbox_address != self.config.mailbox_address
        {
            return Err(Error::InvalidConfig(
                "gmail send sink is bound to another identity or mailbox".to_owned(),
            )
            .into());
        }
        let result = vault.dispatch_outbound_intent_recorded(request, sink)?;
        if result.outcome == OutboundDispatchOutcome::DeliveredToChannel {
            record_sent_thread(vault, identity_ref, actor, &result)?;
        }
        Ok(result)
    }

    fn require_send_grant(&self) -> Result<()> {
        if self.config.grants_send() {
            Ok(())
        } else {
            Err(Error::InvalidConfig(
                "gmail delegated send requires gmail.send on the grant".to_owned(),
            ))
        }
    }

    /// The member-send envelope: `email/send`, a logical ref, a frozen plan
    /// ref, and this adapter's ACTIVE send-capable row bound to the request's
    /// own actor.
    fn require_send_envelope(
        &self,
        vault: &Vault,
        request: &OutboundDispatchRequest,
    ) -> Result<(EntityId, EntityId)> {
        let invalid = || Error::InvalidConfig("invalid gmail member send envelope".to_owned());
        self.require_send_grant()?;
        let identity_ref = request.channel_identity_ref.ok_or_else(invalid)?;
        self.require_active_row_matches_adapter(vault, &identity_ref)?;
        // Whose mailbox it is comes from the binding head (OF-272); whether
        // it may send is custody, on the local row.
        let txn = vault.store.env.read_txn()?;
        let identity = vault
            .get_channel_identity_in_txn(&txn, &identity_ref)?
            .ok_or_else(invalid)?;
        let facts = crate::channel_identity::channel_identity_facts_in_txn(
            &vault.store,
            &txn,
            &identity_ref,
        )?
        .ok_or_else(invalid)?;
        drop(txn);
        let actor = request.actor.actor_entity_ref.ok_or_else(invalid)?;
        if !request
            .intent
            .channel
            .trim()
            .eq_ignore_ascii_case(EMAIL_CHANNEL)
            || !request.intent.verb.trim().eq_ignore_ascii_case("send")
            || request.intent_ref.trim().is_empty()
            || !request
                .intent
                .content_ref
                .as_deref()
                .is_some_and(|content_ref| {
                    content_ref.starts_with(GMAIL_SEND_PLAN_REF_PREFIX)
                        || content_ref.starts_with(GMAIL_ATTACHED_SEND_PLAN_REF_PREFIX)
                })
            || !identity.may_send()
            || facts.binding.actor_ref() != Some(actor)
            || request.actor.actor_ref.as_deref() != Some(actor.to_hex().as_str())
        {
            return Err(invalid());
        }
        Ok((identity_ref, actor))
    }
}

/// The sink a completed member send replays through (fix list row 17645):
/// the ledger's completed record answers the dispatch, so nothing asks it to
/// send. It admits no new call, so a call the ledger has not completed is
/// refused before any decision is recorded, and it sends nothing.
struct CompletedSendSink;

impl OutboundExecutionSink for CompletedSendSink {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        OutboundExecutionOutcome::failed("gmail_send_replay_only")
    }

    fn admit_in(&self, _txn: &heed::RoTxn<'_>) -> Result<()> {
        Err(Error::InvalidConfig(
            "a completed gmail send only replays; it never sends".to_owned(),
        ))
    }

    fn delivers_recipient_lists(&self) -> bool {
        true
    }
}

/// Replays one member send the recorded dispatch door already completed
/// (fix list row 17645), as [`GmailDelegatedAdapter::dispatch_send_recorded`]
/// replays it, but with no adapter: no live row, grant or send capability is
/// needed, because nothing sends. The door validates `request` against the
/// ledger's frozen request, whole, and answers with the outcome it recorded;
/// a delivered send's thread record is projected again. A call the ledger has
/// not completed is refused, never sent.
///
/// # Errors
///
/// An envelope that names no sender, the dispatch door's refusal (a request
/// other than the frozen one among them), or a thread/comm projection failure
/// after delivery (replay the same request to project it again).
pub(crate) fn replay_completed_send_recorded(
    vault: &Vault,
    request: OutboundDispatchRequest,
) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
    let invalid = || Error::InvalidConfig("invalid gmail member send envelope".to_owned());
    let identity_ref = request.channel_identity_ref.ok_or_else(invalid)?;
    let actor = request.actor.actor_entity_ref.ok_or_else(invalid)?;
    let result = vault.dispatch_outbound_intent_recorded(request, &mut CompletedSendSink)?;
    if result.outcome == OutboundDispatchOutcome::DeliveredToChannel {
        record_sent_thread(vault, identity_ref, actor, &result)?;
    }
    Ok(result)
}

/// Projects one delivered member send into the thread record: its
/// `(identity × Message-ID)` passport with References/In-Reply-To, and each
/// recipient's comm last-touch: its counterparty's, and every recipient's of
/// one message to several (fix list row 17645), each party once. Both read
/// the durable receipt, so a replayed Done result re-projects identically;
/// both writes are idempotent.
fn record_sent_thread(
    vault: &Vault,
    identity_ref: EntityId,
    actor: EntityId,
    result: &OutboundDispatchResult,
) -> Result<()> {
    let fields = &result.receipt.fields;
    let Some(message_id) = fields.get(RECEIPT_RFC_MESSAGE_ID) else {
        return Ok(());
    };
    let mut input = ThreadPassportInput::new(
        identity_ref,
        actor,
        canonical_message_id(message_id)?,
        result.receipt.occurred_at,
    );
    if let Some(facts) = vault.channel_identity_facts(&identity_ref)?
        && let Some(facet) = facts.binding.facet_ref()
    {
        input = input.with_facet(facet);
    }
    if let Some(parent) = fields.get(RECEIPT_RFC_IN_REPLY_TO) {
        input = input.with_in_reply_to(canonical_message_id(parent)?);
    }
    if let Some(references) = fields.get(RECEIPT_RFC_REFERENCES) {
        let references = references.split(' ').collect::<Vec<_>>();
        input = input.with_references(canonical_message_id_list(&references)?);
    }
    vault.record_thread_passport(input)?;
    let mut parties: Vec<String> = fields
        .get("counterparty_ref")
        .cloned()
        .into_iter()
        .collect();
    if let Some(listed) = fields.get(crate::outbound::RECIPIENTS_FIELD) {
        let listed: Vec<crate::outbound::OutboundRecipient> = serde_json::from_str(listed)
            .map_err(|_| {
                Error::InvalidConfig("gmail send receipt recipients unreadable".to_owned())
            })?;
        for recipient in listed {
            if !parties.contains(&recipient.address) {
                parties.push(recipient.address);
            }
        }
    }
    for party in &parties {
        vault
            .store
            .record_hooks
            .record_comm_send_receipt(vault, party, EMAIL_CHANNEL, result.receipt.occurred_at)
            .map_err(|err| {
                Error::InvalidConfig(format!("gmail send comm projection failed: {err}"))
            })?;
    }
    Ok(())
}
