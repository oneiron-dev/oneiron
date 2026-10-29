//! The answer and the settlement (DOOR-079 1a). One authenticated owner
//! answer, bound to its exact sealed wait, lands first and once. The held
//! effect then runs once, under its own current gate and its original
//! caller's own grant, and its outcome settles the wait and wakes the parked
//! run in one commit. The answer, the settlement and the run's consumption
//! of the reply (1b) stay three separate facts.

use crate::Vault;
use crate::consent::{
    AuthenticatedOwner, CodeWaitReceiptLinks, ConsentOwnerStamp, ConsentReceipt, EffectDigest,
};
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::outbound_consent::ConnectorCallOutcome;
use crate::store::GateDecisionId;
use crate::task_verb::sdk::ConnectorCallReply;

use super::binding::{put_code_consent_wait_in_txn, read_code_consent_wait_in_txn};
use super::ledger::{LedgerLinks, ledger_links_in_txn};
use super::types::{
    CodeConsentAnswerInput, CodeConsentAnswerStamp, CodeConsentBinding, CodeConsentChoice,
    CodeConsentSavedCredential, CodeConsentSettleOutcome, CodeConsentSettlement,
    CodeConsentWaitRow, CodeConsentWaitView,
};

/// The refusal a new approving answer gets where no host drives a code
/// consent effect (CALLS: host absence). A denial still lands, and a read
/// still works.
pub(crate) const CODE_WAIT_HOST_UNBOUND: &str = "code_wait_host_unbound";

/// The reason a wait the owner denied settles with.
pub(crate) const CODE_WAIT_DENIED: &str = "code_wait_denied";

/// The reason a wait settles with when its original caller's own credential
/// no longer stands. No answer revives it.
pub(crate) const CODE_WAIT_ORIGINAL_AUTHORITY_REFUSED: &str =
    "code_wait_original_authority_refused";

/// The wall clock, in unix ms, as the connector call's own rows keep it.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// What one answer's writer decided.
struct Answered {
    /// The effect is answered, approved and not settled: drive it now.
    drive: bool,
    /// This answer was not the first; the first stands.
    already_answered: bool,
}

impl Vault {
    /// The one authorised answer to a code consent wait (DOOR-079 1a): the
    /// vault's authenticated owner, from any surface the owner is
    /// authenticated on, answers once, with a word the owner gave on the
    /// wait's ask. An unauthenticated caller is refused before any lookup.
    /// The first answer wins; the same answer again returns its evidence,
    /// and any other returns the first, marked `already_answered`, with no
    /// second act. A denial settles the wait in the answering commit. An
    /// approval is driven at once through the installed host, under the
    /// effect's own current gate; a host that fails leaves it settling for
    /// its next pass.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds, an unknown or unsealed wait
    /// ([`Error::EntityNotFound`]), a target that changed
    /// ([`Error::ConcurrentWrite`]), an answer from the opener's own lineage
    /// or with no word of this owner naming this choice, a stale stop-asking
    /// offer, or an approval with no host to drive it.
    pub fn settle_code_consent_wait_as(
        &self,
        owner: &AuthenticatedOwner,
        input: &CodeConsentAnswerInput,
    ) -> Result<CodeConsentWaitView> {
        owner.revalidate(self)?;
        let host = self.code_consent_effect_host();
        if input.choice.approves() && host.is_none() {
            return Err(Error::InvalidConfig(format!(
                "{CODE_WAIT_HOST_UNBOUND}: this vault handle has no served host to run the \
                 effect; answer it on the server that serves this vault"
            )));
        }
        let answered = self.with_write_txn_grouped(|txn| answer_in_txn(self, txn, owner, input))?;
        self.signal_code_owned_call_asks();
        if answered.drive
            && let Some(host) = host
            && let Err(error) = host.resume_answered(self, input.wait_id)
        {
            tracing::warn!(
                wait = %input.wait_id.to_hex(),
                %error,
                "code consent effect left settling for its host's next pass"
            );
        }
        self.code_consent_wait_view(input.wait_id, answered.already_answered)
    }

    /// One code consent wait as its owner reads it: the held effect, its
    /// ask, the answer and the settlement. An unauthenticated caller is
    /// refused before any lookup.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds, or an unknown wait.
    pub fn code_consent_wait_as(
        &self,
        owner: &AuthenticatedOwner,
        wait_id: EntityId,
    ) -> Result<CodeConsentWaitView> {
        owner.revalidate(self)?;
        self.code_consent_wait_view(wait_id, false)
    }

    /// The instrument a wait's original caller was admitted on, for the
    /// host's own check before it drives the effect: the same slip, live now,
    /// whose current scope meets the scope it was admitted under. `None` for
    /// a caller no credential was bound for: its grant alone limits it.
    ///
    /// # Errors
    ///
    /// Storage errors, or an unknown wait.
    pub fn code_consent_wait_credential(
        &self,
        wait_id: EntityId,
    ) -> Result<Option<CodeConsentSavedCredential>> {
        let txn = self.store.env.read_txn()?;
        let row =
            read_code_consent_wait_in_txn(self, &txn, wait_id)?.ok_or(Error::EntityNotFound)?;
        Ok(row.binding.original.credential)
    }

    /// The view of one wait, with its receipts' links as the consent Gate
    /// ledger holds them, read in the same snapshot.
    pub(crate) fn code_consent_wait_view(
        &self,
        wait_id: EntityId,
        already_answered: bool,
    ) -> Result<CodeConsentWaitView> {
        let txn = self.store.env.read_txn()?;
        let row =
            read_code_consent_wait_in_txn(self, &txn, wait_id)?.ok_or(Error::EntityNotFound)?;
        let ledger = ledger_links_in_txn(self, &txn, &row)?;
        Ok(view_of(&row, ledger, already_answered))
    }

    /// The consent evidence of the code consent wait a program's resume
    /// checkpoint parked on (FIX 5883), read in the caller's snapshot `txn`:
    /// the wait's view, its receipts' links joined from the consent Gate
    /// ledger as [`Self::code_consent_wait_view`] joins them, and its binding
    /// digest. `key` is the wait the checkpoint names: its run, wait id and
    /// sealed generation are the identity both sides share (FIX 7186). The
    /// binding's `bridge_seq` stays the mint's call position and is not
    /// compared with the checkpoint's call row, which a retried entry may
    /// move. `None` for a wait no control row binds. Read-only: nothing is
    /// answered, settled, consumed or asked.
    ///
    /// # Errors
    ///
    /// A row bound to another run, or not sealed at `key`'s generation
    /// ([`Error::CorruptedIndex`]); a ledger record that disagrees with the
    /// row; storage.
    pub(crate) fn code_consent_checkpoint_evidence_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        key: &crate::code_run::WaitKey,
    ) -> Result<Option<(CodeConsentWaitView, [u8; 32])>> {
        let Some(wait) = read_code_consent_wait_in_txn(self, txn, key.wait_id)? else {
            return Ok(None);
        };
        let sealed = wait
            .checkpoint
            .as_ref()
            .is_some_and(|sealed| sealed.wait_generation == key.generation);
        if wait.binding.run_id != key.run || !sealed {
            return Err(Error::CorruptedIndex(
                "a code consent wait is not the one its program checkpoint parked on",
            ));
        }
        let ledger = ledger_links_in_txn(self, txn, &wait)?;
        Ok(Some((
            view_of(&wait, ledger, false),
            wait.binding.binding_digest,
        )))
    }
}

/// The answer's writer: the proof again, the exact sealed target, the first
/// answer, the opener's lineage, the owner's word, then the consent act
/// beside the answer stamp. A denial, or an original caller whose own
/// credential no longer stands, settles the wait here.
fn answer_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    input: &CodeConsentAnswerInput,
) -> Result<Answered> {
    let Some(mut row) = read_code_consent_wait_in_txn(vault, txn, input.wait_id)? else {
        return Err(Error::EntityNotFound);
    };
    let answerer = code_consent_answerer_in_txn(vault, txn, &row.binding, owner)?;
    // An unsealed wait reads as unknown: no answer reaches it before its
    // parked step committed.
    let Some(sealed) = row.checkpoint.as_ref() else {
        return Err(Error::EntityNotFound);
    };
    if row.binding.run_id != input.run_id
        || sealed.wait_generation != input.wait_generation
        || sealed.step_hash != input.step_hash
        || row.binding.effect_digest != input.effect_digest
    {
        return Err(Error::ConcurrentWrite("code consent wait target changed"));
    }
    if let Some(first) = &row.answer {
        let same = first.choice == input.choice
            && first.word_ref == input.word_ref
            && first.answerer == answerer;
        return Ok(Answered {
            drive: false,
            already_answered: !same,
        });
    }
    // Settled with no answer (its expiry, or the effect's own release).
    if row.settlement.is_some() {
        return Ok(Answered {
            drive: false,
            already_answered: true,
        });
    }
    let ask = row.ask.ok_or(Error::EntityNotFound)?;
    crate::task_verb::code_consent_word_in_txn(
        vault,
        txn,
        ask,
        input.word_ref,
        answerer,
        input.choice,
    )
    .map_err(|error| match error {
        Error::Record(_) => Error::Gate(GateError::ConsentUnauthenticatedActor(
            "the answer names no word this owner gave on the ask of this wait with this choice",
        )),
        other => other,
    })?;
    let digest = EffectDigest::from_bytes(row.binding.effect_digest);
    let (decision, remembered) = match input.choice {
        CodeConsentChoice::Deny => (vault.deny_consent_in_txn(txn, owner, digest)?, None),
        CodeConsentChoice::ApproveOnce => (vault.approve_once_in_txn(txn, owner, digest)?, None),
        CodeConsentChoice::ApproveAndStopAsking => {
            let offer = row
                .binding
                .remember_offer
                .clone()
                .ok_or(Error::ConcurrentWrite(
                    "this code consent wait offers no stop asking",
                ))?;
            let revision = crate::connector_key::stop_asking_tool_in_txn(
                vault,
                txn,
                owner,
                offer.slate_ref,
                offer.slate_revision,
                &offer.tool,
            )?;
            (
                vault.approve_once_in_txn(txn, owner, digest)?,
                Some((offer.slate_ref, revision)),
            )
        }
    };
    row.answer = Some(CodeConsentAnswerStamp {
        choice: input.choice,
        word_ref: input.word_ref,
        answerer,
        principal_ref: owner.principal_ref_in_txn(vault, txn)?.to_owned(),
        authentication: owner.decision_id(),
        decision: decision.decision_id(),
        remembered,
        policy_frontier: code_consent_policy_basis_in_txn(vault, txn)?,
        answered_at_ms: now_ms(),
    });
    put_code_consent_wait_in_txn(vault, txn, &mut row)?;
    if input.choice == CodeConsentChoice::Deny {
        refuse_code_consent_wait_in_txn(vault, txn, input.wait_id, &[CODE_WAIT_DENIED])?;
    } else if !original_authority_holds_in_txn(vault, txn, &row.binding) {
        refuse_code_consent_wait_in_txn(
            vault,
            txn,
            input.wait_id,
            &[CODE_WAIT_ORIGINAL_AUTHORITY_REFUSED],
        )?;
    }
    let settled = read_code_consent_wait_in_txn(vault, txn, input.wait_id)?
        .is_some_and(|row| row.settlement.is_some());
    Ok(Answered {
        drive: !settled,
        already_answered: false,
    })
}

/// Who may answer a code consent wait (CALLS: owner-only holder subset):
/// the vault's owner, revalidated in the answering writer, from any surface
/// the owner is authenticated on, but never from the opener's lineage, that
/// of the slip the held call was admitted on, or a fork of it (FIX 5064).
/// Canon lets a settlement-policy row name other holders; no gate here can
/// prove one yet, so none is accepted.
fn code_consent_answerer_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding: &CodeConsentBinding,
    owner: &AuthenticatedOwner,
) -> Result<EntityId> {
    let answerer = owner.revalidate_in_txn(vault, txn)?;
    if let Some(slip) = binding.original.opener_slip
        && owner.answers_from_slip_lineage_in_txn(vault, txn, &[slip])?
    {
        return Err(Error::Gate(GateError::ConsentUnauthenticatedActor(
            "the opener lineage never settles its own code consent wait",
        )));
    }
    Ok(answerer)
}

/// The authority basis an answer records (CALLS: settlement policy
/// reference): the owner gate decided it, under the current policy manifest
/// frontier. No settlement-policy row is named, because none decides it.
fn code_consent_policy_basis_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<[u8; 32]> {
    crate::gate::resolve_policy_manifest(&vault.store, txn)?.read_frontier_hash()
}

/// Whether the original caller's own credential still stands at this
/// snapshot: the same slip verifies now, and it is the very instrument the
/// call was admitted on. A caller no credential was bound for has none to
/// lose: its grant alone limits it, at the effect's own gate.
pub(crate) fn original_authority_holds_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding: &CodeConsentBinding,
) -> bool {
    let Some(credential) = &binding.original.credential else {
        return true;
    };
    let Ok(verified) = vault.invocation_slip_in_txn(txn, &credential.witness) else {
        return false;
    };
    let claims = verified.claims();
    binding
        .original
        .opener_slip
        .is_none_or(|slip| slip == claims.slip_id)
        && credential.instrument.as_ref().is_none_or(|instrument| {
            instrument.slip() == Some(claims.slip_id) && instrument.vault == claims.vault_id
        })
}

/// The code-bound approval wait `wait_id` admits its effect under, proved
/// from its row in the admission writer: its binding digest, once the first
/// answer approved and nothing settled it, with the frozen bytes the ones
/// the owner was asked about and the original caller's own credential still
/// standing. `None` for a wait with no answer: its effect meets its own gate
/// as before, and no code approval it never got can release it.
///
/// # Errors
///
/// Other frozen bytes than the bound ones ([`Error::ConcurrentWrite`]), or an
/// original credential that no longer stands.
pub(crate) fn code_consent_admission_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    wait_id: EntityId,
    frozen_digest: &[u8; 32],
) -> Result<Option<[u8; 32]>> {
    let Some(row) = read_code_consent_wait_in_txn(vault, txn, wait_id)? else {
        return Ok(None);
    };
    if !row.approved_unsettled() {
        return Ok(None);
    }
    if row.binding.frozen_input_digest != *frozen_digest {
        return Err(Error::ConcurrentWrite("code consent target changed"));
    }
    if !original_authority_holds_in_txn(vault, txn, &row.binding) {
        return Err(Error::Gate(GateError::ConsentUnauthenticatedActor(
            "the original caller credential of this code consent wait no longer stands",
        )));
    }
    Ok(Some(row.binding.binding_digest))
}

/// Settles wait `wait_id` as refused for `reasons`, in the caller's writer:
/// its held connector row and the wait both, so nothing runs under it. A
/// held browser act has no row of its own: its wait settles refused alone.
pub(crate) fn refuse_code_consent_wait_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
    reasons: &[&str],
) -> Result<()> {
    let Some(row) = read_code_consent_wait_in_txn(vault, txn, wait_id)? else {
        return Ok(());
    };
    let Some(call) = row.binding.pending.connector_call() else {
        return super::browser::refuse_browser_wait_in_txn(vault, txn, row, reasons).map(drop);
    };
    let outcome = ConnectorCallOutcome::Refused {
        decision_ref: None,
        reasons: reasons.iter().map(|reason| (*reason).to_owned()).collect(),
    };
    crate::outbound_consent::settle_code_owned_call_in_txn(vault, txn, &call.call_ref, &outcome)?;
    settle_code_consent_wait_in_txn(vault, txn, wait_id, &outcome)?;
    Ok(())
}

/// Settles wait `wait_id` with the held effect's actual outcome, in the
/// caller's writer: the settlement, its receipt in the consent Gate family,
/// and the reply delivered to the parked run, which wakes its trap in the
/// same commit. An outcome that is not terminal (still held, or a send the
/// ledger retries) settles nothing. A settled wait keeps its first
/// settlement. `true` when this call settled it.
///
/// The reply is delivered first, and the settlement binds the reply as it
/// was stored and delivered (after the side-row wall's masking), so the
/// parked run's consumption verifies the very reply it takes (1b).
pub(crate) fn settle_code_consent_wait_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
    outcome: &ConnectorCallOutcome,
) -> Result<bool> {
    settle_code_consent_wait_listing_in_txn(vault, txn, wait_id, outcome, None)
}

/// [`settle_code_consent_wait_in_txn`], its reply delivered beside `rows`,
/// the rows the call's passes picked (FIX 5455), when they are known.
pub(crate) fn settle_code_consent_wait_listing_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    wait_id: EntityId,
    outcome: &ConnectorCallOutcome,
    rows: Option<&[EntityId]>,
) -> Result<bool> {
    let Some(row) = read_code_consent_wait_in_txn(vault, txn, wait_id)? else {
        return Ok(false);
    };
    if row.settlement.is_some() {
        return Ok(false);
    }
    let Some((settled, reasons)) = settled_outcome(outcome) else {
        return Ok(false);
    };
    let call = row
        .binding
        .pending
        .connector_call()
        .ok_or(Error::InvariantViolation(
            "a connector outcome settles only a held connector call",
        ))?;
    let reply = serde_json::to_value(ConnectorCallReply::project(
        &call.name,
        &call.tool,
        outcome.clone(),
    ))
    .map_err(|_| Error::InvalidConfig("a code consent reply is not JSON".to_owned()))?;
    settle_with_reply_in_txn(vault, txn, row, settled, reasons, &reply, rows)
}

/// Settles `row`'s open wait as `settled` for `reasons`, with `reply`, the
/// reply its parked run is delivered beside `rows`, in the caller's writer:
/// the settlement, its receipt in the consent Gate family, and the delivery
/// that wakes the run, in one commit. Every held effect kind settles here.
pub(super) fn settle_with_reply_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    mut row: CodeConsentWaitRow,
    settled: CodeConsentSettleOutcome,
    reasons: Vec<String>,
    reply: &serde_json::Value,
    rows: Option<&[EntityId]>,
) -> Result<bool> {
    let wait_id = row.binding.wait_id;
    let now = now_ms();
    crate::code_run::deliver_wait_listing_in_txn(vault, txn, wait_id, reply, rows, now)?;
    let delivered = crate::code_run::settled_wait_reply_in_txn(vault, txn, wait_id)?.ok_or(
        Error::InvariantViolation("a settled code consent wait kept no reply"),
    )?;
    let reply_digest = *blake3::hash(delivered.as_bytes()).as_bytes();
    // A settle after an erase of the bound run's actor keeps its outcome,
    // receipt and digest, and no copy of the reply (FIX 5718).
    crate::code_run::erase_settled_reply_of_erased_run_in_txn(
        vault,
        txn,
        wait_id,
        row.binding.run_id,
    )?;
    let receipt_id = GateDecisionId::from_bytes(vault.store.clock.ulid()?);
    let links = CodeWaitReceiptLinks {
        wait_id,
        word_ref: row.answer.as_ref().map(|answer| answer.word_ref),
        prior_receipt: row.answer.as_ref().map(|answer| answer.decision),
        facts_digest: settlement_facts_digest(&row, settled, &reasons, &reply_digest),
    };
    let receipt = ConsentReceipt::CodeWaitSettled {
        decision_id: receipt_id,
        links,
        outcome: settled,
    };
    let answered_by = row.answer.as_ref().map(|answer| ConsentOwnerStamp {
        actor: answer.answerer,
        principal_ref: answer.principal_ref.clone(),
        decision_id: answer.authentication,
    });
    vault.append_code_wait_receipt_in_txn(txn, &receipt, answered_by.as_ref())?;
    row.settlement = Some(CodeConsentSettlement {
        receipt: receipt_id,
        outcome: settled,
        reason_codes: reasons,
        reply_digest,
        settled_at_ms: now,
    });
    put_code_consent_wait_in_txn(vault, txn, &mut row)?;
    Ok(true)
}

/// The settlement an outcome is, with its reasons; `None` while the effect
/// is still held or its send is retried. A delivery the connector answered
/// with questions was delivered. A send that may have reached the connector
/// is never reported as delivered.
fn settled_outcome(
    outcome: &ConnectorCallOutcome,
) -> Option<(CodeConsentSettleOutcome, Vec<String>)> {
    match outcome {
        ConnectorCallOutcome::Delivered { .. } | ConnectorCallOutcome::AwaitingInput { .. } => {
            Some((CodeConsentSettleOutcome::Delivered, Vec::new()))
        }
        ConnectorCallOutcome::Refused { reasons, .. } => {
            Some((CodeConsentSettleOutcome::Refused, reasons.clone()))
        }
        ConnectorCallOutcome::PendingDelivery {
            call_ref: None,
            reasons,
            ..
        } => Some((CodeConsentSettleOutcome::DeliveryUnknown, reasons.clone())),
        ConnectorCallOutcome::Held { .. } | ConnectorCallOutcome::PendingDelivery { .. } => None,
    }
}

/// BLAKE3 of the immutable facts a settlement receipt closes: the binding,
/// the answer's act, the admission, the outcome, its reasons and the reply.
fn settlement_facts_digest(
    row: &CodeConsentWaitRow,
    settled: CodeConsentSettleOutcome,
    reasons: &[String],
    reply_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:code-consent-settled:v1");
    hasher.update(&row.binding.binding_digest);
    hasher.update(&row.binding.effect_digest);
    hasher.update(
        &row.answer
            .as_ref()
            .map_or([0; 16], |answer| answer.decision.as_bytes()),
    );
    hasher.update(
        &row.admission
            .as_ref()
            .map_or([0; 32], |admission| admission.intent_id),
    );
    hasher.update(&[settled.tag()]);
    for reason in reasons {
        hasher.update(&(reason.len() as u64).to_le_bytes());
        hasher.update(reason.as_bytes());
    }
    hasher.update(reply_digest);
    *hasher.finalize().as_bytes()
}

/// The choices a wait offers: approve once and deny always, and approve
/// and stop asking when the hold names a setting it could change.
pub(crate) fn offered_choices(binding: &CodeConsentBinding) -> Vec<CodeConsentChoice> {
    CodeConsentChoice::ALL
        .into_iter()
        .filter(|choice| {
            *choice != CodeConsentChoice::ApproveAndStopAsking || binding.remember_offer.is_some()
        })
        .collect()
}

fn view_of(
    row: &CodeConsentWaitRow,
    ledger: LedgerLinks,
    already_answered: bool,
) -> CodeConsentWaitView {
    let call = row.binding.pending.connector_call();
    let consumed = row.consumption.as_ref();
    CodeConsentWaitView {
        wait_id: row.binding.wait_id,
        run_id: row.binding.run_id,
        state: row.state(),
        verb: row.binding.verb_row.clone(),
        connector: call.map(|call| call.name.clone()).unwrap_or_default(),
        tool: call.map(|call| call.tool.clone()).unwrap_or_default(),
        browser: row.binding.pending.browser_action().cloned(),
        effect_digest: row.binding.effect_digest,
        hold_reasons: row.binding.hold_reasons.clone(),
        ask: row.ask,
        options: offered_choices(&row.binding),
        sealed: row
            .checkpoint
            .as_ref()
            .map(|sealed| (sealed.wait_generation, sealed.step_hash)),
        answer: row.answer.as_ref().map(|answer| answer.choice),
        word_ref: row.answer.as_ref().map(|answer| answer.word_ref),
        answer_receipt: row
            .answer
            .as_ref()
            .map(|answer| format!("gate:{}", answer.decision.to_hex())),
        outcome: row.settlement.as_ref().map(|settled| settled.outcome),
        settlement_receipt: row
            .settlement
            .as_ref()
            .map(|settled| format!("gate:{}", settled.receipt.to_hex())),
        consumption_receipt: row
            .consumption
            .as_ref()
            .map(|consumed| format!("gate:{}", consumed.receipt.to_hex())),
        reasons: row
            .settlement
            .as_ref()
            .map(|settled| settled.reason_codes.clone())
            .unwrap_or_default(),
        answered_at_ms: row.answer.as_ref().map(|answer| answer.answered_at_ms),
        settled_at_ms: row.settlement.as_ref().map(|settled| settled.settled_at_ms),
        settlement_links: ledger.settled,
        consumed_step: consumed.map(|consumed| consumed.step_seq),
        resumed_path: consumed.map(|consumed| consumed.resumed_path.clone()),
        result_handle: consumed.map(|consumed| consumed.result_handle.clone()),
        consumed_at_ms: consumed.map(|consumed| consumed.consumed_at_ms),
        consumption_links: ledger.consumed,
        already_answered,
    }
}
