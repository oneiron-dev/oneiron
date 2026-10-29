//! A held `connector.call` a code consent wait owns (DOOR-079 1a): the first
//! effect a code consent wait binds.
//!
//! A code run's call carries its place in the run on its host origin. When
//! its own gate holds it for consent alone, the held row and a provisional
//! code consent wait are kept in one writer, and the wait asks the owner its
//! own question. Unanswered, the row meets its gate as any held call does,
//! so the connector's own consent and setting doors still release it, and
//! its outcome settles the wait (CALLS: generic release while unanswered).
//! Once the owner approved, it runs only on its host's answered pass: under
//! the code-bound approval its own gate looks up, with the original caller's
//! own grant, and only with the frozen bytes the owner was asked about. Every
//! terminal outcome settles the wait and wakes the parked run.

use crate::Vault;
use crate::code_run::{
    CODE_WAIT_ORIGINAL_AUTHORITY_REFUSED, CodeConsentCallSite, CodeConsentConnectorCall,
    CodeConsentDraft, CodeConsentPendingEffect, CodeConsentPrincipal, CodeConsentRememberOffer,
    CodeConsentWaitView, code_consent_admission_in_txn, mint_code_consent_wait_in_txn,
    offered_choices, original_authority_holds_in_txn, read_code_consent_wait_in_txn,
    refuse_code_consent_wait_in_txn, settle_code_consent_wait_listing_in_txn,
};
use crate::connector_key::SlateDisposition;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::ExternalEffectGateInput;
use crate::memory::Memory;
use crate::outbound_chokepoint::{PreparedAuthorization, PreparedEffect};
use crate::outbound_intent_ledger::IntentLedgerError;
use crate::runtime_hooks::verb::VerbAskRefusal;
use crate::task_verb::sdk::AgentVerb;

use super::connector_call::{
    ConnectorCallHost, ConnectorCallInvocation, ConnectorCallOutcome, PENDING_CALLS,
    PendingConnectorCall, SettledConnectorCall, Step, connector_call_ref, now_ms, refused,
};
use super::connector_call_pending::CONNECTOR_CALL_PENDING_TTL_MS;
use super::scope::ScopedMcpCallContext;
use super::tool_call::PreparedToolCall;

/// The hold reasons a code consent wait answers (CALLS: consent-only hold):
/// the governing key's `always ask` and the consent ladder's own ask. A hold
/// with any other reason (a missing grant or key, manifest drift, a stale
/// snapshot, a budget, a question the connector asked) stays its own state
/// and binds no wait.
const CONSENT_ONLY_HOLD_REASONS: [&str; 3] = [
    SLATE_ALWAYS_ASK,
    "gate.pending.consent.irreversible_effect",
    "gate.pending.consent.bound_exceeded",
];

/// The governing key's `always ask` hold: the one setting a stop-asking
/// answer can change.
const SLATE_ALWAYS_ASK: &str = "connector_key_slate_always_ask";

/// Why an approved call whose freshly prepared bytes are not the bound ones
/// is refused instead of sent.
const CODE_WAIT_TARGET_CHANGED: &str = "code_wait_target_changed";

/// Why an answered call waits for its host's answered pass.
const CODE_WAIT_SETTLING: &str = "code_wait_settling";

/// The most characters of a connector or tool name the question quotes.
const QUESTION_NAME_MAX_CHARS: usize = 120;

/// This pass's code consent context, carried on the pending row in memory
/// and never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CodePass {
    /// A code run's fresh call: what a hold for consent alone mints its wait
    /// with. The pass fills `facts` once it prepared the call.
    Mint {
        site: CodeConsentCallSite,
        principal: CodeConsentPrincipal,
        facts: Option<HeldFacts>,
    },
    /// An approved wait's answered pass: only these frozen bytes go.
    Settle { frozen_digest: [u8; 32] },
}

/// What one pass prepared, before its gate held it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HeldFacts {
    frozen_digest: [u8; 32],
    grant_id: EntityId,
    key_id: EntityId,
    call: ScopedMcpCallContext,
    manifest_hash: [u8; 32],
    protocol_revision: String,
}

/// Whether a hold is for consent alone (CALLS: consent-only hold).
fn code_consent_hold_is_consent_only(reasons: &[String]) -> bool {
    !reasons.is_empty()
        && reasons
            .iter()
            .all(|reason| CONSENT_ONLY_HOLD_REASONS.contains(&reason.as_str()))
}

/// `pending` with the code consent context of the call `memory` makes, when
/// the dispatcher put the call's place in its run on the bound origin.
pub(super) fn with_code_pass(
    memory: &Memory<'_>,
    mut pending: PendingConnectorCall,
) -> PendingConnectorCall {
    if let Some(site) = memory.code_consent_site() {
        pending.code = Some(Box::new(CodePass::Mint {
            site: site.clone(),
            principal: memory.code_consent_principal(),
            facts: None,
        }));
    }
    pending
}

/// The pass's check just before its send: a fresh code call keeps what it
/// prepared, for the mint; an answered pass refuses bytes that are not the
/// ones its wait bound, rather than send replacement bytes unasked.
pub(super) fn before_send(
    pending: &mut PendingConnectorCall,
    prepared: &PreparedToolCall,
    grant_id: EntityId,
    key_id: EntityId,
) -> Option<Step> {
    let frozen_digest = *blake3::hash(prepared.frozen_bytes()).as_bytes();
    match pending.code.as_deref_mut()? {
        CodePass::Mint { facts, .. } => {
            let binding = prepared.manifest_binding()?;
            *facts = Some(HeldFacts {
                frozen_digest,
                grant_id,
                key_id,
                call: prepared.call().clone(),
                manifest_hash: binding.manifest_hash,
                protocol_revision: binding.protocol_revision.clone(),
            });
            None
        }
        CodePass::Settle {
            frozen_digest: bound,
        } => (*bound != frozen_digest).then(|| refused(CODE_WAIT_TARGET_CHANGED)),
    }
}

/// `text`, cut to [`QUESTION_NAME_MAX_CHARS`] characters.
fn clip(text: &str) -> String {
    text.chars().take(QUESTION_NAME_MAX_CHARS).collect()
}

impl Vault {
    /// Keeps a held call's row, and in the same writer mints the code
    /// consent wait a fresh code call held for consent alone binds. Returns
    /// the row's ref and whether a code consent wait owns it.
    pub(super) fn keep_held_connector_call(
        &self,
        call_ref: Option<EntityId>,
        pending: &PendingConnectorCall,
        reasons: &[String],
    ) -> Result<(EntityId, bool), IntentLedgerError> {
        // Only a call its host's identity names finds its row again, so only
        // such a call binds a wait.
        let draft = match call_ref {
            Some(call_ref) => self.code_consent_draft(call_ref, pending, reasons)?,
            None => None,
        };
        let call_ref = call_ref.unwrap_or_else(EntityId::now);
        Ok(self.with_write_txn(|txn| {
            let mut row = pending.clone();
            row.code = None;
            if let Some((draft, gate_input)) = draft
                && row.code_consent_wait.is_none()
            {
                row.code_consent_wait =
                    mint_code_consent_wait_in_txn(self, txn, draft, |binding_digest| {
                        crate::gate::code_wait_approval_digest(&gate_input, binding_digest)
                            .map(|digest| *digest.as_bytes())
                    })?;
            }
            super::connector_call_erase::put_pending_call_in_txn(
                &self.store,
                txn,
                &call_ref,
                &row,
            )?;
            Ok((call_ref, row.code_consent_wait.is_some()))
        })?)
    }

    /// What a fresh code call held for consent alone mints its wait with,
    /// and the gate input its approval digest composes over; `None` for any
    /// other hold or call.
    fn code_consent_draft(
        &self,
        call_ref: EntityId,
        pending: &PendingConnectorCall,
        reasons: &[String],
    ) -> Result<Option<(CodeConsentDraft, ExternalEffectGateInput)>, IntentLedgerError> {
        let Some(CodePass::Mint {
            site,
            principal,
            facts: Some(facts),
        }) = pending.code.as_deref()
        else {
            return Ok(None);
        };
        if !code_consent_hold_is_consent_only(reasons) {
            return Ok(None);
        }
        let remember_offer = if reasons.iter().any(|reason| reason == SLATE_ALWAYS_ASK) {
            self.connector_stop_asking_offer(&facts.key_id, &facts.call.tool)?
        } else {
            None
        };
        let effect = CodeConsentPendingEffect::ConnectorCall(CodeConsentConnectorCall {
            call_ref,
            attempt_id: *pending.attempt_id.as_bytes(),
            call_seq: pending.call_seq,
            grant_ref: facts.grant_id,
            key_ref: facts.key_id,
            name: pending.name.clone(),
            server: facts.call.server.clone(),
            tool: facts.call.tool.clone(),
            endpoint: facts.call.resolved_endpoint.clone(),
            manifest_hash: facts.manifest_hash,
            protocol_revision: facts.protocol_revision.clone(),
            credential_record: pending.credential,
        });
        let gate_input = super::execution::scoped_mcp_gate_input(
            &pending.principal_ref,
            facts.grant_id,
            &facts.call,
        );
        Ok(Some((
            CodeConsentDraft {
                site: site.clone(),
                verb: AgentVerb::ConnectorCall,
                principal: principal.clone(),
                pending: effect,
                frozen_input_digest: facts.frozen_digest,
                hold_reasons: reasons.to_vec(),
                remember_offer,
            },
            gate_input,
        )))
    }

    /// The stop-asking offer for `tool` under the governing key `key_id`
    /// (CALLS: stop-asking for connector.call): the tool's row on the slate
    /// that key meets, at its current revision, when that row asks always.
    /// The answer flips that one row back to `auto`; the tool's own scoped
    /// grant already covers its consent.
    fn connector_stop_asking_offer(
        &self,
        key_id: &EntityId,
        tool: &str,
    ) -> Result<Option<CodeConsentRememberOffer>, IntentLedgerError> {
        let Some(key) = self.get_connector_key(key_id)? else {
            return Ok(None);
        };
        let txn = self.store.env.read_txn().map_err(Error::from)?;
        let Some((slate_ref, slate)) =
            crate::connector_key::governing_slate_in_txn(&self.store, &txn, &key)?
        else {
            return Ok(None);
        };
        Ok(
            (slate.row(tool).is_some() && slate.tool_setting(tool) == SlateDisposition::AlwaysAsk)
                .then(|| CodeConsentRememberOffer {
                    slate_ref,
                    slate_revision: slate.revision(),
                    tool: tool.to_owned(),
                }),
        )
    }

    /// Opens the owner's question for the code consent wait a fresh hold
    /// bound, as the call's own caller. An ask that does not open leaves the
    /// generic held-call ask to stand in, so the owner still hears of it.
    pub(super) fn ask_code_consent_for_hold(
        &self,
        memory: &Memory<'_>,
        outcome: ConnectorCallOutcome,
    ) -> ConnectorCallOutcome {
        let held = match &outcome {
            ConnectorCallOutcome::Held {
                call_ref, reasons, ..
            } => Some((*call_ref, reasons.clone())),
            _ => None,
        };
        let Some((call_ref, reasons)) = held else {
            return outcome;
        };
        let wait = self
            .store
            .env
            .read_txn()
            .map_err(Error::from)
            .and_then(|txn| {
                PENDING_CALLS
                    .get(&self.store, &txn, &call_ref)
                    .map(|row| row.and_then(|row| row.code_consent_wait))
            });
        let wait_id = match wait {
            Ok(Some(wait_id)) => wait_id,
            Ok(None) => return outcome,
            Err(error) => {
                tracing::warn!(call_ref = %call_ref.to_hex(), %error, "code consent wait not read");
                return outcome;
            }
        };
        let asked = self
            .code_consent_question_text(wait_id)
            .map_err(crate::memory::MemoryError::from)
            .and_then(|text| memory.ask_code_consent(wait_id, &text));
        if let Err(error) = asked {
            tracing::warn!(
                wait = %wait_id.to_hex(),
                code = %error.code,
                message = %error.message,
                "code consent ask not opened; the held-call ask stands in"
            );
            if let Err(error) = self.queue_connector_call_owner_ask(&call_ref, &reasons) {
                tracing::warn!(
                    call_ref = %call_ref.to_hex(),
                    %error,
                    "connector call owner ask not queued"
                );
            }
        }
        outcome
    }

    /// The wording of a code consent wait's question: the one place it
    /// lives. It names the connector, the tool, the wait and the hold, the
    /// choices it offers, and that nothing is sent until the owner answers.
    fn code_consent_question_text(&self, wait_id: EntityId) -> crate::Result<String> {
        let txn = self.store.env.read_txn()?;
        let row =
            read_code_consent_wait_in_txn(self, &txn, wait_id)?.ok_or(Error::EntityNotFound)?;
        let call = row
            .binding
            .pending
            .connector_call()
            .ok_or(Error::EntityNotFound)?;
        let choices = offered_choices(&row.binding)
            .into_iter()
            .map(|choice| choice.as_str().replace('_', " "))
            .collect::<Vec<_>>()
            .join(", ");
        let days = CONNECTOR_CALL_PENDING_TTL_MS / (24 * 60 * 60 * 1000);
        Ok(format!(
            "A code run asks before it calls tool \"{tool}\" on connector \"{name}\" (code \
             consent wait {wait}). Its own gate held the call because: {reasons}. Answer one of: \
             {choices}. Nothing is sent until you answer, and the call expires {days} days after \
             it was held.",
            tool = clip(&call.tool),
            name = clip(&call.name),
            wait = wait_id.to_hex(),
            reasons = row.binding.hold_reasons.join(", "),
        ))
    }

    /// One pass over a held call a code consent wait owns. A settled or
    /// expired row settles the wait with its outcome. An answered, approved
    /// wait runs only on its host's answered pass (`answered`), after the
    /// original caller's own credential is checked again, and only with the
    /// bound frozen bytes. An unanswered wait's call meets its own gate as
    /// any held call does. Every terminal outcome settles the wait.
    pub(super) fn resume_code_owned_connector_call<H: ConnectorCallHost>(
        &self,
        call_ref: &EntityId,
        mut pending: PendingConnectorCall,
        host: &mut H,
        answered: bool,
    ) -> Result<(ConnectorCallOutcome, Option<Vec<EntityId>>), IntentLedgerError> {
        // A call whose connector asked for input answers from its row; its
        // wait settled when the questions came (FIX 3837).
        if let Some(outcome) = pending.input_outcome(*call_ref) {
            return Ok((outcome, pending.source_rows));
        }
        let Some(wait_id) = pending.code_consent_wait else {
            return self.drive_connector_call(Some(*call_ref), None, pending, host);
        };
        // A settled or expiring row answers, and settles its wait, with the
        // rows its passes kept (FIX 5455).
        if let Some(settled) = &pending.settled {
            let outcome = settled.outcome();
            self.settle_code_wait(wait_id, &outcome, pending.source_rows.as_deref())?;
            return Ok((outcome, pending.source_rows));
        }
        if let Some(expired) = self.expire_connector_call_if_due(call_ref, &pending, now_ms())? {
            self.settle_code_wait(wait_id, &expired, pending.source_rows.as_deref())?;
            return Ok((expired, pending.source_rows));
        }
        let row = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            read_code_consent_wait_in_txn(self, &txn, wait_id)?.map(|row| {
                (
                    row.approved_unsettled(),
                    original_authority_holds_in_txn(self, &txn, &row.binding),
                    row,
                )
            })
        };
        if let Some((true, authority_holds, row)) = row {
            if !answered {
                // Its owner's answer is the press here: no generic digest.
                let held = ConnectorCallOutcome::Held {
                    call_ref: *call_ref,
                    decision_ref: None,
                    reasons: vec![CODE_WAIT_SETTLING.to_owned()],
                    approval_digest: None,
                };
                return Ok((held, pending.source_rows));
            }
            if !authority_holds {
                self.with_write_txn(|txn| {
                    refuse_code_consent_wait_in_txn(
                        self,
                        txn,
                        wait_id,
                        &[CODE_WAIT_ORIGINAL_AUTHORITY_REFUSED],
                    )
                })?;
                self.signal_code_owned_call_asks();
                let stopped = ConnectorCallOutcome::Refused {
                    decision_ref: None,
                    reasons: vec![CODE_WAIT_ORIGINAL_AUTHORITY_REFUSED.to_owned()],
                };
                return Ok((stopped, pending.source_rows));
            }
            pending.code = Some(Box::new(CodePass::Settle {
                frozen_digest: row.binding.frozen_input_digest,
            }));
        }
        let (outcome, rows) = self.drive_connector_call(Some(*call_ref), None, pending, host)?;
        self.settle_code_wait(wait_id, &outcome, rows.as_deref())?;
        Ok((outcome, rows))
    }

    /// Settles wait `wait_id` with `outcome` in a writer of its own, when the
    /// outcome is terminal, its reply beside the rows the call's passes
    /// picked (FIX 5455).
    fn settle_code_wait(
        &self,
        wait_id: EntityId,
        outcome: &ConnectorCallOutcome,
        rows: Option<&[EntityId]>,
    ) -> Result<(), IntentLedgerError> {
        self.with_write_txn(|txn| {
            settle_code_consent_wait_listing_in_txn(self, txn, wait_id, outcome, rows)
        })?;
        Ok(())
    }

    /// Drives an answered code consent wait's effect once (DOOR-079 1a),
    /// for the host that installed itself to drive them, after its own check
    /// of the original caller's instrument. It takes no answer and cannot
    /// make one: an unanswered, denied or settled wait runs nothing here.
    /// The effect's own current gate decides, under the wait's code-bound
    /// approval and the original caller's own grant.
    ///
    /// # Errors
    ///
    /// An unknown wait, or the effect's own failure.
    pub fn resume_answered_code_consent_wait<H: ConnectorCallHost>(
        &self,
        wait_id: EntityId,
        host: &mut H,
    ) -> Result<CodeConsentWaitView, IntentLedgerError> {
        let call_ref = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            let row = read_code_consent_wait_in_txn(self, &txn, wait_id)?.ok_or(
                IntentLedgerError::InvalidInput("no code consent wait by that id"),
            )?;
            row.binding
                .pending
                .connector_call()
                .filter(|_| row.approved_unsettled())
                .map(|call| call.call_ref)
        };
        if let Some(call_ref) = call_ref {
            let pending = {
                let txn = self.store.env.read_txn().map_err(Error::from)?;
                PENDING_CALLS.get(&self.store, &txn, &call_ref)?
            };
            if let Some(pending) = pending {
                // An off-record caller's sealed arguments open (FIX 9159).
                let pending = pending.opened(&self.store, &call_ref)?;
                self.resume_code_owned_connector_call(&call_ref, pending, host, true)?;
            }
        }
        Ok(self.code_consent_wait_view(wait_id, false)?)
    }

    /// Settles an answered wait as refused because its host found the
    /// original caller's instrument no longer stands (its current scope no
    /// longer meets the one it was admitted under, or the slip is gone). A
    /// refusal that names no credential (the host could not check) settles
    /// nothing: the wait stays settling for the host's next pass.
    ///
    /// # Errors
    ///
    /// An unknown wait, or storage errors.
    pub fn refuse_answered_code_consent_wait(
        &self,
        wait_id: EntityId,
        refusal: VerbAskRefusal,
    ) -> Result<CodeConsentWaitView, IntentLedgerError> {
        if refusal.names_credential() {
            let code = refusal.code().to_ascii_lowercase();
            self.with_write_txn(|txn| {
                let answered = read_code_consent_wait_in_txn(self, txn, wait_id)?
                    .is_some_and(|row| row.approved_unsettled());
                if answered {
                    refuse_code_consent_wait_in_txn(
                        self,
                        txn,
                        wait_id,
                        &[CODE_WAIT_ORIGINAL_AUTHORITY_REFUSED, code.as_str()],
                    )?;
                }
                Ok(())
            })?;
            self.signal_code_owned_call_asks();
        }
        Ok(self.code_consent_wait_view(wait_id, false)?)
    }

    /// The answered, approved, unsettled code consent wait that owns the
    /// held call `call_ref`, if any: the host's answered pass drives it, and
    /// an ordinary settler pass leaves it alone.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn answered_code_consent_wait_for_call(
        &self,
        call_ref: &EntityId,
    ) -> Result<Option<EntityId>, IntentLedgerError> {
        let txn = self.store.env.read_txn().map_err(Error::from)?;
        let Some(wait_id) = PENDING_CALLS
            .get(&self.store, &txn, call_ref)?
            .and_then(|row| row.code_consent_wait)
        else {
            return Ok(None);
        };
        Ok(read_code_consent_wait_in_txn(self, &txn, wait_id)?
            .filter(|row| row.approved_unsettled())
            .map(|_| wait_id))
    }
}

/// Settles a held call a code consent wait owns as refused, in the caller's
/// writer, unless it already settled, so the settler acknowledges it and
/// nothing runs under it. The row withdraws the owner questions it named in
/// the same write (FIX 2551); its committer wakes their waiters with
/// [`Vault::signal_code_owned_call_asks`].
pub(crate) fn settle_code_owned_call_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    call_ref: &EntityId,
    outcome: &ConnectorCallOutcome,
) -> crate::Result<()> {
    let ConnectorCallOutcome::Refused {
        decision_ref,
        reasons,
    } = outcome
    else {
        return Ok(());
    };
    let Some(mut row) = PENDING_CALLS.get(&vault.store, txn, call_ref)? else {
        return Ok(());
    };
    if row.settled.is_some() || row.input.is_some() {
        return Ok(());
    }
    row.settled = Some(SettledConnectorCall::Refused {
        decision_ref: decision_ref.clone(),
        reasons: reasons.clone(),
    });
    vault.withdraw_call_owner_asks_in_txn(txn, call_ref, &mut row);
    PENDING_CALLS.put(&vault.store, txn, call_ref, &row)
}

/// The code-bound approval context a scoped connector effect's admission
/// writer proves from the rows (DOOR-079 1a): the wait that owns the held
/// call this effect's attempt and sequence name, and its binding digest, once
/// its first answer approved. `None` for any other effect, and for a wait no
/// answer approved yet.
///
/// # Errors
///
/// Other frozen bytes than the bound ones, or an original credential that no
/// longer stands.
pub(crate) fn code_wait_admission_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    prepared: &PreparedEffect,
) -> Result<Option<(EntityId, [u8; 32])>, IntentLedgerError> {
    let PreparedAuthorization::ScopedMcp {
        principal_ref,
        prepared: tool_call,
        ..
    } = &prepared.authorization
    else {
        return Ok(None);
    };
    let call_ref = connector_call_ref(
        principal_ref,
        ConnectorCallInvocation {
            attempt_id: prepared.attempt_id,
            call_seq: prepared.call_seq,
        },
    )?;
    let Some(wait_id) = PENDING_CALLS
        .get(&vault.store, txn, &call_ref)?
        .and_then(|row| row.code_consent_wait)
    else {
        return Ok(None);
    };
    let frozen_digest = *blake3::hash(tool_call.frozen_bytes()).as_bytes();
    Ok(
        code_consent_admission_in_txn(vault, txn, wait_id, &frozen_digest)?
            .map(|binding_digest| (wait_id, binding_digest)),
    )
}
