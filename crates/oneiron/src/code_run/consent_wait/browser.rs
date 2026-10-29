//! A browser act a press held, bound to a code consent wait (FIX 10423).
//!
//! A code-mode browser click, click at a point or batch whose grant gave one
//! act no press (a press per send, or a reviewed batch whose sends are
//! spent) binds that exact act to a wait minted at the call's own site: the
//! act and its own input, the row it resolved to, and the page and guest it
//! ran in. The wait asks the vault's owner, and the run parks on it. A
//! payment, which only a person's press in the browser runs, binds none: it
//! stays the person's, as before.
//!
//! An approving answer is driven by the served host
//! ([`super::CodeConsentEffectHost`]). It admits the act once, in the writer
//! that spends the answer's approve-once marker beside the wait's admission,
//! so a retried pass or a replayed step never runs it again; it arms one
//! press for that exact act on the run's live browser, runs the frozen
//! operands, and settles the wait with what the act came to. The press is a
//! person's, per send: it pays no reviewed batch's send. A pass admitted
//! before and never settled may have run: it settles as of unknown delivery
//! and runs nothing.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::{ComposedEffect, EffectDigest, EffectFacts, UndoFidelity};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryResult};
use crate::task_verb::sdk::AgentVerb;

use super::binding::{
    CodeConsentDraft, code_consent_binds, mint_code_consent_wait_in_txn,
    read_code_consent_wait_in_txn, record_code_consent_admission_in_txn,
};
use super::settle::{
    CODE_WAIT_ORIGINAL_AUTHORITY_REFUSED, offered_choices, original_authority_holds_in_txn,
    settle_with_reply_in_txn,
};
use super::types::{
    CodeConsentBrowserAction, CodeConsentPendingEffect, CodeConsentSettleOutcome,
    CodeConsentWaitRow,
};

/// The hold a press per send gives a held browser act.
const BROWSER_PRESS_PER_SEND: &str = "browser_press_per_send";

/// The hold a spent reviewed batch gives a held browser act.
const BROWSER_PRESS_BATCH_SPENT: &str = "browser_press_batch_spent";

/// Why a held browser act whose ask did not open settles refused: no one
/// was asked, so no run parks on it and its call answers as before.
const CODE_WAIT_ASK_UNOPENED: &str = "code_wait_ask_unopened";

/// Why a held browser act settles as of unknown delivery: an earlier
/// answered pass admitted it and never settled, so it may have run.
const CODE_WAIT_PASS_UNSETTLED: &str = "code_wait_pass_unsettled";

/// The hash domain of a held browser act's admission.
const BROWSER_ADMISSION_DOMAIN: &[u8] = b"oneiron:code-consent-browser-admission:v1";

/// The most characters of a row's name or a page the question quotes. The
/// wait's view keeps them whole.
const QUESTION_TEXT_MAX_CHARS: usize = 120;

/// What a held browser act came to, as the host that ran it found it.
#[derive(Debug, Clone, PartialEq)]
pub enum CodeConsentBrowserOutcome {
    /// The act ran: its own answer.
    Delivered(serde_json::Value),
    /// Nothing ran, for these reasons.
    Refused(Vec<String>),
    /// The act's input was sent, and what it came to is not known: its
    /// receipt where one landed. It never runs again.
    DeliveryUnknown {
        reasons: Vec<String>,
        receipt: Option<serde_json::Value>,
    },
}

/// A held browser act the host's answered pass runs now, once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedBrowserAct {
    /// The run whose browser the act runs in.
    pub run_id: EntityId,
    pub action: CodeConsentBrowserAction,
}

/// What a held browser act's parked run is given (FIX 10423): its call's
/// verb and the held act, what the act came to, the act's own answer when
/// it ran, the reasons when it did not, and a held batch's answer at its
/// stop, whose completed steps and receipts stand and whose steps after the
/// held one the run may send again.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct CodeConsentBrowserReply {
    pub(crate) verb: String,
    pub(crate) act: String,
    pub(crate) outcome: CodeConsentSettleOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) answer: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) stopped: Option<serde_json::Value>,
}

impl Memory<'_> {
    /// Binds the browser act a press held on this run's `verb` call to a
    /// code consent wait at the call's own site, and opens the owner's
    /// question as the call's own caller (FIX 10423). Returns the wait.
    ///
    /// `None`, and the call answers as it did, where the bound origin names
    /// no code run's site, where the act's class is a person's own, or where
    /// nothing was minted (the caller's credential no longer verifies, the
    /// vault has no owner). An ask that does not open settles its wait
    /// refused, so no run parks on a question no one was asked.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn hold_browser_press(
        &self,
        verb: AgentVerb,
        action: CodeConsentBrowserAction,
    ) -> MemoryResult<Option<EntityId>> {
        let Some(site) = self.code_consent_site().cloned() else {
            return Ok(None);
        };
        let hold = match action.need.as_str() {
            "per_send" => BROWSER_PRESS_PER_SEND,
            "batch_spent" => BROWSER_PRESS_BATCH_SPENT,
            _ => return Ok(None),
        };
        if !verb.is_browser() || !code_consent_binds(verb) {
            return Ok(None);
        }
        let class = action.class.clone();
        let draft = CodeConsentDraft {
            site,
            verb,
            principal: self.code_consent_principal(),
            frozen_input_digest: *blake3::hash(action.operands.as_bytes()).as_bytes(),
            pending: CodeConsentPendingEffect::BrowserAction(action),
            hold_reasons: vec![hold.to_owned()],
            remember_offer: None,
        };
        let vault = self.vault();
        let minted = vault.with_write_txn(|txn| {
            mint_code_consent_wait_in_txn(vault, txn, draft, |binding| {
                browser_approval_digest(&class, binding)
            })
        })?;
        let Some(wait_id) = minted else {
            return Ok(None);
        };
        let asked = vault
            .browser_question_text(wait_id)
            .map_err(crate::memory::MemoryError::from)
            .and_then(|text| self.ask_code_consent(wait_id, &text));
        if let Err(error) = asked {
            tracing::warn!(
                wait = %wait_id.to_hex(),
                code = %error.code,
                message = %error.message,
                "browser press ask not opened; the call answers as before"
            );
            vault.with_write_txn(|txn| {
                match read_code_consent_wait_in_txn(vault, txn, wait_id)? {
                    Some(row) if row.ask.is_none() => {
                        refuse_browser_wait_in_txn(vault, txn, row, &[CODE_WAIT_ASK_UNOPENED])
                            .map(drop)
                    }
                    _ => Ok(()),
                }
            })?;
            return Ok(None);
        }
        Ok(Some(wait_id))
    }
}

impl Vault {
    /// The held browser act wait `wait_id` binds, when its effect is one
    /// (FIX 10423); `None` for any other effect.
    ///
    /// # Errors
    ///
    /// Storage errors, or an unknown wait.
    pub fn code_consent_held_browser_action(
        &self,
        wait_id: EntityId,
    ) -> Result<Option<CodeConsentBrowserAction>> {
        let txn = self.store.env.read_txn()?;
        let row = read_code_consent_wait_in_txn(self, &txn, wait_id)?.ok_or(Error::EntityNotFound)?;
        Ok(row.binding.pending.browser_action().cloned())
    }

    /// Admits wait `wait_id`'s held browser act for its host's answered
    /// pass, once (FIX 10423): in one writer, the answer's approve-once
    /// marker is spent and the wait records its admission, so no later pass
    /// runs the act again. Returns the act to run now.
    ///
    /// `None` when nothing runs: the wait is unanswered, denied or settled;
    /// an earlier pass admitted it and never settled (it settles as of
    /// unknown delivery now); or the original caller's own credential no
    /// longer stands (it settles refused now).
    ///
    /// # Errors
    ///
    /// An unknown wait or one no browser act binds, an approved wait with no
    /// live approve-once marker, or storage errors.
    pub fn admit_browser_code_consent_wait(
        &self,
        wait_id: EntityId,
    ) -> Result<Option<AdmittedBrowserAct>> {
        self.with_write_txn(|txn| {
            let row =
                read_code_consent_wait_in_txn(self, txn, wait_id)?.ok_or(Error::EntityNotFound)?;
            let action = row
                .binding
                .pending
                .browser_action()
                .cloned()
                .ok_or(Error::InvalidConfig(
                    "this code consent wait binds no browser act".to_owned(),
                ))?;
            if !row.approved_unsettled() {
                return Ok(None);
            }
            if row.admission.is_some() {
                let unknown = CodeConsentBrowserOutcome::DeliveryUnknown {
                    reasons: vec![CODE_WAIT_PASS_UNSETTLED.to_owned()],
                    receipt: None,
                };
                settle_browser_in_txn(self, txn, row, unknown)?;
                return Ok(None);
            }
            if !original_authority_holds_in_txn(self, txn, &row.binding) {
                refuse_browser_wait_in_txn(self, txn, row, &[CODE_WAIT_ORIGINAL_AUTHORITY_REFUSED])?;
                return Ok(None);
            }
            let digest = EffectDigest::from_bytes(row.binding.effect_digest);
            let approval = crate::consent::approve_once_authorization_in_txn(&self.store, txn, &digest)?
                .ok_or(Error::InvariantViolation(
                    "an approved browser code consent wait holds no approve-once marker",
                ))?;
            crate::consent::spend_approve_once_in_txn(&self.store, txn, &approval)?;
            let decision = row
                .answer
                .as_ref()
                .map(|answer| answer.decision)
                .ok_or(Error::InvariantViolation(
                    "an approved browser code consent wait has no answer",
                ))?;
            let mut intent = blake3::Hasher::new();
            intent.update(BROWSER_ADMISSION_DOMAIN);
            intent.update(&row.binding.binding_digest);
            record_code_consent_admission_in_txn(
                self,
                txn,
                wait_id,
                *intent.finalize().as_bytes(),
                decision,
            )?;
            Ok(Some(AdmittedBrowserAct {
                run_id: row.binding.run_id,
                action,
            }))
        })
    }

    /// Settles wait `wait_id`'s held browser act with what it came to, once
    /// (FIX 10423), and delivers the reply to its parked run, which wakes in
    /// the same commit. A settled wait keeps its first settlement. `true`
    /// when this call settled it.
    ///
    /// # Errors
    ///
    /// An unknown wait or one no browser act binds, or storage errors.
    pub fn settle_browser_code_consent_wait(
        &self,
        wait_id: EntityId,
        outcome: CodeConsentBrowserOutcome,
    ) -> Result<bool> {
        self.with_write_txn(|txn| {
            let row =
                read_code_consent_wait_in_txn(self, txn, wait_id)?.ok_or(Error::EntityNotFound)?;
            settle_browser_in_txn(self, txn, row, outcome)
        })
    }

    /// The wording of a held browser act's question: the act, its row and
    /// page, the wait, why its grant gave no press, the choices it offers,
    /// and that nothing is clicked until the owner answers. It sets no
    /// deadline: silence never approves.
    fn browser_question_text(&self, wait_id: EntityId) -> Result<String> {
        let txn = self.store.env.read_txn()?;
        let row = read_code_consent_wait_in_txn(self, &txn, wait_id)?.ok_or(Error::EntityNotFound)?;
        let action = row
            .binding
            .pending
            .browser_action()
            .ok_or(Error::EntityNotFound)?;
        let choices = offered_choices(&row.binding)
            .into_iter()
            .map(|choice| choice.as_str().replace('_', " "))
            .collect::<Vec<_>>()
            .join(", ");
        let need = if action.need == "batch_spent" {
            "a person's press now that its reviewed batch is spent"
        } else {
            "a person's press for each send"
        };
        Ok(format!(
            "A code run asks before it clicks the {role} \"{name}\" on {page} (code consent wait \
             {wait}). Its {class} grant needs {need}. Answer one of: {choices}. Nothing is clicked \
             until you answer.",
            role = clip(&action.role),
            name = clip(&action.name),
            page = action.page.as_deref().map_or_else(|| "the open page".to_owned(), clip),
            wait = wait_id.to_hex(),
            class = action.class,
        ))
    }
}

/// Settles `row`'s held browser act refused for `reasons`, in the caller's
/// writer. `true` when this call settled it.
pub(super) fn refuse_browser_wait_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: CodeConsentWaitRow,
    reasons: &[&str],
) -> Result<bool> {
    let reasons = reasons.iter().map(|reason| (*reason).to_owned()).collect();
    settle_browser_in_txn(vault, txn, row, CodeConsentBrowserOutcome::Refused(reasons))
}

/// Settles `row`'s held browser act with `outcome`, in the caller's writer:
/// its reply names the call's verb, the act, what it came to, and a held
/// batch's answer at its stop. A settled wait keeps its first settlement.
fn settle_browser_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: CodeConsentWaitRow,
    outcome: CodeConsentBrowserOutcome,
) -> Result<bool> {
    if row.settlement.is_some() {
        return Ok(false);
    }
    let action = row
        .binding
        .pending
        .browser_action()
        .ok_or(Error::InvariantViolation(
            "a browser outcome settles only a held browser act",
        ))?;
    let (settled, answer, reasons) = match outcome {
        CodeConsentBrowserOutcome::Delivered(answer) => {
            (CodeConsentSettleOutcome::Delivered, Some(answer), Vec::new())
        }
        CodeConsentBrowserOutcome::Refused(reasons) => {
            (CodeConsentSettleOutcome::Refused, None, reasons)
        }
        CodeConsentBrowserOutcome::DeliveryUnknown { reasons, receipt } => {
            (CodeConsentSettleOutcome::DeliveryUnknown, receipt, reasons)
        }
    };
    let reply = CodeConsentBrowserReply {
        verb: row.binding.verb_row.clone(),
        act: action.act.clone(),
        outcome: settled,
        answer,
        reasons: reasons.clone(),
        stopped: action
            .stopped
            .as_deref()
            .and_then(|stopped| serde_json::from_str(stopped).ok()),
    };
    let reply = serde_json::to_value(reply)
        .map_err(|_| Error::InvalidConfig("a code consent reply is not JSON".to_owned()))?;
    settle_with_reply_in_txn(vault, txn, row, settled, reasons, &reply, None)
}

/// The code-bound approval digest a held browser act's answer names: the
/// consent vocabulary's own digest of an outwardly observed, undoless act of
/// `class`, bound to its wait's binding digest, so the approve-once marker an
/// answer writes covers that wait's act alone.
fn browser_approval_digest(class: &str, binding_digest: &[u8; 32]) -> Option<[u8; 32]> {
    let kind = format!("{class}:code_wait:{}", bytes_to_hex_lower(binding_digest));
    let mut facts = EffectFacts::new(kind).ok()?;
    facts.external_observers = true;
    facts.undo_fidelity = UndoFidelity::None;
    Some(*ComposedEffect::new(facts).digest().as_bytes())
}

/// `text`, cut to [`QUESTION_TEXT_MAX_CHARS`] characters.
fn clip(text: &str) -> String {
    text.chars().take(QUESTION_TEXT_MAX_CHARS).collect()
}
