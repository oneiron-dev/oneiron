//! Code wait doors: resolve a code wait and read its receipt.
//! `Memory::code_wait_resolve_as` is its call surface.
//! `memory::code_wait_doors::types` defines the wire records; `crate::code_run` the consent waits.

use super::*;
use crate::code_run::{
    CodeConsentAnswerInput, CodeConsentChoice, CodeConsentSettleOutcome, CodeConsentWaitState,
    CodeConsentWaitView,
};
use crate::consent::CodeWaitReceiptLinks;
use crate::entity_id::bytes_to_hex_lower;

/// The refusal an answer from a surface bound to generated code's origin
/// gets, before anything is read or recorded (CALLS: generated answer).
/// Code-authored input never becomes a person's consent, whatever
/// credential the code runs under.
const CODE_WAIT_GENERATED_ANSWER: &str =
    "generated code cannot answer a code consent wait in a person's name";

/// The one refusal for a wait this caller cannot answer or read: unknown,
/// another run's, not sealed by its parked step yet, or resting on a record
/// this credential does not read. None of them is told apart (CALLS: wait
/// visibility).
fn wait_unavailable() -> MemoryError {
    MemoryError::not_found("code consent wait is unknown, unsealed or withheld")
}

impl Memory<'_> {
    /// `vault.code.waits.resolve`: answers one exact sealed code consent
    /// wait through the unchanged `Vault::settle_code_consent_wait_as`,
    /// which revalidates the owner in its writer, checks the target, the
    /// opener's lineage and the owner's word, keeps the first answer, and
    /// lets the held effect meet its own current gate once. A later answer
    /// gets the first one back with `already_answered`.
    pub fn code_wait_resolve_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeWaitResolveRequest,
    ) -> MemoryResult<CodeWaitReceiptView> {
        self.code_wait_owner(owner)?;
        if self.writes_generated() {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                CODE_WAIT_GENERATED_ANSWER,
                &["Ask the owner to answer through their own client."],
            ));
        }
        let target = input.target;
        let answer = CodeConsentAnswerInput {
            run_id: target.run_id,
            wait_id: target.wait_id,
            wait_generation: target.generation,
            step_hash: target_digest("target.step_hash", &target.step_hash)?,
            effect_digest: target_digest("target.effect_digest", &target.effect_digest)?,
            choice: consent_choice(input.answer),
            word_ref: input.word_ref,
        };
        // The ask and the word must read through this credential before
        // the word stands as an answer.
        let before = self
            .code_wait_view(owner, answer.wait_id)?
            .filter(|view| view.run_id == answer.run_id)
            .ok_or_else(wait_unavailable)?;
        if !self.code_wait_rows_read(before.ask.into_iter().chain([answer.word_ref]))? {
            return Err(wait_unavailable());
        }
        let view = self.vault.settle_code_consent_wait_as(owner, &answer)?;
        self.code_wait_receipt(view)?.ok_or_else(wait_unavailable)
    }

    /// `vault.code.waits.receipt`: reads one code consent wait through the
    /// unchanged `Vault::code_consent_wait_as`. It answers, resumes and
    /// sends nothing, and enters no run. `None` for a wait this caller
    /// cannot read (CALLS: wait visibility).
    pub fn code_wait_receipt_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeWaitReceiptRequest,
    ) -> MemoryResult<Option<CodeWaitReceiptView>> {
        self.code_wait_owner(owner)?;
        match self
            .code_wait_view(owner, input.wait_id)?
            .filter(|view| view.run_id == input.run_id)
        {
            Some(view) => self.code_wait_receipt(view),
            None => Ok(None),
        }
    }

    /// The engine's read projection of wait `wait_id`; `None` when no wait
    /// has that id.
    fn code_wait_view(
        &self,
        owner: &AuthenticatedOwner,
        wait_id: EntityId,
    ) -> MemoryResult<Option<CodeConsentWaitView>> {
        match self.vault.code_consent_wait_as(owner, wait_id) {
            Ok(view) => Ok(Some(view)),
            Err(crate::Error::EntityNotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// `view` as the doors show it, once its ask and word read through
    /// this credential: listed as the rows it derives from, and `None` for
    /// an unsealed wait or a withheld record (CALLS: wait visibility).
    fn code_wait_receipt(
        &self,
        view: CodeConsentWaitView,
    ) -> MemoryResult<Option<CodeWaitReceiptView>> {
        if !self.code_wait_rows_read(view.ask.into_iter().chain(view.word_ref))? {
            return Ok(None);
        }
        Ok(receipt_view(view))
    }
}

/// A 64-character lowercase hex digest a target names, checked against the
/// stored wait by the engine (CALLS: resolve target).
fn target_digest(field: &str, hex: &str) -> MemoryResult<[u8; 32]> {
    blake3::Hash::from_hex(hex)
        .ok()
        .filter(|_| !hex.bytes().any(|byte| byte.is_ascii_uppercase()))
        .map(|hash| *hash.as_bytes())
        .ok_or_else(|| MemoryError::bad_request(format!("{field} is not 64 lowercase hex")))
}

/// The engine's choice a wire answer names: the same three words.
const fn consent_choice(choice: CodeWaitChoice) -> CodeConsentChoice {
    match choice {
        CodeWaitChoice::ApproveOnce => CodeConsentChoice::ApproveOnce,
        CodeWaitChoice::ApproveAndStopAsking => CodeConsentChoice::ApproveAndStopAsking,
        CodeWaitChoice::Deny => CodeConsentChoice::Deny,
    }
}

/// The wire answer an engine choice is.
const fn wire_choice(choice: CodeConsentChoice) -> CodeWaitChoice {
    match choice {
        CodeConsentChoice::ApproveOnce => CodeWaitChoice::ApproveOnce,
        CodeConsentChoice::ApproveAndStopAsking => CodeWaitChoice::ApproveAndStopAsking,
        CodeConsentChoice::Deny => CodeWaitChoice::Deny,
    }
}

/// The wire outcome an engine settlement is.
const fn wire_outcome(outcome: CodeConsentSettleOutcome) -> CodeWaitSettleOutcome {
    match outcome {
        CodeConsentSettleOutcome::Delivered => CodeWaitSettleOutcome::Delivered,
        CodeConsentSettleOutcome::Refused => CodeWaitSettleOutcome::Refused,
        CodeConsentSettleOutcome::DeliveryUnknown => CodeWaitSettleOutcome::DeliveryUnknown,
    }
}

/// The engine's view projected onto the wire, or `None` for a wait its
/// parked step has not sealed: no answer reaches it, and it has no exact
/// target to name yet.
fn receipt_view(view: CodeConsentWaitView) -> Option<CodeWaitReceiptView> {
    let (generation, step_hash) = view.sealed?;
    let state = match view.state {
        CodeConsentWaitState::Provisional => return None,
        CodeConsentWaitState::Waiting => CodeWaitState::Waiting,
        CodeConsentWaitState::Settling => CodeWaitState::Settling,
        CodeConsentWaitState::Settled => CodeWaitState::Settled,
        CodeConsentWaitState::Consumed => CodeWaitState::Consumed,
    };
    let answer = match (
        view.answer,
        view.word_ref,
        view.answer_receipt,
        view.answered_at_ms,
    ) {
        (Some(answer), Some(word_ref), Some(decision_ref), Some(answered_at_ms)) => {
            Some(CodeWaitAnswerView {
                answer: wire_choice(answer),
                word_ref,
                decision_ref,
                answered_at_ms,
            })
        }
        _ => None,
    };
    let settlement = match (view.outcome, view.settlement_receipt, view.settled_at_ms) {
        (Some(outcome), Some(receipt_ref), Some(settled_at_ms)) => Some(CodeWaitSettlementView {
            receipt_ref,
            outcome: wire_outcome(outcome),
            reason_codes: view.reasons,
            settled_at_ms,
            ledger: view.settlement_links.map(ledger_view),
        }),
        _ => None,
    };
    let consumption = match (
        view.consumption_receipt,
        view.consumed_step,
        view.resumed_path,
        view.result_handle,
        view.consumed_at_ms,
    ) {
        (Some(receipt_ref), Some(step), Some(resumed_path), Some(result_handle), Some(at)) => {
            Some(CodeWaitConsumptionView {
                receipt_ref,
                step,
                resumed_path,
                result_handle,
                consumed_at_ms: at,
                ledger: view.consumption_links.map(ledger_view),
            })
        }
        _ => None,
    };
    Some(CodeWaitReceiptView {
        target: CodeWaitTarget {
            run_id: view.run_id,
            wait_id: view.wait_id,
            generation,
            step_hash: bytes_to_hex_lower(&step_hash),
            effect_digest: bytes_to_hex_lower(&view.effect_digest),
        },
        state,
        verb: view.verb,
        connector: view.connector,
        tool: view.tool,
        browser: view.browser.map(|action| CodeWaitBrowserAction {
            act: action.act,
            class: action.class,
            role: action.role,
            name: action.name,
            locator: action.locator,
            page: action.page,
            press: action.need,
        }),
        hold_reasons: view.hold_reasons,
        ask_ref: view.ask,
        allowed_answers: view.options.into_iter().map(wire_choice).collect(),
        answer,
        settlement,
        consumption,
        already_answered: view.already_answered,
    })
}

/// A receipt's ledger links on the wire.
fn ledger_view(links: CodeWaitReceiptLinks) -> CodeWaitLedgerLinks {
    CodeWaitLedgerLinks {
        prior_ref: links
            .prior_receipt
            .map(|receipt| format!("gate:{}", receipt.to_hex())),
        word_ref: links.word_ref,
        facts_digest: bytes_to_hex_lower(&links.facts_digest),
    }
}
