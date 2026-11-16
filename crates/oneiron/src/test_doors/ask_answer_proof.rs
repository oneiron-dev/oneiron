//! Doors for `tests/ask_answer_proof.rs` (UC-05 PR 2): a code consent
//! ask minted and raised as its caller, a comm widen ask raised for its
//! refused child, and a word admitted with no settlement, so the tests pin
//! whose proof each ask's word and cut take. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use crate::agent_dispatch::CommReach;
use crate::attempt_queue::AttemptId;
use crate::code_run::{
    CodeConsentCallSite, CodeConsentConnectorCall, CodeConsentDraft, CodeConsentPendingEffect,
    CodeConsentPrincipal, mint_code_consent_wait_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::consent::tool_scope::DataClass;
use crate::memory::{Memory, MemoryResult};
use crate::task_verb::sdk::AgentVerb;
use crate::task_verb::{TaskAskAnswer, TaskAskHandle, TaskAskWord};
use crate::{EdgeActorClass, EntityId, Vault, WriteActor};

/// Mints a code consent wait for one held connector call, then raises its
/// ask as `caller` and answers the ask's handle.
///
/// The wait asks the vault's live owners. Its holder settlement is none
/// when `holders` is empty, else the frozen settlement naming exactly
/// `holders` (a test double, not the policy/grant freeze path). The caller
/// is the wait's original caller, so the raised ask is the wait's reserved
/// one.
///
/// # Errors
///
/// The mint's, or the ask's.
pub fn mint_code_consent_ask(
    vault: &Vault,
    caller: EntityId,
    holders: &[EntityId],
) -> MemoryResult<TaskAskHandle> {
    let holder_settlement = if holders.is_empty() {
        None
    } else {
        Some(
            crate::consent::code_settlement::FrozenCodeConsentSettlement::with_holders_for_test(
                holders.iter().copied().collect(),
            ),
        )
    };
    let mut attempt_id = [0_u8; 16];
    attempt_id.copy_from_slice(EntityId::now().as_bytes());
    let draft = CodeConsentDraft {
        site: CodeConsentCallSite {
            wait_id: EntityId::now(),
            run_id: EntityId::now(),
            run_ref: "ask-answer-proof".to_owned(),
            step_start: 0,
            bridge_seq: 0,
            write_ordinal: 0,
            write_receipt_id: EntityId::now(),
            request_digest: [0; 32],
            origin: None,
        },
        verb: AgentVerb::ConnectorCall,
        principal: CodeConsentPrincipal {
            actor_ref: caller,
            actor_class: EdgeActorClass::Human as u8,
            credential: None,
            opener_slip: None,
        },
        pending: CodeConsentPendingEffect::ConnectorCall(CodeConsentConnectorCall {
            call_ref: EntityId::now(),
            attempt_id,
            call_seq: 0,
            grant_ref: EntityId::now(),
            key_ref: EntityId::now(),
            name: "ask-answer-proof".to_owned(),
            server: "ask-answer-proof".to_owned(),
            tool: "ask-answer-proof".to_owned(),
            endpoint: "ask-answer-proof".to_owned(),
            payload_data_class: DataClass::Public,
            remember_context: None,
            manifest_hash: [0; 32],
            protocol_revision: "test".to_owned(),
            credential_record: None,
        }),
        frozen_input_digest: [0; 32],
        holder_settlement,
        hold_reasons: vec!["test".to_owned()],
        remember_offer: None,
        standing_offer: None,
    };
    let wait_id = vault
        .with_write_txn(|txn| mint_code_consent_wait_in_txn(vault, txn, draft, |_| Some([7; 32])))?
        .ok_or_else(|| {
            crate::error::Error::InvariantViolation(
                "a code consent wait mints where the vault has an owner to ask",
            )
        })?;
    let ask = vault
        .memory(caller, EdgeActorClass::Human)
        .ask_code_consent(wait_id, "Approve this call?")?;
    Ok(TaskAskHandle { group_ref: ask })
}

/// Raises the one widen signal for `child`, refused for want of `needed`,
/// on `memory` (the refused run's own bound surface) and answers the ask's
/// handle.
///
/// # Errors
///
/// The raise's, or a missing or unparsable ask on a fresh request.
pub fn raise_comm_widen_ask(
    memory: &Memory<'_>,
    child: AttemptId,
    needed: CommReach,
) -> MemoryResult<TaskAskHandle> {
    let view = memory.raise_comm_widen(child, needed)?;
    let hex = view.ask_ref().ok_or_else(|| {
        crate::error::Error::InvariantViolation("a fresh widen request names its ask")
    })?;
    let group_ref = EntityId::from_hex(&hex).map_err(|_| {
        crate::error::Error::InvariantViolation("a widen ask ref parses as an entity")
    })?;
    Ok(TaskAskHandle { group_ref })
}

/// Admits `word` from `writer` on `handle`'s ask under `proof`, and
/// completes the addressed member, exactly as [`Memory::tasks_answer`]
/// does, but settles nothing: the ask waits for a later cut. Commits in one
/// write transaction and answers the admission.
///
/// # Errors
///
/// The admission's, as `tasks_answer` answers it.
pub fn admit_word_unsettled(
    vault: &Vault,
    handle: &TaskAskHandle,
    writer: WriteActor,
    word: &TaskAskWord,
    proof: Option<&AuthenticatedOwner>,
) -> MemoryResult<TaskAskAnswer> {
    let memory = vault.memory(writer.entity_ref(), writer.actor_class());
    match proof {
        Some(proof) => memory
            .with_owner_authorship(proof)
            .admit_ask_word_unsettled(handle, word),
        None => memory.admit_ask_word_unsettled(handle, word),
    }
}
