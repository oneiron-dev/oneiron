//! Cfg-only setup for `tests/restored_unjoined_code_consent_waits.rs`: bind
//! the host's call site, seal its parked step, and inspect its one-shot marker.

use crate::authority::InvocationSlipBinding;
use crate::code_run::{
    CodeConsentCallSite, CodeRunBridgeCall, CodeRunDeterminism, CodeRunReplayRecord,
    CodeRunStepCheckpoint, ExecutorStorage, ParkedWait, SelfAgentVerbCall, SelfCall,
    SelfDispatchOutcome, SelfDurableWait, SelfDurableWaitReason, SelfEffect, WaitKey,
    seal_parked_code_consent_in_txn,
};
use crate::consent::{EffectDigest, approve_once_authorization_in_txn};
use crate::memory::Memory;
use crate::task_verb::sdk::AgentVerb;
use crate::test_doors::host_write_origin::host_write_origin;
use crate::{EdgeActorClass, EntityId, Error, Result, Vault};

/// Binds the fixture's first bridge call, without a guest or dispatcher.
///
/// # Errors
///
/// If the test host origin cannot be constructed.
pub fn code_consent_memory<'a>(
    vault: &'a Vault,
    actor: EntityId,
    run_id: EntityId,
    wait_id: EntityId,
    witness: Option<&InvocationSlipBinding>,
) -> Result<Memory<'a>> {
    let origin = host_write_origin(actor)?.with_code_consent(CodeConsentCallSite {
        wait_id,
        run_id,
        run_ref: run_id.to_hex(),
        step_start: 0,
        bridge_seq: 0,
        write_ordinal: 0,
        write_receipt_id: EntityId::now(),
        request_digest: [0; 32],
        origin: None,
    });
    let memory = vault
        .memory(actor, EdgeActorClass::Human)
        .with_host_origin(origin);
    Ok(match witness {
        Some(witness) => memory.with_invocation_slip(witness),
        None => memory,
    })
}

/// Commits a one-call parked step with the same seal writer as the executor.
///
/// # Errors
///
/// If the replay, seal or park cannot be written.
pub fn park_code_consent_step(
    vault: &Vault,
    run_id: EntityId,
    wait_id: EntityId,
    verb: AgentVerb,
    input: serde_json::Value,
) -> Result<()> {
    let at = vault.now_recorded_at() * 1_000;
    let mut record = CodeRunReplayRecord::new(run_id, CodeRunDeterminism::new(at, [0; 32]));
    record.bridge_calls.push(CodeRunBridgeCall::record(
        0,
        &SelfCall::AgentVerb(SelfAgentVerbCall { verb, input }),
        &SelfDispatchOutcome::DurableWait(SelfDurableWait {
            wait_id,
            effect: SelfEffect::AgentVerb,
            reason: SelfDurableWaitReason::OutboundEffect,
            prompt: None,
        }),
        at,
        at,
    )?);
    record.step_checkpoints.push(
        CodeRunStepCheckpoint::new(0, "code-consent", [0; 32], at)?
            .ending_at(1)
            .with_bridge_calls(0, 1),
    );
    let key = WaitKey {
        run: run_id,
        wait_id,
        generation: 0,
    };
    vault.put_code_run_replay_record_if_generation_with_heal_and(&record, None, None, |txn| {
        seal_parked_code_consent_in_txn(vault, txn, &record, &ParkedWait { key, step_start: 0 })
    })?;
    if ExecutorStorage::Canonical(vault).park_wait(&key)? {
        return Err(Error::InvariantViolation(
            "the fixture wait already has a reply",
        ));
    }
    Ok(())
}

/// Reads whether the marker is available through the same lookup as admission.
///
/// # Errors
///
/// The marker is already spent, unreadable, or a storage read failed.
pub fn approve_once_available(vault: &Vault, digest: [u8; 32]) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let digest = EffectDigest::from_bytes(digest);
    Ok(approve_once_authorization_in_txn(&vault.store, &txn, &digest)?.is_some())
}
