//! Typed owner setup for weave work and the inbox's real producers.
use crate::claim::{
    WeaveDigestFeedback, WeaveDigestSettingAnswer, WeaveDigestSettingChange,
    WeaveDigestSettingUndo, WeaveReaderRef, WeaveScheduleView,
};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::maintenance::agent_health::COACH_AGENT_HEALTH_FACET;
use crate::dreamer_runner::maintenance::{MAINTENANCE_QUEUE_KIND, validate_owner_in_txn};
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::memory::{DreamerAttemptRef, Memory, MemoryError, MemoryResult};
use crate::{EdgeActorClass, EntityId};
use serde::{Deserialize, Serialize};

/// Admit and enqueue a generated candidate weave recipe, pinned by the
/// engine to its version, content hash, subject and evidence. The recipe
/// executes on the host's workflow runtime, not in the HTTP handler.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveEnqueueRequest {
    pub skill_ref: String,
    pub subject_ref: String,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WeaveScheduleCleared {
    pub cleared: bool,
}

fn owner_handle(memory: &Memory<'_>, owner: &AuthenticatedOwner) -> MemoryResult<()> {
    if memory.actor_class() != EdgeActorClass::Human
        || owner.revalidate(memory.vault())? != memory.actor()
    {
        return Err(MemoryError::new(
            crate::memory::MEMORY_CODE_FORBIDDEN,
            "weave and inbox setup require the owner's own credential handle",
            &["Present the owner's own verified, unattenuated credential."],
        ));
    }
    Ok(())
}

fn queued(outcome: EnqueueDreamerAttemptOutcome) -> DreamerAttemptRef {
    let (status, existing) = match outcome {
        EnqueueDreamerAttemptOutcome::Enqueued(status) => (status, false),
        EnqueueDreamerAttemptOutcome::Existing(status) => (status, true),
    };
    DreamerAttemptRef {
        job_ref: crate::entity_id::bytes_to_hex_lower(status.attempt.id.as_bytes()),
        state: status.attempt.state.as_str().to_owned(),
        existing,
    }
}

pub fn weave_enqueue(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: WeaveEnqueueRequest,
) -> MemoryResult<DreamerAttemptRef> {
    owner_handle(memory, owner)?;
    let entity = |reference: &str| {
        EntityId::from_hex(reference)
            .map_err(|_| MemoryError::bad_request("weave inputs name 32-hex entity ids"))
    };
    let outcome = memory.vault().admit_and_enqueue_weave_recipe(
        owner,
        entity(&input.skill_ref)?,
        entity(&input.subject_ref)?,
        entity(&input.evidence_ref)?,
        memory.vault().now_recorded_at(),
    )?;
    Ok(queued(outcome))
}

pub fn weave_schedules(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
) -> MemoryResult<Vec<WeaveScheduleView>> {
    owner_handle(memory, owner)?;
    Ok(memory
        .vault()
        .weave_digest_schedules(owner)?
        .into_iter()
        .map(|(row, held)| WeaveScheduleView::from_schedule(&row, held))
        .collect())
}

pub fn weave_schedule_put(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: WeaveScheduleView,
) -> MemoryResult<WeaveScheduleView> {
    owner_handle(memory, owner)?;
    let row = input.into_schedule()?;
    memory.vault().set_weave_digest_schedule(owner, &row)?;
    Ok(WeaveScheduleView::from_schedule(&row, None))
}

pub fn weave_schedule_clear(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: WeaveReaderRef,
) -> MemoryResult<WeaveScheduleCleared> {
    owner_handle(memory, owner)?;
    Ok(WeaveScheduleCleared {
        cleared: memory
            .vault()
            .clear_weave_digest_schedule(owner, input.reader()?)?,
    })
}

fn change_ref(value: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(value)
        .map_err(|_| MemoryError::bad_request("change_ref must be a 32-hex change id"))
}

/// The Coach's changes to the owner's own digest settings, newest first
/// (FIX 5495).
pub fn weave_setting_changes(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
) -> MemoryResult<Vec<WeaveDigestSettingChange>> {
    owner_handle(memory, owner)?;
    memory
        .vault()
        .weave_digest_setting_changes(owner)
        .map_err(MemoryError::from)
}

/// The owner accepts, as his own act, or declines one proposed change.
pub fn weave_setting_change_answer(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: WeaveDigestSettingAnswer,
) -> MemoryResult<WeaveDigestSettingChange> {
    owner_handle(memory, owner)?;
    let change = change_ref(&input.change_ref)?;
    memory
        .vault()
        .answer_weave_digest_setting_change(owner, change, input.accept)
        .map_err(MemoryError::from)
}

/// The owner's one-tap undo of an applied or accepted change.
pub fn weave_setting_change_undo(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: WeaveDigestSettingUndo,
) -> MemoryResult<WeaveDigestSettingChange> {
    owner_handle(memory, owner)?;
    let change = change_ref(&input.change_ref)?;
    memory
        .vault()
        .undo_weave_digest_setting_change(owner, change)
        .map_err(MemoryError::from)
}

/// What the owner tells the Coach about his own digest.
pub fn weave_digest_feedback_put(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: WeaveDigestFeedback,
) -> MemoryResult<WeaveDigestFeedback> {
    owner_handle(memory, owner)?;
    memory
        .vault()
        .set_weave_digest_feedback(owner, &input)
        .map_err(MemoryError::from)
}

/// Queue only the Coach's existing health review. Findings, recipients and
/// grouped concern cards come from that review, never from request rows.
pub fn inbox_concerns_review(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
) -> MemoryResult<DreamerAttemptRef> {
    owner_handle(memory, owner)?;
    let vault = memory.vault();
    let outcome = vault.with_write_txn_grouped(|txn| {
        validate_owner_in_txn(vault, txn, owner)?;
        DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
            txn,
            MAINTENANCE_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: COACH_AGENT_HEALTH_FACET.into(),
                input: rmpv::Value::Nil,
                parent_attempt: None,
            },
            Some(COACH_AGENT_HEALTH_FACET.into()),
            None,
            vault.now_recorded_at(),
        )
    })?;
    Ok(queued(outcome))
}
