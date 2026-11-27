//! Runs one NOTE review for `tests/note_review_claim_depends_on_note.rs` and
//! `tests/note_review_claim_takes_note_world.rs`.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use crate::claim::world_access::WorldAuthoritySet;
use crate::claim::{ClaimApprovalStatus, PointRead, ScopedReadActorKey};
use crate::dreamer_consolidation::{
    ConsolidationDecisions, ConsolidationExecutor, RoleBackends, note_review_seen_in_txn,
};
use crate::dreamer_promotion::{DreamerRunContext, PromotionWriterSink};
use crate::dreamer_runner::{
    AdmitDreamerAttempt, CompleteDreamerAttempt, DreamerAdmissionOutcome, DreamerRunnerStore,
    SettleDreamerBudget,
};
use crate::dreamer_wake::{
    DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext, WakePassDeadline,
};
use crate::llm::{HostInferenceBinding, HostInferenceContext};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, ContentPart, DreamerClaimAuthoringStrategy,
    EntityId, Error, FatalLlmError, FinishReason, LlmBackend, LlmCapability, LlmError,
    LlmGenerateFuture, LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest,
    LlmResponse, LlmStreamResult, LlmUsage, ModelId, ModelLocality, Result, UnsupportedCapability,
    Vault,
};

struct ReplyBackend(String);

impl LlmBackend for ReplyBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text: self.0.clone(),
                        signature: None,
                    }],
                },
                usage: LlmUsage {
                    input: LlmInputUsage {
                        total: 40,
                        cache_read: 0,
                        cache_write: 0,
                    },
                    output: LlmOutputUsage {
                        total: 10,
                        text: 10,
                        reasoning: 0,
                    },
                    raw_provider: serde_json::Value::Null,
                    call_metadata: None,
                },
                finish_reason: FinishReason::Stop,
                reply_assertions: Default::default(),
                token_scores: None,
            })
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(LlmError::Fatal(FatalLlmError::Unsupported(
            UnsupportedCapability {
                capability: LlmCapability::Streaming,
                model: None,
                reason: None,
            },
        )))
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the NOTE review did not finish in one poll"),
    }
}

/// Runs one queued NOTE review with `reply` as its scripted model response.
/// Returns newly landed Auto CLAIM ids on a fixture vault with no concurrent writers.
///
/// # Errors
///
/// The vault's, or an attempt that was not admitted or did not complete.
pub fn review_notes_once(vault: &Vault, reply: serde_json::Value) -> Result<Vec<EntityId>> {
    const RUN_ID: &str = "note-review-fixture";
    const LEASE_OWNER: &str = "note-review-test-door";
    const BUDGET_ID: &str = "note-review-wake";
    const BUDGET_TOTAL: u64 = 10_000;
    const RESERVE: u64 = 100;
    const NOW_SECS: u64 = 21;

    super::consolidation::allow_own_server_extraction(vault)?;
    let before: BTreeSet<_> = vault
        .entities_by_type(ENTITY_TYPE_CLAIM)?
        .into_iter()
        .collect();
    let store = DreamerRunnerStore::new(vault);
    vault.with_write_txn_grouped(|txn| {
        store.enqueue_note_review_in_txn(txn, None, None, Some(RUN_ID.into()), NOW_SECS)
    })?;
    let DreamerAdmissionOutcome::Admitted(admitted) =
        store.admit_next_note_review(AdmitDreamerAttempt {
            lease_owner: LEASE_OWNER.into(),
            now: NOW_SECS,
            budget_id: BUDGET_ID.into(),
            budget_total_units: BUDGET_TOTAL,
            reserve_units: RESERVE,
            started_milestone: None,
        })?
    else {
        return Err(Error::InvalidConfig("no NOTE review was admitted".into()));
    };

    let attempt = &admitted.status.attempt;
    let actor = vault.dreamer_actor_for_attempt(attempt.id)?;
    let now_ms = NOW_SECS * 1_000;
    let backend = ReplyBackend(reply.to_string());
    let guard = BudgetGuard::with_reserve_units(
        BUDGET_ID,
        BUDGET_TOTAL,
        RESERVE,
        BudgetExhaustionPolicy::Suspend,
    );
    let mut sink = PromotionWriterSink::new(
        vault,
        DreamerRunContext {
            run_id: RUN_ID.into(),
            attempt_id: attempt.id,
            agent_actor: actor,
            now_ms,
        },
    );
    let model =
        ModelId::new("test/model@r1").map_err(|_| Error::InvalidConfig("model id".into()))?;
    let deadline = WakePassDeadline::with_clock(180_000, Arc::new(|| 0));
    let mut executor = ConsolidationExecutor {
        roles: RoleBackends::default(),
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor,
        inference: HostInferenceContext {
            binding: HostInferenceBinding::Advertised {
                model: model.clone(),
                locality: ModelLocality::OwnServer,
                keyless: false,
            },
            extraction_egress: Some(&|_: &LlmRequest| true),
        },
        model,
        sink: &mut sink,
        scope: None,
        decisions: ConsolidationDecisions::shipped()?,
    };
    let outcome = ready(executor.execute(
        &admitted,
        &mut WakeAttemptContext {
            vault,
            deadline: &deadline,
            cancel: None,
            device_cancel: None,
            budget_id: BUDGET_ID,
            now_ms,
            prepared_wake: None,
            prepared_attempt: None,
            spend_meter: None,
        },
    ))?;
    let DreamerAttemptExecution::Completed {
        completed_units,
        step_bindings,
    } = outcome
    else {
        return Err(Error::InvalidConfig(format!(
            "the NOTE review did not complete: {outcome:?}"
        )));
    };
    store.settle_budget_with_step_receipts(
        SettleDreamerBudget {
            budget_id: BUDGET_ID.into(),
            child_attempt: attempt.id,
            actual_units: completed_units,
            now: NOW_SECS,
        },
        &step_bindings,
    )?;
    store.complete(CompleteDreamerAttempt {
        id: attempt.id,
        lease_owner: LEASE_OWNER.into(),
        attempt_count: attempt.attempt_count,
        now: NOW_SECS,
    })?;

    // NOTE review promotes directly instead of sending candidates to the executor's sink.
    let mut landed = Vec::new();
    for id in vault.entities_by_type(ENTITY_TYPE_CLAIM)? {
        if !before.contains(&id)
            && vault
                .get_claim(&id)?
                .is_some_and(|body| body.approval == ClaimApprovalStatus::Auto)
        {
            landed.push(id);
        }
    }
    Ok(landed)
}

type AfterReplyHook = Box<dyn FnOnce(&Vault) + Send>;

/// Runs one queued NOTE review, invoking `after_reply` once the model reply is accepted.
/// A delete during `generate` makes the durable step discard the reply instead.
///
/// # Errors
///
/// The vault's, or an attempt that did not accept its reply or complete.
pub fn review_notes_once_after_reply(
    vault: &Vault,
    reply: serde_json::Value,
    after_reply: impl FnOnce(&Vault) + Send + 'static,
) -> Result<Vec<EntityId>> {
    let slot = super::vault_state::vault_extension::<Mutex<Option<AfterReplyHook>>>(vault);
    *slot.lock().expect("lock the after-reply hook") = Some(Box::new(after_reply));
    let reviewed = review_notes_once(vault, reply);
    let uncalled = slot.lock().expect("lock the after-reply hook").take();
    let landed = reviewed?;
    if uncalled.is_some() {
        return Err(Error::InvalidConfig(
            "the NOTE review did not accept a reply".into(),
        ));
    }
    Ok(landed)
}

/// Runs the hook armed for this fixture vault, if any.
pub(crate) fn run_after_reply_hook(vault: &Vault) {
    let slot = super::vault_state::vault_extension::<Mutex<Option<AfterReplyHook>>>(vault);
    let hook = slot.lock().expect("lock the after-reply hook").take();
    if let Some(hook) = hook {
        hook(vault);
    }
}

/// Whether the Dreamer's review row for `note` is still stored.
///
/// # Errors
///
/// The vault's, including failure to decode the row.
pub fn note_review_seen(vault: &Vault, note: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    note_review_seen_in_txn(&vault.store, &txn, &note)
}

/// Whether `claim` reads to the owner's lane held to `worlds` (base reality
/// too when `base`): a point read under that world ceiling.
///
/// # Errors
///
/// The vault's, or the owner binding no longer holds.
pub fn claim_reads_in_worlds(
    vault: &Vault,
    claim: EntityId,
    base: bool,
    worlds: &[EntityId],
) -> Result<bool> {
    let owner = crate::vault::embedded_owner_actor_id()?;
    let read = vault
        .scoped_read(ScopedReadActorKey::vault_owner(owner))
        .within_worlds(WorldAuthoritySet::new(base, worlds.iter().copied())?);
    let rows = read.read(&[PointRead::id(claim)], None)?;
    Ok(rows.value[0].is_some())
}

/// Registers the promotion's NOTE dependencies in a grouped write transaction.
///
/// # Errors
///
/// A NOTE was not live at the write, or the vault could not register the dependency.
pub fn record_note_dependencies_for_test(
    vault: &Vault,
    claim: EntityId,
    notes: &[EntityId],
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| vault.record_note_dependencies_in_txn(txn, &claim, notes))
}

/// Whether the dependency walk has a CLAIM-to-NOTE registration.
///
/// # Errors
///
/// The vault's, including failure to decode the dependency index.
pub fn note_dependency_exists(vault: &Vault, claim: EntityId, note: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(crate::ports::dependency_sources_in(&vault.store, &txn, &claim)?.contains(&note))
}
