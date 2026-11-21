//! One Dreamer NOTE review, for tests/note_review_sends_under_its_rows.rs
//! ([DREAMER-UNSOURCED-ROLE-CALLS-SEND-UNFENCED]): an observation NOTE the
//! Dreamer may read, reviewed through the public consolidation executor on a
//! scripted extraction model whose host lends a sourced route, so a test
//! reads the rows each bound call named.

use std::sync::{Arc, Mutex, PoisonError};

use super::consolidation::{ReplyBackend, allow_fixture_extraction, ready};
use super::extraction_verdict::RecordingSourcedRoute;
use crate::dreamer_consolidation::{
    ConsolidationDecisions, ConsolidationExecutor, DREAMER_EXTRACTION_ROLE, RoleBackend,
    RoleBackends, SourcedBackend,
};
use crate::dreamer_promotion::{DreamerRunContext, PromotionWriterSink};
use crate::dreamer_runner::{AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerRunnerStore};
use crate::dreamer_wake::{
    DreamerAttemptExecution, DreamerAttemptExecutor, WakeAttemptContext, WakePassDeadline,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::{HostInferenceBinding, HostInferenceContext};
use crate::vault::Vault;
use crate::write_envelope::WriteActor;
use crate::{
    BudgetExhaustionPolicy, BudgetGuard, DreamerClaimAuthoringStrategy, ModelId, ModelLocality,
};

/// The scripted reply: no candidate, no person, and an importance under the
/// keep line, so the review records the NOTE as seen and lands nothing.
const NO_BELIEF_REPLY: &str = r#"{"candidates":[],"persons":[],"importance":0.1}"#;

/// What one NOTE review sent.
#[derive(Debug, Clone)]
pub struct NoteReviewBound {
    /// The NOTE the review read.
    pub note: EntityId,
    /// The rows each call sent bound to its source rows named, in call
    /// order; a call sent on the role's own route leaves no entry.
    pub bound: Vec<Vec<EntityId>>,
    /// The model calls the review made, bound or not.
    pub calls: usize,
}

/// Writes one observation NOTE holding `markdown` as the owner, publishes its
/// text as the idle loop does, and runs one Dreamer NOTE review over the
/// vault: the extraction role routed to a scripted model that answers
/// [`NO_BELIEF_REPLY`], with a sourced route that records each bound call's
/// rows. `vault` is a fresh [`super::consolidation::open_dreamer_vault`].
///
/// # Errors
///
/// The vault's, or a review that admits no attempt or does not complete.
pub fn note_review_bound_rows(vault: &Vault, markdown: &str) -> Result<NoteReviewBound> {
    let owner = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| Error::InvalidConfig(error.message))?;
    let note = vault
        .create_note(
            "observation",
            markdown,
            WriteActor::new(owner, EdgeActorClass::Human),
        )
        .map_err(|error| Error::InvalidConfig(error.message))?;
    vault.set_indexed_idle_delay_ms(0)?;
    let published = vault.refresh_staged_indexed_at_idle(u64::MAX)?;
    if !published.failed.is_empty() {
        return Err(Error::InvalidConfig(format!(
            "the NOTE's text did not publish: {:?}",
            published.failed
        )));
    }

    let actor = vault.dreamer_authority()?;
    let store = DreamerRunnerStore::new(vault);
    vault.with_write_txn_grouped(|wtxn| {
        store.enqueue_note_review_in_txn(
            wtxn,
            None,
            Some("note-review-door"),
            Some("run-1".to_owned()),
            20,
        )
    })?;
    let DreamerAdmissionOutcome::Admitted(admitted) =
        store.admit_next_note_review(AdmitDreamerAttempt {
            lease_owner: "test-door".to_owned(),
            now: 21,
            budget_id: "wake".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 100,
            started_milestone: None,
        })?
    else {
        return Err(Error::InvalidConfig(
            "no NOTE review attempt was admitted".into(),
        ));
    };

    let model =
        ModelId::new("test/model@r1").map_err(|_| Error::InvalidConfig("model id".into()))?;
    let binding = HostInferenceBinding::Advertised {
        model: model.clone(),
        locality: ModelLocality::OwnServer,
        keyless: false,
    };
    let backend = Arc::new(ReplyBackend {
        reply: NO_BELIEF_REPLY.to_owned(),
        calls: Mutex::new(Vec::new()),
    });
    let route = Arc::new(RecordingSourcedRoute::new(Arc::clone(&backend)));
    let sourced: Arc<dyn SourcedBackend> = Arc::<RecordingSourcedRoute>::clone(&route);
    let roles = RoleBackends::default().with(
        DREAMER_EXTRACTION_ROLE,
        RoleBackend {
            backend: Arc::clone(&backend),
            model: model.clone(),
            binding: binding.clone(),
            sourced: Some(sourced),
        },
    );
    let guard =
        BudgetGuard::with_reserve_units("wake", 10_000, 100, BudgetExhaustionPolicy::Suspend);
    let mut sink = PromotionWriterSink::new(
        vault,
        DreamerRunContext {
            run_id: "run-1".into(),
            attempt_id: admitted.status.attempt.id,
            agent_actor: actor,
            now_ms: 21_000,
        },
    );
    let deadline = WakePassDeadline::with_clock(180_000, Arc::new(|| 0));
    let mut executor = ConsolidationExecutor {
        roles,
        backend: backend.as_ref(),
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor,
        model,
        inference: HostInferenceContext {
            binding,
            extraction_egress: Some(&allow_fixture_extraction),
        },
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
            budget_id: "wake",
            now_ms: 21_000,
            prepared_wake: None,
            prepared_attempt: None,
            spend_meter: None,
        },
    ))?;
    if !matches!(outcome, DreamerAttemptExecution::Completed { .. }) {
        return Err(Error::InvalidConfig(format!(
            "the NOTE review did not complete: {outcome:?}"
        )));
    }
    let calls = backend
        .calls
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .len();
    Ok(NoteReviewBound {
        note,
        bound: route.take(),
        calls,
    })
}
