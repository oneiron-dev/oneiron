use super::*;
use crate::attempt_queue::{AttemptQueue, EnqueueAttempt, EnqueueOutcome};
use crate::edge::EdgeActorClass;
use crate::llm::DurableStepContext;
use crate::write_envelope::WriteActor;
use crate::{EntityId, TimeRange, Vault, VaultConfig};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[test]
fn first_answer_and_both_wait_orders_resume_only_the_calling_step_once() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    let one = EntityId::now();
    let two = EntityId::now();
    let now = crate::unix_seconds_now();
    for actor in [owner, one, two] {
        vault.put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"person",
        )?;
    }
    let facade = vault.memory(owner, EdgeActorClass::Human);
    let queue = AttemptQueue::new(&vault);
    let (EnqueueOutcome::Enqueued(run) | EnqueueOutcome::Existing(run)) =
        queue.enqueue(EnqueueAttempt {
            kind: "ask-test-run".into(),
            payload: vec![],
            dedupe_key: None,
            run_id: Some("ask-run".into()),
            now,
        })?;
    for answer_first in [true, false] {
        let spec = TaskAskSpec {
            question: serde_json::json!({"text":"Choose a result"}),
            holders: [one.to_hex(), two.to_hex()].into(),
            idempotency_key: format!("ask-{answer_first}"),
            outcome_binding: None,
        };
        let receipt = facade.tasks_ask(&spec)?;
        assert_eq!(facade.tasks_ask(&spec)?.handle, receipt.handle);
        let ctx = DurableStepContext {
            vault: &vault,
            attempt_id: run.id,
            run_id: run.run_id.clone(),
            envelope_actor: WriteActor::new(owner, EdgeActorClass::Human),
            subject: owner,
            pinned_config: None,
            deadline: None,
            now_ms: now * 1000,
        };
        let hash = [u8::from(answer_first); 32];
        if !answer_first {
            assert!(matches!(
                facade.tasks_wait_external(&receipt.handle, "external-step")?,
                TaskWaitOutcome::Pending { .. }
            ));
            assert!(matches!(
                facade.tasks_wait(&receipt.handle, &ctx, hash)?,
                TaskWaitOutcome::Pending { .. }
            ));
        }
        // Asking/waiting does not prevent another independent unit of work.
        vault.put_entity(
            &EntityId::now(),
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"work continued",
        )?;
        let winner = vault
            .memory(one, EdgeActorClass::Human)
            .tasks_answer(&receipt.handle, one)?;
        let late = vault
            .memory(two, EdgeActorClass::Human)
            .tasks_answer(&receipt.handle, two)?;
        assert_eq!(late, winner);
        assert_eq!(late.actor_ref, one.to_hex());
        assert_eq!(late.result_ref, one.to_hex());
        assert_eq!(
            facade.tasks_wait(&receipt.handle, &ctx, hash)?,
            TaskWaitOutcome::Ready(winner.clone())
        );
        assert_eq!(
            facade.tasks_wait(&receipt.handle, &ctx, hash)?,
            TaskWaitOutcome::AlreadyResumed(winner)
        );
        assert_eq!(
            facade.tasks_wait_external(&receipt.handle, "external-step")?,
            TaskWaitOutcome::Ready(late.clone())
        );
        assert_eq!(
            facade.tasks_wait_external(&receipt.handle, "external-step")?,
            TaskWaitOutcome::AlreadyResumed(late)
        );
        assert_eq!(queue.get(run.id)?, Some(run.clone()));
    }
    for n in 0..20 {
        let receipt = facade.tasks_ask(&TaskAskSpec {
            question: serde_json::json!({"text":"Count without refusing"}),
            holders: [one.to_hex()].into(),
            idempotency_key: format!("burst-{n}"),
            outcome_binding: None,
        })?;
        assert!(!receipt.replayed);
        assert!(!receipt.handle.task_ref.is_empty());
    }
    Ok(())
}
