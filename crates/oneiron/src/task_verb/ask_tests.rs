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
    super::tests::support::permit_outcome_fixture_predicates(&vault)?;
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
            outcome_binding: Some(crate::llm::decision::questions::OutcomeBinding {
                source: crate::llm::decision::questions::OutcomeSource::Claim {
                    predicate: "outcome.earned".into(),
                },
                horizon: 60,
                mapping: [("won".into(), true)].into(),
                noise_weight: 0.8,
                linked_by: None,
            }),
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
        let mut pending_trap = None;
        if !answer_first {
            assert!(matches!(
                facade.tasks_wait_external(&receipt.handle, "external-step")?,
                TaskWaitOutcome::Pending { .. }
            ));
            let TaskWaitOutcome::Pending { trap_ref } =
                facade.tasks_wait(&receipt.handle, &ctx, hash)?
            else {
                panic!("unanswered ask must wait");
            };
            pending_trap = Some(trap_ref);
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
        assert_eq!(winner.question_version, Some(1));
        let answer_id = EntityId::from_hex(winner.answer_ref.as_deref().expect("typed answer"))?;
        let task_id = EntityId::from_hex(&receipt.handle.task_ref)?;
        let record =
            crate::llm::decision::questions::read_question(&vault, owner, task_id, Some(1))?
                .expect("typed question");
        assert_eq!(record.definition.question.id, task_id);
        assert_eq!(record.definition.binding, spec.outcome_binding);
        assert_eq!(record.definition.units, vec![one]);
        let claim = vault.get_claim(&answer_id)?.expect("winning answer claim");
        let encoded = super::wire_encode::canonical_bytes(&claim.value);
        let typed: crate::llm::decision::questions::AnswerRecord = rmp_serde::from_slice(&encoded)?;
        assert_eq!(typed.claim, answer_id);
        assert_eq!(typed.unit, one);
        assert_eq!(typed.decision.receipt.question, task_id);
        assert_eq!(typed.decision.receipt.question_version, 1);
        assert_eq!(typed.decision.receipt.principal, owner);
        let body = super::wire_decode::task_verb_body(&vault, task_id)?.expect("ask task");
        let terminal = body
            .state
            .as_ref()
            .and_then(TaskExecutionState::terminal)
            .expect("terminal ask");
        assert_eq!(terminal.disposition, TaskTerminalDisposition::Completed);
        assert_eq!(terminal.result_ref, Some(one));
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
        if let Some(trap_ref) = pending_trap {
            let mut head = EntityId::from_hex(&trap_ref)?;
            while let Some(edge) = vault
                .edges_in(&head)?
                .into_iter()
                .find(|edge| edge.kind == crate::edge::EdgeKind::Supersedes)
            {
                head = edge.target;
            }
            let trap = vault.get_claim(&head)?.expect("trap head");
            assert_eq!(trap.lifecycle, crate::claim::ClaimLifecycleStatus::Active);
            let state = trap
                .value
                .as_map()
                .expect("trap map")
                .iter()
                .find(|(key, _)| key.as_str() == Some("state"))
                .map(|(_, value)| value.as_str());
            assert_eq!(state, Some(Some("consumed")));
        }
        let fact = EntityId::now();
        let fact_at = typed.answered_at + 1;
        let fact_body = crate::claim::ClaimBody::new(
            "outcome.earned",
            crate::claim::ClaimSubject::Entity(one),
            rmpv::Value::from("won"),
            1.0,
            crate::claim::ClaimApprovalStatus::Approved,
            crate::claim::ClaimLifecycleStatus::Active,
        );
        vault.put_claim(
            &fact,
            &fact_body,
            TimeRange {
                start: fact_at,
                end: fact_at,
            },
            fact_at,
        )?;
        let pairs = facade.tasks_ask_outcomes(&receipt.handle)?;
        assert_eq!(pairs.len(), 1);
        assert_eq!(
            pairs[0].prediction,
            crate::llm::decision::DecisionAnswer::Choice(one.to_hex())
        );
        assert_eq!(pairs[0].outcome.answer, answer_id);
        assert_eq!(pairs[0].outcome.fact, fact);
        assert!(pairs[0].outcome.label);
        assert_eq!(pairs[0].outcome.noise_weight, 0.8);
        vault.put_claim(
            &fact,
            &fact_body,
            TimeRange {
                start: fact_at,
                end: fact_at,
            },
            fact_at,
        )?;
        assert_eq!(facade.tasks_ask_outcomes(&receipt.handle)?, pairs);
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
