use super::*;
use crate::attempt_queue::{AttemptQueue, EnqueueAttempt, EnqueueOutcome};
use crate::edge::EdgeActorClass;
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
        let mut pending_trap = None;
        if !answer_first {
            let TaskWaitOutcome::Pending { trap_ref } =
                facade.tasks_wait_external(&receipt.handle, "external-step")?
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
            facade.tasks_wait_external(&receipt.handle, "external-step")?,
            TaskWaitOutcome::Ready(winner.clone())
        );
        assert_eq!(
            facade.tasks_wait_external(&receipt.handle, "external-step")?,
            TaskWaitOutcome::AlreadyResumed(winner)
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

#[test]
fn unanswered_terminal_ask_refuses_both_wait_doors_without_a_trap() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    let now = crate::unix_seconds_now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        b"owner",
    )?;
    // Cancellation is an external-effect door: a mode token is not a grant.
    vault.mint_standing_outbound_grant(
        &EntityId::now(),
        &crate::genui::GrantMintIntent {
            principal_ref: owner.to_hex(),
            origin_component_id: "tasks".into(),
            origin_action_id: "cancel".into(),
            origin_receipt_ref: None,
            scope: crate::genui::GrantMintIntentScope::VerbClass {
                verb_class: TasksVerb::Cancel.as_str().into(),
            },
        },
        now,
    )?;
    let facade = vault.memory(owner, EdgeActorClass::Human);
    for cancel in [true, false] {
        let handle = facade
            .tasks_ask(&TaskAskSpec {
                question: serde_json::json!({"text":"Unanswerable"}),
                holders: [owner.to_hex()].into(),
                idempotency_key: format!("terminal-{cancel}"),
                outcome_binding: None,
            })?
            .handle;
        let task = EntityId::from_hex(&handle.task_ref)?;
        if cancel {
            // The cancellation fact records work actually stopped. An ask with
            // no realizing attempt has nothing for tasks.cancel to stop.
            let (EnqueueOutcome::Enqueued(realization) | EnqueueOutcome::Existing(realization)) =
                AttemptQueue::new(&vault).enqueue_with_task_ref(
                    EnqueueAttempt {
                        kind: "ask-holder-fixture".into(),
                        payload: vec![],
                        dedupe_key: None,
                        run_id: None,
                        now,
                    },
                    Some(task.to_hex()),
                )?;
            let cancelled = facade
                .tasks_cancel_with_mode(TaskCancelTarget::Task(task), TaskCancelMode::FullAccess)?;
            assert!(cancelled.effected);
            assert_eq!(
                AttemptQueue::new(&vault)
                    .get(realization.id)?
                    .unwrap()
                    .state,
                crate::attempt_queue::AttemptState::Cancelled,
            );
            assert!(
                vault
                    .task_authority_state(task)?
                    .is_some_and(|state| state.cancelled)
            );
        } else {
            // A non-answer terminal TASK is a separate authoritative refusal.
            let mut body = super::wire_decode::task_verb_body(&vault, task)?.unwrap();
            body.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
                disposition: TaskTerminalDisposition::Completed,
                result_ref: Some(owner),
                summary: None,
                finished_at: now,
                ladder: None,
                counter_task_ref: None,
            }));
            vault.put_entity(
                &task,
                crate::registry::ENTITY_TYPE_TASK,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &super::wire_encode::encode_task_verb_body(body),
            )?;
        }
        let before = vault
            .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
            .len();
        assert!(
            facade
                .tasks_wait_external(&handle, "cancelled-step")
                .is_err()
        );
        assert!(facade.tasks_answer(&handle, owner).is_err());
        assert_eq!(
            vault
                .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
                .len(),
            before
        );
    }
    Ok(())
}

#[test]
fn answer_first_waits_do_not_mint_traps_and_waiter_storage_is_bounded() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    for answered in [true, false] {
        let handle = memory
            .tasks_ask(&TaskAskSpec {
                question: serde_json::json!({"text":"bounded wait"}),
                holders: [owner.to_hex()].into(),
                idempotency_key: format!("bounded-{answered}"),
                outcome_binding: None,
            })?
            .handle;
        let answer = if answered {
            Some(memory.tasks_answer(&handle, owner)?)
        } else {
            None
        };
        let before = vault
            .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
            .len();
        for n in 0..64 {
            let result = memory.tasks_wait_external(&handle, &format!("step-{n}"))?;
            if let Some(answer) = &answer {
                assert_eq!(result, TaskWaitOutcome::Ready(answer.clone()));
                assert_eq!(
                    memory.tasks_wait_external(&handle, &format!("step-{n}"))?,
                    TaskWaitOutcome::AlreadyResumed(answer.clone())
                );
            } else {
                assert!(matches!(result, TaskWaitOutcome::Pending { .. }));
            }
        }
        let full = vault
            .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
            .len();
        if answered {
            assert_eq!(full, before);
        }
        assert!(memory.tasks_wait_external(&handle, "overflow").is_err());
        assert_eq!(
            vault
                .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
                .len(),
            full
        );
        assert!(memory.tasks_wait_external(&handle, "step-0").is_ok());
    }
    Ok(())
}
