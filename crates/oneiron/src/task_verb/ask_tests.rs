use super::*;
use crate::attempt_queue::{AttemptQueue, EnqueueAttempt, EnqueueOutcome};
use crate::edge::EdgeActorClass;
use crate::task_verb::sdk::AgentVerb;
use crate::{EntityId, Vault, VaultConfig};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn spec(vault: &Vault, owner: EntityId, key: &str) -> TaskAskSpec {
    TaskAskSpec {
        intent_key: key.into(),
        ..crate::task_verb::TaskAskSpec::shorthand(
            Some(TaskAskTarget::Responder(TaskAssignee::Human {
                actor_ref: owner,
            })),
            crate::task_verb::TaskAskQuestion {
                reference: super::tests::support::consult_turn(vault, 0x81),
                revision: 1,
                options: Default::default(),
                context_refs: Vec::new(),
                label: None,
                outcome_binding: None,
            },
            Some(u64::MAX),
            crate::task_verb::TaskAskDefault::AskMe,
        )
    }
}

fn settled(memory: &crate::memory::Memory<'_>, handle: TaskAskHandle) -> TaskAskResult {
    let TaskAskStatus::Settled(result) = memory.tasks_ask_status(handle).unwrap() else {
        panic!("settled ask")
    };
    *result
}

#[test]
fn external_ask_wait_orders_resume_only_the_calling_step_once() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let queue = AttemptQueue::new(&vault);
    let (EnqueueOutcome::Enqueued(run) | EnqueueOutcome::Existing(run)) =
        queue.enqueue(EnqueueAttempt {
            kind: "ask-test-run".into(),
            payload: vec![],
            dedupe_key: None,
            run_id: Some("ask-run".into()),
            now: crate::unix_seconds_now(),
        })?;
    for answer_first in [false, true] {
        let input = spec(&vault, owner, &format!("ask-{answer_first}"));
        let receipt = memory.tasks_ask(&input)?;
        assert_eq!(memory.tasks_ask(&input)?.handle, receipt.handle);
        let pending = if !answer_first {
            let TaskAskWait::Pending { trap_ref } =
                memory.tasks_wait(receipt.handle, Some("step"))?
            else {
                panic!("pending external step")
            };
            assert!(matches!(
                memory.tasks_wait(receipt.handle, None)?,
                TaskAskWait::Park(_)
            ));
            assert_eq!(
                memory.tasks_wait(receipt.handle, Some("step"))?,
                TaskAskWait::Pending {
                    trap_ref: trap_ref.clone()
                }
            );
            Some(trap_ref)
        } else {
            None
        };
        let answer = memory.tasks_answer(&receipt.handle, &TaskAskWord::new(owner))?;
        let result = settled(&memory, receipt.handle);
        assert_eq!(result.decision, TaskAskDecision::First(answer));
        let expected = TaskAskWait::Ready(Box::new(result));
        for binding in [Some("step"), Some("step"), None] {
            assert_eq!(memory.tasks_wait(receipt.handle, binding)?, expected);
        }
        if let Some(trap_ref) = pending {
            let mut head = EntityId::from_hex(&trap_ref)?;
            while let Some(edge) = vault
                .edges_in(&head)?
                .into_iter()
                .find(|edge| edge.kind == crate::edge::EdgeKind::Supersedes)
            {
                head = edge.target;
            }
            let trap = vault.get_claim(&head)?.unwrap();
            assert_eq!(trap.lifecycle, crate::claim::ClaimLifecycleStatus::Active);
            let state = trap
                .value
                .as_map()
                .unwrap()
                .iter()
                .find(|(key, _)| key.as_str() == Some("state"))
                .map(|(_, value)| value.as_str());
            assert_eq!(state, Some(Some("consumed")));
        }
        assert_eq!(queue.get(run.id)?, Some(run.clone()));
    }
    Ok(())
}

#[test]
fn answer_first_waits_do_not_mint_traps_and_waiter_storage_is_bounded() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    for answered in [false, true] {
        let handle = memory
            .tasks_ask(&spec(&vault, owner, &format!("bounded-{answered}")))?
            .handle;
        let answer = if answered {
            Some(memory.tasks_answer(&handle, &TaskAskWord::new(owner))?)
        } else {
            None
        };
        let before = vault
            .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
            .len();
        for n in 0..64 {
            let result = memory.tasks_wait(handle, Some(&format!("step-{n}")))?;
            if let Some(answer) = &answer {
                assert_eq!(
                    settled(&memory, handle).decision,
                    TaskAskDecision::First(*answer)
                );
                assert_eq!(
                    result,
                    TaskAskWait::Ready(Box::new(settled(&memory, handle)))
                );
                assert_eq!(
                    memory.tasks_wait(handle, Some(&format!("step-{n}")))?,
                    result
                );
            } else {
                assert!(matches!(result, TaskAskWait::Pending { .. }));
            }
        }
        let full = vault
            .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
            .len();
        if answered {
            assert_eq!(full, before);
        }
        assert!(memory.tasks_wait(handle, Some("overflow")).is_err());
        assert_eq!(
            vault
                .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
                .len(),
            full
        );
        assert!(memory.tasks_wait(handle, Some("step-0")).is_ok());
    }
    Ok(())
}

#[test]
fn ask_wait_is_owner_bound_and_abstention_is_not_an_answer() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let other = EntityId::now();
    vault.put_entity(
        &other,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let input = spec(&vault, owner, "abstain");
    let receipt = memory.tasks_ask(&input)?;
    for key in [None, Some("step")] {
        assert!(
            vault
                .memory(other, EdgeActorClass::Human)
                .tasks_wait(receipt.handle, key)
                .is_err()
        );
    }
    assert!(
        vault
            .memory(other, EdgeActorClass::Human)
            .tasks_answer(&receipt.handle, &TaskAskWord::new(other))
            .is_err()
    );
    memory.land_consult_result(
        receipt.task_refs[0],
        &ConsultResultInput {
            kind: ConsultResultKind::Abstain {
                result_ref: input.what.reference.entity_ref(),
                reason_ref: input.what.reference,
            },
            completed_at: crate::unix_seconds_now(),
        },
    )?;
    assert_eq!(
        memory.tasks_wait(receipt.handle, Some("done"))?,
        TaskAskWait::Ready(Box::new(settled(&memory, receipt.handle)))
    );
    let prior = settled(&memory, receipt.handle);
    assert_eq!(prior.decision, TaskAskDecision::Unknown);
    let late = memory.tasks_answer(&receipt.handle, &TaskAskWord::new(owner))?;
    assert_eq!(settled(&memory, receipt.handle), prior);
    assert!(
        memory
            .tasks_ask_evidence(receipt.handle)?
            .iter()
            .any(|entry| entry.answer == late && entry.reason == TaskAskEvidenceReason::Late)
    );
    Ok(())
}

#[test]
fn cancelled_ask_member_cannot_answer_or_mint_a_wait_trap() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    vault.mint_standing_outbound_grant(
        &EntityId::now(),
        &crate::genui::GrantMintIntent {
            principal_ref: owner.to_hex(),
            origin_component_id: "tasks".into(),
            origin_action_id: "cancel".into(),
            origin_receipt_ref: None,
            scope: crate::genui::GrantMintIntentScope::VerbClass {
                verb_class: AgentVerb::Cancel.as_str().into(),
            },
        },
        1,
    )?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let receipt = memory.tasks_ask(&spec(&vault, owner, "cancelled"))?;
    let task = receipt.task_refs[0];
    AttemptQueue::new(&vault).enqueue_with_task_ref(
        EnqueueAttempt {
            kind: "ask-cancel-fixture".into(),
            payload: vec![],
            dedupe_key: None,
            run_id: None,
            now: crate::unix_seconds_now(),
        },
        Some(task.to_hex()),
    )?;
    assert!(
        memory
            .cancel_with_mode(TaskCancelTarget::Task(task), TaskCancelMode::FullAccess)?
            .effected
    );
    assert!(vault.task_authority_state(task)?.unwrap().cancelled);
    let before = vault
        .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
        .len();
    assert!(
        memory
            .tasks_answer(&receipt.handle, &TaskAskWord::new(owner))
            .is_err()
    );
    assert_eq!(
        memory.tasks_wait(receipt.handle, Some("cancelled-step"))?,
        TaskAskWait::Ready(Box::new(settled(&memory, receipt.handle)))
    );
    assert_eq!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
            .len(),
        before
    );
    Ok(())
}

#[test]
fn ask_rejects_impossible_electorates_options_and_coverage_before_sending() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let other = EntityId::now();
    vault.put_entity(
        &other,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let mut input = spec(&vault, owner, "validation");
    let yes = TaskAskOptionId::new("yes")?;
    input
        .what
        .options
        .insert(yes.clone(), "Same display text".into());
    input
        .what
        .options
        .insert(TaskAskOptionId::new("no")?, "Same display text".into());
    let before = vault.entities_by_type(crate::registry::ENTITY_TYPE_TASK)?;
    let mut bad = input.clone();
    bad.need.of = TaskAskElectorate::People([other].into());
    assert!(memory.tasks_ask(&bad).is_err());
    bad = input.clone();
    bad.decide = Some(TaskAskDecide::All {
        of: TaskAskElectorate::People([other].into()),
        answer: yes.clone(),
    });
    assert!(memory.tasks_ask(&bad).is_err());
    bad = input.clone();
    bad.decide = Some(TaskAskDecide::All {
        of: TaskAskElectorate::Any,
        answer: TaskAskOptionId::new("unknown")?,
    });
    assert!(memory.tasks_ask(&bad).is_err());
    bad = input.clone();
    bad.decide = Some(TaskAskDecide::AtLeast {
        count: 2,
        of: TaskAskElectorate::Any,
        answer: yes,
    });
    assert!(memory.tasks_ask(&bad).is_err());
    bad = input.clone();
    bad.who = Some(TaskAskTarget::People([owner, other].into()));
    bad.need.count = 2;
    assert!(memory.tasks_ask(&bad).is_err());
    bad = input.clone();
    bad.what.revision = 0;
    assert!(memory.tasks_ask(&bad).is_err());
    bad = input.clone();
    bad.remind = Some(vec![2, 1]);
    assert!(memory.tasks_ask(&bad).is_err());
    let mut wire = serde_json::to_value(&input)?;
    wire["need"]["answer"] = serde_json::json!("yes");
    assert!(serde_json::from_value::<TaskAskSpec>(wire).is_err());
    let mut wire = serde_json::to_value(&input)?;
    wire["decide"] = serde_json::json!({"code": "answer"});
    assert!(serde_json::from_value::<TaskAskSpec>(wire).is_err());
    let mut wire = serde_json::to_value(&input)?;
    wire["provisional"] = serde_json::json!("count");
    assert!(serde_json::from_value::<TaskAskSpec>(wire).is_err());
    assert_eq!(
        vault.entities_by_type(crate::registry::ENTITY_TYPE_TASK)?,
        before
    );
    input.who = None;
    input.decide = None;
    let receipt = memory.tasks_ask(&input)?;
    assert_eq!(receipt.task_refs.len(), 1);
    Ok(())
}

#[test]
fn ask_cannot_drop_or_replace_its_task_class_and_defaults_are_policy_bound() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let mut input = spec(&vault, owner, "governed");
    let class = TaskAskClass {
        key: "fixture-governance".into(),
        version: 7,
        governance: true,
        deadline_seconds: 60,
        allowed_recipients: [owner].into(),
        required_people: [owner].into(),
        minimum_responses: 1,
        required_sources: [input.what.reference].into(),
        decision: None,
        disclosure: [(owner, [input.what.reference].into())].into(),
        fallback: [TaskAskDefault::Hold].into(),
        remind: vec![5, 10],
    };
    let encoded = rmp_serde::to_vec_named(&class)?;
    let class_value = rmpv::decode::read_value(&mut encoded.as_slice())?;
    let task = memory
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::Map(vec![(rmpv::Value::from("ask_class"), class_value)]),
            None,
            None,
            None,
        ))?
        .task_ref
        .unwrap();
    input.task_ref = Some(task);
    input.until = None;
    let before = vault.entities_by_type(crate::registry::ENTITY_TYPE_TASK)?;
    let mut bad = input.clone();
    bad.default = TaskAskDefault::Proceed;
    assert!(memory.tasks_ask(&bad).is_err());
    bad = input.clone();
    let mut dropped = class.clone();
    dropped.governance = false;
    bad.class = Some(dropped);
    assert!(memory.tasks_ask(&bad).is_err());
    bad = input.clone();
    bad.what
        .context_refs
        .push(super::tests::support::consult_turn(&vault, 0x82));
    assert!(memory.tasks_ask(&bad).is_err());
    assert_eq!(
        vault.entities_by_type(crate::registry::ENTITY_TYPE_TASK)?,
        before
    );
    let receipt = memory.tasks_ask(&input)?;
    let raw = vault.get_raw(&receipt.handle.group_ref)?.unwrap();
    let fields = rmpv::decode::read_value(&mut &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?;
    let fields = fields.as_map().unwrap();
    let effective: TaskAskSpec = rmp_serde::from_slice(&rmp_serde::to_vec_named(
        &fields
            .iter()
            .find(|(key, _)| key.as_str() == Some("effective"))
            .unwrap()
            .1,
    )?)?;
    let requested: TaskAskSpec = rmp_serde::from_slice(&rmp_serde::to_vec_named(
        &fields
            .iter()
            .find(|(key, _)| key.as_str() == Some("requested"))
            .unwrap()
            .1,
    )?)?;
    assert_eq!(requested, input);
    assert_eq!(effective.class, Some(class));
    assert_eq!(effective.default, TaskAskDefault::Hold);
    assert_eq!(effective.remind, Some(vec![5, 10]));
    assert!(effective.until.is_some());
    Ok(())
}

#[test]
fn ask_retries_bind_every_typed_request_field_without_reminting() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let input = spec(&vault, owner, "whole-spec");
    let first = memory.tasks_ask(&input)?;
    let before = vault.entities_by_type(crate::registry::ENTITY_TYPE_TASK)?;
    let mut variants = Vec::new();
    let mut changed = input.clone();
    changed.default = TaskAskDefault::Hold;
    variants.push(changed);
    let mut changed = input.clone();
    changed.decide = None;
    variants.push(changed);
    let mut changed = input.clone();
    changed.remind = Some(vec![5]);
    variants.push(changed);
    let mut changed = input.clone();
    changed.on_disagree.surface = TaskAskSurface::None;
    variants.push(changed);
    let mut changed = input.clone();
    changed.on_disagree.branch = TaskAskBranch::Proceed;
    variants.push(changed);
    let mut changed = input.clone();
    changed.need.of = TaskAskElectorate::People([owner].into());
    variants.push(changed);
    let mut changed = input.clone();
    changed.who = None;
    variants.push(changed);
    let mut changed = input.clone();
    changed
        .what
        .options
        .insert(TaskAskOptionId::new("choice")?, "text".into());
    variants.push(changed);
    let mut changed = input.clone();
    changed.what.revision = 2;
    variants.push(changed);
    for changed in variants {
        assert!(memory.tasks_ask(&changed).is_err());
    }
    let retry = memory.tasks_ask(&input)?;
    assert!(retry.idempotent_replay);
    assert_eq!(retry.handle, first.handle);
    assert_eq!(retry.task_refs, first.task_refs);
    assert_eq!(
        vault.entities_by_type(crate::registry::ENTITY_TYPE_TASK)?,
        before
    );
    Ok(())
}

struct RuledAskFixture {
    vault: Vault,
    dir: tempfile::TempDir,
    clock: std::sync::Arc<crate::ports::ManualClock>,
    owner: EntityId,
    people: Vec<EntityId>,
    question: ConsultPayloadRef,
}

impl RuledAskFixture {
    fn new(count: usize) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let clock = crate::ports::ManualClock::new(1_000);
        let mut config = crate::test_util::embedding_test_config();
        config.store_clock = clock.bundle();
        let vault = Vault::open(dir.path(), config)?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let mut people = Vec::new();
        for _ in 0..count {
            let person = EntityId::now();
            vault.put_entity(
                &person,
                crate::registry::ENTITY_TYPE_PERSON,
                crate::TimeRange {
                    start: 1_000,
                    end: 1_000,
                },
                1_000,
                b"person",
            )?;
            people.push(person);
        }
        let question = EntityId::now();
        let body =
            rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "question")]))?;
        vault.put_entity(
            &question,
            crate::registry::ENTITY_TYPE_TURN,
            crate::TimeRange {
                start: 1_000,
                end: 1_000,
            },
            1_000,
            &body,
        )?;
        Ok(Self {
            vault,
            dir,
            clock,
            owner,
            people,
            question: ConsultPayloadRef::Turn(question),
        })
    }

    fn spec(&self) -> TaskAskSpec {
        let mut question = TaskAskQuestion::new(self.question);
        question.options = [
            (
                TaskAskOptionId::new("yes").unwrap(),
                "same display text".into(),
            ),
            (
                TaskAskOptionId::new("no").unwrap(),
                "same display text".into(),
            ),
        ]
        .into();
        TaskAskSpec::shorthand(
            Some(TaskAskTarget::People(self.people.iter().copied().collect())),
            question,
            Some(1_100),
            TaskAskDefault::AskMe,
        )
    }

    fn all(&self) -> TaskAskSpec {
        let mut spec = self.spec();
        spec.need = TaskAskNeed {
            count: self.people.len().try_into().unwrap(),
            of: TaskAskElectorate::People(self.people.iter().copied().collect()),
        };
        spec.decide = Some(TaskAskDecide::All {
            of: TaskAskElectorate::Any,
            answer: TaskAskOptionId::new("yes").unwrap(),
        });
        spec
    }

    fn policy(&self, governance: bool) -> TaskAskClass {
        TaskAskClass {
            key: "fixture-policy-row".into(),
            version: 7,
            governance,
            deadline_seconds: 100,
            allowed_recipients: self.people.iter().copied().collect(),
            required_people: self.people.iter().copied().collect(),
            minimum_responses: self.people.len().try_into().unwrap(),
            required_sources: Default::default(),
            decision: None,
            disclosure: self
                .people
                .iter()
                .map(|person| (*person, [self.question].into()))
                .collect(),
            fallback: if governance {
                [TaskAskDefault::Hold].into()
            } else {
                [
                    TaskAskDefault::Proceed,
                    TaskAskDefault::Hold,
                    TaskAskDefault::AskMe,
                ]
                .into()
            },
            remind: vec![20, 40],
        }
    }

    fn ask(&self, spec: &TaskAskSpec) -> Result<TaskAskHandle> {
        Ok(self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .tasks_ask(spec)?
            .handle)
    }

    fn word(&self, handle: TaskAskHandle, seat: usize, option: &str) -> Result<TaskAskAnswer> {
        Ok(self
            .vault
            .memory(self.people[seat], EdgeActorClass::Human)
            .tasks_answer(
                &handle,
                &TaskAskWord {
                    result_ref: self.people[seat],
                    option: Some(TaskAskOptionId::new(option)?),
                    inform_for: None,
                    provenance_refs: Default::default(),
                },
            )?)
    }

    fn result(&self, handle: TaskAskHandle) -> Result<TaskAskResult> {
        let TaskAskWait::Ready(result) = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .tasks_wait(handle, None)?
        else {
            panic!("settled ask")
        };
        Ok(*result)
    }
}

#[test]
fn ask_three_replies_one_yes_all_has_coverage_but_no_decision_and_fallback() -> Result<()> {
    let fixture = RuledAskFixture::new(3)?;
    let mut spec = fixture.all();
    spec.default = TaskAskDefault::Hold;
    let handle = fixture.ask(&spec)?;
    fixture.word(handle, 0, "yes")?;
    fixture.word(handle, 1, "no")?;
    assert!(matches!(
        fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .tasks_wait(handle, None)?,
        TaskAskWait::Park(_)
    ));
    fixture.word(handle, 2, "no")?;
    let result = fixture.result(handle)?;
    assert!(result.coverage.met);
    assert_eq!(result.coverage.responded.len(), 3);
    assert!(result.coverage.unknown.is_empty());
    assert_eq!(result.decision, TaskAskDecision::No);
    assert_eq!(
        result.fallback,
        Some(TaskAskFallback {
            branch: TaskAskDefault::Hold,
            surface: TaskAskSurface::Card
        })
    );
    assert_eq!(result.evidence.len(), 3);
    assert!(
        result
            .evidence
            .iter()
            .all(|entry| entry.source == TaskAskSource::Human
                && entry.reason == TaskAskEvidenceReason::Counted)
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|entry| entry.word.option.as_ref().unwrap().as_str() == "yes")
            .count(),
        1
    );
    Ok(())
}

#[test]
fn ask_silent_founder_is_unknown_and_default_is_one_aggregate_event() -> Result<()> {
    let fixture = RuledAskFixture::new(2)?;
    let mut spec = fixture.all();
    spec.class = Some(fixture.policy(false));
    spec.until = None;
    spec.default = TaskAskDefault::Proceed;
    spec.what.outcome_binding = Some(crate::llm::decision::questions::OutcomeBinding {
        source: crate::llm::decision::questions::OutcomeSource::Claim {
            predicate: "outcome.earned".into(),
        },
        horizon: 60,
        mapping: [("won".into(), true)].into(),
        noise_weight: 1.0,
        linked_by: None,
    });
    let handle = fixture.ask(&spec)?;
    fixture.word(handle, 0, "yes")?;
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    assert!(
        crate::llm::decision::questions::read_question(
            &fixture.vault,
            fixture.owner,
            handle.group_ref,
            None
        )?
        .is_none()
    );
    let before = fixture
        .vault
        .entities_by_type(crate::registry::ENTITY_TYPE_TASK)?
        .len();
    fixture.clock.set(1_101);
    let result = fixture.result(handle)?;
    assert!(!result.coverage.met);
    assert_eq!(result.coverage.unknown, [fixture.people[1]].into());
    assert_eq!(result.coverage.unmet_people, [fixture.people[1]].into());
    assert_eq!(result.decision, TaskAskDecision::Unknown);
    assert_eq!(
        result.fallback.as_ref().unwrap().branch,
        TaskAskDefault::Proceed
    );
    assert_eq!(result.evidence.len(), 1);
    assert_eq!(result.settlement.reason, TaskAskSettlementReason::Deadline);
    assert!(result.settlement.outcome_answer_ref.is_none());
    assert!(memory.tasks_ask_outcomes(&handle)?.is_empty());
    assert!(
        crate::llm::decision::questions::read_question(
            &fixture.vault,
            fixture.owner,
            handle.group_ref,
            None
        )?
        .is_none()
    );
    assert_eq!(
        fixture
            .vault
            .entities_by_type(crate::registry::ENTITY_TYPE_TASK)?
            .len(),
        before + 1
    );
    assert_eq!(fixture.result(handle)?, result);
    assert_eq!(
        fixture
            .vault
            .entities_by_type(crate::registry::ENTITY_TYPE_TASK)?
            .len(),
        before + 1
    );
    Ok(())
}

#[test]
fn ask_two_founders_disagree_under_all_without_first_answer_shortcut() -> Result<()> {
    let fixture = RuledAskFixture::new(2)?;
    let mut spec = fixture.all();
    spec.default = TaskAskDefault::Hold;
    spec.on_disagree = TaskAskDisagree {
        branch: TaskAskBranch::Proceed,
        surface: TaskAskSurface::Card,
    };
    let handle = fixture.ask(&spec)?;
    fixture.word(handle, 0, "yes")?;
    assert!(matches!(
        fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .tasks_wait(handle, None)?,
        TaskAskWait::Park(_)
    ));
    fixture.word(handle, 1, "no")?;
    let result = fixture.result(handle)?;
    assert!(result.coverage.met);
    assert_eq!(result.decision, TaskAskDecision::Conflict);
    assert_eq!(
        result.fallback,
        Some(TaskAskFallback {
            branch: TaskAskDefault::Proceed,
            surface: TaskAskSurface::Card
        })
    );
    assert_eq!(result.evidence.len(), 2);
    assert!(result.settlement.outcome_answer_ref.is_none());
    Ok(())
}

#[test]
fn ask_human_no_dominates_companion_inform_yes_in_the_same_revision() -> Result<()> {
    let fixture = RuledAskFixture::new(1)?;
    let handle = fixture.ask(&fixture.all())?;
    let inform = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Agent)
        .tasks_answer(
            &handle,
            &TaskAskWord {
                result_ref: fixture.owner,
                option: Some(TaskAskOptionId::new("yes")?),
                inform_for: Some(fixture.people[0]),
                provenance_refs: Default::default(),
            },
        )?;
    assert!(matches!(
        fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .tasks_wait(handle, None)?,
        TaskAskWait::Park(_)
    ));
    let human = fixture.word(handle, 0, "no")?;
    let result = fixture.result(handle)?;
    assert!(result.coverage.met);
    assert_eq!(result.decision, TaskAskDecision::No);
    assert_eq!(
        result
            .evidence
            .iter()
            .find(|entry| entry.answer == inform)
            .unwrap()
            .reason,
        TaskAskEvidenceReason::HumanDominates
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .find(|entry| entry.answer == human)
            .unwrap()
            .reason,
        TaskAskEvidenceReason::Counted
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|entry| entry.reason == TaskAskEvidenceReason::Counted)
            .count(),
        1
    );
    Ok(())
}

#[test]
fn ask_cutoff_includes_word_admitted_after_timer_fires_before_close() -> Result<()> {
    let fixture = RuledAskFixture::new(2)?;
    let handle = fixture.ask(&fixture.all())?;
    let first = fixture.word(handle, 0, "yes")?;
    fixture.clock.set(1_101);
    let second = fixture.word(handle, 1, "yes")?;
    let before = fixture
        .vault
        .entities_by_type(crate::registry::ENTITY_TYPE_TASK)?;
    let result = fixture.result(handle)?;
    assert!(result.coverage.met);
    assert_eq!(
        result.decision,
        TaskAskDecision::Answer(TaskAskOptionId::new("yes")?)
    );
    assert!(result.fallback.is_none());
    assert_eq!(result.settlement.reason, TaskAskSettlementReason::Deadline);
    assert_eq!(result.settlement.cutoff_order, 2);
    assert_eq!(
        result
            .evidence
            .iter()
            .map(|entry| entry.answer)
            .collect::<Vec<_>>(),
        vec![first, second]
    );
    fixture.clock.set(1_102);
    assert_eq!(fixture.result(handle)?, result);
    assert_eq!(
        fixture
            .vault
            .entities_by_type(crate::registry::ENTITY_TYPE_TASK)?,
        before
    );
    Ok(())
}

#[test]
fn ask_word_after_settlement_is_late_evidence_without_changing_the_receipt() -> Result<()> {
    let fixture = RuledAskFixture::new(1)?;
    let handle = fixture.ask(&fixture.spec())?;
    let first = fixture.word(handle, 0, "yes")?;
    let result = fixture.result(handle)?;
    let receipt = fixture
        .vault
        .get_raw(&result.settlement.reference)?
        .unwrap();
    let late = fixture.word(handle, 0, "no")?;
    assert_ne!(late.word_ref, first.word_ref);
    assert_eq!(fixture.result(handle)?, result);
    assert_eq!(
        fixture
            .vault
            .get_raw(&result.settlement.reference)?
            .unwrap(),
        receipt
    );
    let evidence = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .tasks_ask_evidence(handle)?;
    assert_eq!(evidence.len(), 2);
    let late = evidence.iter().find(|entry| entry.answer == late).unwrap();
    assert_eq!(late.reason, TaskAskEvidenceReason::Late);
    assert!(late.order > result.settlement.cutoff_order);
    let mut body =
        rmpv::decode::read_value(&mut &receipt[crate::batch::ENTITY_METADATA_HEADER_LEN..])?;
    let rmpv::Value::Map(fields) = &mut body else {
        panic!("settlement map")
    };
    fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("decision"))
        .unwrap()
        .1 = rmpv::Value::from("unknown");
    let forged = rmp_serde::to_vec_named(&body)?;
    assert!(
        fixture
            .vault
            .batch()
            .put_replicated(
                &result.settlement.reference,
                crate::registry::ENTITY_TYPE_TASK,
                crate::TimeRange {
                    start: 1_000,
                    end: 1_000
                },
                1_000,
                &forged
            )
            .commit()
            .is_err()
    );
    assert_eq!(
        fixture
            .vault
            .get_raw(&result.settlement.reference)?
            .unwrap(),
        receipt
    );
    Ok(())
}

#[test]
fn ask_omitted_class_keeps_owning_task_obligations_in_the_settlement_receipt() -> Result<()> {
    let fixture = RuledAskFixture::new(2)?;
    let class = fixture.policy(true);
    let value = rmpv::decode::read_value(&mut rmp_serde::to_vec_named(&class)?.as_slice())?;
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let task = memory
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::Map(vec![(rmpv::Value::from("ask_class"), value)]),
            None,
            None,
            Some(1_000),
        ))?
        .task_ref
        .unwrap();
    let mut spec = fixture.all();
    spec.task_ref = Some(task);
    spec.until = None;
    assert!(spec.class.is_none());
    let mut dropped = spec.clone();
    dropped.default = TaskAskDefault::Proceed;
    assert!(memory.tasks_ask(&dropped).is_err());
    let handle = fixture.ask(&spec)?;
    fixture.word(handle, 0, "yes")?;
    fixture.clock.set(1_041);
    crate::human_task::HumanTaskFollowupDriver::new(&fixture.vault).run_due(1_041, 16)?;
    assert!(matches!(
        memory.tasks_wait(handle, None)?,
        TaskAskWait::Park(_)
    ));
    fixture.clock.set(1_101);
    let result = fixture.result(handle)?;
    assert!(result.settlement.requested.class.is_none());
    assert_eq!(result.settlement.effective.class, Some(class));
    assert_eq!(result.settlement.effective.default, TaskAskDefault::Hold);
    assert_eq!(result.settlement.effective.remind, Some(vec![20, 40]));
    assert_eq!(result.settlement.effective.until, Some(1_100));
    assert_eq!(result.coverage.unmet_people, [fixture.people[1]].into());
    assert_eq!(result.decision, TaskAskDecision::Unknown);
    assert_eq!(result.fallback.unwrap().branch, TaskAskDefault::Hold);
    Ok(())
}

#[test]
fn ask_wait_retries_and_reopen_return_the_same_settlement() -> Result<()> {
    let fixture = RuledAskFixture::new(1)?;
    let handle = fixture.ask(&fixture.spec())?;
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    assert!(matches!(
        memory.tasks_wait(handle, Some("durable-step"))?,
        TaskAskWait::Pending { .. }
    ));
    fixture.word(handle, 0, "yes")?;
    let first = memory.tasks_wait(handle, Some("durable-step"))?;
    let TaskAskWait::Ready(result) = &first else {
        panic!("settled wait")
    };
    assert!(result.coverage.met);
    let before = fixture
        .vault
        .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?;
    fixture.clock.set(1_200);
    assert_eq!(memory.tasks_wait(handle, Some("durable-step"))?, first);
    assert_eq!(memory.tasks_wait(handle, None)?, first);
    assert_eq!(
        fixture
            .vault
            .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?,
        before
    );
    let owner = fixture.owner;
    let mut config = crate::test_util::embedding_test_config();
    config.store_clock = fixture.clock.bundle();
    drop(fixture.vault);
    let reopened = Vault::open(fixture.dir.path(), config)?;
    assert_eq!(
        reopened
            .memory(owner, EdgeActorClass::Human)
            .tasks_wait(handle, Some("durable-step"))?,
        first
    );
    Ok(())
}

#[test]
fn ask_authority_schema_matches_the_serialized_scope_not_its_private_fields() -> Result<()> {
    let scope = AskAuthorityScope {
        class: crate::consent::ActionClass::new("review")?,
        envelope: crate::consent::ActionEnvelope::new(["project:fixture".into()])?
            .with_budget(7)
            .with_receipt_required(true),
    };
    let wire = serde_json::to_value(&scope)?;
    let schema = crate::code_run::vault_read::request_schema::<AskAuthorityScope>();
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["properties"]["class"]["type"], "string");
    assert_eq!(schema["properties"]["selectors"]["type"], "array");
    assert_eq!(
        wire.as_object()
            .unwrap()
            .keys()
            .collect::<std::collections::BTreeSet<_>>(),
        schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<std::collections::BTreeSet<_>>()
    );
    assert_eq!(serde_json::from_value::<AskAuthorityScope>(wire)?, scope);
    Ok(())
}

/// Agent A, an auto-ceiling asker holding one live TASK whose spec binds the
/// fixture's governance class over both people.
fn governed_agent(fixture: &RuledAskFixture) -> Result<(EntityId, TaskAskClass)> {
    let agent = EntityId::now();
    fixture.vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange {
            start: 1_000,
            end: 1_000,
        },
        1_000,
        b"agent",
    )?;
    let mut manifest: serde_json::Value =
        rmp_serde::from_slice(&crate::gate::default_policy_manifest())?;
    manifest["actor_ceilings"]
        .as_array_mut()
        .ok_or("default actor ceilings")?
        .push(serde_json::json!({"actor_class": "agent", "actor_ref": agent.to_hex(), "ceiling": "auto"}));
    crate::test_util::put_policy_manifest_bytes(
        &fixture.vault,
        crate::gate::default_policy_manifest_id()?,
        &rmp_serde::to_vec_named(&manifest)?,
    )?;
    let class = fixture.policy(true);
    assign_governed_task(fixture, agent, &class)?;
    Ok((agent, class))
}

fn assign_governed_task(
    fixture: &RuledAskFixture,
    agent: EntityId,
    class: &TaskAskClass,
) -> Result<()> {
    let value = rmpv::decode::read_value(&mut rmp_serde::to_vec_named(class)?.as_slice())?;
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .tasks_create(
            &TaskCreateSpec::new(
                rmpv::Value::Map(vec![(rmpv::Value::from("ask_class"), value)]),
                None,
                None,
                Some(1_000),
            )
            .with_assignee(TaskAssignee::Peer { actor_ref: agent }),
        )?;
    Ok(())
}

#[test]
fn omitted_task_ref_binds_the_class_of_the_callers_governed_task() -> Result<()> {
    let fixture = RuledAskFixture::new(2)?;
    let (agent, class) = governed_agent(&fixture)?;
    let mut spec = fixture.all();
    spec.default = TaskAskDefault::Hold;
    let receipt = fixture
        .vault
        .memory(agent, EdgeActorClass::Agent)
        .tasks_ask(&spec)?;
    let txn = fixture.vault.store.env.read_txn()?;
    let group = super::ask_record::read_group(&fixture.vault, &txn, receipt.handle.group_ref)?
        .ok_or("stored ask group")?;
    assert_eq!(group.context_class, Some(class));
    Ok(())
}

#[test]
fn omitted_task_ref_cannot_admit_proceed_on_a_governed_task() -> Result<()> {
    let fixture = RuledAskFixture::new(2)?;
    let (agent, _) = governed_agent(&fixture)?;
    let mut spec = fixture.spec();
    spec.default = TaskAskDefault::Proceed;
    spec.decide = Some(TaskAskDecide::First);
    let refused = fixture
        .vault
        .memory(agent, EdgeActorClass::Agent)
        .tasks_ask(&spec)
        .expect_err("a governed task's class binds and refuses proceed");
    assert_eq!(refused.code, crate::memory::MEMORY_CODE_BAD_REQUEST);
    Ok(())
}

#[test]
fn omitted_task_ref_is_refused_when_two_governed_tasks_could_bind() -> Result<()> {
    let fixture = RuledAskFixture::new(2)?;
    let (agent, class) = governed_agent(&fixture)?;
    assign_governed_task(&fixture, agent, &class)?;
    let mut spec = fixture.all();
    spec.default = TaskAskDefault::Hold;
    let refused = fixture
        .vault
        .memory(agent, EdgeActorClass::Agent)
        .tasks_ask(&spec)
        .expect_err("two governed tasks cannot both bind one ask");
    assert_eq!(refused.code, crate::memory::MEMORY_CODE_BAD_REQUEST);
    Ok(())
}
