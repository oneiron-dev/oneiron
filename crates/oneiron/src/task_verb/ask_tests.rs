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
                ladder_answer: None,
                class_key: None,
                commitment: false,
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
        assert_eq!(
            result.effect_authorization,
            TaskAskEffectAuthorization::NotEvaluatedByAsk
        );
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
        self.word_with_sources(handle, seat, option, Default::default())
    }

    fn word_with_sources(
        &self,
        handle: TaskAskHandle,
        seat: usize,
        option: &str,
        provenance_refs: std::collections::BTreeSet<ConsultPayloadRef>,
    ) -> Result<TaskAskAnswer> {
        Ok(self
            .vault
            .memory(self.people[seat], EdgeActorClass::Human)
            .tasks_answer(
                &handle,
                &TaskAskWord {
                    result_ref: self.people[seat],
                    option: Some(TaskAskOptionId::new(option)?),
                    inform_for: None,
                    companion_for: None,
                    provenance_refs,
                },
            )?)
    }

    fn ask_with_uncounted_word(&self, bind: bool) -> Result<TaskAskResult> {
        let mut spec = self.spec();
        let mut class = self.policy(false);
        class.required_sources = [self.question].into();
        spec.class = Some(class);
        spec.need = TaskAskNeed {
            count: 3,
            of: TaskAskElectorate::Any,
        };
        spec.decide = Some(TaskAskDecide::AtLeast {
            count: 2,
            of: TaskAskElectorate::Any,
            answer: TaskAskOptionId::new("yes")?,
        });
        if bind {
            super::tests::support::permit_outcome_fixture_predicates(&self.vault, self.owner)?;
            spec.what.outcome_binding = Some(crate::llm::decision::questions::OutcomeBinding {
                source: crate::llm::decision::questions::OutcomeSource::Claim {
                    predicate: "outcome.earned".into(),
                },
                horizon: 60,
                mapping: [("yes".into(), true), ("no".into(), false)].into(),
                noise_weight: 1.0,
                linked_by: None,
            });
        }
        let handle = self.ask(&spec)?;
        self.word_with_sources(handle, 0, "yes", [self.question].into())?;
        self.word_with_sources(handle, 1, "yes", [self.question].into())?;
        self.word(handle, 2, "no")?;
        self.clock.set(1_101);
        self.result(handle)
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

// A PERSON holder explicitly addressed as a peer is an agent-bound consult TASK.
fn peer_option_ask() -> Result<(RuledAskFixture, TaskAskHandle, EntityId, EntityId)> {
    let fixture = RuledAskFixture::new(1)?;
    let peer = fixture.people[0];
    let mut spec = fixture.spec();
    spec.who = Some(TaskAskTarget::Responder(TaskAssignee::Peer {
        actor_ref: peer,
    }));
    let receipt = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .tasks_ask(&spec)?;
    let task = receipt.task_refs[0];
    Ok((fixture, receipt.handle, peer, task))
}

#[test]
fn consult_result_with_an_option_settles_its_member_task() -> Result<()> {
    let (fixture, handle, peer, task) = peer_option_ask()?;
    let yes = TaskAskOptionId::new("yes")?;
    let input = ConsultResultInput {
        kind: ConsultResultKind::Answer {
            result_ref: fixture.question.entity_ref(),
            option: Some(yes.clone()),
            evidence_refs: vec![fixture.question],
        },
        completed_at: 1_001,
    };
    fixture
        .vault
        .memory(peer, EdgeActorClass::Agent)
        .land_consult_result(task, &input)?;
    assert!(
        super::wire_decode::task_verb_body(&fixture.vault, task)?
            .expect("member task")
            .terminal()
            .is_some()
    );
    let evidence = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .tasks_ask_evidence(handle)?;
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].word.option, Some(yes));
    Ok(())
}

#[test]
fn consult_result_replay_requires_the_stored_ask_option() -> Result<()> {
    let (fixture, handle, peer, task) = peer_option_ask()?;
    let memory = fixture.vault.memory(peer, EdgeActorClass::Agent);
    let input = ConsultResultInput {
        kind: ConsultResultKind::Answer {
            result_ref: fixture.question.entity_ref(),
            option: Some(TaskAskOptionId::new("yes")?),
            evidence_refs: vec![fixture.question],
        },
        completed_at: 1_001,
    };
    let first = memory.land_consult_result(task, &input)?;
    assert!(!first.idempotent_replay);
    let replay = memory.land_consult_result(task, &input)?;
    assert!(replay.idempotent_replay);
    assert_eq!(replay.terminal, first.terminal);

    let original_evidence = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .tasks_ask_evidence(handle)?;
    for option in [Some("no"), None, Some("unknown")] {
        let mut changed = input.clone();
        if let ConsultResultKind::Answer {
            option: selected, ..
        } = &mut changed.kind
        {
            *selected = option.map(TaskAskOptionId::new).transpose()?;
        }
        let error = memory
            .land_consult_result(task, &changed)
            .expect_err("a changed option cannot be an idempotent replay");
        assert_eq!(
            error.code,
            if option == Some("no") {
                crate::memory::MEMORY_CODE_INVALID_STATE
            } else {
                crate::memory::MEMORY_CODE_BAD_REQUEST
            }
        );
        assert_eq!(
            fixture
                .vault
                .memory(fixture.owner, EdgeActorClass::Human)
                .tasks_ask_evidence(handle)?,
            original_evidence
        );
        assert_eq!(
            super::wire_decode::task_verb_body(&fixture.vault, task)?
                .expect("member task")
                .terminal(),
            Some(&first.terminal)
        );
    }
    assert!(memory.land_consult_result(task, &input)?.idempotent_replay);
    Ok(())
}

#[test]
fn consult_result_without_an_option_on_an_options_ask_is_refused_before_the_write() -> Result<()> {
    let (fixture, _handle, peer, task) = peer_option_ask()?;
    let input = ConsultResultInput {
        kind: ConsultResultKind::Answer {
            result_ref: fixture.question.entity_ref(),
            option: None,
            evidence_refs: vec![fixture.question],
        },
        completed_at: 1_001,
    };
    let refused = fixture
        .vault
        .memory(peer, EdgeActorClass::Agent)
        .land_consult_result(task, &input)
        .expect_err("an options ask needs an option id");
    assert_eq!(refused.code, crate::memory::MEMORY_CODE_BAD_REQUEST);
    assert!(refused.suggestions.iter().any(|s| s.contains("option ids")));
    assert!(
        super::wire_decode::task_verb_body(&fixture.vault, task)?
            .expect("member task")
            .terminal()
            .is_none()
    );
    Ok(())
}

#[test]
fn uncounted_source_less_reply_cannot_restore_an_impossible_threshold() -> Result<()> {
    let fixture = RuledAskFixture::new(3)?;
    let mut spec = fixture.spec();
    let mut class = fixture.policy(false);
    class.required_sources = [fixture.question].into();
    spec.class = Some(class);
    spec.need = TaskAskNeed {
        count: 3,
        of: TaskAskElectorate::Any,
    };
    spec.decide = Some(TaskAskDecide::AtLeast {
        count: 2,
        of: TaskAskElectorate::Any,
        answer: TaskAskOptionId::new("yes")?,
    });
    let handle = fixture.ask(&spec)?;
    fixture.word_with_sources(handle, 0, "no", [fixture.question].into())?;
    fixture.word(handle, 1, "yes")?;
    fixture.clock.set(1_101);
    let result = fixture.result(handle)?;
    assert_eq!(result.decision, TaskAskDecision::No);
    assert_eq!(result.coverage.unknown, [fixture.people[2]].into());
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|entry| entry.reason == TaskAskEvidenceReason::MissingSource)
            .count(),
        1
    );
    Ok(())
}

#[test]
fn ask_word_missing_a_required_source_does_not_veto_the_counted_words() -> Result<()> {
    let fixture = RuledAskFixture::new(3)?;
    let result = fixture.ask_with_uncounted_word(false)?;
    assert_eq!(
        result.decision,
        TaskAskDecision::Answer(TaskAskOptionId::new("yes")?)
    );
    assert_eq!(result.settlement.unmet_sources, [fixture.question].into());
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|entry| entry.reason == TaskAskEvidenceReason::MissingSource)
            .count(),
        1
    );
    Ok(())
}

#[test]
fn ask_decided_despite_an_uncounted_word_binds_its_outcome() -> Result<()> {
    let fixture = RuledAskFixture::new(3)?;
    let result = fixture.ask_with_uncounted_word(true)?;
    assert_eq!(
        result.decision,
        TaskAskDecision::Answer(TaskAskOptionId::new("yes")?)
    );
    assert!(result.settlement.outcome_answer_ref.is_some());
    Ok(())
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
fn ask_peek_round_trips_word_companion_and_silent_unknown_with_distinct_attribution() -> Result<()>
{
    let fixture = RuledAskFixture::new(3)?;
    let mut spec = fixture.all();
    spec.default = TaskAskDefault::Proceed;
    let handle = fixture.ask(&spec)?;
    let owner = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    fixture.word(handle, 0, "yes")?;
    fixture.clock.set(1_010);
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Agent)
        .tasks_answer(
            &handle,
            &TaskAskWord {
                result_ref: fixture.owner,
                option: Some(TaskAskOptionId::new("no")?),
                inform_for: Some(fixture.people[1]),
                provenance_refs: Default::default(),
            },
        )?;
    let partial = owner.tasks_ask_peek(handle)?;
    assert_eq!(partial.len(), 2);
    let human = partial
        .iter()
        .find(|entry| entry.who == fixture.people[0])
        .unwrap();
    assert_eq!(human.kind, TaskAskPersonKind::Word);
    assert_eq!(human.at, 1_000);
    assert_eq!(human.source, Some(fixture.people[0]));
    let companion = partial
        .iter()
        .find(|entry| entry.who == fixture.people[1])
        .unwrap();
    assert_eq!(companion.kind, TaskAskPersonKind::Companion);
    assert_eq!(companion.at, 1_010);
    assert_eq!(companion.source, Some(fixture.owner));
    fixture.clock.set(1_101);
    let result = fixture.result(handle)?;
    assert_eq!(
        result.coverage.unknown,
        [fixture.people[1], fixture.people[2]].into()
    );
    assert_eq!(
        result.fallback.as_ref().unwrap().branch,
        TaskAskDefault::Proceed
    );
    let evidence = owner.tasks_ask_peek(handle)?;
    assert_eq!(evidence.len(), 3);
    let silent = evidence
        .iter()
        .find(|entry| entry.who == fixture.people[2])
        .unwrap();
    assert_eq!(silent.kind, TaskAskPersonKind::Unknown);
    assert_eq!(silent.answer, None);
    assert_eq!(silent.at, 1_101);
    assert_eq!(silent.source, None);
    assert!(
        evidence
            .iter()
            .all(|entry| entry.kind != TaskAskPersonKind::Default)
    );
    let json = serde_json::to_string(&evidence)?;
    assert_eq!(
        serde_json::from_str::<Vec<TaskAskPersonEvidence>>(&json)?,
        evidence
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
                companion_for: None,
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
    spec.what.ladder_answer = Some(TaskAskLadderPrediction {
        option: TaskAskOptionId::new("yes")?,
        rung: crate::llm::decision::DecisionRung::Rule,
        probability: None,
    });
    let receipt = fixture
        .vault
        .memory(agent, EdgeActorClass::Agent)
        .tasks_ask(&spec)?;
    let txn = fixture.vault.store.env.read_txn()?;
    let group = super::ask_record::read_group(&fixture.vault, &txn, receipt.handle.group_ref)?
        .ok_or("stored ask group")?;
    assert_eq!(group.context_class, Some(class.clone()));
    assert_eq!(
        group.effective.what.class_key.as_deref(),
        Some(class.key.as_str())
    );
    drop(txn);
    fixture.word(receipt.handle, 0, "yes")?;
    fixture.word(receipt.handle, 1, "no")?;
    let TaskAskWait::Ready(result) = fixture
        .vault
        .memory(agent, EdgeActorClass::Agent)
        .tasks_wait(receipt.handle, None)?
    else {
        panic!("settled governed ask");
    };
    assert_eq!(
        result
            .evidence
            .iter()
            .map(|e| e.ladder_changed)
            .collect::<Vec<_>>(),
        vec![Some(false), Some(true)]
    );
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

#[test]
fn omitted_short_target_uses_verified_human_task_owner_not_agent_actor() -> Result<()> {
    let (_dir, vault) = super::tests::support::open_vault();
    let human = vault.ensure_embedded_owner_actor()?;
    let agent = super::tests::support::own_agent(&vault);
    let question = super::tests::support::consult_turn(&vault, 0x81);
    let agent_memory = vault.memory(agent, EdgeActorClass::Agent);
    let input = serde_json::json!({
        "what": {"reference": question, "revision": 1, "options": {}, "context_refs": []}
    });
    assert_eq!(
        crate::task_verb::sdk::invoke(&agent_memory, "tasks.ask", input.clone())
            .unwrap_err()
            .code,
        crate::memory::MEMORY_CODE_BAD_REQUEST
    );
    // An own-auto agent may choose a foreign `owner_ref` at tasks.create,
    // but that owner proof is not an authenticated human assignment.
    let forged = agent_memory.tasks_create(
        &TaskCreateSpec::new(
            rmpv::Value::from("agent-nominated owner"),
            None,
            Some(human),
            None,
        )
        .with_assignee(TaskAssignee::Peer { actor_ref: agent }),
    )?;
    assert!(forged.effected);
    assert_eq!(
        crate::task_verb::sdk::invoke(&agent_memory, "tasks.ask", input.clone())
            .unwrap_err()
            .code,
        crate::memory::MEMORY_CODE_BAD_REQUEST,
    );
    // A genuine human assignment to B is not a principal binding for A,
    // even if a public raw TASK rewrite later retargets its mutable body.
    let other_agent = EntityId::now();
    super::tests::support::put_person(&vault, other_agent);
    let for_other = vault.memory(human, EdgeActorClass::Human).tasks_create(
        &TaskCreateSpec::new(rmpv::Value::from("other agent"), None, None, None).with_assignee(
            TaskAssignee::Peer {
                actor_ref: other_agent,
            },
        ),
    )?;
    let other_task = for_other.task_ref.expect("human assignment for B");
    let mut rewritten =
        super::wire_decode::task_verb_body(&vault, other_task)?.expect("typed task body");
    rewritten.assignee = Some(TaskAssignee::Peer { actor_ref: agent });
    let rewritten_bytes = super::wire_encode::encode_task_verb_body(rewritten);
    let now = crate::unix_seconds_now() + 5;
    vault.put_entity(
        &other_task,
        crate::registry::ENTITY_TYPE_TASK,
        crate::temporal::TimeRange {
            start: now,
            end: now,
        },
        now,
        &rewritten_bytes,
    )?;
    assert_eq!(
        super::wire_decode::task_verb_body(&vault, other_task)?
            .unwrap()
            .assignee,
        Some(TaskAssignee::Peer { actor_ref: agent }),
    );
    assert_eq!(
        crate::task_verb::sdk::invoke(&agent_memory, "tasks.ask", input.clone())
            .unwrap_err()
            .code,
        crate::memory::MEMORY_CODE_BAD_REQUEST,
    );
    let assignment = vault.memory(human, EdgeActorClass::Human).tasks_create(
        &TaskCreateSpec::new(rmpv::Value::from("owned assignment"), None, None, None)
            .with_assignee(TaskAssignee::Peer { actor_ref: agent }),
    )?;
    assert!(assignment.effected);
    let receipt = crate::task_verb::sdk::invoke(&agent_memory, "tasks.ask", input)?;
    let handle: TaskAskHandle = serde_json::from_value(receipt["handle"].clone())?;
    let task: EntityId = serde_json::from_value(receipt["task_refs"][0].clone())?;
    assert_eq!(
        super::wire_decode::task_verb_body(&vault, task)?
            .unwrap()
            .assignee,
        Some(TaskAssignee::Human { actor_ref: human })
    );
    let answer = vault
        .memory(human, EdgeActorClass::Human)
        .tasks_answer(&handle, &TaskAskWord::new(human))?;
    let result = settled(&agent_memory, handle);
    assert_eq!(result.decision, TaskAskDecision::First(answer));
    assert_eq!(result.coverage.responded, [human].into());
    Ok(())
}

#[test]
fn ask_receipt_labels_only_counted_human_words_against_pinned_ladder_option() -> Result<()> {
    let fixture = RuledAskFixture::new(3)?;
    let mut spec = fixture.all();
    spec.what.class_key = Some("fixture-choice-class".into());
    spec.what.ladder_answer = Some(TaskAskLadderPrediction {
        option: TaskAskOptionId::new("yes")?,
        rung: crate::llm::decision::DecisionRung::SystemOne,
        probability: Some(0.6),
    });
    let handle = fixture.ask(&spec)?;
    fixture.word(handle, 0, "yes")?;
    fixture.word(handle, 1, "no")?;
    fixture.word(handle, 2, "yes")?;
    let receipt = fixture.result(handle)?;
    assert_eq!(
        receipt
            .evidence
            .iter()
            .map(|e| e.ladder_changed)
            .collect::<Vec<_>>(),
        vec![Some(false), Some(true), Some(false)]
    );
    assert_eq!(
        receipt.settlement.effective.what.class_key.as_deref(),
        Some("fixture-choice-class")
    );
    assert_eq!(fixture.result(handle)?, receipt);

    let mut invalid = fixture.spec();
    invalid.what.ladder_answer = Some(TaskAskLadderPrediction {
        option: TaskAskOptionId::new("missing")?,
        rung: crate::llm::decision::DecisionRung::Rule,
        probability: None,
    });
    assert!(fixture.ask(&invalid).is_err());
    Ok(())
}

#[test]
fn comparable_ask_without_question_class_is_refused_before_admission() -> Result<()> {
    let fixture = RuledAskFixture::new(1)?;
    let mut spec = fixture.spec();
    spec.what.ladder_answer = Some(TaskAskLadderPrediction {
        option: TaskAskOptionId::new("yes")?,
        rung: crate::llm::decision::DecisionRung::SystemOne,
        probability: Some(0.6),
    });
    let before = fixture
        .vault
        .entities_by_type(crate::registry::ENTITY_TYPE_TASK)?;
    let refused = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .tasks_ask(&spec)
        .expect_err("comparable prediction needs a question class");
    assert_eq!(refused.code, crate::memory::MEMORY_CODE_BAD_REQUEST);
    assert_eq!(
        fixture
            .vault
            .entities_by_type(crate::registry::ENTITY_TYPE_TASK)?,
        before
    );
    // An explicit, ungoverned learning class admits the same question.
    spec.what.class_key = Some("ungoverned-choice".into());
    let handle = fixture.ask(&spec)?;
    fixture.word(handle, 0, "no")?;
    assert_eq!(
        fixture.result(handle)?.evidence[0].ladder_changed,
        Some(true)
    );
    Ok(())
}

#[test]
fn stale_question_receipt_is_evidence_but_never_trains_its_band() -> Result<()> {
    use crate::llm::decision::DecisionBand;
    use crate::skill_optimize::{AskBandLabel, AskBandPolicy};
    struct Never;
    impl AskBandPolicy for Never {
        fn revise(&self, _: DecisionBand, _: &[AskBandLabel]) -> crate::Result<DecisionBand> {
            panic!("stale comparison must not reach the optimizer");
        }
    }
    let fixture = RuledAskFixture::new(1)?;
    let mut spec = fixture.spec();
    spec.what.class_key = Some("stale-choice".into());
    spec.what.ladder_answer = Some(TaskAskLadderPrediction {
        option: TaskAskOptionId::new("yes")?,
        rung: crate::llm::decision::DecisionRung::Rule,
        probability: None,
    });
    let handle = fixture.ask(&spec)?;
    let changed_question = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([(
        "role",
        "revised question",
    )]))?;
    fixture.vault.put_entity(
        &fixture.question.entity_ref(),
        crate::registry::ENTITY_TYPE_TURN,
        crate::TimeRange {
            start: 1_001,
            end: 1_001,
        },
        1_001,
        &changed_question,
    )?;
    fixture.word(handle, 0, "no")?;
    let receipt = fixture.result(handle)?;
    assert_eq!(receipt.settlement.reason, TaskAskSettlementReason::Stale);
    assert_eq!(receipt.decision, TaskAskDecision::Unknown);
    assert_eq!(receipt.evidence.len(), 1);
    assert_eq!(receipt.evidence[0].ladder_changed, None);
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    assert_eq!(
        memory.tasks_optimize_ask_band("stale-choice", &[handle], &Never)?,
        DecisionBand::default()
    );
    assert_eq!(
        memory.tasks_ask_band("stale-choice")?,
        DecisionBand::default()
    );
    assert_eq!(fixture.result(handle)?, receipt);
    Ok(())
}

#[test]
fn ask_class_band_consumes_42_rubber_stamps_then_30_overrules_once() -> Result<()> {
    use crate::llm::decision::DecisionBand;
    use crate::skill_optimize::{AskBandLabel, AskBandPolicy};
    struct Policy {
        expected: usize,
        changes: usize,
        band: DecisionBand,
    }
    impl AskBandPolicy for Policy {
        fn revise(&self, _: DecisionBand, labels: &[AskBandLabel]) -> crate::Result<DecisionBand> {
            assert_eq!(labels.len(), self.expected);
            assert_eq!(
                labels.iter().filter(|label| label.changed).count(),
                self.changes
            );
            Ok(self.band)
        }
    }
    let fixture = RuledAskFixture::new(1)?;
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let mut first = Vec::new();
    for i in 0..42 {
        let mut spec = fixture.spec();
        spec.intent_key = format!("same-{i}");
        spec.what.class_key = Some("one-question-class".into());
        spec.what.ladder_answer = Some(TaskAskLadderPrediction {
            option: TaskAskOptionId::new("yes")?,
            rung: crate::llm::decision::DecisionRung::SystemOne,
            probability: Some(0.6),
        });
        let handle = fixture.ask(&spec)?;
        fixture.word(handle, 0, if i < 40 { "yes" } else { "no" })?;
        assert_eq!(
            fixture.result(handle)?.evidence[0].ladder_changed,
            Some(i >= 40)
        );
        first.push(handle);
    }
    // An invalid policy band rolls back both the band and consume markers.
    assert!(
        memory
            .tasks_optimize_ask_band(
                "one-question-class",
                &first,
                &Policy {
                    expected: 42,
                    changes: 2,
                    band: DecisionBand {
                        low: 0.9,
                        high: 0.1
                    }
                }
            )
            .is_err()
    );
    assert_eq!(
        memory.tasks_ask_band("one-question-class")?,
        DecisionBand::default()
    );
    first.push(first[0]); // repeated handle in the same optimization pass
    let no_ask = DecisionBand {
        low: 0.7,
        high: 0.9,
    };
    assert_eq!(
        memory.tasks_optimize_ask_band(
            "one-question-class",
            &first,
            &Policy {
                expected: 42,
                changes: 2,
                band: no_ask
            }
        )?,
        no_ask
    );
    assert!(!memory.tasks_should_ask("one-question-class", 0.6)?);
    // Re-reading a receipt cannot train the class twice, even with a
    // different policy proposal.
    assert_eq!(
        memory.tasks_optimize_ask_band(
            "one-question-class",
            &first,
            &Policy {
                expected: 0,
                changes: 0,
                band: DecisionBand::default()
            }
        )?,
        no_ask
    );
    let mut second = Vec::new();
    for i in 0..30 {
        let mut spec = fixture.spec();
        spec.intent_key = format!("changed-{i}");
        spec.what.class_key = Some("one-question-class".into());
        spec.what.ladder_answer = Some(TaskAskLadderPrediction {
            option: TaskAskOptionId::new("yes")?,
            rung: crate::llm::decision::DecisionRung::Rule,
            probability: Some(0.6),
        });
        let handle = fixture.ask(&spec)?;
        fixture.word(handle, 0, "no")?;
        assert_eq!(
            fixture.result(handle)?.evidence[0].ladder_changed,
            Some(true)
        );
        second.push(handle);
    }
    let earlier = DecisionBand {
        low: 0.5,
        high: 0.9,
    };
    assert_eq!(
        memory.tasks_optimize_ask_band(
            "one-question-class",
            &second,
            &Policy {
                expected: 30,
                changes: 30,
                band: earlier
            }
        )?,
        earlier
    );
    assert!(memory.tasks_should_ask("one-question-class", 0.6)?);
    assert_eq!(
        memory.tasks_ask_band("other-question-class")?,
        DecisionBand::default()
    );
    Ok(())
}

/// Owner-stamped grant fixtures: the foreign asker sees one exact fact; an
/// independent action grant can delegate one answer class to the companion.
fn guest_fixture(
    fixture: &RuledAskFixture,
    person: EntityId,
    companion: EntityId,
    delegate: bool,
) -> Result<TaskAskGuest> {
    use crate::consent::{
        ActionClass, ActionEnvelope, ActorBound, AudienceBound, DisclosureClass,
        DisclosureEnvelope, GrantBound,
    };
    let owner = fixture.vault.authenticate_owner(
        person,
        &person.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let bound = GrantBound::disclosure(
        AudienceBound::new([fixture.owner.to_hex(), person.to_hex()])?,
        DisclosureClass::new("meeting")?,
        DisclosureEnvelope::new([fixture.question.entity_ref().to_hex()])?,
    )?;
    let disclosure_grant_ref = bound.digest().to_hex();
    fixture.vault.create_standing_grant(&owner, bound)?;
    if delegate {
        fixture.vault.create_standing_grant(
            &owner,
            GrantBound::action(
                ActorBound::new(companion.to_hex())?.with_actor_class("agent")?,
                ActionClass::new("ask.answer.meeting")?,
                ActionEnvelope::new(["answer".to_owned()])?.with_target(person.to_hex())?,
            )?,
        )?;
    }
    Ok(TaskAskGuest {
        companion_ref: companion,
        disclosure_grant_ref,
    })
}

#[test]
fn guest_answers_are_attributed_hints_or_class_delegated_not_human_words() -> Result<()> {
    let fixture = RuledAskFixture::new(2)?;
    let companions: Vec<_> = (0..2).map(|_| EntityId::now()).collect();
    for companion in &companions {
        fixture.vault.put_entity(
            companion,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::TimeRange {
                start: 1_000,
                end: 1_000,
            },
            1_000,
            b"companion",
        )?;
    }
    let guests = fixture
        .people
        .iter()
        .zip(&companions)
        .enumerate()
        .map(|(i, (person, companion))| {
            Ok((
                *person,
                guest_fixture(&fixture, *person, *companion, i == 1)?,
            ))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
    let mut spec = fixture.spec();
    spec.what.class_key = Some("meeting".into());
    spec.who = Some(TaskAskTarget::Guests(guests));
    spec.need.count = 2;
    spec.decide = Some(TaskAskDecide::AtLeast {
        count: 2,
        of: TaskAskElectorate::Any,
        answer: TaskAskOptionId::new("yes")?,
    });
    spec.default = TaskAskDefault::Hold;
    let handle = fixture.ask(&spec)?;
    for (i, companion) in companions.iter().enumerate() {
        fixture
            .vault
            .memory(*companion, EdgeActorClass::Agent)
            .tasks_answer(
                &handle,
                &TaskAskWord {
                    result_ref: fixture.question.entity_ref(),
                    option: Some(TaskAskOptionId::new("yes")?),
                    inform_for: None,
                    companion_for: Some(fixture.people[i]),
                    provenance_refs: Default::default(),
                },
            )?;
    }
    let evidence = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .tasks_ask_evidence(handle)?;
    assert_eq!(evidence[0].source, TaskAskSource::Companion);
    assert_eq!(evidence[0].person_ref, fixture.people[0]);
    assert_eq!(evidence[0].reason, TaskAskEvidenceReason::CompanionHint);
    assert_eq!(evidence[1].reason, TaskAskEvidenceReason::Counted);
    assert!(evidence[1].delegation_grant_ref.is_some());
    assert!(matches!(
        fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .tasks_ask_status(handle)?,
        TaskAskStatus::Pending { .. }
    ));
    fixture.clock.set(1_101);
    let result = fixture.result(handle)?;
    assert_eq!(result.coverage.responded.len(), 1);
    assert!(!result.coverage.met);
    assert_eq!(result.fallback.unwrap().branch, TaskAskDefault::Hold);
    assert_eq!(
        result.effect_authorization,
        TaskAskEffectAuthorization::NotEvaluatedByAsk
    );
    Ok(())
}

#[test]
fn companion_commitment_notices_once_and_deadline_holds_without_booking() -> Result<()> {
    let fixture = RuledAskFixture::new(1)?;
    let person = fixture.people[0];
    let companion = EntityId::now();
    fixture.vault.put_entity(
        &companion,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange {
            start: 1_000,
            end: 1_000,
        },
        1_000,
        b"companion",
    )?;
    let guest = guest_fixture(&fixture, person, companion, true)?;
    let mut spec = fixture.spec();
    spec.who = Some(TaskAskTarget::Guests([(person, guest)].into()));
    spec.what.class_key = Some("meeting".into());
    spec.what.commitment = true;
    spec.default = TaskAskDefault::Hold;
    let handle = fixture.ask(&spec)?;
    let word = TaskAskWord {
        result_ref: fixture.question.entity_ref(),
        option: Some(TaskAskOptionId::new("yes")?),
        inform_for: None,
        companion_for: Some(person),
        provenance_refs: Default::default(),
    };
    let memory = fixture.vault.memory(companion, EdgeActorClass::Agent);
    let answer = memory.tasks_answer(&handle, &word)?;
    assert_eq!(memory.tasks_answer(&handle, &word)?, answer);
    let notice = fixture
        .vault
        .memory(person, EdgeActorClass::Human)
        .tasks_ask_soft_confirm_notice(handle, person)?
        .expect("notice");
    assert_eq!(notice.revision, spec.what.revision);
    assert_eq!(notice.companion_answer_ref, answer.word_ref);
    assert_eq!(notice.option, word.option);
    assert!(matches!(
        fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .tasks_ask_status(handle)?,
        TaskAskStatus::Pending { .. }
    ));
    fixture.clock.set(1_101);
    let result = fixture.result(handle)?;
    assert_eq!(result.fallback.unwrap().branch, TaskAskDefault::Hold);
    assert_eq!(
        result.effect_authorization,
        TaskAskEffectAuthorization::NotEvaluatedByAsk
    );
    assert!(result.evidence[0].soft_confirm);
    Ok(())
}

#[test]
fn guest_ask_reuses_only_live_person_disclosure_and_is_not_membership() -> Result<()> {
    let fixture = RuledAskFixture::new(1)?;
    let person = fixture.people[0];
    let companion = EntityId::now();
    fixture.vault.put_entity(
        &companion,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange {
            start: 1_000,
            end: 1_000,
        },
        1_000,
        b"companion",
    )?;
    let guest = guest_fixture(&fixture, person, companion, false)?;
    let mut spec = fixture.spec();
    spec.who = Some(TaskAskTarget::Guests([(person, guest.clone())].into()));
    spec.what.class_key = Some("meeting".into());
    let second = EntityId::now();
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "question")]))?;
    fixture.vault.put_entity(
        &second,
        crate::registry::ENTITY_TYPE_TURN,
        crate::TimeRange {
            start: 1_000,
            end: 1_000,
        },
        1_000,
        &body,
    )?;
    spec.what.context_refs.push(ConsultPayloadRef::Turn(second));
    assert!(
        fixture.ask(&spec).is_err(),
        "undisclosed fact must not be granted"
    );
    spec.what.context_refs.clear();
    let handle = fixture.ask(&spec)?;
    let txn = fixture.vault.store.env.read_txn()?;
    let group = super::ask_record::read_group(&fixture.vault, &txn, handle.group_ref)?.unwrap();
    let id = group.guest_grants[&person];
    let raw = fixture.vault.get_raw_in(&txn, &id)?.unwrap();
    let grant = crate::federation::decode_federation_grant_body(
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )?;
    assert_eq!(grant.role, crate::federation::FederationGrantRole::Guest);
    assert!(!grant.is_admin());
    assert!(!grant.allows_ask_fact(
        EntityId::now(),
        companion,
        person,
        fixture.owner,
        fixture.question.entity_ref()
    ));
    assert!(!grant.allows_ask_fact(handle.group_ref, companion, person, fixture.owner, second));
    drop(txn);
    assert!(
        fixture
            .vault
            .memory(companion, EdgeActorClass::Agent)
            .tasks_answer(
                &handle,
                &TaskAskWord {
                    result_ref: second,
                    option: Some(TaskAskOptionId::new("yes")?),
                    inform_for: None,
                    companion_for: Some(person),
                    provenance_refs: Default::default(),
                }
            )
            .is_err(),
        "undisclosed answer fact must not pass the ask guest grant"
    );
    let owner = fixture.vault.authenticate_owner(
        person,
        &person.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    fixture
        .vault
        .revoke_consent_grant(&owner, &guest.disclosure_grant_ref)?;
    assert!(
        fixture
            .vault
            .memory(companion, EdgeActorClass::Agent)
            .tasks_answer(
                &handle,
                &TaskAskWord {
                    result_ref: fixture.question.entity_ref(),
                    option: Some(TaskAskOptionId::new("yes")?),
                    inform_for: None,
                    companion_for: Some(person),
                    provenance_refs: Default::default(),
                }
            )
            .is_err(),
        "revocation must stop companion intake"
    );
    Ok(())
}

#[test]
fn person_word_overrides_companion_hint_without_authorizing_an_effect() -> Result<()> {
    let fixture = RuledAskFixture::new(1)?;
    let person = fixture.people[0];
    let companion = EntityId::now();
    fixture.vault.put_entity(
        &companion,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange {
            start: 1_000,
            end: 1_000,
        },
        1_000,
        b"companion",
    )?;
    let guest = guest_fixture(&fixture, person, companion, false)?;
    let mut spec = fixture.spec();
    spec.who = Some(TaskAskTarget::Guests([(person, guest)].into()));
    spec.what.class_key = Some("meeting".into());
    let handle = fixture.ask(&spec)?;
    fixture
        .vault
        .memory(companion, EdgeActorClass::Agent)
        .tasks_answer(
            &handle,
            &TaskAskWord {
                result_ref: fixture.question.entity_ref(),
                option: Some(TaskAskOptionId::new("yes")?),
                inform_for: None,
                companion_for: Some(person),
                provenance_refs: Default::default(),
            },
        )?;
    assert!(matches!(
        fixture
            .vault
            .memory(fixture.owner, EdgeActorClass::Human)
            .tasks_ask_status(handle)?,
        TaskAskStatus::Pending { .. }
    ));
    fixture.word(handle, 0, "no")?;
    let result = fixture.result(handle)?;
    assert_eq!(result.coverage.responded, [person].into());
    assert_eq!(result.evidence[0].source, TaskAskSource::Companion);
    assert_eq!(
        result.evidence[0].reason,
        TaskAskEvidenceReason::HumanDominates
    );
    assert_eq!(result.evidence[1].source, TaskAskSource::Human);
    assert_eq!(
        result.decision,
        TaskAskDecision::First(result.evidence[1].answer)
    );
    assert_eq!(
        result.effect_authorization,
        TaskAskEffectAuthorization::NotEvaluatedByAsk
    );
    Ok(())
}

#[test]
fn human_no_reply_to_soft_confirm_uses_normal_answer_intake() -> Result<()> {
    let fixture = RuledAskFixture::new(1)?;
    let person = fixture.people[0];
    let companion = EntityId::now();
    fixture.vault.put_entity(
        &companion,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange {
            start: 1_000,
            end: 1_000,
        },
        1_000,
        b"companion",
    )?;
    let guest = guest_fixture(&fixture, person, companion, true)?;
    let mut spec = fixture.spec();
    spec.who = Some(TaskAskTarget::Guests([(person, guest)].into()));
    spec.what.class_key = Some("meeting".into());
    spec.what.commitment = true;
    let handle = fixture.ask(&spec)?;
    fixture
        .vault
        .memory(companion, EdgeActorClass::Agent)
        .tasks_answer(
            &handle,
            &TaskAskWord {
                result_ref: fixture.question.entity_ref(),
                option: Some(TaskAskOptionId::new("yes")?),
                inform_for: None,
                companion_for: Some(person),
                provenance_refs: Default::default(),
            },
        )?;
    let notice = fixture
        .vault
        .memory(person, EdgeActorClass::Human)
        .tasks_ask_soft_confirm_notice(handle, person)?
        .expect("typed notice");
    assert_eq!(notice.revision, spec.what.revision);
    let reply = fixture.word(handle, 0, "no")?;
    let result = fixture.result(handle)?;
    assert_eq!(result.decision, TaskAskDecision::First(reply));
    assert_eq!(
        result.evidence[0].reason,
        TaskAskEvidenceReason::HumanDominates
    );
    assert_eq!(result.evidence[1].source, TaskAskSource::Human);
    assert_eq!(
        result.effect_authorization,
        TaskAskEffectAuthorization::NotEvaluatedByAsk
    );
    Ok(())
}

#[test]
fn reachable_companion_soft_confirm_schedules_one_approve_or_no_delivery() -> Result<()> {
    use crate::channel_identity::{
        ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityState,
        SelfHeldShape,
    };
    use crate::counterparty_contact::CounterpartyContactRecord;
    use crate::genui::{GrantMintIntent, GrantMintIntentScope};
    use crate::registry::ENTITY_TYPE_TASK;
    let fixture = RuledAskFixture::new(0)?;
    let person =
        crate::comm::resolve_or_create_comm_party(&fixture.vault, "recipient@example.test")?;
    let identity_ref = EntityId::now();
    fixture.vault.create_channel_identity(
        &identity_ref,
        &ChannelIdentity::requested(
            "email",
            "sender@example.test",
            SelfHeldShape::DedicatedAddress,
            ChannelIdentityBinding::vault(1),
            1_000,
        ),
    )?;
    fixture.vault.transition_channel_identity(
        &identity_ref,
        ChannelIdentityState::PendingFulfillment,
        Some(ChannelIdentityFulfillment::Api),
        1_000,
        None,
    )?;
    fixture.vault.transition_channel_identity(
        &identity_ref,
        ChannelIdentityState::Active,
        None,
        1_000,
        None,
    )?;
    fixture.vault.create_counterparty_contact(
        &EntityId::now(),
        &CounterpartyContactRecord::user_introduction(
            identity_ref,
            "recipient@example.test",
            1_000,
        )?,
    )?;
    let companion = EntityId::now();
    fixture.vault.put_entity(
        &companion,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange {
            start: 1_000,
            end: 1_000,
        },
        1_000,
        b"companion",
    )?;
    fixture.vault.mint_standing_outbound_grant(
        &EntityId::now(),
        &GrantMintIntent {
            principal_ref: companion.to_hex(),
            origin_component_id: "tasks".into(),
            origin_action_id: "ask.soft_confirm".into(),
            origin_receipt_ref: None,
            scope: GrantMintIntentScope::VerbClass {
                verb_class: "send".into(),
            },
        },
        1_000,
    )?;
    let guest = guest_fixture(&fixture, person, companion, false)?;
    let mut spec = fixture.spec();
    spec.who = Some(TaskAskTarget::Guests([(person, guest)].into()));
    spec.what.class_key = Some("meeting".into());
    spec.what.commitment = true;
    let handle = fixture.ask(&spec)?;
    let word = TaskAskWord {
        result_ref: fixture.question.entity_ref(),
        option: Some(TaskAskOptionId::new("yes")?),
        inform_for: None,
        companion_for: Some(person),
        provenance_refs: Default::default(),
    };
    let memory = fixture.vault.memory(companion, EdgeActorClass::Agent);
    memory.tasks_answer(&handle, &word)?;
    memory.tasks_answer(&handle, &word)?;
    let key = format!(
        "ask-soft-confirm/{}/{}",
        handle.group_ref.to_hex(),
        person.to_hex()
    );
    let sends = fixture
        .vault
        .entities_by_type(ENTITY_TYPE_TASK)?
        .into_iter()
        .filter(|id| {
            fixture
                .vault
                .connector_send_task(id)
                .ok()
                .flatten()
                .is_some_and(|send| send.intent.idempotency_key.as_deref() == Some(key.as_str()))
        })
        .count();
    assert_eq!(sends, 1, "the reachable person gets one scheduled notice");
    Ok(())
}
