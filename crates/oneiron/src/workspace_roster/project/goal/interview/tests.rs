use super::*;
use crate::TimeRange;
use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use crate::edge::EdgeActorClass;
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SKILL};

fn speak(
    vault: &Vault,
    room: EntityId,
    actor: EntityId,
    class: EdgeActorClass,
    text: &str,
    reply: Option<EntityId>,
    at: u64,
) -> EntityId {
    let id = EntityId::now();
    let metadata = reply.map(|ref_id| serde_json::json!({"room_reply_to": ref_id.to_hex()}));
    vault
        .memory(actor, class)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(id.to_hex()),
            occurred_at: at,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: if class == EdgeActorClass::Human {
                    WitnessAuthor::User
                } else {
                    WitnessAuthor::Companion
                },
                message_type: "text".into(),
                content: text.into(),
                metadata,
                is_visible: true,
                order: 0,
            }],
        })
        .unwrap();
    id
}

/// A host worker leases the attempt before loading the skill onto it.
fn load_leased(
    vault: &Vault,
    attempt: AttemptId,
    skill: &EntityId,
    now: u64,
) -> Result<crate::skill::LoadedSkillPack> {
    let crate::attempt_queue::ClaimOutcome::Claimed(leased) =
        AttemptQueue::new(vault).claim(crate::attempt_queue::ClaimAttempt {
            lease_owner: "worker".to_owned(),
            now,
        })?
    else {
        panic!("attempt must lease")
    };
    assert_eq!(leased.id, attempt);
    vault.load_attempt_skill_pack(
        attempt,
        skill,
        "worker",
        leased.attempt_count,
        "fixture/model@1",
        now,
    )
}

#[test]
fn loaded_skill_agent_asks_and_witnessed_human_confirmation_commits_goal() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let project = vault.root_project()?;
    let mut spec = vault.project(project)?.unwrap();
    let agent = EntityId::from_hex(&spec.leader)?;
    let human = EntityId::now();
    vault.put_entity(
        &human,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"human",
    )?;
    spec.roster.push(human.to_hex());
    vault.put_project(project, &spec, 2)?;
    let room = EntityId::from_hex(&spec.home_room)?;
    let owner = vault.authenticate_owner(
        human,
        &human.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let attempt = match AgentDispatcher::new(&vault).dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(agent),
        parent_attempt: None,
        dedupe_key: Some("goal-intake-e2e".into()),
        run_id: None,
        now: 3,
    })? {
        AgentDispatchOutcome::Dispatched(status) => status.attempt.id,
        _ => panic!("agent attempt must dispatch"),
    };
    let skill = vault
        .entities_by_type(ENTITY_TYPE_SKILL)?
        .into_iter()
        .find(|id| {
            vault
                .get_skill_record(id)
                .ok()
                .flatten()
                .is_some_and(|row| row.skill_id == "goal-intake")
        })
        .expect("seeded active goal-intake");
    let loaded = load_leased(&vault, attempt, &skill, 4)?;
    let markdown = loaded
        .source_files
        .unwrap()
        .into_iter()
        .find(|f| f.path == "SKILL.md")
        .unwrap()
        .content;
    let markdown = std::str::from_utf8(&markdown).unwrap();
    // Deterministic agent substitute: choose the question from the loaded
    // skill's actual required fields, then use the real room witness doors.
    let requested = [
        "goal",
        "why",
        "primary_axes",
        "floor_axes",
        "cost_axes",
        "preferences",
        "exploration_budget",
    ];
    assert!(requested.iter().all(|field| markdown.contains(field)));
    let initial = speak(
        &vault,
        room,
        human,
        EdgeActorClass::Human,
        "Please help define this goal",
        None,
        5,
    );
    let agent_memory = vault.memory(agent, EdgeActorClass::Agent);
    assert!(
        agent_memory
            .rooms_messages(room)
            .unwrap()
            .iter()
            .any(|turn| turn.turn_id == initial.to_hex())
    );
    agent_memory.rooms_claim(room, initial, 6).unwrap();
    let question = speak(
        &vault,
        room,
        agent,
        EdgeActorClass::Agent,
        &format!("Please answer: {}", requested.join(", ")),
        Some(initial),
        7,
    );
    assert!(vault.project_intake_goal(project)?.is_none());

    // First human answer omits required axes: even a confirmation cannot
    // turn an incomplete witnessed answer into an admitted goal.
    let partial = speak(
        &vault,
        room,
        human,
        EdgeActorClass::Human,
        r#"{"goal":"Answer requests","why":"Reduce repeats"}"#,
        Some(question),
        8,
    );
    agent_memory.rooms_claim(room, partial, 9).unwrap();
    let partial_draft = r#"{"goal":"Answer requests","why":"Reduce repeats"}"#;
    let rejected_draft = speak(
        &vault,
        room,
        agent,
        EdgeActorClass::Agent,
        partial_draft,
        Some(partial),
        10,
    );
    let rejected_confirm = speak(
        &vault,
        room,
        human,
        EdgeActorClass::Human,
        &format!(
            "confirm {}",
            GoalInterviewTurns::confirmation_digest(
                partial_draft,
                vault.project_goal_generation(project)?
            )
        ),
        Some(rejected_draft),
        11,
    );
    assert!(
        vault
            .write_project_goal_from_room_intake(
                &owner,
                project,
                attempt,
                GoalInterviewTurns {
                    question,
                    answer: partial,
                    draft: rejected_draft,
                    confirmation: rejected_confirm,
                },
                12
            )
            .is_err()
    );
    assert!(vault.project_intake_goal(project)?.is_none());

    let expected = crate::workspace_roster::project::goal::tests::transcript_record();
    let answer_json = serde_json::to_string(&expected).unwrap();
    let answer = speak(
        &vault,
        room,
        human,
        EdgeActorClass::Human,
        &answer_json,
        Some(question),
        13,
    );
    assert!(
        vault
            .write_project_goal_from_room_intake(
                &owner,
                project,
                attempt,
                GoalInterviewTurns {
                    question,
                    answer,
                    draft: rejected_draft,
                    confirmation: rejected_confirm,
                },
                14
            )
            .is_err()
    );
    assert!(vault.project_intake_goal(project)?.is_none());
    assert!(
        agent_memory
            .rooms_messages(room)
            .unwrap()
            .iter()
            .any(|turn| turn.turn_id == answer.to_hex())
    );
    agent_memory.rooms_claim(room, answer, 15).unwrap();
    let draft = speak(
        &vault,
        room,
        agent,
        EdgeActorClass::Agent,
        &answer_json,
        Some(answer),
        16,
    );
    assert!(vault.project_intake_goal(project)?.is_none());
    assert!(
        vault
            .write_project_goal_from_room_intake(
                &owner,
                project,
                attempt,
                GoalInterviewTurns {
                    question,
                    answer,
                    draft,
                    confirmation: EntityId::now()
                },
                17,
            )
            .is_err()
    );
    assert!(vault.project_intake_goal(project)?.is_none());
    let confirmation = speak(
        &vault,
        room,
        human,
        EdgeActorClass::Human,
        &format!(
            "confirm {}",
            GoalInterviewTurns::confirmation_digest(
                &answer_json,
                vault.project_goal_generation(project)?
            )
        ),
        Some(draft),
        17,
    );
    let unloaded = match AgentDispatcher::new(&vault).dispatch_default_base(
        None,
        Some("goal-intake-unloaded".into()),
        None,
        18,
    )? {
        AgentDispatchOutcome::Dispatched(status) => status.attempt.id,
        _ => panic!("second attempt must dispatch"),
    };
    assert!(
        vault
            .write_project_goal_from_room_intake(
                &owner,
                project,
                unloaded,
                GoalInterviewTurns {
                    question,
                    answer,
                    draft,
                    confirmation
                },
                18,
            )
            .is_err()
    );
    assert!(vault.project_intake_goal(project)?.is_none());
    let id = vault.write_project_goal_from_room_intake(
        &owner,
        project,
        attempt,
        GoalInterviewTurns {
            question,
            answer,
            draft,
            confirmation,
        },
        18,
    )?;
    let first_claim_count = vault.count_entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?;
    let first = GoalInterviewTurns {
        question,
        answer,
        draft,
        confirmation,
    };
    assert_eq!(
        vault.write_project_goal_from_room_intake(&owner, project, attempt, first, 19)?,
        id
    );
    assert_eq!(
        vault.count_entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?,
        first_claim_count
    );
    // New interview B supersedes A. A's old confirmation can no longer roll
    // back B, even after restart or on a delayed retry.
    let question_b = speak(
        &vault,
        room,
        human,
        EdgeActorClass::Human,
        "Another goal",
        None,
        20,
    );
    agent_memory.rooms_claim(room, question_b, 21).unwrap();
    let question_b = speak(
        &vault,
        room,
        agent,
        EdgeActorClass::Agent,
        "What changed?",
        Some(question_b),
        22,
    );
    let mut next = expected;
    next.primary_axes[0].bound = ">= 95".into();
    let answer_b_json = serde_json::to_string(&next).unwrap();
    let answer_b = speak(
        &vault,
        room,
        human,
        EdgeActorClass::Human,
        &answer_b_json,
        Some(question_b),
        23,
    );
    agent_memory.rooms_claim(room, answer_b, 24).unwrap();
    let draft_b = speak(
        &vault,
        room,
        agent,
        EdgeActorClass::Agent,
        &answer_b_json,
        Some(answer_b),
        25,
    );
    let confirm_b = speak(
        &vault,
        room,
        human,
        EdgeActorClass::Human,
        &format!(
            "confirm {}",
            GoalInterviewTurns::confirmation_digest(
                &answer_b_json,
                vault.project_goal_generation(project)?
            )
        ),
        Some(draft_b),
        26,
    );
    let second = vault.write_project_goal_from_room_intake(
        &owner,
        project,
        attempt,
        GoalInterviewTurns {
            question: question_b,
            answer: answer_b,
            draft: draft_b,
            confirmation: confirm_b,
        },
        27,
    )?;
    assert_ne!(id, second);
    assert!(
        vault
            .write_project_goal_from_room_intake(&owner, project, attempt, first, 28)
            .is_err()
    );
    assert_eq!(vault.project_intake_goal(project)?, Some(next.clone()));
    assert_eq!(vault.project(project)?.unwrap().goal, Some(second.to_hex()));
    drop(vault);
    let reopened = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(reopened.project_intake_goal(project)?, Some(next));
    Ok(())
}

struct Interview {
    _dir: tempfile::TempDir,
    vault: Vault,
    project: EntityId,
    room: EntityId,
    agent: EntityId,
    human: EntityId,
    owner: AuthenticatedOwner,
    attempt: AttemptId,
}

fn loaded_interview(dedupe: &str) -> Result<Interview> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let project = vault.root_project()?;
    let mut spec = vault.project(project)?.unwrap();
    let agent = EntityId::from_hex(&spec.leader)?;
    let human = EntityId::now();
    vault.put_entity(
        &human,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"human",
    )?;
    spec.roster.push(human.to_hex());
    vault.put_project(project, &spec, 2)?;
    let room = EntityId::from_hex(&spec.home_room)?;
    let owner = vault.authenticate_owner(
        human,
        &human.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let attempt = match AgentDispatcher::new(&vault).dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(agent),
        parent_attempt: None,
        dedupe_key: Some(dedupe.into()),
        run_id: None,
        now: 3,
    })? {
        AgentDispatchOutcome::Dispatched(status) => status.attempt.id,
        _ => panic!("agent attempt must dispatch"),
    };
    let skill = vault
        .entities_by_type(ENTITY_TYPE_SKILL)?
        .into_iter()
        .find(|id| {
            vault
                .get_skill_record(id)
                .ok()
                .flatten()
                .is_some_and(|row| row.skill_id == "goal-intake")
        })
        .expect("seeded active goal-intake");
    load_leased(&vault, attempt, &skill, 4)?;
    Ok(Interview {
        _dir: dir,
        vault,
        project,
        room,
        agent,
        human,
        owner,
        attempt,
    })
}

/// One witnessed round, confirmed but not applied. The draft is shown
/// against the goal generation read when it is posted.
fn confirmed(s: &Interview, record: &GoalRecord, at: u64) -> Result<(GoalInterviewTurns, u64)> {
    let agent = s.vault.memory(s.agent, EdgeActorClass::Agent);
    let human = EdgeActorClass::Human;
    let opening = speak(&s.vault, s.room, s.human, human, "A goal", None, at);
    agent.rooms_claim(s.room, opening, at + 1).unwrap();
    let question = speak(
        &s.vault,
        s.room,
        s.agent,
        EdgeActorClass::Agent,
        "What is the goal?",
        Some(opening),
        at + 2,
    );
    let json = serde_json::to_string(record).unwrap();
    let answer = speak(
        &s.vault,
        s.room,
        s.human,
        human,
        &json,
        Some(question),
        at + 3,
    );
    agent.rooms_claim(s.room, answer, at + 4).unwrap();
    let generation = s.vault.project_goal_generation(s.project)?;
    let draft = speak(
        &s.vault,
        s.room,
        s.agent,
        EdgeActorClass::Agent,
        &json,
        Some(answer),
        at + 5,
    );
    let confirmation = speak(
        &s.vault,
        s.room,
        s.human,
        human,
        &format!(
            "confirm {}",
            GoalInterviewTurns::confirmation_digest(&json, generation)
        ),
        Some(draft),
        at + 6,
    );
    Ok((
        GoalInterviewTurns {
            question,
            answer,
            draft,
            confirmation,
        },
        generation,
    ))
}

fn revised() -> GoalRecord {
    let mut record = crate::workspace_roster::project::goal::tests::transcript_record();
    record.primary_axes[0].bound = ">= 95".into();
    record
}

#[test]
fn stale_first_confirmation_cannot_replace_a_newer_goal() -> Result<()> {
    let s = loaded_interview("goal-intake-stale")?;
    let older = crate::workspace_roster::project::goal::tests::transcript_record();
    let newer = revised();
    let (a, a_generation) = confirmed(&s, &older, 10)?;
    let (b, b_generation) = confirmed(&s, &newer, 20)?;
    assert_eq!(a_generation, b_generation);
    let b_id = s
        .vault
        .write_project_goal_from_room_intake(&s.owner, s.project, s.attempt, b, 30)?;
    assert!(
        s.vault
            .write_project_goal_from_room_intake(&s.owner, s.project, s.attempt, a, 31)
            .is_err()
    );
    assert_eq!(s.vault.project_intake_goal(s.project)?, Some(newer.clone()));
    assert_eq!(
        s.vault.project(s.project)?.unwrap().goal,
        Some(b_id.to_hex())
    );
    // A second confirmation drafted against the generation B committed from
    // is stale too; only B's own consumed confirmation retries idempotently.
    let again = speak(
        &s.vault,
        s.room,
        s.human,
        EdgeActorClass::Human,
        &format!(
            "confirm {}",
            GoalInterviewTurns::confirmation_digest(
                &serde_json::to_string(&newer).unwrap(),
                b_generation
            )
        ),
        Some(b.draft),
        32,
    );
    assert!(
        s.vault
            .write_project_goal_from_room_intake(
                &s.owner,
                s.project,
                s.attempt,
                GoalInterviewTurns {
                    confirmation: again,
                    ..b
                },
                33,
            )
            .is_err()
    );
    assert_eq!(
        s.vault
            .write_project_goal_from_room_intake(&s.owner, s.project, s.attempt, b, 34)?,
        b_id
    );
    assert_eq!(s.vault.project_intake_goal(s.project)?, Some(newer));
    assert_eq!(
        s.vault.project(s.project)?.unwrap().goal,
        Some(b_id.to_hex())
    );
    assert_eq!(
        s.vault.project_goal_generation(s.project)?,
        b_generation + 1
    );
    Ok(())
}

#[test]
fn confirmation_is_refused_after_its_goal_is_deleted() -> Result<()> {
    let s = loaded_interview("goal-intake-deleted")?;
    let current = s
        .vault
        .write_project_goal_from_intake(&s.owner, s.project, &revised(), 5)?;
    let (a, _) = confirmed(
        &s,
        &crate::workspace_roster::project::goal::tests::transcript_record(),
        10,
    )?;
    s.vault
        .memory(s.human, EdgeActorClass::Human)
        .safe_delete(
            &current.to_hex(),
            crate::memory::SafeDeleteReason::UserDelete,
        )
        .map_err(|_| invalid())?;
    assert!(s.vault.project_intake_goal(s.project)?.is_none());
    assert!(
        s.vault
            .write_project_goal_from_room_intake(&s.owner, s.project, s.attempt, a, 20)
            .is_err()
    );
    assert!(s.vault.project_intake_goal(s.project)?.is_none());
    assert!(s.vault.project(s.project)?.unwrap().goal.is_none());
    Ok(())
}

#[test]
fn unrelated_project_edit_keeps_a_pending_interview_valid() -> Result<()> {
    let s = loaded_interview("goal-intake-unrelated")?;
    let current = s
        .vault
        .write_project_goal_from_intake(&s.owner, s.project, &revised(), 5)?;
    let record = crate::workspace_roster::project::goal::tests::transcript_record();
    let (a, generation) = confirmed(&s, &record, 10)?;
    // Same goal pointer, other fields changed, stamped with any timestamp.
    let mut edited = s.vault.project(s.project)?.unwrap();
    assert_eq!(edited.goal, Some(current.to_hex()));
    edited.budget = Some(EntityId::now().to_hex());
    s.vault.put_project(s.project, &edited, 30)?;
    assert_eq!(s.vault.project_goal_generation(s.project)?, generation);
    let id = s
        .vault
        .write_project_goal_from_room_intake(&s.owner, s.project, s.attempt, a, 31)?;
    assert_ne!(id, current);
    assert_eq!(s.vault.project_intake_goal(s.project)?, Some(record));
    let project = s.vault.project(s.project)?.unwrap();
    assert_eq!(project.goal, Some(id.to_hex()));
    assert_eq!(project.budget, edited.budget);
    Ok(())
}
