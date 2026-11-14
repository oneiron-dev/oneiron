//! The goal-intake interview on its thread TASK (RULINGS ARM05-GOAL-INTAKE =
//! A and GOAL-INTAKE-DRAFT-RUN = A, 14 Nov 2026). Each case opens the
//! interview on the vault's own project, as the owner's tap opens it on a
//! minted one: the owner's header, a stored card that minted the project
//! with its leader, and the opening, whose first intake run a host worker
//! leases and loads with the goal-intake skill. The leader then speaks only
//! through the interview TASK the opening bound to the card's thread.
use super::*;
use crate::agent_dispatch::{AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchOutcome, AgentDispatcher};
use crate::attempt_queue::{ClaimAttempt, ClaimOutcome};
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::edge::EdgeActorClass;
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::run_budget::LeaseUnit;
use crate::task_verb::TaskTerminalDisposition;
use crate::workspace_roster::RoomClaimOutcome;
use crate::workspace_roster::project::{GoalAxis, GoalExplorationBudget, GoalPreference};

const HUMAN: EdgeActorClass = EdgeActorClass::Human;
const AGENT: EdgeActorClass = EdgeActorClass::Agent;

/// Witnesses one turn of `actor` in `room` with `metadata`, through the
/// room's speech door.
fn say(
    vault: &Vault,
    room: EntityId,
    actor: EntityId,
    class: EdgeActorClass,
    text: &str,
    metadata: Option<serde_json::Value>,
    at: u64,
) -> EntityId {
    let id = EntityId::now();
    vault
        .memory(actor, class)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(id.to_hex()),
            thread_audience: None,
            occurred_at: at,
            assertions: Default::default(),
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: if class == HUMAN {
                    WitnessAuthor::User
                } else {
                    WitnessAuthor::Companion
                },
                message_type: "text".into(),
                content: text.into(),
                parts: None,
                metadata,
                is_visible: true,
                order: 0,
                quote: None,
            }],
        })
        .unwrap();
    id
}

/// Witnesses `actor`'s reply to `parent` in `room`.
fn reply(
    vault: &Vault,
    room: EntityId,
    actor: EntityId,
    class: EdgeActorClass,
    text: &str,
    parent: EntityId,
    at: u64,
) -> EntityId {
    let metadata = serde_json::json!({ "room_reply_to": parent.to_hex() });
    say(vault, room, actor, class, text, Some(metadata), at)
}

/// The goal record a full interview answer carries.
fn transcript_record() -> GoalRecord {
    let axis = |name: &str, measure: &str, bound: &str| GoalAxis {
        name: name.into(),
        measure: measure.into(),
        bound: bound.into(),
    };
    GoalRecord {
        goal: "Answer customer requests correctly".into(),
        why: "Reduce repeat support tickets".into(),
        primary_axes: vec![axis(
            "confirmed_answers",
            "resolved requests per week from receipts",
            ">= 90",
        )],
        floor_axes: vec![axis(
            "unsafe_answers",
            "held-out unsafe answer count",
            "= 0",
        )],
        cost_axes: vec![
            axis(
                "human_minutes",
                "minutes of review and asks per week",
                "<= 30",
            ),
            axis("tokens", "token spend per week", "<= 10000"),
        ],
        preferences: vec![GoalPreference {
            prefer: "lower cost".into(),
            over: "faster response".into(),
            reason: "The human chose cost on this tradeoff".into(),
        }],
        exploration_budget: GoalExplorationBudget {
            max_spend: 1000,
            exploration_slice: 100,
            unit: LeaseUnit::tokens(),
            human_minutes: 20,
        },
    }
}

fn revised() -> GoalRecord {
    let mut record = transcript_record();
    record.primary_axes[0].bound = ">= 95".into();
    record
}

/// One opened interview on the vault's own project.
struct Interview {
    _dir: tempfile::TempDir,
    vault: Vault,
    project: EntityId,
    room: EntityId,
    agent: EntityId,
    human: EntityId,
    owner: AuthenticatedOwner,
    /// The owner's header the interview thread opens on.
    header: EntityId,
    /// The interview's thread root: the card's turn.
    thread: EntityId,
    /// The leader's interview TASK bound to the thread root.
    task: EntityId,
    /// The first intake run, leased and loaded with the skill.
    attempt: AttemptId,
    /// The SKILL.md that run loaded.
    skill_markdown: String,
}

impl Interview {
    /// The leader's claim of `turn`.
    fn claim(&self, turn: EntityId, at: u64) -> RoomClaimOutcome {
        self.vault
            .memory(self.agent, AGENT)
            .rooms_claim(self.room, turn, at)
            .unwrap()
    }

    fn context(&self) -> Result<ProjectGoalInterviewContextView> {
        let context = self
            .vault
            .project_goal_interview_context(self.project, true)?;
        Ok(ProjectGoalInterviewContextView {
            thread: context.interview_thread,
            attempt: context.attempt_ref,
        })
    }
}

/// The interview fields of the intake context.
#[derive(Debug, PartialEq, Eq)]
struct ProjectGoalInterviewContextView {
    thread: Option<EntityId>,
    attempt: Option<AttemptId>,
}

/// The owner's header, the stored card that minted the vault's project with
/// its leader, and the interview the owner's tap opens on them, its first
/// run leased and loaded.
fn opened_interview() -> Result<Interview> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let project = vault.root_project()?;
    let mut spec = vault.project(project)?.unwrap();
    let agent = EntityId::from_hex(&spec.leader)?;
    let human = vault.ensure_embedded_owner_actor().unwrap();
    spec.roster.push(human.to_hex());
    vault.put_project(project, &spec, 2)?;
    let room = EntityId::from_hex(&spec.home_room)?;
    // Membership reads nothing; the agent reads the room through its grant.
    vault.install_read_permit_for_test(crate::WriteActor::new(agent, AGENT))?;
    let owner = vault.authenticate_owner(
        human,
        &human.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    // The header a tap witnesses at a project's birth.
    let header = say(&vault, room, human, HUMAN, "A goal", None, 3);
    let card = EntityId::now().to_hex();
    vault.put_minted_card_for_test(&card, project, agent, human, (room, EntityId::now()))?;
    let Some(AgentDispatchOutcome::Dispatched(first)) =
        vault.open_project_goal_interview(&owner, &card, project, room, agent, 4)?
    else {
        panic!("the opening dispatches the leader's first intake run");
    };
    let context = vault.project_goal_interview_context(project, true)?;
    let thread = context
        .interview_thread
        .expect("the opening names its thread");
    // No run has loaded the skill yet.
    assert_eq!(context.attempt_ref, None);
    let task = {
        let txn = vault.store.env.read_txn()?;
        let root = turn_in(&vault, &txn, thread)?;
        let [task] = root.task_ids.as_slice() else {
            panic!("the thread root binds the one interview TASK");
        };
        EntityId::from_hex(task)?
    };
    let skill_markdown = load_run(&vault, first.attempt.id)?;
    Ok(Interview {
        _dir: dir,
        vault,
        project,
        room,
        agent,
        human,
        owner,
        header,
        thread,
        task,
        attempt: first.attempt.id,
        skill_markdown,
    })
}

/// A host worker leases the intake run `attempt` and prepares it: the
/// project conversation's load of the goal-intake skill. Returns the
/// SKILL.md it loaded.
fn load_run(vault: &Vault, attempt: AttemptId) -> Result<String> {
    let now = vault.store.clock.now_recorded_at();
    let claimed = vault.with_write_txn(|txn| {
        AttemptQueue::new(vault).claim_id_in_txn(
            txn,
            attempt,
            ClaimAttempt {
                lease_owner: "worker".to_owned(),
                now,
            },
        )
    })?;
    let ClaimOutcome::Claimed(leased) = claimed else {
        panic!("the intake run must lease");
    };
    let loaded = AgentDispatcher::new(vault)
        .prepare_default_project_conversation_run(&leased, "fixture/model@1", now)?
        .expect("an intake run loads the goal-intake skill");
    assert_eq!(loaded.record.skill_id, "goal-intake");
    let markdown = loaded
        .source_files
        .into_iter()
        .flatten()
        .find(|file| file.path == "SKILL.md")
        .expect("the skill has a SKILL.md")
        .content;
    Ok(String::from_utf8(markdown).expect("SKILL.md is UTF-8"))
}

/// The leader's intake runs of `project` the queue holds, oldest first.
fn intake_runs(vault: &Vault, project: EntityId) -> Result<Vec<AttemptId>> {
    let txn = vault.store.env.read_txn()?;
    let run_id = format!("project:{}", project.to_hex());
    Ok(AttemptQueue::new(vault)
        .kind_working_rows_in_txn(&txn, DREAMER_RUNNER_ATTEMPT_KIND)?
        .into_iter()
        .filter(|row| row.run_id.as_deref() == Some(run_id.as_str()))
        .map(|row| row.id)
        .collect())
}

/// The queued intake run `turn` woke, if any.
fn woken_run(vault: &Vault, project: EntityId, turn: EntityId) -> Result<Option<AttemptId>> {
    let key = format!(
        "{AGENT_DISPATCH_ATTEMPT_TYPE}:project-goal-intake:{}:{}",
        project.to_hex(),
        turn.to_hex()
    );
    Ok(AttemptQueue::new(vault)
        .pending_dedupe(DREAMER_RUNNER_ATTEMPT_KIND, &key)?
        .map(|row| row.id))
}

/// One witnessed round in the interview thread, confirmed but not applied:
/// the leader claims `after` through its TASK and asks, the owner answers,
/// the leader claims the answer and drafts, the owner confirms. The draft is
/// shown against the goal generation read when it is posted.
fn confirmed(
    s: &Interview,
    after: EntityId,
    record: &GoalRecord,
    at: u64,
) -> Result<(GoalInterviewTurns, u64)> {
    let (vault, room) = (&s.vault, s.room);
    assert!(matches!(s.claim(after, at), RoomClaimOutcome::Claimed(_)));
    let question = reply(
        vault,
        room,
        s.agent,
        AGENT,
        "What is the goal?",
        after,
        at + 1,
    );
    let json = serde_json::to_string(record).unwrap();
    let answer = reply(vault, room, s.human, HUMAN, &json, question, at + 2);
    assert!(matches!(
        s.claim(answer, at + 3),
        RoomClaimOutcome::Claimed(_)
    ));
    let generation = vault.project_goal_generation(s.project)?;
    let draft = reply(vault, room, s.agent, AGENT, &json, answer, at + 4);
    let digest = GoalInterviewTurns::confirmation_digest(&json, generation);
    let confirmation = reply(
        vault,
        room,
        s.human,
        HUMAN,
        &format!("confirm {digest}"),
        draft,
        at + 5,
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

#[test]
fn opening_binds_the_leaders_interview_task_to_the_cards_thread() -> Result<()> {
    let s = opened_interview()?;
    let txn = s.vault.store.env.read_txn()?;
    let root = turn_in(&s.vault, &txn, s.thread)?;
    // The card's turn is the owner's thread root on the header.
    assert_eq!(root.actor, s.human.to_hex());
    assert_eq!(root.thread_of, Some(s.header.to_hex()));
    assert_eq!(root.reply_to, None);
    assert_eq!(root.room_id, s.room.to_hex());
    // The interview TASK is open and held by the leader.
    assert!(crate::task_verb::thread_task_is_open_in(
        &s.vault, &txn, s.task
    )?);
    assert_eq!(
        crate::task_verb::open_thread_task_holder_in(
            &s.vault,
            &txn,
            s.task,
            crate::gate::TaskHolderFallback::AssigneeOnly,
        )?,
        Some(s.agent)
    );
    drop(txn);
    // The opening dispatched one run, the one that loaded the skill.
    assert_eq!(intake_runs(&s.vault, s.project)?, vec![s.attempt]);
    assert_eq!(
        s.context()?,
        ProjectGoalInterviewContextView {
            thread: Some(s.thread),
            attempt: Some(s.attempt),
        }
    );
    // The held TASK addresses the leader to the card's turn.
    assert!(matches!(s.claim(s.thread, 5), RoomClaimOutcome::Claimed(_)));
    Ok(())
}

#[test]
fn a_leader_without_the_task_or_outside_the_thread_is_not_addressed() -> Result<()> {
    let s = opened_interview()?;
    // A trunk turn names no one and binds no TASK.
    let trunk = say(&s.vault, s.room, s.human, HUMAN, "Unrelated", None, 5);
    assert!(matches!(s.claim(trunk, 6), RoomClaimOutcome::NotAddressed));
    // Another thread on the same header carries no interview TASK.
    let other = say(
        &s.vault,
        s.room,
        s.human,
        HUMAN,
        "Another thread",
        Some(serde_json::json!({ "room_thread_of": s.header.to_hex() })),
        7,
    );
    assert!(matches!(s.claim(other, 8), RoomClaimOutcome::NotAddressed));
    let inside = reply(
        &s.vault,
        s.room,
        s.human,
        HUMAN,
        "Still unrelated",
        other,
        9,
    );
    assert!(matches!(
        s.claim(inside, 10),
        RoomClaimOutcome::NotAddressed
    ));
    // Neither wakes an intake run.
    assert_eq!(intake_runs(&s.vault, s.project)?, vec![s.attempt]);
    // Inside the interview thread the TASK addresses the leader.
    assert!(matches!(
        s.claim(s.thread, 11),
        RoomClaimOutcome::Claimed(_)
    ));
    Ok(())
}

#[test]
fn the_owners_answer_dispatches_the_leaders_draft_run_once() -> Result<()> {
    let s = opened_interview()?;
    assert!(matches!(s.claim(s.thread, 5), RoomClaimOutcome::Claimed(_)));
    let question = reply(
        &s.vault,
        s.room,
        s.agent,
        AGENT,
        "What is the goal?",
        s.thread,
        6,
    );
    // The leader's own turn wakes no one.
    assert_eq!(woken_run(&s.vault, s.project, question)?, None);
    assert_eq!(intake_runs(&s.vault, s.project)?, vec![s.attempt]);
    let json = serde_json::to_string(&transcript_record()).unwrap();
    let answer = reply(&s.vault, s.room, s.human, HUMAN, &json, question, 7);
    let draft_run = woken_run(&s.vault, s.project, answer)?
        .expect("the owner's answer dispatches the leader's next intake run");
    assert_eq!(
        intake_runs(&s.vault, s.project)?,
        vec![s.attempt, draft_run]
    );
    // A turn outside the interview thread dispatches nothing more.
    say(&s.vault, s.room, s.human, HUMAN, "Elsewhere", None, 8);
    assert_eq!(
        intake_runs(&s.vault, s.project)?,
        vec![s.attempt, draft_run]
    );
    // The run is an intake run of the interview: its brief passes the
    // load's checks and it loads the skill.
    let _ = load_run(&s.vault, draft_run)?;
    assert!(matches!(s.claim(answer, 9), RoomClaimOutcome::Claimed(_)));
    Ok(())
}

/// The conversations the house mind's queued project questions ask about,
/// each leased as its worker leases it.
fn project_questions(vault: &Vault) -> Result<Vec<EntityId>> {
    let mut asked = Vec::new();
    while let Some(claimed) = crate::workspace_roster::claim_project_detection(
        vault,
        "worker",
        vault.store.clock.now_recorded_at(),
    )? {
        asked.push(claimed.conversation);
    }
    Ok(asked)
}

#[test]
fn the_owners_words_in_the_interview_ask_no_project_question() -> Result<()> {
    let s = opened_interview()?;
    assert!(matches!(s.claim(s.thread, 5), RoomClaimOutcome::Claimed(_)));
    let question = reply(
        &s.vault,
        s.room,
        s.agent,
        AGENT,
        "What is the goal?",
        s.thread,
        6,
    );
    let json = serde_json::to_string(&transcript_record()).unwrap();
    let _answer = reply(&s.vault, s.room, s.human, HUMAN, &json, question, 7);
    // The interview's thread holds the project's own goal: the owner's
    // answer there is no project of its own to convert.
    assert_eq!(project_questions(&s.vault)?, Vec::<EntityId>::new());
    // Another thread of the home room still asks, toward its conversion.
    let thread_of = serde_json::json!({ "room_thread_of": s.header.to_hex() });
    say(
        &s.vault,
        s.room,
        s.human,
        HUMAN,
        "Plan the launch event",
        Some(thread_of),
        8,
    );
    assert_eq!(project_questions(&s.vault)?, vec![s.room]);
    Ok(())
}

#[test]
fn the_context_names_the_attempt_that_loaded_the_skill() -> Result<()> {
    let s = opened_interview()?;
    assert_eq!(s.context()?.attempt, Some(s.attempt));
    assert!(matches!(s.claim(s.thread, 5), RoomClaimOutcome::Claimed(_)));
    let question = reply(
        &s.vault,
        s.room,
        s.agent,
        AGENT,
        "What is the goal?",
        s.thread,
        6,
    );
    let answer = reply(&s.vault, s.room, s.human, HUMAN, "{}", question, 7);
    let draft_run = woken_run(&s.vault, s.project, answer)?.expect("the answer wakes a run");
    // A dispatched run that has not loaded the skill is not named.
    assert_eq!(s.context()?.attempt, Some(s.attempt));
    let _ = load_run(&s.vault, draft_run)?;
    assert_eq!(
        s.context()?,
        ProjectGoalInterviewContextView {
            thread: Some(s.thread),
            attempt: Some(draft_run),
        }
    );
    Ok(())
}

#[test]
fn complete_ends_the_interview_task() -> Result<()> {
    let s = opened_interview()?;
    let (turns, _) = confirmed(&s, s.thread, &transcript_record(), 10)?;
    let attempt = s.context()?.attempt.expect("a loaded intake run");
    let goal = s
        .vault
        .write_project_goal_from_room_intake(&s.owner, s.project, attempt, turns, 20)?;
    assert!(matches!(
        crate::task_verb::settled_task_result_binding(&s.vault, s.task)?,
        Some((TaskTerminalDisposition::Completed, result)) if result == goal
    ));
    // The interview ended: no open thread, the last run stays named.
    assert_eq!(
        s.context()?,
        ProjectGoalInterviewContextView {
            thread: None,
            attempt: Some(attempt),
        }
    );
    // A later turn of the thread wakes no run and addresses no one.
    let runs = intake_runs(&s.vault, s.project)?;
    let later = reply(
        &s.vault,
        s.room,
        s.human,
        HUMAN,
        "Thanks",
        turns.confirmation,
        21,
    );
    assert_eq!(woken_run(&s.vault, s.project, later)?, None);
    assert_eq!(intake_runs(&s.vault, s.project)?, runs);
    assert!(matches!(s.claim(later, 22), RoomClaimOutcome::NotAddressed));
    Ok(())
}

#[test]
fn loaded_skill_agent_asks_and_witnessed_human_confirmation_commits_goal() -> Result<()> {
    let s = opened_interview()?;
    let (vault, room, project) = (&s.vault, s.room, s.project);
    // Deterministic agent substitute: the question names the fields the
    // skill the first run loaded requires.
    let requested = [
        "goal",
        "why",
        "primary_axes",
        "floor_axes",
        "cost_axes",
        "preferences",
        "exploration_budget",
    ];
    assert!(
        requested
            .iter()
            .all(|field| s.skill_markdown.contains(field))
    );
    assert!(matches!(s.claim(s.thread, 5), RoomClaimOutcome::Claimed(_)));
    let question = reply(
        vault,
        room,
        s.agent,
        AGENT,
        &format!("Please answer: {}", requested.join(", ")),
        s.thread,
        7,
    );
    assert!(vault.project_intake_goal(project)?.is_none());

    // First human answer omits required axes: even a confirmation cannot
    // turn an incomplete witnessed answer into an admitted goal.
    let partial_draft = r#"{"goal":"Answer requests","why":"Reduce repeats"}"#;
    let partial = reply(vault, room, s.human, HUMAN, partial_draft, question, 8);
    assert!(matches!(s.claim(partial, 9), RoomClaimOutcome::Claimed(_)));
    let rejected_draft = reply(vault, room, s.agent, AGENT, partial_draft, partial, 10);
    let rejected_confirm = reply(
        vault,
        room,
        s.human,
        HUMAN,
        &format!(
            "confirm {}",
            GoalInterviewTurns::confirmation_digest(
                partial_draft,
                vault.project_goal_generation(project)?
            )
        ),
        rejected_draft,
        11,
    );
    let first = GoalInterviewTurns {
        question,
        answer: partial,
        draft: rejected_draft,
        confirmation: rejected_confirm,
    };
    assert!(
        vault
            .write_project_goal_from_room_intake(&s.owner, project, s.attempt, first, 12)
            .is_err()
    );
    assert!(vault.project_intake_goal(project)?.is_none());

    let expected = transcript_record();
    let answer_json = serde_json::to_string(&expected).unwrap();
    let answer = reply(vault, room, s.human, HUMAN, &answer_json, question, 13);
    let mismatched = GoalInterviewTurns {
        question,
        answer,
        draft: rejected_draft,
        confirmation: rejected_confirm,
    };
    assert!(
        vault
            .write_project_goal_from_room_intake(&s.owner, project, s.attempt, mismatched, 14)
            .is_err()
    );
    assert!(vault.project_intake_goal(project)?.is_none());
    assert!(matches!(s.claim(answer, 15), RoomClaimOutcome::Claimed(_)));
    let draft = reply(vault, room, s.agent, AGENT, &answer_json, answer, 16);
    assert!(vault.project_intake_goal(project)?.is_none());
    let unconfirmed = GoalInterviewTurns {
        question,
        answer,
        draft,
        confirmation: EntityId::now(),
    };
    assert!(
        vault
            .write_project_goal_from_room_intake(&s.owner, project, s.attempt, unconfirmed, 17)
            .is_err()
    );
    assert!(vault.project_intake_goal(project)?.is_none());
    let confirmation = reply(
        vault,
        room,
        s.human,
        HUMAN,
        &format!(
            "confirm {}",
            GoalInterviewTurns::confirmation_digest(
                &answer_json,
                vault.project_goal_generation(project)?
            )
        ),
        draft,
        17,
    );
    let turns = GoalInterviewTurns {
        question,
        answer,
        draft,
        confirmation,
    };
    // The owner's answer woke an intake run that loaded nothing: it cannot
    // complete the interview.
    let unloaded = woken_run(vault, project, answer)?.expect("the answer wakes a run");
    assert!(
        vault
            .write_project_goal_from_room_intake(&s.owner, project, unloaded, turns, 18)
            .is_err()
    );
    assert!(vault.project_intake_goal(project)?.is_none());
    let attempt = s.context()?.attempt.expect("a loaded intake run");
    assert_eq!(attempt, s.attempt);
    let id = vault.write_project_goal_from_room_intake(&s.owner, project, attempt, turns, 18)?;
    let first_claim_count = vault.count_entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?;
    assert_eq!(
        vault.write_project_goal_from_room_intake(&s.owner, project, attempt, turns, 19)?,
        id
    );
    assert_eq!(
        vault.count_entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?,
        first_claim_count
    );
    assert_eq!(vault.project_intake_goal(project)?, Some(expected.clone()));
    assert_eq!(vault.project(project)?.unwrap().goal, Some(id.to_hex()));
    let Interview {
        _dir: dir, vault, ..
    } = s;
    drop(vault);
    let reopened = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert_eq!(reopened.project_intake_goal(project)?, Some(expected));
    Ok(())
}

#[test]
fn stale_first_confirmation_cannot_replace_a_newer_goal() -> Result<()> {
    let s = opened_interview()?;
    let older = transcript_record();
    let newer = revised();
    let (a, a_generation) = confirmed(&s, s.thread, &older, 10)?;
    // The leader asks again in the same thread, after the first confirmation.
    let (b, b_generation) = confirmed(&s, a.confirmation, &newer, 20)?;
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
    let again = reply(
        &s.vault,
        s.room,
        s.human,
        HUMAN,
        &format!(
            "confirm {}",
            GoalInterviewTurns::confirmation_digest(
                &serde_json::to_string(&newer).unwrap(),
                b_generation
            )
        ),
        b.draft,
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
    let s = opened_interview()?;
    let current = s
        .vault
        .write_project_goal_from_intake(&s.owner, s.project, &revised(), 5)?;
    let (a, _) = confirmed(&s, s.thread, &transcript_record(), 10)?;
    s.vault
        .memory(s.human, HUMAN)
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
    // A refused confirmation leaves the interview open.
    assert_eq!(s.context()?.thread, Some(s.thread));
    Ok(())
}

#[test]
fn unrelated_project_edit_keeps_a_pending_interview_valid() -> Result<()> {
    let s = opened_interview()?;
    let current = s
        .vault
        .write_project_goal_from_intake(&s.owner, s.project, &revised(), 5)?;
    let record = transcript_record();
    let (a, generation) = confirmed(&s, s.thread, &record, 10)?;
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
