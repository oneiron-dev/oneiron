//! Census L2-30, row UNBUILT-04 (ROLES-EVERYWHERE = A, 2026-10-16): a
//! context-board ask goes to the next authorised role, ending at the vault
//! owner role. ARCH-0067 #tasks: "An ask is a TASK that waits for its
//! authorised role, agent or person."
//!
//! A `TaskAskTarget::Role` ask resolves through the decision ladders' own
//! role chain (`Vault::next_ask_role_in_txn`): a responsible actor, then the
//! boards of its project and their parents, then the owners. A role with no
//! live holder is climbed past; past the ask's ceiling it never goes. The
//! group keeps the role it reached (Engine RULING UNBUILT-04-CLIMB = A), and
//! it stands while that role keeps the live holders it was put to, as an
//! authority ask does. A task ask by role carries a judgment: a person-only
//! act (an e-signature, a payment) is refused.
//!
//! On main the target has no role variant, so this file does not compile
//! there.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test task_ask_role_routing`.
#![cfg(oneiron_test_support)]

use oneiron::llm::decision::{AnswerActor, AskAct, AskRole, AskTo, RoleRank};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskHandle, TaskAskQuestion, TaskAskSettlementReason,
    TaskAskSpec, TaskAskStatus, TaskAskTarget,
};
use oneiron::test_doors::task_ask_role_routing::ask_group_route;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    question: ConsultPayloadRef,
    _dir: tempfile::TempDir,
}

fn open_fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let turn = EntityId::from_bytes([0x5a; 16])?;
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("role"),
            rmpv::Value::from("question"),
        )]),
    )?;
    vault.put_entity(
        &turn,
        ENTITY_TYPE_TURN,
        TimeRange { start: 2, end: 2 },
        2,
        &body,
    )?;
    let question = ConsultPayloadRef::parse(&vault, &format!("tn_{}", turn.to_hex()))?;
    Ok(Fixture {
        vault,
        owner,
        question,
        _dir: dir,
    })
}

/// A live PERSON.
fn person(fixture: &Fixture) -> TestResult<EntityId> {
    let id = EntityId::now();
    fixture.vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    Ok(id)
}

/// A project under the root, led by `leader` and boarded by `board`. An
/// unsigned owner-door row serves its stored leader and board as its
/// effective authority at once.
fn project(
    fixture: &Fixture,
    leader: EntityId,
    board: &[EntityId],
) -> TestResult<(EntityId, ProjectRecord)> {
    let root = fixture.vault.root_project()?;
    let id = EntityId::now();
    let mut record = ProjectRecord::new(id, Some(root), root, leader)?;
    record.board = board.iter().map(EntityId::to_hex).collect();
    fixture.vault.put_project(id, &record, 10)?;
    Ok((id, record))
}

/// The owner's ask of `intent` to `to`.
fn ask(fixture: &Fixture, intent: &str, to: AskTo) -> TestResult<TaskAskHandle> {
    let spec = TaskAskSpec {
        intent_key: intent.into(),
        ..TaskAskSpec::shorthand(
            Some(TaskAskTarget::Role(to)),
            TaskAskQuestion::new(fixture.question),
            Some(u64::MAX),
            TaskAskDefault::AskMe,
        )
    };
    Ok(fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .tasks_ask(&spec)?
        .handle)
}

/// Who `handle`'s members were put to, and the role its group reached.
fn route(fixture: &Fixture, handle: TaskAskHandle) -> TestResult<(Vec<EntityId>, AskRole)> {
    let (actors, reached) =
        ask_group_route(&fixture.vault, handle)?.ok_or("the ask lands a group")?;
    Ok((
        actors,
        reached.ok_or("a role ask keeps the role it reached")?,
    ))
}

fn judgment(role: AskRole, ceiling: RoleRank) -> AskTo {
    AskTo {
        role,
        ceiling,
        act: AskAct::Judgment,
    }
}

#[test]
fn board_ask_goes_to_next_authorised_role_ending_at_owner() -> TestResult {
    let fixture = open_fixture()?;
    let leader = person(&fixture)?;
    let member = person(&fixture)?;
    let (project, _) = project(&fixture, leader, &[member])?;

    // A board ask goes to the board's live holders, and only to them.
    let board = ask(
        &fixture,
        "role-ask-board",
        judgment(AskRole::Board { project }, RoleRank::Owner),
    )?;
    let (actors, reached) = route(&fixture, board)?;
    assert_eq!(actors, vec![member], "the board member is asked");
    assert_eq!(reached, AskRole::Board { project });

    // A responsible actor who holds nothing now, with no project above it:
    // the chain ends at the vault owner role.
    let gone = EntityId::from_bytes([0x6b; 16])?;
    let ended = ask(
        &fixture,
        "role-ask-owner",
        judgment(
            AskRole::Responsible {
                actor: AnswerActor::Actor(gone),
                project: None,
            },
            RoleRank::Owner,
        ),
    )?;
    let (actors, reached) = route(&fixture, ended)?;
    assert_eq!(actors, vec![fixture.owner], "the vault owner is asked");
    assert_eq!(reached, AskRole::Owner);
    Ok(())
}

#[test]
fn board_ask_climbs_past_a_role_with_no_live_holder() -> TestResult {
    let fixture = open_fixture()?;
    let leader = person(&fixture)?;
    let member = person(&fixture)?;
    let (project, _) = project(&fixture, leader, &[member])?;

    // The responsible actor is no live holder: the ask climbs to the board
    // of its project, not past it.
    let gone = EntityId::from_bytes([0x7c; 16])?;
    let handle = ask(
        &fixture,
        "role-ask-climb",
        judgment(
            AskRole::Responsible {
                actor: AnswerActor::Actor(gone),
                project: Some(project),
            },
            RoleRank::Owner,
        ),
    )?;
    let (actors, reached) = route(&fixture, handle)?;
    assert_eq!(actors, vec![member]);
    assert_eq!(reached, AskRole::Board { project });

    // A live responsible actor is asked first, and alone.
    let handle = ask(
        &fixture,
        "role-ask-responsible",
        judgment(
            AskRole::Responsible {
                actor: AnswerActor::Actor(leader),
                project: Some(project),
            },
            RoleRank::Owner,
        ),
    )?;
    let (actors, reached) = route(&fixture, handle)?;
    assert_eq!(actors, vec![leader]);
    assert_eq!(
        reached,
        AskRole::Responsible {
            actor: AnswerActor::Actor(leader),
            project: Some(project),
        }
    );
    Ok(())
}

#[test]
fn board_ask_with_no_live_holder_up_to_its_ceiling_is_refused() -> TestResult {
    let fixture = open_fixture()?;
    let leader = person(&fixture)?;
    let (project, _) = project(&fixture, leader, &[])?;
    let gone = EntityId::from_bytes([0x8d; 16])?;
    let refused = ask(
        &fixture,
        "role-ask-ceiling",
        judgment(
            AskRole::Responsible {
                actor: AnswerActor::Actor(gone),
                project: Some(project),
            },
            RoleRank::Responsible,
        ),
    );
    assert!(
        refused.is_err(),
        "no role up to the ceiling has a live holder: the ask never goes wider"
    );
    Ok(())
}

#[test]
fn board_ask_for_a_person_only_act_is_refused() -> TestResult {
    let fixture = open_fixture()?;
    let refused = ask(
        &fixture,
        "role-ask-esign",
        AskTo {
            role: AskRole::Owner,
            ceiling: RoleRank::Owner,
            act: AskAct::ESignature,
        },
    );
    assert!(
        refused.is_err(),
        "an e-signature asks through its own door, never a task ask's word"
    );
    Ok(())
}

#[test]
fn board_ask_settles_stale_when_its_board_member_is_gone() -> TestResult {
    let fixture = open_fixture()?;
    let leader = person(&fixture)?;
    let member = person(&fixture)?;
    let (project, _) = project(&fixture, leader, &[member])?;
    let handle = ask(
        &fixture,
        "role-ask-stale",
        judgment(AskRole::Board { project }, RoleRank::Owner),
    )?;
    let memory = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    assert!(
        matches!(
            memory.tasks_ask_status(handle)?,
            TaskAskStatus::Pending { .. }
        ),
        "the ask waits on its board"
    );

    // The board's only member is gone: the electorate the ask was put to no
    // longer holds the role.
    assert!(
        fixture.vault.delete_entity(&member)?,
        "the member is deleted"
    );
    match memory.tasks_ask_status(handle)? {
        TaskAskStatus::Settled(result) => {
            assert_eq!(result.settlement.reason, TaskAskSettlementReason::Stale);
        }
        other => {
            return Err(format!("a gone board member settles the ask stale, got {other:?}").into());
        }
    }
    Ok(())
}
