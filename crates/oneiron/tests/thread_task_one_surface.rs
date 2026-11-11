//! A plain thread reply in a project room lands on the same surface as a
//! witness turn (THREAD-TASK-ONE-SURFACE): it keeps a room row, wakes the
//! holder of the thread's bound TASK in its own write, and never answers an
//! ask or steers a run.
//!
//! Fixture: a project whose roster seats owen, the vault's owner, and two
//! agents, A and B, each holding a grant over the room's messages; a private
//! thread rooted on a witness turn whose audience is owen and A; two open
//! TASKs owen owns and binds to that thread, one assigned to A and one to B.
//! owen replies through `Vault::reply_in_thread`, the REST thread reply's
//! door. owen is the owner because a PERSON with no contact clearance reads
//! only public rows, and a room's TURNs and MESSAGEs are born Sensitive.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test thread_task_one_surface`.

use std::collections::BTreeSet;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, EnqueueAttempt, EnqueueOutcome,
};
use oneiron::conversation_dag::{AddressMode, AppendRecord, QuoteSpan, ReplyStripsRequest};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use oneiron::run_tree::RunTreeAdapter;
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskOption, TaskAskOptionId, TaskAskQuestion,
    TaskAskSource, TaskAskSpec, TaskAskStatus, TaskAskTarget, TaskAskWait, TaskAskWord,
    TaskAssignee, TaskCreateSpec,
};
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

/// The label, attempt kind, run id and wait step this file's rows carry.
const FIXTURE_PATH: &str = "crates/oneiron/tests/thread_task_one_surface.rs";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    vault: Vault,
    owen: EntityId,
    agent_a: EntityId,
    agent_b: EntityId,
    room: EntityId,
    /// The private thread's root, a witness turn.
    thread: EntityId,
    /// The root's MESSAGE.
    root_message: EntityId,
    /// The open TASK assigned to A, bound to the thread.
    task: EntityId,
    _directory: tempfile::TempDir,
}

/// owen's witness turn `turn` in `room`, one MESSAGE: a trunk turn, or with
/// `anchor` the root of a thread on it, private to `audience` when named.
/// Returns the MESSAGE id.
fn speak_turn(
    vault: &Vault,
    owen: EntityId,
    room: EntityId,
    turn: EntityId,
    anchor: Option<EntityId>,
    audience: Option<BTreeSet<EntityId>>,
) -> TestResult<EntityId> {
    let metadata = match anchor {
        Some(anchor) => serde_json::json!({"room_thread_of": anchor.to_hex()}),
        None => serde_json::json!({}),
    };
    let message = EntityId::now();
    vault
        .memory(owen, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: audience,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "owen".into(),
                parts: None,
                metadata: Some(metadata),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;
    Ok(message)
}

/// An open TASK owen owns, assigned to `agent`, bound to `thread`.
fn bind_task(
    vault: &Vault,
    owen: EntityId,
    room: EntityId,
    thread: EntityId,
    agent: EntityId,
    label: &str,
) -> TestResult<EntityId> {
    let created = vault.memory(owen, EdgeActorClass::Human).tasks_create(
        &TaskCreateSpec::new(
            rmpv::Value::Nil,
            Some(label.into()),
            Some(owen),
            Some(vault.now_recorded_at()),
        )
        .with_assignee(TaskAssignee::AgentDef {
            agent_def_ref: agent,
        }),
    )?;
    let task = created
        .task_ref
        .ok_or("TASK creation did not take effect")?;
    vault.bind_room_thread_task(owen, room, thread, task)?;
    Ok(task)
}

fn open_fixture() -> TestResult<Fixture> {
    let directory = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    let owen = owner;
    let agent_a = EntityId::now();
    let agent_b = EntityId::now();
    for (agent, name) in [(agent_a, "yuki"), (agent_b, "yuki-two")] {
        let definition: AgentDefinitionSpec = serde_json::from_value(serde_json::json!({
            "agent_id": name,
            "display_name": name,
            "desc": name,
            "version": "1",
            "ceiling": "auto",
        }))?;
        oneiron::verbs::create_agent_definition_as(
            &vault,
            &proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: agent,
                definition,
            },
        )?;
    }
    // A asks under its own Auto ceiling; owen, A and B read the vault's
    // records. The shipped rows stay.
    let view =
        policy_manifests_as_owner(&vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    manifest.actor_ceilings.push(ActorCeiling {
        actor_class: "agent".into(),
        actor_ref: Some(agent_a.to_hex()),
        ceiling: PolicyCeiling::Auto,
    });
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    for actor in [owen, agent_a, agent_b] {
        rows.push(PolicyScopedGrantRow {
            // Bare census keys carry no actor class.
            actor_class: None,
            actor_ref: Some(actor.to_hex()),
            effector: "core:read".into(),
            scope: Scope::top(),
            selectors: None,
            budget: None,
            receipt_required: false,
        });
    }
    manifest.scoped_grants = Some(rows);
    put_policy_manifest_as_owner(
        &vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )?;
    let root_project = vault.root_project()?;
    let project_id = EntityId::now();
    let mut project = ProjectRecord::new(project_id, Some(root_project), root_project, owen)?;
    project.roster.extend([agent_a.to_hex(), agent_b.to_hex()]);
    vault.put_project(project_id, &project, vault.now_recorded_at())?;
    let room = EntityId::from_hex(&project.home_room)?;
    // A room read admits a row only when every reader of its audience may:
    // A and B each read the room's MESSAGEs under a grant.
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    for principal in [agent_a, agent_b] {
        vault.create_access_grant(
            &EntityId::now(),
            &AccessGrant {
                authority_scope: authority_scope.clone(),
                principal_ref: principal,
                scope: AccessGrantScope::ConversationMessages {
                    conversation_ref: room,
                },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
                revoked_at: None,
                expires_at: None,
                companion_bounds: None,
            },
        )?;
    }
    let anchor = EntityId::now();
    speak_turn(&vault, owen, room, anchor, None, None)?;
    let thread = EntityId::now();
    let root_message = speak_turn(
        &vault,
        owen,
        room,
        thread,
        Some(anchor),
        Some(BTreeSet::from([owen, agent_a])),
    )?;
    let task = bind_task(&vault, owen, room, thread, agent_a, "thread task for yuki")?;
    // B holds a TASK of the thread too, but is off its private audience.
    bind_task(
        &vault,
        owen,
        room,
        thread,
        agent_b,
        "thread task for yuki-two",
    )?;
    // owen reads the thread's root row and its MESSAGE before any reply, so
    // a reader that cannot see the thread never passes for a missing row.
    let rows = vault
        .memory(owen, EdgeActorClass::Human)
        .rooms_messages(room)?;
    if !rows.iter().any(|row| {
        row.turn_id == thread.to_hex() && row.message_ids.contains(&root_message.to_hex())
    }) {
        return Err("fixture: owen reads no room row for the thread's root".into());
    }
    Ok(Fixture {
        vault,
        owen,
        agent_a,
        agent_b,
        room,
        thread,
        root_message,
        task,
        _directory: directory,
    })
}

/// owen's plain reply in the thread, through the REST thread reply's door;
/// with `quote`, it quotes that span. Returns the reply TURN.
fn plain_reply(fixture: &Fixture, quote: Option<QuoteSpan>) -> TestResult<EntityId> {
    let now = fixture.vault.now_recorded_at();
    let input = AppendRecord {
        conversation: fixture.room,
        parent: None,
        reply_to: None,
        quote,
        address: AddressMode::Broadcast,
        recipients: vec![],
        advance: false,
        kind: ENTITY_TYPE_TURN,
        containing_turn: None,
        occurred: TimeRange {
            start: now,
            end: now,
        },
        learned_at: now,
        body: rmp_serde::to_vec_named(&serde_json::json!({"txt": "owen"}))?,
        text: vec![],
        session: None,
        actor: WriteActor::new(fixture.owen, EdgeActorClass::Human),
        thread_audience: None,
    };
    let writer = fixture.vault.memory(fixture.owen, EdgeActorClass::Human);
    Ok(fixture
        .vault
        .reply_in_thread(&writer, fixture.thread, &input)?
        .id)
}

#[test]
fn plain_thread_reply_wakes_only_the_bound_task_assignee() -> TestResult {
    let fixture = open_fixture()?;
    let reply = plain_reply(&fixture, None)?;
    let agents: Vec<_> = fixture
        .vault
        .staged_room_wakes()?
        .into_iter()
        .filter(|entry| entry.wake.turn == reply)
        .map(|entry| entry.wake.agent)
        .collect();
    // A holds the thread's TASK and is in its audience: one wake. owen spoke
    // it, and B holds a TASK but is off the audience: none.
    assert_eq!(agents, vec![fixture.agent_a]);
    assert!(!agents.contains(&fixture.owen));
    assert!(!agents.contains(&fixture.agent_b));
    Ok(())
}

#[test]
fn plain_thread_reply_message_joins_its_room_row() -> TestResult {
    let fixture = open_fixture()?;
    let reply = plain_reply(&fixture, None)?;
    let now = fixture.vault.now_recorded_at();
    let message = fixture.vault.append_dag_record(
        &fixture.vault.memory(fixture.owen, EdgeActorClass::Human),
        &AppendRecord {
            conversation: fixture.room,
            parent: None,
            reply_to: None,
            quote: None,
            address: AddressMode::Broadcast,
            recipients: vec![],
            advance: false,
            kind: ENTITY_TYPE_MESSAGE,
            containing_turn: Some(reply),
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            body: rmp_serde::to_vec_named(&serde_json::json!({
                "author": "user",
                "type": "text",
                "content": "owen",
                "is_visible": true,
                "order": 0,
            }))?,
            text: vec![],
            session: None,
            actor: WriteActor::new(fixture.owen, EdgeActorClass::Human),
            thread_audience: None,
        },
    )?;
    let rows = fixture
        .vault
        .memory(fixture.owen, EdgeActorClass::Human)
        .rooms_messages(fixture.room)?;
    let row = rows
        .iter()
        .find(|row| row.turn_id == reply.to_hex())
        .ok_or("the plain reply keeps no room row")?;
    assert_eq!(row.reply_to, Some(fixture.thread.to_hex()));
    assert_eq!(row.message_ids, vec![message.id.to_hex()]);
    // The MESSAGE wakes no one again.
    let wakes = fixture
        .vault
        .staged_room_wakes()?
        .into_iter()
        .filter(|entry| entry.wake.turn == reply)
        .count();
    assert_eq!(wakes, 1);
    Ok(())
}

#[test]
fn plain_quoted_reply_keeps_its_quote_strip() -> TestResult {
    let fixture = open_fixture()?;
    let reply = plain_reply(
        &fixture,
        Some(QuoteSpan {
            message: fixture.root_message,
            start: 0,
            end: 4,
        }),
    )?;
    // The reply keeps a room row with no MESSAGE and so no row quote: the
    // strip below comes from the reply TURN itself.
    let rows = fixture
        .vault
        .memory(fixture.owen, EdgeActorClass::Human)
        .rooms_messages(fixture.room)?;
    let row = rows
        .iter()
        .find(|row| row.turn_id == reply.to_hex())
        .ok_or("the quoted plain reply keeps no room row")?;
    assert!(row.message_ids.is_empty());
    assert!(row.quotes.is_empty());
    let page = fixture
        .vault
        .memory(fixture.owen, EdgeActorClass::Human)
        .rooms_reply_strips(&ReplyStripsRequest {
            room_ref: fixture.room.to_hex(),
            thread_ref: fixture.thread.to_hex(),
            after: None,
            limit: None,
        })?;
    let strips: Vec<_> = page
        .groups
        .iter()
        .filter(|group| group.message_ref == fixture.root_message.to_hex())
        .flat_map(|group| &group.strips)
        .filter(|strip| strip.reply_turn == reply.to_hex())
        .collect();
    // The reply's TURN cites its quote; no MESSAGE does.
    assert_eq!(strips.len(), 1);
    assert_eq!(strips[0].reply_message, None);
    Ok(())
}

#[test]
fn explicit_human_answer_retains_plain_reply_provenance() -> TestResult {
    let fixture = open_fixture()?;
    let agent = fixture.vault.memory(fixture.agent_a, EdgeActorClass::Agent);
    let mut question = TaskAskQuestion::new(ConsultPayloadRef::Turn(fixture.thread));
    let option = TaskAskOptionId::new("owen")?;
    question
        .options
        .insert(option.clone(), TaskAskOption::new("owen"));
    let spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::People(BTreeSet::from([fixture.owen]))),
        question,
        None,
        TaskAskDefault::AskMe,
    );
    let handle = agent.tasks_ask(&spec)?.handle;
    assert!(matches!(
        agent.tasks_ask_status(handle)?,
        TaskAskStatus::Pending { .. }
    ));
    assert!(matches!(
        agent.tasks_wait(handle, None)?,
        TaskAskWait::Park(_)
    ));
    assert!(matches!(
        agent.tasks_wait(handle, Some(FIXTURE_PATH))?,
        TaskAskWait::Pending { .. },
    ));
    // A plain reply answers no ask.
    let reply = plain_reply(&fixture, None)?;
    assert!(matches!(
        agent.tasks_ask_status(handle)?,
        TaskAskStatus::Pending { .. }
    ));
    assert!(agent.tasks_ask_evidence(handle)?.is_empty());
    // owen's explicit answer settles it, citing the reply TURN.
    let mut word = TaskAskWord::new(reply);
    word.option = Some(option);
    word.provenance_refs = BTreeSet::from([ConsultPayloadRef::Turn(reply)]);
    let answer = fixture
        .vault
        .memory(fixture.owen, EdgeActorClass::Human)
        .tasks_answer(&handle, &word)?;
    assert_eq!(answer.actor_ref, fixture.owen);
    assert!(matches!(
        agent.tasks_ask_status(handle)?,
        TaskAskStatus::Settled(_)
    ));
    assert!(matches!(
        agent.tasks_wait(handle, Some(FIXTURE_PATH))?,
        TaskAskWait::Ready(_),
    ));
    let evidence = agent.tasks_ask_evidence(handle)?;
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].answer.actor_ref, fixture.owen);
    assert_eq!(evidence[0].source, TaskAskSource::Human);
    assert_eq!(evidence[0].word.provenance_refs, word.provenance_refs);
    Ok(())
}

#[test]
fn plain_thread_reply_leaves_live_branch_signals_unchanged() -> TestResult {
    let fixture = open_fixture()?;
    let queue = AttemptQueue::new(&fixture.vault);
    let now = fixture.vault.now_recorded_at();
    let branch = match queue.enqueue_with_task_ref(
        EnqueueAttempt {
            kind: FIXTURE_PATH.into(),
            payload: vec![],
            dedupe_key: None,
            run_id: Some(FIXTURE_PATH.into()),
            now,
        },
        Some(fixture.task.to_hex()),
    )? {
        EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record) => record.id,
        _ => return Err("unexpected enqueue outcome".into()),
    };
    match queue.claim_kind(
        FIXTURE_PATH,
        ClaimAttempt {
            lease_owner: FIXTURE_PATH.into(),
            now,
        },
    )? {
        ClaimOutcome::Claimed(record) => {
            assert_eq!(record.id, branch);
            assert_eq!(record.task_ref, Some(fixture.task.to_hex()));
            assert_eq!(record.run_id.as_deref(), Some(FIXTURE_PATH));
        }
        _ => return Err("TASK-linked attempt was not claimed".into()),
    }
    let adapter = RunTreeAdapter::new(&fixture.vault);
    let before = adapter.read_branch_signals(branch, FIXTURE_PATH)?;
    assert_eq!(before, Some(vec![]));
    // A plain reply steers no run.
    plain_reply(&fixture, None)?;
    let after = adapter.read_branch_signals(branch, FIXTURE_PATH)?;
    assert_eq!(before, after);
    Ok(())
}
