//! OPUS-GATECENSUS row 2 (Engine ruling 12 Nov 16:2x): green pins for three
//! write gates added or tightened since 1 Oct that no counted test drove with
//! the inputs their production callers pass (census/GATE-CENSUS.md, class
//! GAP-PASSES). Each test drives the public door a real caller uses, with
//! that caller's input, through the gate, and asserts the write lands. A pin
//! that goes red is a live refusal of a real caller (GAP-BROKEN).
//!
//! - G31 `workspace_roster::thread_binding` (rooms/audience.rs): a thread
//!   reply reads its root's binding, which refuses an empty or malformed
//!   audience. Its one producer is the thread door's root stamp.
//! - G286 `federation::record_scope::stamp_task_birth`: the task door stamps
//!   the TASK it just put, refusing any other prior scope.
//! - G309 `batch::lexical_query_hints::validate_public_raw_put`: a host's raw
//!   put refuses a source-audience key, a source-bearing claim, an expression
//!   preference and a NOTE; the rows hosts put raw pass, and the expression
//!   preference family lands through its typed door.
//!
//! `cargo test --locked -p oneiron --all-features --test gate_census_pins`.

use std::collections::BTreeSet;

use oneiron::claim::{ExpressionPreferenceOrigin, ExpressionPreferenceValue};
use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::core_write::{ConversationCreateInput, DagRecordAppendInput};
use oneiron::memory::ExpressionPreferenceInput;
use oneiron::registry::{
    ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, ENTITY_TYPE_TASK, ENTITY_TYPE_TURN,
};
use oneiron::task_verb::TaskCreateSpec;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A default vault this process owns and its embedded owner. The vault
/// closes before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok(Fixture {
        vault,
        owner,
        _dir: dir,
    })
}

/// The owner's thread reply under `trunk`, opening a private thread when
/// `audience` is given.
fn thread_reply(
    fixture: &Fixture,
    conversation: EntityId,
    trunk: EntityId,
    text: &str,
    audience: Option<BTreeSet<EntityId>>,
) -> TestResult<EntityId> {
    let host = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let now = fixture.vault.now_recorded_at();
    let reply = fixture.vault.reply_in_thread(
        &host,
        trunk,
        &AppendRecord {
            conversation,
            parent: None,
            reply_to: None,
            quote: None,
            address: AddressMode::Broadcast,
            recipients: Vec::new(),
            advance: false,
            kind: ENTITY_TYPE_TURN,
            containing_turn: None,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            body: rmp_serde::to_vec_named(&json!({"txt": text, "speaker": "user"}))?,
            text: Vec::new(),
            session: None,
            actor: WriteActor::new(fixture.owner, EdgeActorClass::Human),
            thread_audience: audience,
        },
    )?;
    Ok(reply.id)
}

/// G31: the owner opens a private thread naming its audience, then replies
/// again. The second reply continues that thread, so the thread door read the
/// root's stamped binding through `thread_binding` and admitted it.
#[test]
fn a_private_thread_root_binding_admits_the_next_reply() -> TestResult {
    let fixture = open()?;
    let host = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let conversation = EntityId::from_hex(
        &host
            .conversations_create(&ConversationCreateInput {
                id: None,
                occurred_start: None,
                occurred_end: None,
                learned_at: None,
                body: json!({}),
                text: None,
            })?
            .id,
    )?;
    let first = host.conversations_records_append(&DagRecordAppendInput {
        conversation: conversation.to_hex(),
        parent: None,
        reply_to: None,
        containing_turn: None,
        addr: None,
        to: None,
        advance: true,
        body: json!({"txt": "the plan", "speaker": "user"}),
        text: None,
        occurred_start: None,
        occurred_end: None,
        learned_at: None,
        session: None,
        quote: None,
        thread_audience: None,
    })?;
    let trunk = EntityId::from_hex(&first.id)?;
    let root = thread_reply(
        &fixture,
        conversation,
        trunk,
        "a private side question",
        Some(BTreeSet::from([fixture.owner])),
    )
    .map_err(|error| format!("the private thread's root: {error}"))?;
    let next = thread_reply(&fixture, conversation, trunk, "a follow-up", None)
        .map_err(|error| format!("the private thread's next reply: {error}"))?;
    assert_ne!(next, root);
    assert_eq!(
        fixture.vault.thread_roots(trunk)?,
        vec![root],
        "the follow-up continues the private thread instead of opening another"
    );
    Ok(())
}

/// G286: the owner creates a TASK through the task door, which stamps the
/// TASK's birth scope in the same write.
#[test]
fn the_task_door_stamps_the_birth_of_the_task_it_creates() -> TestResult {
    let fixture = open()?;
    let created = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::Nil,
            Some("gate census pin".into()),
            Some(fixture.owner),
            Some(fixture.vault.now_recorded_at()),
        ))
        .map_err(|error| format!("the task door: {error:?}"))?;
    let task = created.task_ref.ok_or("the TASK creation took effect")?;
    assert!(
        fixture
            .vault
            .entities_by_type(ENTITY_TYPE_TASK)?
            .contains(&task),
        "the created TASK is stored"
    );
    Ok(())
}

/// G309: the rows a host puts raw (a SESSION, a TURN, a PERSON) pass the raw
/// put's refusals, and an expression preference, which the raw put refuses,
/// lands through its typed Memory door.
#[test]
fn raw_puts_hosts_make_and_the_typed_preference_door_pass() -> TestResult {
    let fixture = open()?;
    let at = fixture.vault.now_recorded_at();
    let put = |entity_type, body: Vec<u8>| -> TestResult<EntityId> {
        let id = EntityId::now();
        fixture
            .vault
            .put_entity(
                &id,
                entity_type,
                TimeRange { start: at, end: at },
                at,
                &body,
            )
            .map_err(|error| format!("a host's raw put of type {entity_type}: {error}"))?;
        Ok(id)
    };
    put(
        ENTITY_TYPE_SESSION,
        rmp_serde::to_vec_named(&json!({"title": "gate census pin"}))?,
    )?;
    put(
        ENTITY_TYPE_TURN,
        rmp_serde::to_vec_named(&json!({"text": "alpha beta"}))?,
    )?;
    let person = put(ENTITY_TYPE_PERSON, b"someone".to_vec())?;
    let receipt = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .set_expression_preference(
            &ExpressionPreferenceInput {
                subject_ref: person.to_hex(),
                value: ExpressionPreferenceValue::Language("en-US".to_owned()),
                origin: ExpressionPreferenceOrigin::ExplicitUser,
                valid_from: at,
            },
            at,
        )
        .map_err(|error| format!("the typed expression-preference door: {error:?}"))?;
    assert!(!receipt.claim_short_id.is_empty());
    Ok(())
}
