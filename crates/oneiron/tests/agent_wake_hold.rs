//! The wake hold of a sleeping resident (AGM-4 = C; agent-mind-design-v1
//! §1.6 #inbox-wake, ARCH-0067 #wake-hold): any message its wake mode allows
//! wakes it after a short hold, a setting of a few seconds, and every
//! message that arrives within the hold joins that one wake. Room turns
//! hold the same way, room by room.
//!
//! Fixture: the vault's owner (`owen`) and a custom agent (`yuki`), bound
//! as a resident with a 3 s hold under `AllAddressed`, on a fake store
//! clock. An inbox message is the identity-stamped surface-event row a
//! routed message leaves, admitted through the test door
//! `resident_wake_hold::admit_inbox_message`; its arrival is the store
//! clock's. A room turn addresses yuki by handle, so the witness stages its
//! room wake. Each test calls the host's inbox pass,
//! `AgentDispatcher::dispatch_resident_inbox`, at chosen instants and counts
//! the wakes on yuki's run.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test agent_wake_hold`.
#![cfg(oneiron_test_support)]

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatcher, ResidentAgentSpec, ResidentGoalRecord,
    ResidentInboxDispatch, ResidentWakeMode,
};
use oneiron::attempt_queue::AttemptQueue;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::ConsultPayloadRef;
use oneiron::test_doors::resident_wake_hold::admit_inbox_message;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_testkit::FakeClock;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The hold every test binds: three seconds.
const HOLD_SECS: u32 = 3;

/// A bound resident and what its tests read.
struct Fixture {
    owen: EntityId,
    yuki: EntityId,
    inbox: EntityId,
}

fn config(clock: &FakeClock) -> VaultConfig {
    let mut config = VaultConfig::default();
    config.store_clock = clock.store_clock();
    config
}

fn owner_proof(vault: &Vault, owner: EntityId) -> TestResult<AuthenticatedOwner> {
    Ok(vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?)
}

/// Declares `agent.resident` normal in the stored default manifest, at its
/// own id (as `room_pins_work_room.rs` does): the shipped manifest names it
/// in no rule, so its binding would pend at the criticality floor.
fn declare_resident_binding_normal(vault: &Vault, proof: &AuthenticatedOwner) -> TestResult {
    use rmpv::Value;

    let id = oneiron_store::policy_record::default_policy_manifest_id()?;
    let body = vault
        .get(&id)?
        .ok_or("the default policy manifest is stored")?;
    let Value::Map(mut fields) = rmpv::decode::read_value(&mut body.as_slice())? else {
        return Err("the default policy manifest is a map".into());
    };
    let Some((_, Value::Array(rules))) = fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("rules"))
    else {
        return Err("the default policy manifest has a rules array".into());
    };
    rules.push(Value::Map(vec![
        (Value::from("prefix"), Value::from("agent.resident")),
        (Value::from("exact"), Value::Boolean(true)),
        (
            Value::from("axes"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
    ]));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(fields))?;
    vault.install_owner_policy_manifest(proof, id, bytes, vault.now_recorded_at())?;
    Ok(())
}

/// One plain text message by the owner at `node` in `conversation`.
fn witness_message(conversation: EntityId, node: EntityId, now: u64) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: conversation.to_hex(),
        turn_ref: None,
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: Some(node.to_hex()),
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: "owen".into(),
            parts: None,
            metadata: None,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: now,
        assertions: Default::default(),
    }
}

/// Binds the agent `yuki` as a resident of `vault` with a hold of
/// [`HOLD_SECS`], waking on every message addressed to it.
fn bind_resident(vault: &Vault) -> TestResult<Fixture> {
    let owen = vault.ensure_embedded_owner_actor()?;
    let proof = owner_proof(vault, owen)?;
    let yuki = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(serde_json::json!({
        "agent_id": "yuki",
        "display_name": "yuki",
        "desc": "yuki",
        "version": "1",
        "ceiling": "auto",
    }))?;
    oneiron::verbs::create_agent_definition_as(
        vault,
        &proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: yuki,
            definition,
        },
    )?;
    let now = vault.now_recorded_at();
    let goal = EntityId::now();
    vault.put_entity(
        &goal,
        ENTITY_TYPE_TURN,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        &[0x80],
    )?;
    let inbox = EntityId::now();
    vault.create_own_app_channel_identity(&inbox, yuki, now)?;
    let home_room = EntityId::now();
    let home_node = EntityId::now();
    vault
        .memory(owen, EdgeActorClass::Human)
        .witness(&witness_message(home_room, home_node, now))?;
    let spec = ResidentAgentSpec {
        agent_def_ref: yuki,
        inbox_identity_ref: inbox,
        home_conversation_ref: home_room,
        home_message_ref: home_node,
        goal: ResidentGoalRecord {
            goal: ConsultPayloadRef::Turn(goal),
            why: ConsultPayloadRef::Turn(goal),
            axes: vec![],
        },
        wake: ResidentWakeMode::AllAddressed,
        wake_hold_secs: HOLD_SECS,
    };
    declare_resident_binding_normal(vault, &proof)?;
    vault
        .bind_resident_agent(&proof, &spec, now)
        .map_err(|error| format!("the owner binds the resident: {error:?}"))?;
    let bound = vault
        .settled_resident_agent(yuki)?
        .ok_or("the binding settles")?;
    assert_eq!(bound.wake_hold_secs, HOLD_SECS, "the hold round-trips");
    Ok(Fixture { owen, yuki, inbox })
}

/// The host's inbox pass for `agent` at `now`.
fn inbox_pass(vault: &Vault, agent: EntityId, now: u64) -> TestResult<ResidentInboxDispatch> {
    Ok(AgentDispatcher::new(vault).dispatch_resident_inbox(agent, 16, now)?)
}

/// Every wake on `agent`'s resident run.
fn wakes(vault: &Vault, agent: EntityId) -> TestResult<usize> {
    Ok(AttemptQueue::new(vault)
        .list_run(&format!("resident:{}", agent.to_hex()))?
        .len())
}

/// The keys the one wake in `pass` carries besides its own dedupe key, and
/// that dedupe key.
fn the_wake(pass: &ResidentInboxDispatch) -> TestResult<(String, Vec<String>)> {
    let [AgentDispatchOutcome::Dispatched(status)] = pass.outcomes.as_slice() else {
        return Err(format!("one wake dispatches, got {:?}", pass.outcomes).into());
    };
    let key = status
        .attempt
        .dedupe_key
        .clone()
        .ok_or("a wake has a dedupe key")?;
    Ok((key, status.input.carried_wake_keys.clone()))
}

/// The wake key of the inbox message `correlation_id` to `fixture`'s
/// resident, as its dispatch names it.
fn message_key(fixture: &Fixture, correlation_id: &str) -> String {
    format!(
        "resident:{}:{}:{}",
        fixture.yuki.to_hex(),
        fixture.inbox.to_hex(),
        blake3::hash(correlation_id.as_bytes()).to_hex()
    )
}

/// AGM-4: five messages that reach a sleeping resident within its hold give
/// one wake, which carries all five. Before the hold ends there is no wake,
/// and the pass names when it falls due.
#[test]
fn five_messages_within_the_hold_give_one_wake() -> TestResult {
    let clock = FakeClock::default();
    let start = clock.now();
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), config(&clock))?;
    let fixture = bind_resident(&vault)?;
    let sent = ["m1", "m2", "m3", "m4", "m5"];
    admit_inbox_message(&vault, fixture.inbox, fixture.yuki, "mina", sent[0])?;
    clock.advance(1);
    admit_inbox_message(&vault, fixture.inbox, fixture.yuki, "mina", sent[1])?;
    admit_inbox_message(&vault, fixture.inbox, fixture.yuki, "ken", sent[2])?;
    clock.advance(1);
    admit_inbox_message(&vault, fixture.inbox, fixture.yuki, "mina", sent[3])?;
    admit_inbox_message(&vault, fixture.inbox, fixture.yuki, "ken", sent[4])?;

    let held = inbox_pass(&vault, fixture.yuki, clock.now())?;
    assert!(held.outcomes.is_empty(), "the hold still runs: {held:?}");
    assert_eq!(held.held_until, Some(start + u64::from(HOLD_SECS)));
    assert_eq!(wakes(&vault, fixture.yuki)?, 0);

    clock.advance(1);
    let pass = inbox_pass(&vault, fixture.yuki, clock.now())?;
    let (key, carried) = the_wake(&pass)?;
    assert_eq!(
        key,
        format!("agent.dispatch:{}", message_key(&fixture, sent[0])),
        "the wake's own key is its first message's"
    );
    let mut expected: Vec<String> = sent[1..]
        .iter()
        .map(|sent| message_key(&fixture, sent))
        .collect();
    let mut carried = carried;
    expected.sort();
    carried.sort();
    assert_eq!(carried, expected, "the wake carries the other four");
    assert_eq!(pass.held_until, None);
    assert_eq!(wakes(&vault, fixture.yuki)?, 1, "five messages, one wake");

    clock.advance(5);
    let again = inbox_pass(&vault, fixture.yuki, clock.now())?;
    assert!(
        again.outcomes.is_empty(),
        "no message wakes twice: {again:?}"
    );
    assert_eq!(again.held_until, None);
    assert_eq!(wakes(&vault, fixture.yuki)?, 1);
    Ok(())
}

/// AGM-4: a message that arrives after a wake took the hold's messages
/// opens a hold of its own, and gives a second wake once it has run.
#[test]
fn a_message_after_the_hold_gives_a_second_wake() -> TestResult {
    let clock = FakeClock::default();
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), config(&clock))?;
    let fixture = bind_resident(&vault)?;
    admit_inbox_message(&vault, fixture.inbox, fixture.yuki, "mina", "first")?;
    clock.advance(u64::from(HOLD_SECS));
    let (_, carried) = the_wake(&inbox_pass(&vault, fixture.yuki, clock.now())?)?;
    assert!(carried.is_empty(), "a lone message carries no other");
    assert_eq!(wakes(&vault, fixture.yuki)?, 1);

    clock.advance(2);
    let later = clock.now();
    admit_inbox_message(&vault, fixture.inbox, fixture.yuki, "mina", "second")?;
    let held = inbox_pass(&vault, fixture.yuki, clock.now())?;
    assert!(held.outcomes.is_empty(), "the second hold runs: {held:?}");
    assert_eq!(held.held_until, Some(later + u64::from(HOLD_SECS)));
    assert_eq!(wakes(&vault, fixture.yuki)?, 1);

    clock.advance(u64::from(HOLD_SECS));
    let (key, carried) = the_wake(&inbox_pass(&vault, fixture.yuki, clock.now())?)?;
    assert_eq!(
        key,
        format!("agent.dispatch:{}", message_key(&fixture, "second"))
    );
    assert!(carried.is_empty());
    assert_eq!(wakes(&vault, fixture.yuki)?, 2, "a second wake");
    Ok(())
}

/// AGM-4: a hold the host was running when it stopped still runs after the
/// vault reopens. The messages are durable rows, so the reopened pass
/// gives the one wake that carries them all.
#[test]
fn the_held_wake_survives_a_restart() -> TestResult {
    let clock = FakeClock::default();
    let start = clock.now();
    let dir = tempfile::tempdir()?;
    let fixture = {
        let vault = Vault::open_owned(dir.path(), config(&clock))?;
        let fixture = bind_resident(&vault)?;
        admit_inbox_message(&vault, fixture.inbox, fixture.yuki, "mina", "r1")?;
        clock.advance(1);
        admit_inbox_message(&vault, fixture.inbox, fixture.yuki, "ken", "r2")?;
        admit_inbox_message(&vault, fixture.inbox, fixture.yuki, "mina", "r3")?;
        let held = inbox_pass(&vault, fixture.yuki, clock.now())?;
        assert!(held.outcomes.is_empty(), "the hold runs: {held:?}");
        assert_eq!(held.held_until, Some(start + u64::from(HOLD_SECS)));
        fixture
    };

    let vault = Vault::open_owned(dir.path(), config(&clock))?;
    assert_eq!(
        wakes(&vault, fixture.yuki)?,
        0,
        "nothing woke before the stop"
    );
    let early = inbox_pass(&vault, fixture.yuki, clock.now())?;
    assert!(early.outcomes.is_empty(), "the reopened hold still runs");
    assert_eq!(early.held_until, Some(start + u64::from(HOLD_SECS)));

    clock.advance(u64::from(HOLD_SECS));
    let pass = inbox_pass(&vault, fixture.yuki, clock.now())?;
    let (key, carried) = the_wake(&pass)?;
    assert_eq!(
        key,
        format!("agent.dispatch:{}", message_key(&fixture, "r1"))
    );
    let mut carried = carried;
    carried.sort();
    let mut expected = vec![message_key(&fixture, "r2"), message_key(&fixture, "r3")];
    expected.sort();
    assert_eq!(carried, expected);
    assert_eq!(
        wakes(&vault, fixture.yuki)?,
        1,
        "one wake after the restart"
    );
    Ok(())
}

/// A project room that seats `owen` and `yuki`, with `@yuki` bound to the
/// agent.
fn room_with_yuki(vault: &Vault, fixture: &Fixture) -> TestResult<EntityId> {
    let root = vault.root_project()?;
    let project_id = EntityId::now();
    let mut project = ProjectRecord::new(project_id, Some(root), root, fixture.owen)?;
    project.roster.push(fixture.yuki.to_hex());
    vault.put_project(project_id, &project, vault.now_recorded_at())?;
    let room = EntityId::from_hex(&project.home_room)?;
    vault.bind_room_handle(room, "@yuki", fixture.yuki)?;
    Ok(room)
}

/// A trunk turn by `owen` in `room` that addresses `@yuki`.
fn address_yuki(vault: &Vault, fixture: &Fixture, room: EntityId) -> TestResult<EntityId> {
    let turn = EntityId::now();
    vault
        .memory(fixture.owen, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "owen".into(),
                parts: None,
                metadata: Some(serde_json::json!({"room_mentions": ["@yuki"]})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;
    Ok(turn)
}

/// AGM-4 for room turns: three turns of one room that address the
/// resident within its hold give one room wake. Its key names the first
/// turn, the room its run works in, and it carries the other two. The
/// turns stay staged until the wake takes them.
#[test]
fn room_turns_within_the_hold_give_one_room_wake() -> TestResult {
    let clock = FakeClock::default();
    let start = clock.now();
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), config(&clock))?;
    let fixture = bind_resident(&vault)?;
    let room = room_with_yuki(&vault, &fixture)?;
    let first = address_yuki(&vault, &fixture, room)?;
    clock.advance(1);
    let second = address_yuki(&vault, &fixture, room)?;
    let third = address_yuki(&vault, &fixture, room)?;
    let staged = |vault: &Vault| -> TestResult<usize> {
        Ok(vault
            .staged_room_wakes()?
            .iter()
            .filter(|staged| staged.wake.agent == fixture.yuki)
            .count())
    };
    assert_eq!(staged(&vault)?, 3, "each addressing turn stages a wake");

    let held = inbox_pass(&vault, fixture.yuki, clock.now())?;
    assert!(held.outcomes.is_empty(), "the room's hold runs: {held:?}");
    assert_eq!(held.held_until, Some(start + u64::from(HOLD_SECS)));
    assert_eq!(staged(&vault)?, 3, "held turns stay staged");

    clock.advance(u64::from(HOLD_SECS));
    let pass = inbox_pass(&vault, fixture.yuki, clock.now())?;
    let (key, carried) = the_wake(&pass)?;
    let room_key =
        |turn: EntityId| format!("resident:{}:room:{}", fixture.yuki.to_hex(), turn.to_hex());
    assert_eq!(key, format!("agent.dispatch:{}", room_key(first)));
    let mut carried = carried;
    carried.sort();
    let mut expected = vec![room_key(second), room_key(third)];
    expected.sort();
    assert_eq!(carried, expected, "the room wake carries the other turns");
    assert_eq!(staged(&vault)?, 0, "the wake settles every turn it took");
    assert_eq!(wakes(&vault, fixture.yuki)?, 1, "three turns, one wake");
    Ok(())
}
