//! A busy resident gets no second wake (AGM-2 = C; FIX
//! BUSY-RESIDENT-ROOM-AND-DIARY-WAKES; UNBUILT3-38). A resident is busy while
//! a wake of its run is queued or running. A room turn that addresses it
//! lands on the running wake when that wake is a room wake of the turn's
//! room, at its next step boundary, and otherwise waits staged
//! (BUSY-ROOM-TURN-ROUTE = C, Engine 17 Nov 00:11). A pending review of a
//! read of its diary waits in its inbox (BUSY-DIARY-REVIEW-ROUTE = A): a
//! review is no message. Whatever waits wakes the resident once the run has
//! ended, and a turn a wake never applied is not lost.
//!
//! Fixture: the vault's owner (`owen`) and a custom agent (`yuki`), bound as
//! a resident with a 3 s hold under `AllAddressed`, on a fake store clock,
//! as in `agent_message_classes.rs`. Each room is a project home room that
//! seats both, with `@yuki` bound to the agent, as in `agent_wake_hold.rs`;
//! owen addresses yuki there by handle, so the witness stages a room wake.
//! This test's worker leases and completes yuki's wakes. A diary review is
//! filed through the test door `resident_wake_hold::file_diary_review`.
//!
//! Red on main (cc184ff09aea): the inbox pass dispatches a second wake on
//! the busy run for the room turn and for the review.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test resident_busy_wakes`.
#![cfg(oneiron_test_support)]

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchStatus, AgentDispatcher, ResidentAgentSpec,
    ResidentGoalRecord, ResidentInboxDispatch, ResidentWakeMode,
};
use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::run_tree::{RunBranchSignal, RunSignalKind, RunTreeAdapter};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::ConsultPayloadRef;
use oneiron::test_doors::resident_wake_hold::file_diary_review;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{AttemptId, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_testkit::FakeClock;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The hold every test binds: three seconds.
const HOLD_SECS: u32 = 3;

/// This test's worker, which leases yuki's wakes.
const WORKER: &str = "resident-busy-wakes-worker";

/// A bound resident and what its tests read.
struct Fixture {
    owen: EntityId,
    yuki: EntityId,
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
/// own id (as `agent_message_classes.rs` does): the shipped manifest names it
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
        project: None,
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

/// Creates the custom agent `name` as the owner.
fn create_agent(vault: &Vault, proof: &AuthenticatedOwner, name: &str) -> TestResult<EntityId> {
    let agent = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(serde_json::json!({
        "agent_id": name,
        "display_name": name,
        "desc": name,
        "version": "1",
        "ceiling": "auto",
    }))?;
    oneiron::verbs::create_agent_definition_as(
        vault,
        proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition,
        },
    )?;
    Ok(agent)
}

/// Binds the agent `yuki` as a resident of `vault` with a hold of
/// [`HOLD_SECS`], waking on every message and room turn addressed to it.
fn bind_resident(vault: &Vault) -> TestResult<Fixture> {
    let owen = vault.ensure_embedded_owner_actor()?;
    let proof = owner_proof(vault, owen)?;
    let yuki = create_agent(vault, &proof, "yuki")?;
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
        digest_delay_secs: oneiron::agent_dispatch::RESIDENT_DIGEST_DELAY_DEFAULT_SECS,
    };
    declare_resident_binding_normal(vault, &proof)?;
    vault
        .bind_resident_agent(&proof, &spec, now)
        .map_err(|error| format!("the owner binds the resident: {error:?}"))?;
    vault
        .settled_resident_agent(yuki)?
        .ok_or("the binding settles")?;
    Ok(Fixture { owen, yuki })
}

/// The host's inbox pass for `agent` at `now`.
fn inbox_pass(vault: &Vault, agent: EntityId, now: u64) -> TestResult<ResidentInboxDispatch> {
    Ok(AgentDispatcher::new(vault).dispatch_resident_inbox(agent, 16, now)?)
}

/// Every wake on `agent`'s resident run.
fn wakes(vault: &Vault, agent: EntityId) -> TestResult<usize> {
    Ok(AttemptQueue::new(vault).list_run(&run_id(agent))?.len())
}

/// The run id of `agent`'s resident wakes.
fn run_id(agent: EntityId) -> String {
    format!("resident:{}", agent.to_hex())
}

/// The one wake `pass` dispatched.
fn the_wake(pass: &ResidentInboxDispatch) -> TestResult<AgentDispatchStatus> {
    let [AgentDispatchOutcome::Dispatched(status)] = pass.outcomes.as_slice() else {
        return Err(format!("one wake dispatches, got {:?}", pass.outcomes).into());
    };
    Ok(status.clone())
}

/// Leases wake `id` to this test's worker and answers its row as leased.
fn lease(vault: &Vault, id: AttemptId) -> TestResult<AttemptRecord> {
    let queue = AttemptQueue::new(vault);
    for _ in 0..16 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now: u64::MAX,
            },
        )?
        else {
            break;
        };
        if row.id == id {
            return Ok(queue.get(id)?.ok_or("a leased wake reads back")?);
        }
    }
    Err("the wake is ready to lease".into())
}

/// Ends leased wake `leased`: its run completed.
fn complete(vault: &Vault, leased: &AttemptRecord) -> TestResult {
    AttemptQueue::new(vault).complete(CompleteAttempt {
        id: leased.id,
        lease_owner: WORKER.to_owned(),
        attempt_count: leased.attempt_count,
        now: leased.updated_at,
    })?;
    Ok(())
}

/// The steers and messages on wake `id`'s branch.
fn signals(vault: &Vault, agent: EntityId, id: AttemptId) -> TestResult<Vec<RunBranchSignal>> {
    Ok(RunTreeAdapter::new(vault)
        .read_branch_signals(id, &run_id(agent))?
        .ok_or("the wake's branch reads")?)
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
            project: None,
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

/// The room wake key of `turn` for `fixture`'s resident, unprefixed: the
/// key a turn's landing on a running wake names.
fn room_key(fixture: &Fixture, turn: EntityId) -> String {
    format!("resident:{}:room:{}", fixture.yuki.to_hex(), turn.to_hex())
}

/// Whether the room wake of `turn` to `fixture`'s resident is still staged.
fn staged(vault: &Vault, fixture: &Fixture, turn: EntityId) -> TestResult<bool> {
    Ok(vault
        .staged_room_wakes()?
        .iter()
        .any(|row| row.wake.agent == fixture.yuki && row.wake.turn == turn))
}

/// Opens a vault on `clock`, binds yuki, and gives it one running room wake
/// in a room of its own: owen addresses yuki there, the hold passes, the
/// wake dispatches and is leased. Returns that room with the wake.
fn busy_in_room(
    clock: &FakeClock,
    dir: &tempfile::TempDir,
) -> TestResult<(Vault, Fixture, EntityId, AgentDispatchStatus, AttemptRecord)> {
    let vault = Vault::open_owned(dir.path(), config(clock))?;
    let fixture = bind_resident(&vault)?;
    let room = room_with_yuki(&vault, &fixture)?;
    let first = address_yuki(&vault, &fixture, room)?;
    clock.advance(u64::from(HOLD_SECS));
    let wake = the_wake(&inbox_pass(&vault, fixture.yuki, clock.now())?)?;
    assert_eq!(
        wake.attempt.dedupe_key.as_deref(),
        Some(format!("agent.dispatch:{}", room_key(&fixture, first)).as_str()),
        "the room turn wakes the resident"
    );
    let leased = lease(&vault, wake.attempt.id)?;
    assert_eq!(wakes(&vault, fixture.yuki)?, 1);
    Ok((vault, fixture, room, wake, leased))
}

/// BUSY-ROOM-TURN-ROUTE = C: a turn of another room to a resident whose
/// room wake is running starts no second wake and does not land on the
/// running wake, which works in its own room. It stays staged, and wakes the
/// resident once the run has ended. Red on main: the pass dispatched a
/// second wake on the busy run.
#[test]
fn a_room_turn_of_another_room_to_a_busy_resident_waits_for_the_run_to_end() -> TestResult {
    let clock = FakeClock::default();
    let dir = tempfile::tempdir()?;
    let (vault, fixture, _room, wake, leased) = busy_in_room(&clock, &dir)?;
    let other = room_with_yuki(&vault, &fixture)?;
    let turn = address_yuki(&vault, &fixture, other)?;

    clock.advance(u64::from(HOLD_SECS) + 1);
    let pass = inbox_pass(&vault, fixture.yuki, clock.now())?;
    assert!(
        pass.outcomes.is_empty(),
        "a busy resident gets no second wake: {pass:?}"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 1, "no second wake");
    assert!(
        signals(&vault, fixture.yuki, wake.attempt.id)?.is_empty(),
        "another room's turn does not land on the running room wake"
    );
    assert!(staged(&vault, &fixture, turn)?, "the turn waits staged");

    complete(&vault, &leased)?;
    let after = the_wake(&inbox_pass(&vault, fixture.yuki, clock.now())?)?;
    assert_eq!(
        after.attempt.dedupe_key.as_deref(),
        Some(format!("agent.dispatch:{}", room_key(&fixture, turn)).as_str()),
        "the run has ended, so the turn wakes the resident"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 2);
    Ok(())
}

/// BUSY-ROOM-TURN-ROUTE = C: a turn of the room a resident's running room
/// wake works in lands on that wake, once, as one line naming the room and
/// the turn, and starts no second wake. It stays staged until a step
/// applies it: the wake ends without one here, so the turn wakes the
/// resident once the run has ended. Red on main: the pass dispatched a
/// second wake on the busy run.
#[test]
fn a_room_turn_to_a_busy_room_wake_of_its_room_lands_on_it() -> TestResult {
    let clock = FakeClock::default();
    let dir = tempfile::tempdir()?;
    let (vault, fixture, room, wake, leased) = busy_in_room(&clock, &dir)?;
    let turn = address_yuki(&vault, &fixture, room)?;

    clock.advance(u64::from(HOLD_SECS) + 1);
    for pass_no in 0..2 {
        let pass = inbox_pass(&vault, fixture.yuki, clock.now())?;
        assert!(
            pass.outcomes.is_empty(),
            "pass {pass_no}: a busy resident gets no second wake: {pass:?}"
        );
        assert_eq!(
            wakes(&vault, fixture.yuki)?,
            1,
            "pass {pass_no}: no second wake"
        );
        let landed = signals(&vault, fixture.yuki, wake.attempt.id)?;
        let [signal] = landed.as_slice() else {
            return Err(format!(
                "pass {pass_no}: the turn lands on the running wake once, got {landed:?}"
            )
            .into());
        };
        assert_eq!(signal.key, room_key(&fixture, turn));
        let RunSignalKind::Interject { content } = &signal.kind else {
            return Err(format!("the turn lands as an interjection, got {signal:?}").into());
        };
        let line: serde_json::Value = serde_json::from_str(content)?;
        assert_eq!(line["room"], room.to_hex(), "the line names the room");
        assert_eq!(line["turn"], turn.to_hex(), "the line names the turn");
        assert!(
            staged(&vault, &fixture, turn)?,
            "pass {pass_no}: a landed turn stays staged until a step applies it"
        );
    }

    complete(&vault, &leased)?;
    let after = the_wake(&inbox_pass(&vault, fixture.yuki, clock.now())?)?;
    assert_eq!(
        after.attempt.dedupe_key.as_deref(),
        Some(format!("agent.dispatch:{}", room_key(&fixture, turn)).as_str()),
        "the wake ended without applying the turn, so the turn wakes the resident"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 2);
    Ok(())
}

/// BUSY-DIARY-REVIEW-ROUTE = A: a pending review of a read of a busy
/// resident's diary starts no second wake and never lands on the running
/// wake: a review is no message. It waits in the inbox and wakes the
/// resident once the run has ended. Red on main: the pass dispatched a
/// second wake on the busy run.
#[test]
fn a_diary_review_to_a_busy_resident_waits_for_the_run_to_end() -> TestResult {
    let clock = FakeClock::default();
    let dir = tempfile::tempdir()?;
    let (vault, fixture, _room, wake, leased) = busy_in_room(&clock, &dir)?;
    let request = file_diary_review(&vault, fixture.yuki, fixture.owen, "audit")?;

    let pass = inbox_pass(&vault, fixture.yuki, clock.now())?;
    assert!(
        pass.outcomes.is_empty(),
        "a busy resident gets no second wake: {pass:?}"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 1, "no second wake");
    assert!(
        signals(&vault, fixture.yuki, wake.attempt.id)?.is_empty(),
        "a review never lands on the running wake"
    );

    complete(&vault, &leased)?;
    let after = the_wake(&inbox_pass(&vault, fixture.yuki, clock.now())?)?;
    assert_eq!(
        after.attempt.dedupe_key.as_deref(),
        Some(
            format!(
                "agent.dispatch:resident:{}:diary-read:{}",
                fixture.yuki.to_hex(),
                request.to_hex()
            )
            .as_str()
        ),
        "the run has ended, so the review wakes the resident"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 2);
    Ok(())
}
