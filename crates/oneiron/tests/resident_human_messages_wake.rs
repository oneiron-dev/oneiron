//! A resident set to wake on human messages (`ResidentWakeMode::HumanMessages`)
//! wakes on a human's message alone (FIX RESIDENT-HUMANMESSAGES-ADMITS-AGENTS;
//! ARCH-0067 #wake-hold: a sleeping agent wakes on any message its wake mode
//! allows). Every agent is a PERSON of model substrate
//! (`context_board/people.rs`), so the sender's substrate, not its entity
//! type, tells a human, as it does for a busy resident's message classes.
//!
//! Fixture: the vault's owner (`owen`) and a custom agent (`yuki`), bound as
//! a resident with a 3 s hold under `HumanMessages`, on a fake store clock
//! an hour ahead of the wall clock, as in `agent_message_classes.rs`. A
//! second custom agent (`kai`) sends as its model PERSON. Messages are
//! admitted through the test doors `resident_wake_hold::admit_inbox_message`
//! and `admit_person_message`.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test resident_human_messages_wake`.
#![cfg(oneiron_test_support)]

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchStatus, AgentDispatcher, ResidentAgentSpec,
    ResidentGoalRecord, ResidentInboxDispatch, ResidentWakeMode,
};
use oneiron::attempt_queue::AttemptQueue;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::clustering::ClusterMergeRequest;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::ConsultPayloadRef;
use oneiron::test_doors::resident_wake_hold::{
    admit_inbox_message, admit_person_message, agent_person,
};
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_testkit::{FAKE_EPOCH, FakeClock};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The hold every test binds: three seconds.
const HOLD_SECS: u32 = 3;

/// A bound resident and what its tests read.
struct Fixture {
    owen: EntityId,
    yuki: EntityId,
    inbox: EntityId,
}

/// A fake store clock an hour ahead of the wall clock, and no earlier than
/// the testkit's epoch. An agent's PERSON takes its model substrate at the
/// wall-clock time the agent is created (`create_agent_definition_as`), and
/// a substrate reads only from then on, so every fake instant must come
/// after it.
fn test_clock() -> TestResult<FakeClock> {
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok(FakeClock::at(wall.saturating_add(3_600).max(FAKE_EPOCH)))
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
/// own id (as `agent_message_classes.rs` does): the shipped manifest names
/// it in no rule, so its binding would pend at the criticality floor.
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
/// [`HOLD_SECS`], waking on human messages alone.
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
        wake: ResidentWakeMode::HumanMessages,
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

/// The one wake `pass` dispatched.
fn the_wake(pass: &ResidentInboxDispatch) -> TestResult<AgentDispatchStatus> {
    let [AgentDispatchOutcome::Dispatched(status)] = pass.outcomes.as_slice() else {
        return Err(format!("one wake dispatches, got {:?}", pass.outcomes).into());
    };
    Ok(status.clone())
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

/// Another agent's message is no human's: it reaches the resident's inbox,
/// and the resident sleeps through it. Red on main: the agent's model
/// PERSON has entity type PERSON, so its message woke the resident.
#[test]
fn a_human_messages_resident_sleeps_through_an_agents_message() -> TestResult {
    let clock = test_clock()?;
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), config(&clock))?;
    let fixture = bind_resident(&vault)?;
    let proof = owner_proof(&vault, fixture.owen)?;
    let kai = create_agent(&vault, &proof, "kai")?;

    admit_person_message(
        &vault,
        fixture.inbox,
        fixture.yuki,
        agent_person(kai)?,
        "from-kai",
    )?;
    clock.advance(u64::from(HOLD_SECS) + 1);
    let pass = inbox_pass(&vault, fixture.yuki, clock.now())?;
    assert!(
        pass.outcomes.is_empty(),
        "an agent's message wakes no human-messages resident: {pass:?}"
    );
    assert_eq!(pass.held_until, None, "no hold opens for it");
    assert_eq!(wakes(&vault, fixture.yuki)?, 0, "no wake on its run");
    Ok(())
}

/// A person's message still wakes the resident once its hold has passed,
/// keyed by its own wake key. Green on main and on the head: the fix
/// filters agents, not people.
#[test]
fn a_human_messages_resident_wakes_on_a_persons_message() -> TestResult {
    let clock = test_clock()?;
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), config(&clock))?;
    let fixture = bind_resident(&vault)?;

    admit_person_message(
        &vault,
        fixture.inbox,
        fixture.yuki,
        fixture.owen,
        "from-owen",
    )?;
    clock.advance(u64::from(HOLD_SECS) + 1);
    let wake = the_wake(&inbox_pass(&vault, fixture.yuki, clock.now())?)?;
    assert_eq!(
        wake.attempt.dedupe_key.as_deref(),
        Some(format!("agent.dispatch:{}", message_key(&fixture, "from-owen")).as_str()),
        "the owner's message wakes the resident"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 1);
    Ok(())
}

/// A sender the engine does not know is no known human either: the
/// resident sleeps through its message. Green on main and on the head.
#[test]
fn a_human_messages_resident_sleeps_through_an_unknown_sender() -> TestResult {
    let clock = test_clock()?;
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), config(&clock))?;
    let fixture = bind_resident(&vault)?;

    admit_inbox_message(&vault, fixture.inbox, fixture.yuki, "mina", "from-mina")?;
    clock.advance(u64::from(HOLD_SECS) + 1);
    let pass = inbox_pass(&vault, fixture.yuki, clock.now())?;
    assert!(
        pass.outcomes.is_empty(),
        "an unknown sender's message wakes no human-messages resident: {pass:?}"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 0);
    Ok(())
}

/// A PERSON merged into a named agent's principal is that agent: its
/// message wakes no human-messages resident, as the principal's own does not
/// (REVIEW-9173 P1). The principal (`ensure_agent_principal`) carries no
/// substrate; the alias, an ordinary PERSON with none either, is merged into
/// it through the owner's cluster merge. Red on the round-1 head 2b5b1c2d08:
/// the named-agent check read the alias's own body, not its canonical
/// PERSON's, so the alias's message woke the resident.
#[test]
fn a_human_messages_resident_sleeps_through_a_person_merged_into_a_named_agent() -> TestResult {
    let clock = test_clock()?;
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), config(&clock))?;
    let fixture = bind_resident(&vault)?;
    let proof = owner_proof(&vault, fixture.owen)?;
    let bot = vault.ensure_agent_principal("bot")?;
    let alias = EntityId::now();
    let now = vault.now_recorded_at();
    vault.put_entity(
        &alias,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        &rmp_serde::to_vec_named(&serde_json::json!({ "name": "bot alias" }))?,
    )?;
    let merge: ClusterMergeRequest = serde_json::from_value(serde_json::json!({
        "merge": {
            "sources": [alias.to_hex()],
            "survivor": bot.to_hex(),
            "evidence": { "refs": [], "rationale": "the bot, written twice" },
        },
    }))?;
    vault
        .memory(fixture.owen, EdgeActorClass::Human)
        .cluster_merge(Some(&proof), &merge)
        .map_err(|error| format!("the owner merges the alias into the bot: {error:?}"))?;
    assert_eq!(
        vault.resolve_entity(&alias)?,
        vec![bot],
        "the alias resolves to the named agent's principal"
    );

    admit_person_message(&vault, fixture.inbox, fixture.yuki, alias, "from-alias")?;
    clock.advance(u64::from(HOLD_SECS) + 1);
    let pass = inbox_pass(&vault, fixture.yuki, clock.now())?;
    assert!(
        pass.outcomes.is_empty(),
        "a message from a PERSON merged into a named agent wakes no human-messages resident: {pass:?}"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 0, "no wake on its run");
    Ok(())
}

/// A named agent's principal merged into an ordinary PERSON is still that
/// agent: its message wakes no human-messages resident (REVIEW-9173 round 2
/// P1). The merge runs the other way from the test above: the principal
/// (`ensure_agent_principal`, no substrate) is the absorbed side and the
/// ordinary PERSON (no substrate either) survives, so the principal resolves
/// to a survivor whose own body names no agent. Red on the round-2 head
/// 11fb813f1d: the named-agent check read only the survivor's body, so the
/// principal's message woke the resident.
#[test]
fn a_human_messages_resident_sleeps_through_a_named_agent_merged_into_a_person() -> TestResult {
    let clock = test_clock()?;
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), config(&clock))?;
    let fixture = bind_resident(&vault)?;
    let proof = owner_proof(&vault, fixture.owen)?;
    let bot = vault.ensure_agent_principal("bot")?;
    let survivor = EntityId::now();
    let now = vault.now_recorded_at();
    vault.put_entity(
        &survivor,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        &rmp_serde::to_vec_named(&serde_json::json!({ "name": "the bot's other record" }))?,
    )?;
    let merge: ClusterMergeRequest = serde_json::from_value(serde_json::json!({
        "merge": {
            "sources": [bot.to_hex()],
            "survivor": survivor.to_hex(),
            "evidence": { "refs": [], "rationale": "the bot, written twice" },
        },
    }))?;
    vault
        .memory(fixture.owen, EdgeActorClass::Human)
        .cluster_merge(Some(&proof), &merge)
        .map_err(|error| format!("the owner merges the bot into the other record: {error:?}"))?;
    assert_eq!(
        vault.resolve_entity(&bot)?,
        vec![survivor],
        "the named agent's principal resolves to the surviving PERSON"
    );

    admit_person_message(&vault, fixture.inbox, fixture.yuki, bot, "from-merged-bot")?;
    clock.advance(u64::from(HOLD_SECS) + 1);
    let pass = inbox_pass(&vault, fixture.yuki, clock.now())?;
    assert!(
        pass.outcomes.is_empty(),
        "a message from a named agent merged into a PERSON wakes no human-messages resident: {pass:?}"
    );
    assert_eq!(wakes(&vault, fixture.yuki)?, 0, "no wake on its run");
    Ok(())
}
