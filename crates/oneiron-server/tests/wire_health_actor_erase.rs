#![cfg(oneiron_test_support)]
//! An actor's erase (FIX 3520) out of the health check's copies past
//! own-rate: its verdict-spend check goes with its ask's burst, and the
//! wire call-volume checks that named it stay over the actors left, with
//! their asks. The crossing unit claim an ask binds names no actor at any
//! bind, since no erase reaches it. A pass that asks a check an erase
//! scrubbed while the ladder ran asks it again fresh, never over the stale
//! crossing. The owner's answer settling a check is main's poll path, which
//! this slice does not change.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --no-fail-fast --test wire_health_actor_erase`.

use std::future::Future;
use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::llm::decision::{AnswerActor, AskTo, DecisionAsk};
use oneiron::test_doors::inquiry::erase_actor_in_tables_in_order;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::ENGINE_THREAD_STACK_BYTES;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::build_server::build_served_server;
use oneiron_server::test_doors::wire_health_sweep::{
    ask_read_check, fold_once, raise_spend, record_wire_calls, set_wire_thresholds, sweep_once,
};
use oneiron_server::wire_health::{self, CheckState, HealthCheck};
use oneiron_server::wire_telemetry::WireThresholds;
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// When every test call lands, the start of a window of its own.
const NOW: u64 = 1_800_000_000;
/// The verb every test call counts under.
const VERB: &str = "GET /api/health";
/// The wire actor the tests erase: an id no vault holds, so no grant
/// clears its burst and the ladder asks it.
const ERASED_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// A second wire actor, whose burst stays.
const KEPT_HEX: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
/// The table an actor's erase scrubs for its health-check copies.
const ERASE_TABLES: [&str; 1] = ["WIRE_HEALTH_CHECK"];

/// Runs `test` on a multi-thread runtime whose threads have the engine's
/// stack, driven from a thread that has it too, as the server's binary runs.
fn on_engine_stack<F, Fut>(test: F) -> TestResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = TestResult>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(test())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        // A failed assertion fails the test with its own message.
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// A rooted vault with its embedded owner, served with the default `[serve]`
/// settings: the host ladder is the rule table and the owner's ask queue.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: SyncServer,
    owner: EntityId,
    _owner_proof: oneiron::consent::AuthenticatedOwner,
}

async fn served() -> TestResult<Served> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let (owner, owner_proof) = embedded_owner(&vault)?;
    vault.ensure_host_root_slip(&issuer)?;
    let server = build_served_server(
        Arc::clone(&vault),
        dir.path(),
        Some("wire-health-actor-erase".into()),
    )
    .await?;
    Ok(Served {
        _dir: dir,
        vault,
        server,
        owner,
        _owner_proof: owner_proof,
    })
}

/// A served vault with its crossings kept but nothing asked yet: two wire
/// call-volume questions, the first crossed by the erased actor alone, the
/// second by both actors, and one spend check per caller.
struct Fixture {
    served: Served,
    erased: EntityId,
    spender: EntityId,
}

async fn fixture() -> TestResult<Fixture> {
    let served = served().await?;
    let erased = EntityId::from_hex(ERASED_HEX).map_err(|_| "the erased test actor parses")?;
    let kept = EntityId::from_hex(KEPT_HEX).map_err(|_| "the kept test actor parses")?;
    let spender = served.vault.new_entity_id()?;
    set_wire_thresholds(
        &served.server,
        &WireThresholds {
            window_secs: 60,
            per_verb: 1_000_000,
            per_actor: 2,
        },
    )?;
    record_wire_calls(&served.server, VERB, ERASED_HEX, 3, NOW)?;
    record_wire_calls(&served.server, VERB, &kept.to_hex(), 3, NOW)?;
    raise_spend(&served.vault, erased, 9, 5, NOW, NOW)?;
    raise_spend(&served.vault, spender, 7, 5, NOW, NOW)?;
    Ok(Fixture {
        served,
        erased,
        spender,
    })
}

fn spend_subject(caller: EntityId) -> String {
    format!("spend:ai.verdict:{}", caller.to_hex())
}

/// The health check kept for `subject`, if any.
fn check_for(vault: &Vault, subject: &str) -> TestResult<Option<HealthCheck>> {
    Ok(wire_health::checks(vault)?
        .into_iter()
        .find(|check| check.subject == subject))
}

/// Every wire call-volume check, oldest first.
fn wire_checks(vault: &Vault) -> TestResult<Vec<HealthCheck>> {
    let mut checks: Vec<HealthCheck> = wire_health::checks(vault)?
        .into_iter()
        .filter(|check| check.subject.starts_with("wire:"))
        .collect();
    checks.sort_by_key(|check| check.crossing["seq"].as_u64().unwrap_or(u64::MAX));
    Ok(checks)
}

/// Every ask, open or answered, raised on the question `question` (hex).
fn asks_on(vault: &Vault, question: &str) -> TestResult<Vec<DecisionAsk>> {
    Ok(vault
        .decision_asks(None, 10_000, false)?
        .into_iter()
        .filter(|ask| ask.question.id.to_hex() == question)
        .collect())
}

/// The crossing unit an asked check's answer is bound to.
fn asked_unit(check: &HealthCheck) -> TestResult<EntityId> {
    match &check.state {
        CheckState::Asked { unit, .. } => {
            Ok(EntityId::from_hex(unit).map_err(|_| "an asked check names its unit")?)
        }
        other => Err(format!("the check waits in an ask queue, not {other:?}").into()),
    }
}

/// The question an asked check waits on.
fn asked_question(check: &HealthCheck) -> TestResult<String> {
    match &check.state {
        CheckState::Asked { question, .. } => Ok(question.clone()),
        other => Err(format!("the check waits in an ask queue, not {other:?}").into()),
    }
}

/// The crossing unit claim `unit` holds, as readable text.
fn claim_text(vault: &Vault, unit: &EntityId) -> TestResult<String> {
    let body = vault
        .get_claim(unit)?
        .ok_or("the crossing unit claim stays")?;
    Ok(format!("{body:?}"))
}

/// A pass binds every crossing's unit claim naming no actor: a wire claim
/// keeps the burst figures without the actors, a spend claim the spend
/// figures without the caller. The claim outlives the check and no erase
/// reaches it, so it is born naming no one.
#[test]
fn a_pass_binds_unit_claims_naming_no_actor() -> TestResult {
    on_engine_stack(pass_binds_unit_claims_naming_no_actor)
}

async fn pass_binds_unit_claims_naming_no_actor() -> TestResult {
    let fixture = fixture().await?;
    let vault = &fixture.served.vault;
    sweep_once(&fixture.served.server)?;

    let wires = wire_checks(vault)?;
    assert_eq!(wires.len(), 2, "one check per wire question");
    for check in &wires {
        let claim = claim_text(vault, &asked_unit(check)?)?;
        assert!(
            !claim.contains(ERASED_HEX),
            "a wire claim names no wire actor: {claim}"
        );
        assert!(
            !claim.contains(KEPT_HEX),
            "a wire claim names no wire actor: {claim}"
        );
        assert!(
            claim.contains("calls"),
            "a wire claim keeps the burst figures: {claim}"
        );
        assert!(
            claim.contains("crossed"),
            "a wire claim keeps what crossed: {claim}"
        );
    }
    for caller in [fixture.erased, fixture.spender] {
        let subject = spend_subject(caller);
        let check = check_for(vault, &subject)?.ok_or("a spend crossing keeps its check")?;
        let claim = claim_text(vault, &asked_unit(&check)?)?;
        assert!(
            !claim.contains(&caller.to_hex()),
            "a spend claim names no caller: {claim}"
        );
        assert!(
            claim.contains("spent_units"),
            "a spend claim keeps the spend figures: {claim}"
        );
    }
    Ok(())
}

/// An actor's erase takes its spend check and scrubs it out of the wire
/// checks: the wire checks stay over the actors left, with their calls.
/// The spend ask drops the burst it was asked over and leaves the owner's
/// queue; the wire asks stay open over the scrubbed bursts. Another
/// caller's spend check and ask stay, and the next pass brings nothing
/// back.
#[test]
fn an_actor_erase_takes_its_spend_check_and_scrubs_the_wire_checks() -> TestResult {
    on_engine_stack(actor_erase_takes_spend_and_scrubs_wire)
}

async fn actor_erase_takes_spend_and_scrubs_wire() -> TestResult {
    let fixture = fixture().await?;
    let vault = &fixture.served.vault;
    sweep_once(&fixture.served.server)?;

    let wires = wire_checks(vault)?;
    assert_eq!(wires.len(), 2, "one check per wire question");
    let alone_ask = asked_question(&wires[0])?;
    let together_ask = asked_question(&wires[1])?;
    let spent = spend_subject(fixture.erased);
    let spent_question =
        asked_question(&check_for(vault, &spent)?.ok_or("the erased caller's check is kept")?)?;
    let kept_spent = spend_subject(fixture.spender);
    let kept_question =
        asked_question(&check_for(vault, &kept_spent)?.ok_or("another caller's check is kept")?)?;
    for question in [&alone_ask, &together_ask, &spent_question, &kept_question] {
        let asks = asks_on(vault, question)?;
        assert_eq!(asks.len(), 1, "one ask for the crossing");
        assert!(asks[0].is_open(), "the ask waits for its answer");
        assert_eq!(
            asks[0].to,
            AskTo::owner(),
            "a burst ask goes to the vault owner role"
        );
        assert_eq!(asks[0].principal, AnswerActor::Actor(fixture.served.owner));
    }
    let alone_unit = asked_unit(&wires[0])?;
    let together_unit = asked_unit(&wires[1])?;

    let scrubbed = erase_actor_in_tables_in_order(vault, &fixture.erased, &ERASE_TABLES)?;
    assert_eq!(
        scrubbed,
        ERASE_TABLES.len(),
        "the health table registers its scrub"
    );

    assert!(
        check_for(vault, &spent)?.is_none(),
        "the erase takes the actor's spend check"
    );
    let kept_check = check_for(vault, &kept_spent)?.ok_or("another caller's spend check stays")?;
    assert_eq!(
        kept_check.crossing["caller"].as_str(),
        Some(fixture.spender.to_hex()).as_deref(),
        "another caller's spend check keeps its caller"
    );

    let wires = wire_checks(vault)?;
    assert_eq!(wires.len(), 2, "wire checks stay over the actors left");
    let alone = &wires[0];
    assert_eq!(
        alone.crossing["actors"].as_array().map(Vec::len),
        Some(0),
        "no named caller is left"
    );
    assert_eq!(
        alone.crossing["crossed"]["actors"].as_array().map(Vec::len),
        Some(0),
        "no crossed actor is left"
    );
    assert_eq!(
        alone.crossing["actor_tools"].as_array().map(Vec::len),
        Some(0),
        "no caller's tools are left"
    );
    assert_eq!(
        alone.crossing["tool_callers"].as_array().map(Vec::len),
        Some(0),
        "no tool's callers are left"
    );
    assert_eq!(
        alone.crossing["calls"], 3u64,
        "the calls stay: they happened"
    );
    let together = &wires[1];
    assert_eq!(
        together.crossing["actors"].as_array().map(Vec::len),
        Some(1),
        "the actor left stays named"
    );
    assert_eq!(
        together.crossing["actors"][0]["actor"].as_str(),
        Some(KEPT_HEX)
    );
    assert_eq!(together.crossing["actors"][0]["calls"], 3u64);
    assert_eq!(
        together.crossing["crossed"]["actors"]
            .as_array()
            .map(|actors| actors.iter().filter_map(Value::as_str).collect::<Vec<_>>()),
        Some(vec![KEPT_HEX]),
        "the crossed set is the actors left"
    );
    assert_eq!(
        together.crossing["calls"], 6u64,
        "the calls stay: they happened"
    );

    let asks = asks_on(vault, &alone_ask)?;
    assert_eq!(asks.len(), 1, "the ask's question stays");
    assert!(
        asks[0].is_open(),
        "a wire ask stays open over the actors left"
    );
    let state = asks[0]
        .pack_state
        .as_ref()
        .ok_or("a wire ask keeps the burst it was asked over")?;
    assert!(
        !state.to_string().contains(ERASED_HEX),
        "a wire ask names no erased actor"
    );
    assert_eq!(
        state["actors_known_under_grant"].as_bool(),
        Some(false),
        "with no actor left, none is known under a grant"
    );
    let asks = asks_on(vault, &together_ask)?;
    assert_eq!(asks.len(), 1, "the ask's question stays");
    assert!(
        asks[0].is_open(),
        "a wire ask stays open over the actors left"
    );
    let state = asks[0]
        .pack_state
        .as_ref()
        .ok_or("a wire ask keeps the burst it was asked over")?;
    assert!(
        state.to_string().contains(KEPT_HEX),
        "the actor left stays named in the ask"
    );
    assert!(
        !state.to_string().contains(ERASED_HEX),
        "a wire ask names no erased actor"
    );
    let asks = asks_on(vault, &spent_question)?;
    assert_eq!(asks.len(), 1, "the ask's question stays");
    assert!(
        asks[0].withdrawn_at.is_some(),
        "the ask the erased check raised leaves the owner's queue"
    );
    assert!(
        asks[0].pack_state.is_none(),
        "the ask drops the burst it was asked over"
    );
    let asks = asks_on(vault, &kept_question)?;
    assert_eq!(asks.len(), 1, "another caller's ask stays");
    assert!(asks[0].is_open() && asks[0].pack_state.is_some());

    for unit in [alone_unit, together_unit] {
        let claim = claim_text(vault, &unit)?;
        assert!(
            !claim.contains(ERASED_HEX),
            "no unit claim names the erased actor: {claim}"
        );
    }

    sweep_once(&fixture.served.server)?;
    assert!(
        check_for(vault, &spent)?.is_none(),
        "the next pass does not bring the erased check back"
    );
    assert_eq!(
        wire_checks(vault)?.len(),
        2,
        "the next pass keeps the scrubbed checks"
    );
    Ok(())
}

/// An erase that lands between a pass's fold of a wire check and its ask:
/// the pass does not write the stale crossing back and does not ask over
/// it. The ask it queued drops the burst and leaves the owner's queue, and
/// the next pass asks the check again over the scrubbed crossing.
#[test]
fn a_wire_ask_raised_after_the_erase_is_asked_again_fresh() -> TestResult {
    on_engine_stack(wire_ask_raised_after_the_erase_is_asked_again_fresh)
}

async fn wire_ask_raised_after_the_erase_is_asked_again_fresh() -> TestResult {
    let fixture = fixture().await?;
    let vault = &fixture.served.vault;
    fold_once(&fixture.served.server)?;
    let mut wires = wire_checks(vault)?;
    assert_eq!(wires.len(), 2, "the fold keeps both wire checks");
    let read = wires.remove(0);
    assert!(
        matches!(read.state, CheckState::Held),
        "the fold asks nothing"
    );
    assert!(
        read.crossing.to_string().contains(ERASED_HEX),
        "the read names the actor"
    );

    erase_actor_in_tables_in_order(vault, &fixture.erased, &ERASE_TABLES)?;
    let last = vault
        .decision_asks(None, 10_000, false)?
        .last()
        .map(|ask| ask.seq);
    ask_read_check(&fixture.served.server, read)?;

    let rerun = wire_checks(vault)?
        .into_iter()
        .find(|check| check.crossing["seq"].as_u64() == Some(0))
        .ok_or("the scrubbed check stays")?;
    assert!(
        matches!(rerun.state, CheckState::Held),
        "the pass does not ask over the stale crossing"
    );
    assert!(
        !rerun.crossing.to_string().contains(ERASED_HEX),
        "the pass does not write the stale crossing back"
    );
    let raised = vault.decision_asks(last, 10_000, false)?;
    assert_eq!(raised.len(), 1, "the pass queued its ask");
    assert!(
        raised[0].withdrawn_at.is_some(),
        "the stale ask leaves the owner's queue"
    );
    assert!(
        raised[0].pack_state.is_none(),
        "the stale ask drops the burst it was asked over"
    );

    sweep_once(&fixture.served.server)?;
    let asked = wire_checks(vault)?
        .into_iter()
        .find(|check| check.crossing["seq"].as_u64() == Some(0))
        .ok_or("the scrubbed check stays")?;
    let question = asked_question(&asked)?;
    let asks = asks_on(vault, &question)?;
    assert_eq!(
        asks.len(),
        2,
        "the next pass asks again over the scrubbed crossing"
    );
    let (open, withdrawn): (Vec<_>, Vec<_>) = asks.into_iter().partition(|ask| ask.is_open());
    assert_eq!(open.len(), 1);
    assert_eq!(withdrawn.len(), 1);
    assert!(withdrawn[0].pack_state.is_none());
    let state = open[0]
        .pack_state
        .as_ref()
        .ok_or("the fresh ask holds its burst")?;
    assert!(
        !state.to_string().contains(ERASED_HEX),
        "the fresh ask names no erased actor"
    );
    let claim = claim_text(vault, &asked_unit(&asked)?)?;
    assert!(
        !claim.contains(ERASED_HEX),
        "no unit claim names the erased actor: {claim}"
    );
    Ok(())
}
