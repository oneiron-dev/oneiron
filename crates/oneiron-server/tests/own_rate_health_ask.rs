#![cfg(oneiron_test_support)]
//! An own actor's acts past their advisory rate (ARCH-0044 C5) join the
//! health check as their own crossing source: the worker reads each kept
//! crossing past its cursor, in the order crossings were kept, and asks it
//! once on the host's ladder, to wire rate's recipients, the vault owner
//! role (ARCH-0076 #roles-everywhere). A later crossing by the same actor of
//! the same kind counts on the open check. The actor's erase takes its check,
//! and the ask the check raised drops the burst it was asked over and leaves
//! the owner's queue, also when the erase lands between a pass's read of the
//! check and its ask (FIX 3520). The owner's answer settling a check is main's poll path, which
//! this slice does not change; its test is ignored until FIX
//! [WIRE-HEALTH-OWNER-ANSWER-FLOOR] lands: the poll's outcome write is an
//! Approved claim with no owner proof, which keeps the criticality floor on a
//! seeded vault, so the check stays Asked for every crossing source.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --no-fail-fast --test own_rate_health_ask`.

use std::future::Future;
use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::llm::decision::{AnswerActor, AskTo, DecisionAnswer, DecisionAsk};
use oneiron::own_rate::OwnRateKind;
use oneiron::test_doors::advisory_rate_window::count_own_acts;
use oneiron::test_doors::inquiry::erase_actor_in_tables_in_order;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::ENGINE_THREAD_STACK_BYTES;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::build_server::build_served_server;
use oneiron_server::test_doors::wire_health_sweep::{ask_read_check, fold_once, sweep_once};
use oneiron_server::wire_health::{self, AnsweredBy, CheckState, HealthCheck};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The advisory threshold these tests count against.
const THRESHOLD: u64 = 2;
/// A window wider than the clock's range, so every act of one test lands in
/// the same window whatever second it runs at.
const WINDOW_SECONDS: u64 = 1 << 40;
/// The tables an actor's erase scrubs for its own-rate rows: the counter's
/// three and the host health check that holds a copy.
const OWN_RATE_TABLES: [&str; 4] = [
    "OWN_RATE_WINDOW",
    "OWN_RATE_CHECK",
    "OWN_RATE_CHECK_ORDER",
    "WIRE_HEALTH_CHECK",
];

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
    owner_proof: oneiron::consent::AuthenticatedOwner,
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
        Some("own-rate-health-ask".into()),
    )
    .await?;
    Ok(Served {
        _dir: dir,
        vault,
        server,
        owner,
        owner_proof,
    })
}

fn own_rate_subject(kind: OwnRateKind, actor: EntityId) -> String {
    format!("own_rate:{}:{}", kind.token(), actor.to_hex())
}

/// The health check kept for `subject`, if any.
fn check_for(vault: &Vault, subject: &str) -> TestResult<Option<HealthCheck>> {
    Ok(wire_health::checks(vault)?
        .into_iter()
        .find(|check| check.subject == subject))
}

/// Every own-rate check the health check keeps.
fn own_rate_checks(vault: &Vault) -> TestResult<Vec<HealthCheck>> {
    Ok(wire_health::checks(vault)?
        .into_iter()
        .filter(|check| check.subject.starts_with("own_rate:"))
        .collect())
}

/// Every ask, open or answered, raised on the question `question` (hex).
fn asks_on(vault: &Vault, question: &str) -> TestResult<Vec<DecisionAsk>> {
    Ok(vault
        .decision_asks(None, 10_000, false)?
        .into_iter()
        .filter(|ask| ask.question.id.to_hex() == question)
        .collect())
}

/// No ask, open or answered, holds `actor`'s id in the state it was asked
/// over.
fn assert_no_ask_state_names(vault: &Vault, actor: EntityId) -> TestResult {
    let actor = actor.to_hex();
    for ask in vault.decision_asks(None, 10_000, false)? {
        let state = ask
            .pack_state
            .as_ref()
            .map(serde_json::Value::to_string)
            .unwrap_or_default();
        assert!(
            !state.contains(&actor),
            "ask {} still holds the erased actor's burst",
            ask.seq
        );
    }
    Ok(())
}

/// The question an asked check waits on.
fn asked_question(check: &HealthCheck) -> TestResult<String> {
    match &check.state {
        CheckState::Asked { question, .. } => Ok(question.clone()),
        other => Err(format!("the check waits in an ask queue, not {other:?}").into()),
    }
}

#[test]
fn an_own_actor_rate_crossing_is_asked_once_in_the_owner_queue() -> TestResult {
    on_engine_stack(own_actor_rate_crossing_is_asked_once)
}

async fn own_actor_rate_crossing_is_asked_once() -> TestResult {
    let served = served().await?;
    let vault = &served.vault;
    let actor = vault.new_entity_id()?;
    let count = count_own_acts(
        vault,
        OwnRateKind::TaskCreate,
        actor,
        THRESHOLD + 1,
        THRESHOLD,
        WINDOW_SECONDS,
    )?;
    assert_eq!(count, THRESHOLD + 1, "the third act crossed the window");

    sweep_once(&served.server)?;

    let subject = own_rate_subject(OwnRateKind::TaskCreate, actor);
    let check = check_for(vault, &subject)?
        .ok_or("the sweep keeps a health check for the own actor's crossing")?;
    assert_eq!(
        serde_json::to_value(check.source)?,
        "own_rate",
        "an own-rate crossing is its own crossing source"
    );
    assert_eq!(check.crossing["actor"], actor.to_hex());
    assert_eq!(check.crossing["count"], THRESHOLD + 1);
    assert_eq!(check.crossing["threshold"], THRESHOLD);
    assert_eq!(check.crossing["rate"], "task_create");
    assert_eq!(check.crossings, 1);
    let question = asked_question(&check)?;
    let asks = asks_on(vault, &question)?;
    assert_eq!(asks.len(), 1, "one ask for the crossing");
    let ask = &asks[0];
    assert!(ask.is_open(), "the ask waits for its answer");
    assert_eq!(
        ask.to,
        AskTo::owner(),
        "an own-rate check goes to wire rate's recipients: the vault owner role"
    );
    assert_eq!(ask.principal, AnswerActor::Actor(served.owner));

    sweep_once(&served.server)?;
    assert_eq!(
        asks_on(vault, &question)?.len(),
        1,
        "the next sweep reads past its cursor and asks nothing again"
    );
    assert_eq!(own_rate_checks(vault)?.len(), 1);
    Ok(())
}

#[test]
fn a_later_crossing_of_the_same_actor_and_kind_counts_on_the_open_check() -> TestResult {
    on_engine_stack(later_crossing_counts_on_the_open_check)
}

async fn later_crossing_counts_on_the_open_check() -> TestResult {
    let served = served().await?;
    let vault = &served.vault;
    let actor = vault.new_entity_id()?;
    count_own_acts(
        vault,
        OwnRateKind::TaskCreate,
        actor,
        THRESHOLD + 1,
        THRESHOLD,
        WINDOW_SECONDS,
    )?;
    sweep_once(&served.server)?;
    let subject = own_rate_subject(OwnRateKind::TaskCreate, actor);
    let first = check_for(vault, &subject)?.ok_or("the first crossing is kept")?;
    let question = asked_question(&first)?;

    // A narrowed threshold makes the next act a new crossing in the same
    // window; another actor's crossing is its own subject.
    count_own_acts(
        vault,
        OwnRateKind::TaskCreate,
        actor,
        1,
        THRESHOLD - 1,
        WINDOW_SECONDS,
    )?;
    let other = vault.new_entity_id()?;
    count_own_acts(
        vault,
        OwnRateKind::TaskCreate,
        other,
        THRESHOLD + 1,
        THRESHOLD,
        WINDOW_SECONDS,
    )?;
    sweep_once(&served.server)?;

    let later = check_for(vault, &subject)?.ok_or("the actor's check stays")?;
    assert_eq!(
        later.crossings, 2,
        "the later crossing counts on the open check"
    );
    assert_eq!(
        asked_question(&later)?,
        question,
        "the open check is not asked again"
    );
    assert_eq!(asks_on(vault, &question)?.len(), 1);
    let other_check = check_for(vault, &own_rate_subject(OwnRateKind::TaskCreate, other))?
        .ok_or("another actor's crossing is a check of its own")?;
    let other_question = asked_question(&other_check)?;
    assert_ne!(other_question, question);
    assert_eq!(asks_on(vault, &other_question)?.len(), 1);
    assert_eq!(own_rate_checks(vault)?.len(), 2);
    Ok(())
}

#[test]
#[ignore = "FIX [WIRE-HEALTH-OWNER-ANSWER-FLOOR]: the poll's outcome write keeps the criticality floor"]
fn the_owner_answer_settles_an_own_rate_check() -> TestResult {
    on_engine_stack(owner_answer_settles_an_own_rate_check)
}

async fn owner_answer_settles_an_own_rate_check() -> TestResult {
    let served = served().await?;
    let vault = &served.vault;
    let actor = vault.new_entity_id()?;
    count_own_acts(
        vault,
        OwnRateKind::ConsultFanout,
        actor,
        THRESHOLD + 1,
        THRESHOLD,
        WINDOW_SECONDS,
    )?;
    sweep_once(&served.server)?;
    let subject = own_rate_subject(OwnRateKind::ConsultFanout, actor);
    let check = check_for(vault, &subject)?.ok_or("the crossing is kept")?;
    let question = asked_question(&check)?;
    let asks = asks_on(vault, &question)?;
    let ask = asks.first().ok_or("the crossing is asked")?;

    vault.answer_decision_ask(
        &served.owner_proof,
        ask.seq,
        DecisionAnswer::Choice(wire_health::VALID_BURST.to_owned()),
    )?;
    sweep_once(&served.server)?;

    let settled = check_for(vault, &subject)?.ok_or("the check stays")?;
    match settled.state {
        CheckState::Answered {
            answer,
            by,
            question: answered,
            ..
        } => {
            assert_eq!(answer, wire_health::VALID_BURST);
            assert_eq!(by, AnsweredBy::Owner, "the owner role answered");
            assert_eq!(answered, question);
        }
        other => panic!("the owner's answer settles the check, not {other:?}"),
    }
    Ok(())
}

/// An actor's erase takes its own-rate health check (FIX 3520): the check's
/// subject names the actor. The ask the check raised drops the burst it was
/// asked over and leaves the owner's queue. Another actor's check and ask
/// stay, and the next pass does not bring the erased check back. The red pin
/// has no own-rate source, so it keeps no check to take.
#[test]
fn an_actor_erase_takes_its_own_rate_check() -> TestResult {
    on_engine_stack(actor_erase_takes_its_own_rate_check)
}

async fn actor_erase_takes_its_own_rate_check() -> TestResult {
    let served = served().await?;
    let vault = &served.vault;
    let actor = vault.new_entity_id()?;
    let other = vault.new_entity_id()?;
    for counted in [actor, other] {
        count_own_acts(
            vault,
            OwnRateKind::AutoWrite,
            counted,
            THRESHOLD + 1,
            THRESHOLD,
            WINDOW_SECONDS,
        )?;
    }
    sweep_once(&served.server)?;
    let erased = own_rate_subject(OwnRateKind::AutoWrite, actor);
    let kept = own_rate_subject(OwnRateKind::AutoWrite, other);
    let erased_question =
        asked_question(&check_for(vault, &erased)?.ok_or("the actor's crossing is kept")?)?;
    let kept_question =
        asked_question(&check_for(vault, &kept)?.ok_or("the other actor's crossing is kept")?)?;

    let scrubbed = erase_actor_in_tables_in_order(vault, &actor, &OWN_RATE_TABLES)?;
    assert_eq!(
        scrubbed,
        OWN_RATE_TABLES.len(),
        "each table that holds the actor registers its scrub"
    );
    assert!(
        check_for(vault, &erased)?.is_none(),
        "the erase takes the actor's health check"
    );
    let asks = asks_on(vault, &erased_question)?;
    assert_eq!(asks.len(), 1, "the ask's question stays");
    assert!(
        asks[0].withdrawn_at.is_some(),
        "the ask the erased check raised leaves the owner's queue"
    );
    assert!(
        asks[0].pack_state.is_none(),
        "the ask drops the burst it was asked over"
    );
    assert_no_ask_state_names(vault, actor)?;
    let other_asks = asks_on(vault, &kept_question)?;
    assert_eq!(other_asks.len(), 1);
    assert!(
        other_asks[0].is_open() && other_asks[0].pack_state.is_some(),
        "another actor's ask stays open with its burst"
    );
    sweep_once(&served.server)?;
    assert!(
        check_for(vault, &erased)?.is_none(),
        "the next pass does not bring the erased check back"
    );
    assert!(
        check_for(vault, &kept)?.is_some(),
        "another actor's check stays"
    );
    Ok(())
}

/// An erase that lands between a pass's read of a held check and its ask
/// (FIX 3520): the pass does not write the erased check back, and the ask it
/// queued drops the burst and leaves the owner's queue.
#[test]
fn an_ask_raised_after_the_erase_took_its_check_is_withdrawn() -> TestResult {
    on_engine_stack(ask_raised_after_the_erase_is_withdrawn)
}

async fn ask_raised_after_the_erase_is_withdrawn() -> TestResult {
    let served = served().await?;
    let vault = &served.vault;
    let actor = vault.new_entity_id()?;
    count_own_acts(
        vault,
        OwnRateKind::TaskCreate,
        actor,
        THRESHOLD + 1,
        THRESHOLD,
        WINDOW_SECONDS,
    )?;
    fold_once(&served.server)?;
    let subject = own_rate_subject(OwnRateKind::TaskCreate, actor);
    let read = check_for(vault, &subject)?.ok_or("the fold keeps the crossing's check")?;
    assert!(
        matches!(read.state, CheckState::Held),
        "the fold asks nothing"
    );

    erase_actor_in_tables_in_order(vault, &actor, &OWN_RATE_TABLES)?;
    let last = vault
        .decision_asks(None, 10_000, false)?
        .last()
        .map(|ask| ask.seq);
    ask_read_check(&served.server, read)?;

    assert!(
        check_for(vault, &subject)?.is_none(),
        "the pass does not write the erased check back"
    );
    let raised = vault.decision_asks(last, 10_000, false)?;
    assert_eq!(raised.len(), 1, "the pass queued its ask");
    assert!(
        raised[0].withdrawn_at.is_some(),
        "the ask raised after the erase leaves the owner's queue"
    );
    assert!(
        raised[0].pack_state.is_none(),
        "the ask drops the burst it was asked over"
    );
    assert_no_ask_state_names(vault, actor)?;
    Ok(())
}

/// Control: acts within the threshold keep no crossing, so the sweep keeps
/// no own-rate check.
#[test]
fn acts_within_the_threshold_keep_no_check() -> TestResult {
    on_engine_stack(acts_within_the_threshold_keep_no_check_case)
}

async fn acts_within_the_threshold_keep_no_check_case() -> TestResult {
    let served = served().await?;
    let vault = &served.vault;
    let actor = vault.new_entity_id()?;
    let count = count_own_acts(
        vault,
        OwnRateKind::TaskCreate,
        actor,
        THRESHOLD,
        THRESHOLD,
        WINDOW_SECONDS,
    )?;
    assert_eq!(count, THRESHOLD);
    sweep_once(&served.server)?;
    assert!(own_rate_checks(vault)?.is_empty());
    Ok(())
}
