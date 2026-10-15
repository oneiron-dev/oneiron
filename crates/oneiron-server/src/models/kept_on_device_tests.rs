//! World privacy on a fallback ladder (owner ruling 2026-10-14, "Models": no
//! silent fallback to a cloud model; Engine ruling 2026-10-15 on calls that
//! name no world). A call whose work stays on the device never reaches a
//! cloud fallback: it waits within its one wait for an offer on the device,
//! then is held with a typed outcome, and each hold writes a run receipt.
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use futures_util::StreamExt;
use oneiron::llm::run_admission::{
    MemoryReceipts, RunDenied, RunEvent, RunReceipt, RunReceiptSink,
};
use oneiron::recovery::checkpoint::RestoreReason;
use oneiron::store::ports::ManualClock;
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, EntityId, LlmStreamEvent, Vault, VaultConfig};
use serde_json::json;

use super::fallback_tests::{
    T0, about, clocked_vault, kept, kept_here, portable_world, private_world, refusal, two_offers,
};
use super::tests::{config, request, test_run, text_of};
use super::*;
use crate::fake_llm::{FakeLlm, Reply};

/// A run whose receipts go to `receipts`.
fn run_into(receipts: Arc<dyn RunReceiptSink>) -> RunAdmission {
    let meter = BudgetGuard::new("kept-test", 100_000, BudgetExhaustionPolicy::Suspend);
    undeclared_run("kept-test", meter, receipts)
}

/// The model each of the run's holds kept a call from: its `Denied` rows.
fn holds(rows: &[RunReceipt]) -> Vec<String> {
    rows.iter()
        .filter_map(|row| match &row.event {
            RunEvent::Denied {
                subject,
                reason: RunDenied::KeptOnDevice,
                ..
            } => subject.clone(),
            _ => None,
        })
        .collect()
}

/// Done means (Engine ruling): in a vault with a private world, a call that
/// names no world never reaches a cloud rung after its offer on the device
/// fails. It waits within its one wait for that offer, else returns the
/// typed hold with a receipt. In a vault with no private world the same call
/// falls back as before.
#[tokio::test]
async fn a_call_that_names_no_world_stays_on_the_device_while_any_world_does() {
    let first = FakeLlm::start(
        vec![Reply::Status(500)],
        Some(Reply::text("from the device")),
    )
    .await;
    let second = FakeLlm::start(vec![], Some(Reply::text("from the cloud"))).await;
    let (dir, clock) = (tempfile::tempdir().unwrap(), ManualClock::new(T0));
    let vault = clocked_vault(dir.path(), &clock);
    let runtime = kept(&two_offers(&first, &second, ""), &vault, &clock);
    let seat = runtime.seat(ModelRole::Checker).expect("seat");
    let receipts = Arc::new(MemoryReceipts::default());
    let run = run_into(receipts.clone());
    let call = || request(&seat.model, "check this");

    let answer = seat.ladder.generate(&run, call(), None).await;
    let answer = answer.expect("no world stays here: the cloud offer answers");
    assert_eq!(text_of(&answer.message), "from the cloud");

    private_world(&vault);
    first.push(Reply::Status(500));
    let error = seat.ladder.generate(&run, call(), None).await;
    assert_eq!(error.expect_err("held"), kept_here(None));
    first.push(Reply::Status(500));
    let mut events = seat.ladder.stream(&run, call(), None).expect("a stream");
    let error = events.next().await.expect("an event").expect_err("held");
    assert_eq!(error, kept_here(None));
    assert_eq!(second.seen().len(), 1, "no held call reached the cloud");
    assert_eq!(
        holds(&receipts.rows()).len(),
        2,
        "each held call is receipted"
    );

    // A call held from the cloud waits for the offer on the device, within
    // its one wait, and answers from it.
    let limit = |seconds: &str| {
        refusal(
            429,
            &[("retry-after", seconds)],
            json!({"error": {"message": "rate limit"}}),
        )
    };
    first.push(limit("1"));
    let answer = seat.ladder.generate(&run, call(), None).await;
    let answer = answer.expect("the offer on the device answers after the wait");
    assert_eq!(text_of(&answer.message), "from the device");
    assert_eq!(
        answer.usage.raw_provider["passed_over"][1],
        json!({"rung": 1, "provider": "second", "model": "big", "passed": "kept_on_device"})
    );

    // Past the longest wait, the hold says when that offer is back.
    clock.set(T0 + 10);
    first.push(limit("3600"));
    let error = seat.ladder.generate(&run, call(), None).await;
    assert_eq!(error.expect_err("held"), kept_here(Some((3600, T0 + 3610))));
    assert_eq!(second.seen().len(), 1, "no held call reached the cloud");
    let held = holds(&receipts.rows());
    assert_eq!(held.len(), 4);
    assert!(held.iter().all(|model| model.contains("big")), "{held:?}");
}

/// Review repro (Astra R1 P1, Sol R4 P1): a call that names a world this
/// vault does not hold, or holds only as a deleted row, is no call about a
/// world that may leave: it stays on the device, while a call about a live
/// world the vault holds at its default settings goes.
#[tokio::test]
async fn a_call_about_a_world_this_vault_does_not_hold_stays_on_the_device() {
    let first = FakeLlm::start(vec![], Some(Reply::Status(500))).await;
    let second = FakeLlm::start(vec![], Some(Reply::text("from the cloud"))).await;
    let (dir, clock) = (tempfile::tempdir().unwrap(), ManualClock::new(T0));
    let vault = clocked_vault(dir.path(), &clock);
    let runtime = kept(&two_offers(&first, &second, ""), &vault, &clock);
    let seat = runtime.seat(ModelRole::Checker).expect("seat");
    let deleted = portable_world(&vault);
    assert!(vault.delete_entity(&deleted).unwrap());
    let error = seat
        .ladder
        .generate(&test_run(), about(seat, deleted), None)
        .await;
    assert_eq!(error.expect_err("held"), kept_here(None));
    let unknown = about(seat, EntityId::now());
    let error = seat
        .ladder
        .generate(&test_run(), unknown.clone(), None)
        .await;
    assert_eq!(error.expect_err("held"), kept_here(None));
    let mut events = seat
        .ladder
        .stream(&test_run(), unknown, None)
        .expect("a stream");
    let error = events.next().await.expect("an event").expect_err("held");
    assert_eq!(error, kept_here(None));
    assert!(second.seen().is_empty(), "an unknown world stayed here");

    let portable = about(seat, portable_world(&vault));
    let answer = seat.ladder.generate(&test_run(), portable, None).await;
    let answer = answer.expect("a world that may leave goes");
    assert_eq!(text_of(&answer.message), "from the cloud");
}

/// Receipts that make the next world in line private as a cloud offer is
/// admitted: the owner's edit lands while the call waits in admission.
struct PrivateOnAdmission {
    vault: Arc<Vault>,
    next: Mutex<Option<EntityId>>,
    rows: MemoryReceipts,
}

impl RunReceiptSink for PrivateOnAdmission {
    fn record(&self, receipt: RunReceipt) {
        if let RunEvent::Admitted(facts) = &receipt.event
            && facts.locality == ModelLocality::ThirdParty
            && let Some(world) = self.next.lock().unwrap().take()
        {
            self.vault
                .keep_world_on_this_machine_for_test(world, true)
                .unwrap();
        }
        self.rows.record(receipt);
    }
}

/// Review repro (Astra R1 P1): a world made private while its call's cloud
/// fallback waits in admission is judged again before the rung is sent, so
/// the call is held, in a stream too, and the admitted rung is never sent.
#[tokio::test]
async fn a_world_made_private_while_its_fallback_is_admitted_never_goes_out() {
    let first = FakeLlm::start(vec![], Some(Reply::Status(500))).await;
    let second = FakeLlm::start(vec![], Some(Reply::text("from the cloud"))).await;
    let (dir, clock) = (tempfile::tempdir().unwrap(), ManualClock::new(T0));
    let vault = clocked_vault(dir.path(), &clock);
    let runtime = kept(&two_offers(&first, &second, ""), &vault, &clock);
    let seat = runtime.seat(ModelRole::Checker).expect("seat");
    let (one, two) = (portable_world(&vault), portable_world(&vault));
    let sink = Arc::new(PrivateOnAdmission {
        vault: Arc::clone(&vault),
        next: Mutex::new(Some(one)),
        rows: MemoryReceipts::default(),
    });
    let run = run_into(sink.clone());

    let error = seat.ladder.generate(&run, about(seat, one), None).await;
    assert_eq!(error.expect_err("held"), kept_here(None));
    *sink.next.lock().unwrap() = Some(two);
    let mut events = seat
        .ladder
        .stream(&run, about(seat, two), None)
        .expect("a stream");
    let error = events.next().await.expect("an event").expect_err("held");
    assert_eq!(error, kept_here(None));
    assert!(second.seen().is_empty(), "the worlds' text stayed here");
    assert_eq!(holds(&sink.rows.rows()).len(), 2);
}

/// Review repro (Sol R4 P2, Sol R5 P2): a stream that opens with every
/// offer resting admits the first one back before it waits. When that
/// admission sees the world kept on the device, every rung is judged again,
/// so the one wait goes past both cloud offers to the offer on the device,
/// which then answers.
#[tokio::test]
async fn a_stream_spends_its_one_wait_on_an_offer_its_world_may_use() {
    let limit = |seconds: &str| {
        refusal(
            429,
            &[("retry-after", seconds)],
            json!({"error": {"message": "rate limit"}}),
        )
    };
    let local = FakeLlm::start(vec![limit("3")], Some(Reply::text("from the device"))).await;
    let cloud = FakeLlm::start(vec![limit("1"), limit("1")], None).await;
    let other_cloud = FakeLlm::start(vec![limit("2")], None).await;
    let models = config(&format!(
        r#"
[providers.local]
kind = "local-openai-compat"
base_url = "{}"
[providers.cloud]
kind = "openai-compat"
base_url = "{}"
[providers.other]
kind = "openai-compat"
base_url = "{}"
[roles.checker]
rungs = [{{ model = "local:small" }}, {{ model = "cloud:big" }}, {{ model = "other:big" }}]
"#,
        local.base_url, cloud.base_url, other_cloud.base_url
    ));
    let (dir, clock) = (tempfile::tempdir().unwrap(), ManualClock::new(T0));
    let vault = clocked_vault(dir.path(), &clock);
    let runtime = kept(&models, &vault, &clock);
    let seat = runtime.seat(ModelRole::Checker).expect("seat");
    let (other, world) = (portable_world(&vault), portable_world(&vault));
    // Each offer refuses; after the call's wait the first cloud offer refuses
    // again. The local offer rests until T0 + 3, both cloud ones until T0 + 2.
    let error = seat
        .ladder
        .generate(&test_run(), about(seat, other), None)
        .await;
    assert!(error.is_err(), "every offer rests");

    let sink = Arc::new(PrivateOnAdmission {
        vault: Arc::clone(&vault),
        next: Mutex::new(Some(world)),
        rows: MemoryReceipts::default(),
    });
    let run = run_into(sink.clone());
    let mut events = seat
        .ladder
        .stream(&run, about(seat, world), None)
        .expect("a stream");
    let mut text = String::new();
    while let Some(event) = events.next().await {
        if let LlmStreamEvent::TextDelta { text: delta, .. } = event.expect("an answer") {
            text.push_str(&delta);
        }
    }
    assert_eq!(text, "from the device");
    assert_eq!(
        (cloud.seen().len(), other_cloud.seen().len()),
        (2, 1),
        "the world's text stayed here"
    );
    assert_eq!(holds(&sink.rows.rows()).len(), 2);
}

/// Review repro (Astra R1 P2): an offer's cooldown belongs to the deployment
/// that met the refusal. A checkpoint carries none, so a vault restored from
/// one asks the offer again.
#[tokio::test]
async fn a_checkpoint_carries_no_offer_cooldown() {
    let first = FakeLlm::start(
        vec![refusal(
            429,
            &[("retry-after", "300")],
            json!({"error": {"message": "rate limit"}}),
        )],
        Some(Reply::text("first answers")),
    )
    .await;
    let second = FakeLlm::start(vec![], Some(Reply::text("from second"))).await;
    let models = two_offers(&first, &second, "");
    let (dir, clock) = (tempfile::tempdir().unwrap(), ManualClock::new(T0));
    let vault = clocked_vault(dir.path(), &clock);
    let call = |seat: &Seat| request(&seat.model, "check this");
    {
        let runtime = kept(&models, &vault, &clock);
        let seat = runtime.seat(ModelRole::Checker).expect("seat");
        let answer = seat.ladder.generate(&test_run(), call(seat), None).await;
        assert_eq!(text_of(&answer.expect("answered").message), "from second");
    }
    let image = dir.path().join("checkpoint");
    vault.snapshot_checkpoint(&image, T0).unwrap();
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let restored = Vault::restore_checkpoint(
        &image,
        &dir.path().join("restored"),
        config,
        RestoreReason::Restore,
        T0,
    )
    .unwrap()
    .0;
    let restored = Arc::new(restored);
    let runtime = kept(&models, &restored, &clock);
    let seat = runtime.seat(ModelRole::Checker).expect("seat");
    let answer = seat.ladder.generate(&test_run(), call(seat), None).await;
    let answer = answer.expect("the first offer answers");
    assert_eq!(text_of(&answer.message), "first answers");
    assert_eq!(first.seen().len(), 2, "the restored vault rests no offer");
}

/// Every place in this crate that reaches a fallback ladder, and where its
/// call's world comes from. A call that names no world is held by the
/// vault-wide floor while any world stays on the device, so a new caller
/// that passes no world fails closed; this list makes it name its source.
const LADDER_CALLERS: [(&str, &str); 10] = [
    (
        "api/llm.rs",
        "the caller's envelope; a world it names must be held here",
    ),
    ("api/ai/chat.rs", "none: the floor"),
    (
        "models/declared.rs",
        "the declared run's envelope; a world it names must be held here",
    ),
    ("models/raw.rs", "one host-injected offer, never a fallback"),
    (
        "models/run_backend.rs",
        "the engine's envelope: a consolidation pass names its partition's world, the rest none (the floor)",
    ),
    (
        "ai_host/dreamer.rs",
        "the engine's envelope, through a run backend",
    ),
    (
        "ai_host/code_mode.rs",
        "the executor's envelope, which names no world: the floor",
    ),
    (
        "ai_host/step.rs",
        "none, as nothing proves its text's worlds: the floor",
    ),
    ("ai_host/compaction.rs", "none: the floor"),
    (
        "server/recall_rerank.rs",
        "none: the floor, beside rerank's own row check",
    ),
];

/// How a ladder is reached: its entry points, and the backend that wraps one,
/// matched with every whitespace taken out, so a call split over lines is
/// found too. A caller binds the ladder it reaches as `ladder`.
const ENTRY_POINTS: [&str; 4] = [
    "ladder.generate(",
    "ladder.stream(",
    ".generate_while(",
    "RunBackend::new(",
];

fn sources(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

/// Engine ruling 2026-10-15, the class check: each call site in this crate's
/// own code that can reach a fallback ladder is listed with where its world
/// comes from, so none reaches one unjudged.
#[test]
fn every_ladder_caller_names_where_its_world_comes_from() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&root, &mut files);
    let mut callers = Vec::new();
    for file in files {
        let name = file
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let test_only = name.ends_with("tests.rs")
            || name.starts_with("tests/")
            || name.contains("/tests/")
            || name.ends_with("test_support.rs");
        if test_only || name == "models/ladder.rs" {
            continue;
        }
        let text: String = std::fs::read_to_string(&file)
            .unwrap()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if ENTRY_POINTS.iter().any(|entry| text.contains(entry)) {
            callers.push(name);
        }
    }
    callers.sort();
    let mut listed: Vec<String> = LADDER_CALLERS
        .iter()
        .map(|(file, _)| (*file).to_owned())
        .collect();
    listed.sort();
    assert_eq!(
        callers, listed,
        "a ladder caller is missing from the list, or gone"
    );
}
