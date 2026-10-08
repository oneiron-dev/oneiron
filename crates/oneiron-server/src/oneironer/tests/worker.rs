//! The worker against the stub tagger: shadow writes nothing but the job
//! tables, a failing tagger never fails a write, and a restart resumes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::attempt_queue::AttemptState;
use oneiron::tagging::{OutputRefusal, TaggingFailure, TaggingOutcome};
use oneiron::{EntityId, Vault};

use super::support::{
    Answer, NOW, StubTagger, card, copy_dir, endpoint_config, markers, open_vault, server, speaker,
    wait_until, witness, witness_at,
};
use crate::server::SyncServer;

const TEXTS: [&str; 4] = [
    "Ada sailed north before dawn",
    "Grace stayed behind with the maps",
    "they wrote letters every week",
    "the harbour froze that winter",
];

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("worker runtime")
}

struct Running {
    runtime: tokio::runtime::Runtime,
    worker: Option<tokio::task::JoinHandle<()>>,
}

impl Running {
    fn start(server: &Arc<SyncServer>) -> Self {
        let runtime = runtime();
        let worker = {
            let _entered = runtime.enter();
            server.spawn_tagging_worker()
        };
        assert!(worker.is_some(), "a configured tagger starts a worker");
        Self { runtime, worker }
    }

    fn stop(mut self) {
        if let Some(worker) = self.worker.take() {
            worker.abort();
            let _ = self.runtime.block_on(worker);
        }
        self.runtime.shutdown_timeout(Duration::from_secs(5));
    }
}

fn outcomes(server: &SyncServer) -> Vec<TaggingOutcome> {
    server
        .tagger
        .as_ref()
        .expect("slot")
        .traces()
        .into_iter()
        .map(|logged| logged.trace.outcome)
        .collect()
}

fn shadowed(server: &SyncServer) -> usize {
    outcomes(server)
        .iter()
        .filter(|outcome| matches!(outcome, TaggingOutcome::Shadowed { .. }))
        .count()
}

/// The outcomes of the turn's recorded traces, oldest first.
fn history(vault: &Vault, turn: &EntityId) -> Vec<TaggingOutcome> {
    vault
        .tagging_trace_history(Some(turn))
        .expect("trace history")
        .into_iter()
        .map(|record| record.trace.outcome)
        .collect()
}

fn content_digests(vault: &Vault) -> Vec<(&'static str, [u8; 32])> {
    vault
        .database_digests()
        .expect("digests")
        .into_iter()
        .filter(|(name, _)| !name.starts_with("job_"))
        .collect()
}

fn job_digests(vault: &Vault) -> Vec<(&'static str, [u8; 32])> {
    vault
        .database_digests()
        .expect("digests")
        .into_iter()
        .filter(|(name, _)| name.starts_with("job_"))
        .collect()
}

/// Shadow mode, acceptance line 1: after the same writes, a vault whose
/// worker tagged every turn through the stub holds the same bytes in every
/// content database as a vault with no tagger. The job state is left out by
/// name (`job_records`, `job_ready`, `job_dedupe`, and `vault_meta`'s job
/// rows as `job_meta`): it holds the markers and their trace history, the
/// one thing the tagger run is meant to add.
#[test]
fn shadow_tagging_leaves_every_content_database_as_a_run_with_no_tagger() {
    let stub = StubTagger::start(Answer::Good);
    // An open seeds some rows under fresh random ids, so the two arms start
    // from byte copies of one closed vault, then take the same writes.
    let tagged_dir = tempfile::tempdir().expect("dir");
    let plain_dir = tempfile::tempdir().expect("dir");
    {
        let seed = open_vault(tagged_dir.path(), false, true);
        speaker(&seed);
        // A server's first start on a vault writes its own rows once.
        drop(server(&seed, None));
    }
    copy_dir(tagged_dir.path(), plain_dir.path());
    let tagged_vault = open_vault(tagged_dir.path(), true, true);
    let plain_vault = open_vault(plain_dir.path(), false, true);
    let tagged = server(&tagged_vault, Some(&stub.config()));
    let plain = server(&plain_vault, None);
    assert!(plain.spawn_tagging_worker().is_none());
    assert_eq!(
        content_digests(&tagged_vault),
        content_digests(&plain_vault)
    );
    let running = Running::start(&tagged);
    let mut turns = Vec::new();
    for text in TEXTS {
        turns.push(witness(&tagged_vault, text));
        witness(&plain_vault, text);
    }
    assert!(wait_until(|| shadowed(&tagged) == TEXTS.len()));
    running.stop();

    assert_eq!(stub.extracts().len(), TEXTS.len());
    // Every turn settled once; its marker left the job ledger, its trace
    // stayed.
    assert!(markers(&tagged_vault).is_empty());
    for turn in &turns {
        let outcomes = history(&tagged_vault, turn);
        assert_eq!(outcomes.len(), 1);
        assert!(matches!(outcomes[0], TaggingOutcome::Shadowed { .. }));
    }
    assert!(markers(&plain_vault).is_empty());
    let tagged_content = content_digests(&tagged_vault);
    assert_eq!(
        tagged_content.len(),
        25,
        "every content database is compared"
    );
    assert_eq!(tagged_content, content_digests(&plain_vault));
    // The exclusion is real: the job state does differ.
    assert_ne!(job_digests(&tagged_vault), job_digests(&plain_vault));
}

/// Acceptance line 4: a tagger that fails, times out or returns bad offsets
/// leaves every write successful, writes one trace per attempt, and retries
/// the turn until a good answer settles it.
#[test]
fn a_failing_slow_or_wrong_tagger_never_fails_the_write_and_is_retried() {
    let stub = StubTagger::start(Answer::ServerError);
    let dir = tempfile::tempdir().expect("dir");
    // The store's own clock, so a retry's backoff second actually passes.
    let vault = open_vault(dir.path(), true, false);
    let mut config = endpoint_config(&stub.base);
    config.retry_backoff_secs = 1;
    config.max_retry_backoff_secs = 1;
    let tagged = server(&vault, Some(&config));
    let running = Running::start(&tagged);
    let turn = witness(&vault, TEXTS[0]);
    let step = |answer: Answer, seen: &dyn Fn(&TaggingOutcome) -> bool| {
        stub.set_answer(answer);
        assert!(
            wait_until_long(|| outcomes(&tagged).iter().any(seen)),
            "no trace for {answer:?}"
        );
    };
    step(Answer::ServerError, &|outcome| {
        matches!(outcome, TaggingOutcome::Failed { failure: TaggingFailure::Call { code }, .. }
            if code == "tagger extract returned HTTP 500")
    });
    step(Answer::Slow, &|outcome| {
        matches!(outcome, TaggingOutcome::Failed { failure: TaggingFailure::Call { code }, .. }
            if code == "tagger extract timed out")
    });
    step(Answer::BadOffsets, &|outcome| {
        matches!(
            outcome,
            TaggingOutcome::Failed {
                failure: TaggingFailure::Refused {
                    refusal: OutputRefusal::BadOffsets
                },
                ..
            }
        )
    });
    step(Answer::Good, &|outcome| {
        matches!(outcome, TaggingOutcome::Shadowed { .. })
    });
    running.stop();

    // The write stands, and every try left exactly one trace.
    assert!(vault.get(&turn).expect("turn read").is_some());
    let traces: Vec<_> = tagged
        .tagger
        .as_ref()
        .expect("slot")
        .traces()
        .into_iter()
        .map(|logged| logged.trace)
        .collect();
    let traced: BTreeSet<String> = traces.iter().map(|trace| trace.attempt.clone()).collect();
    assert_eq!(traced.len(), traces.len(), "one trace per attempt");
    // The settled marker left the job ledger with every try it retried; the
    // turn's newest traces stayed, the ones the worker logged.
    assert!(markers(&vault).is_empty());
    let recorded: Vec<_> = vault
        .tagging_trace_history(Some(&turn))
        .expect("trace history")
        .into_iter()
        .map(|record| record.trace)
        .collect();
    let kept = traces
        .len()
        .min(oneiron::tagging::DEFAULT_TRACES_PER_TURN as usize);
    assert_eq!(recorded, traces[traces.len() - kept..].to_vec());
    assert!(traces.iter().all(|trace| trace.turn == Some(turn)));
    assert!(traces.len() >= 4);
}

/// A probe whose card body breaks off is an unreachable tagger, not a
/// refused one: the worker backs off and probes again, and a turn witnessed
/// after the broken read is tagged by the same worker, with no restart.
#[test]
fn a_card_read_that_breaks_off_leaves_the_worker_running() {
    let stub = StubTagger::start(Answer::Good);
    let dir = tempfile::tempdir().expect("dir");
    let vault = open_vault(dir.path(), true, false);
    let tagged = server(&vault, Some(&stub.config()));
    let running = Running::start(&tagged);
    witness(&vault, TEXTS[0]);
    assert!(wait_until(|| shadowed(&tagged) == 1));
    // The worker's next probe, after its idle wait, reads half a card.
    stub.break_card_bodies(1);
    assert!(
        wait_until(|| stub.card_bodies_broken() == 1),
        "the worker probes after its idle wait"
    );
    witness(&vault, TEXTS[1]);
    assert!(
        wait_until(|| shadowed(&tagged) == 2),
        "the same worker tags a turn witnessed after the broken read"
    );
    assert!(
        running
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
    );
    running.stop();
    assert_eq!(stub.extracts().len(), 2);
}

/// Acceptance line 5: markers committed right before the process died are on
/// disk; a restarted server tags each turn once, with no repair step.
#[test]
fn a_restarted_server_resumes_the_markers_of_a_crashed_one() {
    let stub = StubTagger::start(Answer::Good);
    let dir = tempfile::tempdir().expect("dir");
    let turns: Vec<EntityId> = {
        let vault = open_vault(dir.path(), true, false);
        let crashed = server(&vault, Some(&stub.config()));
        // The worker never ran: the process died right after the commits.
        let turns = TEXTS.iter().map(|text| witness(&vault, text)).collect();
        drop(crashed);
        turns
    };
    assert!(stub.extracts().is_empty());
    let vault = open_vault(dir.path(), true, false);
    assert_eq!(markers(&vault).len(), TEXTS.len());
    let restarted = server(&vault, Some(&stub.config()));
    let running = Running::start(&restarted);
    assert!(wait_until(|| shadowed(&restarted) == TEXTS.len()));
    running.stop();
    let mut tagged: Vec<EntityId> = restarted
        .tagger
        .as_ref()
        .expect("slot")
        .traces()
        .into_iter()
        .filter_map(|logged| logged.trace.turn)
        .collect();
    tagged.sort_by_key(|turn| *turn.as_bytes());
    let mut expected = turns;
    expected.sort_by_key(|turn| *turn.as_bytes());
    assert_eq!(tagged, expected, "each turn tagged once");
    assert_eq!(stub.extracts().len(), TEXTS.len());
    assert!(markers(&vault).is_empty());
}

/// A tagger that turns into another checkpoint after startup is caught by
/// the probe that follows the worker's next idle wait: the worker stops and
/// later markers wait, so no answer settles under the configured identity.
#[test]
fn a_tagger_swapped_for_another_checkpoint_stops_the_worker_after_its_idle_wait() {
    let stub = StubTagger::start(Answer::Good);
    let dir = tempfile::tempdir().expect("dir");
    let vault = open_vault(dir.path(), true, false);
    let tagged = server(&vault, Some(&stub.config()));
    let running = Running::start(&tagged);
    witness(&vault, TEXTS[0]);
    assert!(wait_until(|| shadowed(&tagged) == 1));
    stub.set_card(card("ffffffffffffffff"));
    assert!(
        wait_until(|| running
            .worker
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)),
        "the worker stops once a probe finds another checkpoint"
    );
    let waiting = witness(&vault, TEXTS[1]);
    running.stop();
    assert_eq!(stub.extracts().len(), 1);
    let queued: Vec<_> = markers(&vault)
        .into_iter()
        .filter(|row| row.state == AttemptState::Queued)
        .collect();
    assert_eq!(queued.len(), 1);
    assert!(
        queued[0]
            .dedupe_key
            .as_deref()
            .is_some_and(|key| key.starts_with(&waiting.to_hex()))
    );
}

/// A tagger swapped for another checkpoint while the worker drains a backlog
/// larger than one batch: no answer the other model gave settles under the
/// configured checkpoint. The turn it answered and every turn after it still
/// owe a pass, and the worker stops.
#[test]
fn a_tagger_swapped_mid_backlog_settles_no_answer_under_the_configured_checkpoint() {
    let stub = StubTagger::start(Answer::Good);
    let dir = tempfile::tempdir().expect("dir");
    let vault = open_vault(dir.path(), true, false);
    // The backlog is on disk before the worker starts.
    let backlog: BTreeSet<EntityId> = (0..6)
        .map(|index| witness(&vault, &format!("backlog turn {index} where Ada met Grace")))
        .collect();
    let mut config = stub.config();
    config.batch_size = 2;
    // The configured checkpoint answers the first batch; another model
    // answers the third extract and every one after it.
    stub.swap_card_at_extract(3, card("ffffffffffffffff"));
    let tagged = server(&vault, Some(&config));
    let running = Running::start(&tagged);
    assert!(
        wait_until(|| running
            .worker
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)),
        "the worker stops once the tagger is another checkpoint"
    );
    running.stop();

    let extracts = stub.extracts();
    assert!(extracts.len() >= 3, "the other model answered a call");
    let answered_as_configured: BTreeSet<EntityId> = extracts[..2]
        .iter()
        .map(|body| EntityId::from_hex(body["turn"].as_str().expect("turn")).expect("turn id"))
        .collect();
    let rows = markers(&vault);
    let turns_in = |wanted: &dyn Fn(AttemptState) -> bool| -> BTreeSet<EntityId> {
        rows.iter()
            .filter(|row| wanted(row.state))
            .map(|row| {
                let key = row.dedupe_key.as_deref().expect("marker dedupe key");
                EntityId::from_hex(key.split('@').next().expect("turn half")).expect("turn id")
            })
            .collect()
    };
    // A settled marker has left the job ledger; its trace says so.
    let completed: BTreeSet<EntityId> = backlog
        .iter()
        .filter(|turn| {
            history(&vault, turn)
                .iter()
                .any(|outcome| matches!(outcome, TaggingOutcome::Shadowed { .. }))
        })
        .copied()
        .collect();
    let pending =
        turns_in(&|state| matches!(state, AttemptState::Queued | AttemptState::Scheduled));
    assert_eq!(completed, answered_as_configured);
    assert_eq!(
        pending,
        backlog.difference(&completed).copied().collect(),
        "every turn the configured checkpoint did not answer still owes a pass"
    );
}

/// The extract carries the live window under the contract's `context` key:
/// the conversation's earlier turns, oldest first, each with its messages,
/// and never a later turn, even one witnessed before the worker read it.
#[test]
fn the_extract_carries_the_earlier_window_and_never_a_later_turn() {
    let stub = StubTagger::start(Answer::Good);
    let dir = tempfile::tempdir().expect("dir");
    let vault = open_vault(dir.path(), true, false);
    let turns: Vec<EntityId> = TEXTS
        .iter()
        .zip(0_u64..)
        .map(|(text, at)| witness_at(&vault, text, NOW + at))
        .collect();
    let tagged = server(&vault, Some(&stub.config()));
    let running = Running::start(&tagged);
    assert!(wait_until(|| shadowed(&tagged) == TEXTS.len()));
    running.stop();
    let extracts = stub.extracts();
    for (index, turn) in turns.iter().enumerate() {
        let body = extracts
            .iter()
            .find(|body| body["turn"] == turn.to_hex())
            .expect("the turn was tagged");
        let context = body["context"].as_array().expect("a context array");
        let earlier: Vec<(&str, &str)> = context
            .iter()
            .map(|entry| {
                let messages = entry["messages"].as_array().expect("messages");
                assert_eq!(messages.len(), 1);
                (
                    entry["turn"].as_str().expect("turn"),
                    messages[0]["text"].as_str().expect("text"),
                )
            })
            .collect();
        let hexes: Vec<String> = turns[..index].iter().map(EntityId::to_hex).collect();
        let expected: Vec<(&str, &str)> = hexes
            .iter()
            .map(String::as_str)
            .zip(TEXTS[..index].iter().copied())
            .collect();
        assert_eq!(
            earlier, expected,
            "turn {index} reads exactly the turns before it"
        );
        assert_eq!(body["messages"][0]["text"], TEXTS[index]);
    }
}

fn wait_until_long(mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    done()
}

fn percentile(sorted: &[Duration], fraction: f64) -> f64 {
    let index = ((sorted.len() as f64 - 1.0) * fraction).round() as usize;
    sorted[index].as_secs_f64() * 1_000.0
}

fn summary(mut samples: Vec<Duration>) -> serde_json::Value {
    samples.sort();
    serde_json::json!({
        "n": samples.len(),
        "p50_ms": percentile(&samples, 0.50),
        "p95_ms": percentile(&samples, 0.95),
    })
}

/// Acceptance lines 2 and 3, a measurement rather than a law. Three vaults
/// take the same writes in rotating order, round by round, so drift on the
/// host lands on every arm: no tagger; markers on with no worker running (the
/// write's own cost); markers on with the worker draining them against the
/// stub (the cost under a live worker). Write-to-trace is read twice on the
/// live arm: during those bursts, and for turns written one at a time.
/// Run alone on a quiet host:
/// `cargo test --locked -p oneiron-server --lib oneironer::tests::worker::timing -- --ignored --nocapture`
#[test]
#[ignore = "timing run; needs a quiet host"]
fn timing_write_latency_and_write_to_trace() {
    const WARMUP: usize = 20;
    const ROUNDS: usize = 12;
    const PER_ROUND: usize = 50;
    const PACED: usize = 100;
    let stub = StubTagger::start(Answer::Good);
    let dirs: Vec<_> = (0..3).map(|_| tempfile::tempdir().expect("dir")).collect();
    let plain = open_vault(dirs[0].path(), false, false);
    let markers_only = open_vault(dirs[1].path(), true, false);
    let live = open_vault(dirs[2].path(), true, false);
    let live_server = server(&live, Some(&stub.config()));
    let running = Running::start(&live_server);
    let arms = [&plain, &markers_only, &live];
    for index in 0..WARMUP {
        for vault in arms {
            witness(vault, &format!("warm up turn number {index}"));
        }
    }
    let mut latency: [Vec<Duration>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    let mut written: BTreeMap<EntityId, Instant> = BTreeMap::new();
    for round in 0..ROUNDS {
        for step in 0..3 {
            let arm = (round + step) % 3;
            for index in 0..PER_ROUND {
                let text = format!("round {round} turn {index} where Ada met Grace by the sea");
                let started = Instant::now();
                let turn = witness(arms[arm], &text);
                let done = Instant::now();
                latency[arm].push(done - started);
                if arm == 2 {
                    written.insert(turn, done);
                }
            }
        }
    }
    let burst_turns = WARMUP + ROUNDS * PER_ROUND;
    assert!(wait_until_long(|| shadowed(&live_server) == burst_turns));
    let mut paced: BTreeMap<EntityId, Instant> = BTreeMap::new();
    for index in 0..PACED {
        let turn = witness(
            &live,
            &format!("paced turn {index} where Grace wrote to Ada"),
        );
        paced.insert(turn, Instant::now());
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(wait_until_long(
        || shadowed(&live_server) == burst_turns + PACED
    ));
    running.stop();
    let to_trace = |turns: &BTreeMap<EntityId, Instant>| -> Vec<Duration> {
        live_server
            .tagger
            .as_ref()
            .expect("slot")
            .traces()
            .into_iter()
            .filter(|logged| matches!(logged.trace.outcome, TaggingOutcome::Shadowed { .. }))
            .filter_map(|logged| {
                let turn = logged.trace.turn?;
                turns
                    .get(&turn)
                    .map(|at| logged.at.saturating_duration_since(*at))
            })
            .collect()
    };
    let burst = to_trace(&written);
    let one_at_a_time = to_trace(&paced);
    assert_eq!(burst.len(), ROUNDS * PER_ROUND);
    assert_eq!(one_at_a_time.len(), PACED);
    assert_eq!(markers(&markers_only).len(), burst_turns);
    let [no_tagger, marker_only, marker_live] = latency;
    println!(
        "{}",
        serde_json::json!({
            "write_latency_no_tagger": summary(no_tagger),
            "write_latency_marker_on_no_worker": summary(marker_only),
            "write_latency_marker_on_live_worker": summary(marker_live),
            "write_to_trace_during_bursts": summary(burst),
            "write_to_trace_one_at_a_time": summary(one_at_a_time),
        })
    );
}
