//! Laws of the tagging marker and its drain, observed through the job tables,
//! the traces and the vault's stored rows.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::*;
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome, CleanupAttemptLeases,
    RetryAttempt,
};
use crate::edge::EdgeActorClass;
use crate::error::ErrorKind;
use crate::memory::extraction::{EncoderInput, EncoderOutput, ExtractionEncoder};
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::off_record::{FloorWrites, OffRecordBackendClass};
use crate::ports::ManualClock;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;
use crate::{EntityId, ModelId, Vault, VaultConfig};

const CHECKPOINT: &str = "0123456789abcdef";
const OTHER_CHECKPOINT: &str = "fedcba9876543210";
const NOW: u64 = 1_790_000_000;
const ROOM: &str = "51515151515151515151515151515151";

/// What the scripted tagger answers on its next call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    Good,
    Fail,
    BadOffsets,
    Panic,
}

struct Scripted {
    model: ModelId,
    answer: Mutex<Answer>,
    calls: AtomicUsize,
    /// Every input the tagger was called with, in call order.
    inputs: Mutex<Vec<EncoderInput>>,
    /// Runs inside the call, outside every write transaction.
    during_call: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Scripted {
    fn new(answer: Answer) -> Arc<Self> {
        Arc::new(Self {
            model: "fixture/tagger@v1".parse().expect("model id"),
            answer: Mutex::new(answer),
            calls: AtomicUsize::new(0),
            inputs: Mutex::new(Vec::new()),
            during_call: Mutex::new(None),
        })
    }
    fn set(&self, answer: Answer) {
        *self.answer.lock().expect("answer lock") = answer;
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ExtractionEncoder for Scripted {
    fn model_id(&self) -> &ModelId {
        &self.model
    }
    fn locality(&self) -> crate::embed::EmbedderLocality {
        crate::embed::EmbedderLocality::OnDevice
    }
    fn infer(&self, input: &EncoderInput) -> crate::Result<EncoderOutput> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inputs.lock().expect("inputs lock").push(input.clone());
        if let Some(hook) = self.during_call.lock().expect("hook lock").take() {
            hook();
        }
        let answer = *self.answer.lock().expect("answer lock");
        match answer {
            Answer::Fail => Err(crate::Error::UpstreamToolFailure {
                tool: "fixture-tagger",
                code: "fixture tagger unreachable".into(),
            }),
            Answer::Panic => panic!("fixture tagger panicked"),
            Answer::Good | Answer::BadOffsets => {
                let text = &input.messages[0].text;
                let end = if answer == Answer::BadOffsets {
                    text.len() + 3
                } else {
                    text.find(' ').unwrap_or(text.len())
                };
                Ok(answer_json(serde_json::json!({
                    "spans": [
                        {"message": 0, "start": 0, "end": end, "label": "PERSON", "confidence": 0.9},
                        {"message": 0, "start": 0, "end": end, "label": "UNMAPPED", "confidence": 0.4}
                    ],
                    "links": [{"span": 1, "antecedent": 0}],
                    "vad": {"valence": 0.2, "arousal": 0.4, "dominance": 0.6}
                })))
            }
        }
    }
}

/// Answers are built from the wire shape, so these tests read the same
/// whether the contract's mood is a value or optional (ONE-2167).
fn answer_json(value: serde_json::Value) -> EncoderOutput {
    serde_json::from_value(value).expect("an answer in the contract's wire shape")
}

/// One span over `0..end` of the first message, no links, a neutral mood.
fn held(end: usize) -> EncoderOutput {
    answer_json(serde_json::json!({
        "spans": [{"message": 0, "start": 0, "end": end, "label": "PERSON", "confidence": 1.0}],
        "links": [],
        "vad": {"valence": 0.0, "arousal": 0.5, "dominance": 0.5}
    }))
}

fn config(armed: bool) -> VaultConfig {
    let mut config = VaultConfig::device();
    config.store_clock = ManualClock::new(NOW).bundle();
    if armed {
        config.tagging = Some(TaggingMarkerConfig::new(CHECKPOINT).expect("checkpoint"));
    }
    config
}

fn open(path: &std::path::Path, armed: bool) -> Arc<Vault> {
    Arc::new(Vault::open(path, config(armed)).expect("open vault"))
}

fn speaker(vault: &Vault) -> EntityId {
    let id = EntityId::from_bytes([0x21; 16]).expect("speaker id");
    if vault.get(&id).expect("speaker read").is_none() {
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&serde_json::json!({"name": "fixture speaker"}))
                    .expect("speaker body"),
            )
            .expect("speaker");
    }
    id
}

fn message(order: u32, content: &str) -> WitnessMessage {
    WitnessMessage {
        id: None,
        author: WitnessAuthor::User,
        message_type: "text".into(),
        content: content.into(),
        metadata: None,
        is_visible: true,
        order,
    }
}

fn turn(turn_ref: Option<String>, messages: Vec<WitnessMessage>) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: ROOM.into(),
        turn_ref,
        messages,
        occurred_at: NOW,
    }
}

/// Witnesses one fresh turn and returns its id.
fn witness(vault: &Vault, content: &str) -> EntityId {
    let receipt = vault
        .memory(speaker(vault), EdgeActorClass::Human)
        .witness(&turn(None, vec![message(0, content)]))
        .expect("witness");
    receipt_turn(&receipt)
}

fn receipt_turn(receipt: &crate::memory::WitnessReceipt) -> EntityId {
    EntityId::from_hex(receipt.receipt_ref.trim_start_matches("witness:")).expect("turn id")
}

fn markers(vault: &Vault) -> Vec<AttemptRecord> {
    AttemptQueue::new(vault)
        .list()
        .expect("attempt rows")
        .into_iter()
        .filter(|record| record.kind == TAGGING_MARKER_KIND)
        .collect()
}

fn count(vault: &Vault, state: AttemptState) -> usize {
    markers(vault)
        .iter()
        .filter(|record| record.state == state)
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

/// The turn's recorded traces that settled a marker: every outcome but a
/// failed, superseded or handed-back try.
fn settled(vault: &Vault, turn: &EntityId) -> usize {
    history(vault, turn)
        .iter()
        .filter(|outcome| {
            !matches!(
                outcome,
                TaggingOutcome::Failed { .. }
                    | TaggingOutcome::Superseded { .. }
                    | TaggingOutcome::HandedBack { .. }
            )
        })
        .count()
}

fn reconciler(vault: &Arc<Vault>, tagger: &Arc<Scripted>) -> TaggingReconciler {
    TaggingReconciler::new(
        Arc::clone(vault),
        Arc::clone(tagger) as Arc<dyn ExtractionEncoder>,
    )
    .expect("reconciler")
    .with_backoff(TaggingBackoff {
        first_secs: 0,
        max_secs: 0,
    })
    .with_label_kinds(BTreeMap::from([("PERSON".to_owned(), ENTITY_TYPE_PERSON)]))
}

/// Copies a closed vault's files, so two vaults start from the same bytes.
fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    for entry in std::fs::read_dir(from).expect("read vault dir") {
        let entry = entry.expect("vault dir entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("entry type").is_dir() {
            std::fs::create_dir_all(&target).expect("create dir");
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy vault file");
        }
    }
}

/// The content databases whose digests differ.
fn differing_content(left: &Vault, right: &Vault) -> Vec<&'static str> {
    content_digests(left)
        .into_iter()
        .zip(content_digests(right))
        .filter(|(a, b)| a.1 != b.1)
        .map(|(a, _)| a.0)
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

fn content_digests(vault: &Vault) -> Vec<(&'static str, [u8; 32])> {
    vault
        .database_digests()
        .expect("digests")
        .into_iter()
        .filter(|(name, _)| !name.starts_with("job_"))
        .collect()
}

/// Two vaults from byte copies of one closed seed, each on its own manual
/// clock. An open seeds some rows under fresh random ids, so the arms share
/// their starting bytes, then take the same writes and the same ticks. The
/// tagged arm is armed, the plain arm is not.
struct Arms {
    tagged_dir: tempfile::TempDir,
    plain_dir: tempfile::TempDir,
    tagged_clock: Arc<ManualClock>,
    plain_clock: Arc<ManualClock>,
}

impl Arms {
    fn new() -> Self {
        let tagged_dir = tempfile::tempdir().expect("dir");
        let plain_dir = tempfile::tempdir().expect("dir");
        {
            let seed = open(tagged_dir.path(), false);
            speaker(&seed);
        }
        copy_dir(tagged_dir.path(), plain_dir.path());
        Self {
            tagged_dir,
            plain_dir,
            tagged_clock: ManualClock::new(NOW),
            plain_clock: ManualClock::new(NOW),
        }
    }

    /// Opens both arms: tagged, then plain.
    fn open(&self) -> (Arc<Vault>, Arc<Vault>) {
        let on = |path: &std::path::Path, armed: bool, clock: &Arc<ManualClock>| {
            let mut config = config(armed);
            config.store_clock = clock.bundle();
            Arc::new(Vault::open(path, config).expect("open vault"))
        };
        (
            on(self.tagged_dir.path(), true, &self.tagged_clock),
            on(self.plain_dir.path(), false, &self.plain_clock),
        )
    }

    fn tick(&self, at: u64) {
        self.tagged_clock.set(at);
        self.plain_clock.set(at);
    }
}

/// Witnesses `text` in both arms; both mint the same turn id.
fn witness_both(tagged: &Vault, plain: &Vault, text: &str) -> EntityId {
    let turn = witness(tagged, text);
    assert_eq!(
        turn,
        witness(plain, text),
        "both arms mint the same turn id"
    );
    turn
}

/// Every content database matches; the job state, left out by name (the job
/// tables and `vault_meta`'s job rows, digested as `job_meta`), is where the
/// tagged run differs.
fn assert_only_job_tables_differ(tagged: &Vault, plain: &Vault) {
    let differing = differing_content(tagged, plain);
    assert!(
        differing.is_empty(),
        "content databases differ: {differing:?}"
    );
    assert_ne!(job_digests(tagged), job_digests(plain));
}

#[test]
fn an_armed_witness_commits_one_marker_and_an_unarmed_one_commits_none() {
    for armed in [true, false] {
        let dir = tempfile::tempdir().expect("dir");
        let vault = open(dir.path(), armed);
        let turn = witness(&vault, "Ada met Grace at the harbour");
        let markers = markers(&vault);
        if !armed {
            assert!(markers.is_empty());
            continue;
        }
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].state, AttemptState::Queued);
        assert_eq!(
            markers[0].dedupe_key.as_deref(),
            Some(format!("{}@{CHECKPOINT}", turn.to_hex()).as_str())
        );
    }
}

#[test]
fn a_witness_that_rolls_back_leaves_no_marker() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let refused = vault
        .memory(speaker(&vault), EdgeActorClass::Human)
        .witness_with_route_and_txn_effect(
            &turn(None, vec![message(0, "rolled back with the turn")]),
            None,
            || {},
            |_| Err(crate::Error::InvalidConfig("fixture refusal".into()).into()),
        );
    assert!(refused.is_err());
    assert!(markers(&vault).is_empty());
}

#[test]
fn an_exact_retry_owes_nothing_and_new_text_marks_the_turn_again() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let memory = vault.memory(speaker(&vault), EdgeActorClass::Human);
    let mut first = message(0, "first words of the turn");
    first.id = Some("61616161616161616161616161616161".into());
    let turn_ref = Some("62626262626262626262626262626262".into());
    memory
        .witness(&turn(turn_ref.clone(), vec![first.clone()]))
        .expect("witness");
    // A live marker absorbs a second mark of the same turn.
    memory
        .witness(&turn(turn_ref.clone(), vec![first.clone()]))
        .expect("exact retry");
    assert_eq!(markers(&vault).len(), 1);

    let tagger = Scripted::new(Answer::Good);
    reconciler(&vault, &tagger).drain_once().expect("drain");
    // The settled marker left the job ledger; its trace stayed.
    let tagged = EntityId::from_hex(turn_ref.as_deref().expect("turn ref")).expect("turn id");
    assert!(markers(&vault).is_empty());
    assert_eq!(settled(&vault, &tagged), 1);
    // A settled turn: the exact retry stages nothing and owes nothing.
    memory
        .witness(&turn(turn_ref.clone(), vec![first]))
        .expect("exact retry after settlement");
    assert!(markers(&vault).is_empty());
    // New text in the same turn owes a new pass.
    memory
        .witness(&turn(turn_ref, vec![message(1, "and a second message")]))
        .expect("append");
    assert_eq!(markers(&vault).len(), 1);
    assert_eq!(count(&vault, AttemptState::Queued), 1);
}

#[test]
fn a_moved_indexed_frontier_marks_the_turn_again() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    crate::test_util::publish_seeded_revisions(&vault);
    let turn = witness(&vault, "words the tagger read once");
    let tagger = Scripted::new(Answer::Good);
    reconciler(&vault, &tagger).drain_once().expect("drain");
    assert!(markers(&vault).is_empty());
    assert_eq!(settled(&vault, &turn), 1);

    let raw = vault.get(&turn).expect("read").expect("turn body");
    let mut body: serde_json::Value = rmp_serde::from_slice(&raw).expect("decode body");
    body["topic"] = serde_json::json!("an edited grouping fact");
    vault
        .batch()
        .put(
            &turn,
            crate::registry::ENTITY_TYPE_TURN,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
            &rmp_serde::to_vec_named(&body).expect("encode body"),
        )
        .commit()
        .expect("edit");
    // The edit moves the live revision; the indexed frontier waits for idle.
    assert!(markers(&vault).is_empty());
    vault.set_indexed_idle_delay_ms(0).expect("delay");
    let report = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("publish");
    assert!(report.refreshed.iter().any(|(entity, _)| *entity == turn));
    assert_eq!(count(&vault, AttemptState::Queued), 1);
    let pass = reconciler(&vault, &tagger).drain_once().expect("drain");
    assert_eq!(pass.traces.len(), 1);
    assert_eq!(pass.traces[0].turn, Some(turn));
    assert!(matches!(
        pass.traces[0].outcome,
        TaggingOutcome::Shadowed { .. }
    ));
}

#[test]
fn a_message_frontier_marks_the_turn_it_is_part_of() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let mut first = message(0, "a message whose text moves");
    first.id = Some("63636363636363636363636363636363".into());
    let receipt = vault
        .memory(speaker(&vault), EdgeActorClass::Human)
        .witness(&turn(None, vec![first.clone()]))
        .expect("witness");
    let turn = receipt_turn(&receipt);
    let tagger = Scripted::new(Answer::Good);
    reconciler(&vault, &tagger).drain_once().expect("drain");
    let message = EntityId::from_hex(first.id.as_deref().unwrap()).expect("message id");
    vault
        .try_with_write_txn(|txn| {
            super::mark_on_publication_in_txn(&vault, txn, &message, ENTITY_TYPE_MESSAGE)
        })
        .expect("publication mark");
    let queued: Vec<_> = markers(&vault)
        .into_iter()
        .filter(|record| record.state == AttemptState::Queued)
        .collect();
    assert_eq!(queued.len(), 1);
    assert_eq!(
        queued[0].dedupe_key.as_deref(),
        Some(format!("{}@{CHECKPOINT}", turn.to_hex()).as_str())
    );
}

/// Shadow writes nothing outside the job state (the three job tables and the
/// trace history), through the paths that retry a marker too (a failed call,
/// a refused answer, a lease a stopped worker left) and while the store clock
/// runs, an empty pass included. A write after them allocates the same entity
/// ids in both arms, even after the clock rolls back: no retry drew from the
/// vault's id source, and no pass moved the vault's clock floor, on disk or
/// in memory.
#[test]
fn shadow_leaves_every_content_database_as_a_run_with_no_tagger_leaves_it() {
    let arms = Arms::new();
    let tagger = Scripted::new(Answer::Fail);
    let mut turns = Vec::new();
    {
        let (tagged, plain) = arms.open();
        assert_eq!(content_digests(&tagged), content_digests(&plain));
        for text in [
            "Ada sailed north",
            "Grace stayed behind",
            "they wrote letters",
        ] {
            turns.push(witness_both(&tagged, &plain, text));
        }
        let reconciler = reconciler(&tagged, &tagger);
        let pass = reconciler.drain_once().expect("drain");
        assert_eq!(pass.traces.len(), 1);
        assert!(matches!(
            pass.traces[0].outcome,
            TaggingOutcome::Failed { .. }
        ));
        // The worker stops mid-call: its marker is still leased at restart.
        let leased = AttemptQueue::new(&tagged)
            .claim_kind(
                TAGGING_MARKER_KIND,
                ClaimAttempt {
                    lease_owner: "oneironer-tagging".into(),
                    now: u64::MAX,
                },
            )
            .expect("claim");
        assert!(matches!(leased, ClaimOutcome::Claimed(_)));
        arms.tick(NOW + 30);
        tagger.set(Answer::BadOffsets);
        let pass = reconciler.drain_once().expect("drain");
        assert_eq!(pass.traces.len(), 1);
        assert!(matches!(
            pass.traces[0].outcome,
            TaggingOutcome::Failed { .. }
        ));
        arms.tick(NOW + 60);
    }
    // Both arms restart, so the reopen is no difference between them.
    let (tagged, plain) = arms.open();
    let reconciler = reconciler(&tagged, &tagger);
    assert_eq!(reconciler.release_stale_leases().expect("release"), 1);
    arms.tick(NOW + 90);
    tagger.set(Answer::Good);
    let pass = reconciler.drain_once().expect("drain");
    assert_eq!(pass.traces.len(), 3);
    assert!(pass.traces.iter().all(|trace| matches!(
        trace.outcome,
        TaggingOutcome::Shadowed {
            spans: 2,
            links: 1,
            mood: true,
            mapped_spans: 1
        }
    )));
    // Every turn settled once, and its marker left the job ledger with the
    // two retried tries and the restarted lease. The two failed calls, the
    // handed-back lease and the three answers are the traces.
    assert!(markers(&tagged).is_empty());
    assert!(turns.iter().all(|turn| settled(&tagged, turn) == 1));
    assert_eq!(
        turns
            .iter()
            .map(|turn| history(&tagged, turn).len())
            .sum::<usize>(),
        6
    );
    arms.tick(NOW + 120);
    assert!(reconciler.drain_once().expect("drain").traces.is_empty());
    witness_both(&tagged, &plain, "the harbour froze that winter");
    arms.tick(NOW + 150);
    assert_eq!(reconciler.drain_once().expect("drain").traces.len(), 1);
    arms.tick(NOW + 130);
    witness_both(&tagged, &plain, "spring came late");
    assert_only_job_tables_differ(&tagged, &plain);
}

#[test]
fn a_failed_call_a_panic_and_bad_offsets_each_trace_and_retry_without_failing_the_write() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let turn = witness(&vault, "Ada sailed north");
    let tagger = Scripted::new(Answer::Fail);
    let reconciler = reconciler(&vault, &tagger);
    let mut traces = Vec::new();
    for answer in [
        Answer::Fail,
        Answer::Panic,
        Answer::BadOffsets,
        Answer::Good,
    ] {
        tagger.set(answer);
        let pass = reconciler.drain_once().expect("drain");
        assert_eq!(pass.traces.len(), 1, "one trace per attempt");
        traces.extend(pass.traces);
    }
    let outcomes: Vec<_> = traces.iter().map(|trace| trace.outcome.clone()).collect();
    assert!(matches!(
        &outcomes[0],
        TaggingOutcome::Failed { failure: TaggingFailure::Call { code }, .. }
            if code == "fixture tagger unreachable"
    ));
    assert!(matches!(
        outcomes[1],
        TaggingOutcome::Failed {
            failure: TaggingFailure::Panicked,
            ..
        }
    ));
    assert!(matches!(
        outcomes[2],
        TaggingOutcome::Failed {
            failure: TaggingFailure::Refused {
                refusal: OutputRefusal::BadOffsets
            },
            ..
        }
    ));
    assert!(matches!(outcomes[3], TaggingOutcome::Shadowed { .. }));
    assert_eq!(
        traces
            .iter()
            .map(|trace| trace.try_number)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    assert!(traces.iter().all(|trace| trace.turn == Some(turn)));
    assert_eq!(tagger.calls(), 4);
    // Every try's trace is recorded; the three retried tries left the job
    // ledger with the one that settled, and nothing is left owed.
    assert_eq!(history(&vault, &turn), outcomes);
    assert!(markers(&vault).is_empty());
    assert!(vault.get(&turn).expect("turn read").is_some());
}

#[test]
fn a_failed_call_ends_the_pass_and_waits_for_its_backoff() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    witness(&vault, "Ada sailed north");
    witness(&vault, "Grace stayed behind");
    let tagger = Scripted::new(Answer::Fail);
    let reconciler = reconciler(&vault, &tagger).with_backoff(TaggingBackoff {
        first_secs: 30,
        max_secs: 60,
    });
    let pass = reconciler.drain_once().expect("drain");
    assert_eq!(
        (pass.calls, pass.failed_calls, pass.traces.len()),
        (1, 1, 1)
    );
    let TaggingOutcome::Failed { retry_at, .. } = pass.traces[0].outcome else {
        panic!("the call failed");
    };
    assert_eq!(retry_at, NOW + 30);
    // The pass itself says when its failed marker is next owed a call.
    assert_eq!(pass.earliest_retry_at(), Some(NOW + 30));
    let failed_turn = pass.traces[0].turn;
    // The untouched marker is next; the failed one waits for its instant.
    tagger.set(Answer::Good);
    let pass = reconciler.drain_once().expect("drain");
    assert_eq!(pass.traces.len(), 1);
    assert_ne!(pass.traces[0].turn, failed_turn);
    assert_eq!(pass.earliest_retry_at(), None);
    assert!(reconciler.drain_once().expect("drain").traces.is_empty());
    assert_eq!(tagger.calls(), 2);
}

#[test]
fn a_crash_right_after_the_commit_resumes_with_no_lost_and_no_doubled_turn() {
    let dir = tempfile::tempdir().expect("dir");
    let turns = {
        let vault = open(dir.path(), true);
        let turns = [
            witness(&vault, "Ada sailed north"),
            witness(&vault, "Grace stayed behind"),
        ];
        // The second marker is mid-call when the process dies: leased, not
        // settled.
        let leased = AttemptQueue::new(&vault)
            .claim_kind(
                TAGGING_MARKER_KIND,
                ClaimAttempt {
                    lease_owner: "oneironer-tagging".into(),
                    now: u64::MAX,
                },
            )
            .expect("claim");
        assert!(matches!(leased, ClaimOutcome::Claimed(_)));
        turns
    };
    let vault = open(dir.path(), true);
    let tagger = Scripted::new(Answer::Good);
    let reconciler = reconciler(&vault, &tagger);
    assert_eq!(reconciler.release_stale_leases().expect("release"), 1);
    let pass = reconciler.drain_once().expect("drain");
    let mut tagged: Vec<EntityId> = pass.traces.iter().filter_map(|trace| trace.turn).collect();
    tagged.sort_by_key(|turn| *turn.as_bytes());
    let mut expected = turns.to_vec();
    expected.sort_by_key(|turn| *turn.as_bytes());
    assert_eq!(tagged, expected);
    assert_eq!(tagger.calls(), 2);
    assert_eq!(reconciler.drain_once().expect("drain").traces.len(), 0);
    // One settled marker per turn, gone from the job ledger with the
    // abandoned lease's retried try.
    assert!(turns.iter().all(|turn| settled(&vault, turn) == 1));
    assert!(markers(&vault).is_empty());
}

/// A claimed marker whose settlement fails on storage stays this worker's:
/// the same reconciler hands it back and settles it on its next pass, with no
/// restart and no lease sweep. Both settling writes are covered, the one that
/// completes an answer and the one that schedules a failed call's retry.
#[test]
fn a_settlement_that_fails_after_the_claim_is_settled_by_the_same_worker() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let tagger = Scripted::new(Answer::Good);
    let reconciler = reconciler(&vault, &tagger);
    let mut turns = Vec::new();
    for (call, text) in [
        (Answer::Good, "Ada sailed north"),
        (Answer::Fail, "Grace stayed behind"),
    ] {
        let turn = witness(&vault, text);
        turns.push(turn);
        tagger.set(call);
        vault.test_hooks().arm_fail_next_tagging_settlement();
        let error = reconciler
            .drain_once()
            .expect_err("the settling write fails");
        assert_eq!(error.kind(), ErrorKind::MapFull);
        assert_eq!(count(&vault, AttemptState::Leased), 1);
        // Storage is back.
        tagger.set(Answer::Good);
        let pass = reconciler.drain_once().expect("drain");
        assert_eq!(pass.traces.len(), 1);
        assert_eq!(pass.traces[0].turn, Some(turn));
        assert!(matches!(
            pass.traces[0].outcome,
            TaggingOutcome::Shadowed { .. }
        ));
        assert_eq!(count(&vault, AttemptState::Leased), 0);
        assert!(reconciler.drain_once().expect("drain").traces.is_empty());
    }
    assert!(turns.iter().all(|turn| settled(&vault, turn) == 1));
    assert!(markers(&vault).is_empty());
}

/// A stale-lease release at worker start that fails on storage stays owed:
/// the same reconciler releases the marker a stopped worker left on its next
/// pass and settles it, with no second restart.
#[test]
fn a_stale_lease_release_that_fails_is_finished_by_the_same_worker() {
    let dir = tempfile::tempdir().expect("dir");
    let turn = {
        let vault = open(dir.path(), true);
        let turn = witness(&vault, "Ada sailed north");
        let leased = AttemptQueue::new(&vault)
            .claim_kind(
                TAGGING_MARKER_KIND,
                ClaimAttempt {
                    lease_owner: "oneironer-tagging".into(),
                    now: u64::MAX,
                },
            )
            .expect("claim");
        assert!(matches!(leased, ClaimOutcome::Claimed(_)));
        turn
    };
    let vault = open(dir.path(), true);
    let tagger = Scripted::new(Answer::Good);
    let reconciler = reconciler(&vault, &tagger);
    vault.test_hooks().arm_fail_next_tagging_settlement();
    let error = reconciler
        .release_stale_leases()
        .expect_err("the release write fails");
    assert_eq!(error.kind(), ErrorKind::MapFull);
    assert_eq!(count(&vault, AttemptState::Leased), 1);
    // Storage is back.
    let pass = reconciler.drain_once().expect("drain");
    assert_eq!(pass.traces.len(), 1);
    assert_eq!(pass.traces[0].turn, Some(turn));
    assert!(matches!(
        pass.traces[0].outcome,
        TaggingOutcome::Shadowed { .. }
    ));
    assert_eq!(count(&vault, AttemptState::Leased), 0);
    assert_eq!(settled(&vault, &turn), 1);
    assert!(markers(&vault).is_empty());
}

/// A MESSAGE whose text lives in an entity document marks its turn again when
/// an edit changes the text, in the edit's transaction. Moving the text into
/// the document changes no text and owes nothing, nor does an edit set that
/// rolls back.
#[cfg(feature = "sync")]
#[test]
fn an_edit_that_changes_a_message_document_marks_its_turn_again() {
    use crate::entity_doc::{AnchoredEdit, DocAuthorization, EditVerb, TextField};
    use crate::write_envelope::WriteActor;

    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let writer = speaker(&vault);
    let mut first = message(0, "Ada sailed north");
    first.id = Some("66666666666666666666666666666666".into());
    let receipt = vault
        .memory(writer, EdgeActorClass::Human)
        .witness(&turn(None, vec![first.clone()]))
        .expect("witness");
    let tagged = receipt_turn(&receipt);
    let message = EntityId::from_hex(first.id.as_deref().expect("id")).expect("message id");
    let tagger = Scripted::new(Answer::Good);
    let reconciler = reconciler(&vault, &tagger);
    let read = reconciler.drain_once().expect("drain");
    assert_eq!(read.traces.len(), 1);

    let actor = WriteActor::new(writer, EdgeActorClass::Human);
    let owner = vault
        .authenticate_owner(
            writer,
            "principal:tagging-test",
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner");
    let authorization = DocAuthorization::Owner(&owner);
    vault
        .migrate_entity_text(
            &message,
            &TextField::MapField("content".into()),
            actor,
            &authorization,
        )
        .expect("migrate");
    assert_eq!(
        count(&vault, AttemptState::Queued),
        0,
        "moving the text into a document changes no text"
    );
    let end = vault.entity_text(&message).expect("text").chars().count();
    let append = AnchoredEdit {
        actor: Some(actor),
        verb: EditVerb::AppendToSection {
            section: vault
                .entity_text_anchor(&message, end, end)
                .expect("anchor"),
            text: " and Grace followed".into(),
        },
    };
    let mut unattributed = append.clone();
    unattributed.actor = None;
    assert!(
        vault
            .edit_entity_text(
                &message,
                &[append.clone(), unattributed],
                &authorization,
                NOW
            )
            .is_err()
    );
    assert_eq!(count(&vault, AttemptState::Queued), 0);

    vault
        .edit_entity_text(&message, &[append], &authorization, NOW)
        .expect("edit");
    let owed: Vec<_> = markers(&vault)
        .into_iter()
        .filter(|record| record.state == AttemptState::Queued)
        .collect();
    assert_eq!(owed.len(), 1);
    assert_eq!(
        owed[0].dedupe_key.as_deref(),
        Some(format!("{}@{CHECKPOINT}", tagged.to_hex()).as_str())
    );
    let pass = reconciler.drain_once().expect("drain");
    assert_eq!(pass.traces.len(), 1);
    assert!(matches!(
        pass.traces[0].outcome,
        TaggingOutcome::Shadowed { .. }
    ));
    assert_ne!(
        pass.traces[0].input_hash, read.traces[0].input_hash,
        "the pass reads the edited text"
    );
}

/// A stream continuation appends to a MESSAGE whose turn was already tagged:
/// the appended text owes the turn a pass, committed with it. An append whose
/// transaction rolls back owes nothing, nor does recovering the same text.
#[cfg(feature = "sync")]
#[test]
fn a_stream_continuation_marks_its_turn_again() {
    use crate::memory::MessageWriteMode;
    use crate::write_envelope::WriteActor;

    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let writer = speaker(&vault);
    let memory = vault.memory(writer, EdgeActorClass::Human);
    let mut streamed = message(0, "");
    streamed.id = Some("67676767676767676767676767676767".into());
    let input = turn(
        Some("68686868686868686868686868686868".into()),
        vec![streamed],
    );
    let first = memory
        .begin_message_stream(&input, Some(MessageWriteMode::Atomic))
        .expect("begin");
    memory
        .append_to_stream(first, "Ada sailed north")
        .expect("append");
    memory.finalize_stream(first).expect("finalize");
    let tagger = Scripted::new(Answer::Good);
    let reconciler = reconciler(&vault, &tagger);
    let read = reconciler.drain_once().expect("drain");
    assert_eq!(read.traces.len(), 1);
    let tagged = read.traces[0].turn.expect("turn");

    let message = first.message_id();
    let aborted = vault.with_write_txn(|txn| {
        crate::entity_doc::append_message_stream_in_txn(
            &vault,
            txn,
            &message,
            " rolled back",
            WriteActor::new(writer, EdgeActorClass::Human),
            NOW,
        )?;
        Err::<(), _>(crate::Error::InvalidConfig("fixture abort".into()))
    });
    assert!(aborted.is_err());
    assert_eq!(count(&vault, AttemptState::Queued), 0);

    let second = memory
        .begin_message_stream(&input, Some(MessageWriteMode::Atomic))
        .expect("continue");
    memory
        .append_to_stream(second, " and Grace followed")
        .expect("append");
    memory.finalize_stream(second).expect("finalize");
    let owed: Vec<_> = markers(&vault)
        .into_iter()
        .filter(|record| record.state == AttemptState::Queued)
        .collect();
    assert_eq!(owed.len(), 1);
    assert_eq!(
        owed[0].dedupe_key.as_deref(),
        Some(format!("{}@{CHECKPOINT}", tagged.to_hex()).as_str())
    );
    let pass = reconciler.drain_once().expect("drain");
    assert_eq!(pass.traces.len(), 1);
    assert!(matches!(
        pass.traces[0].outcome,
        TaggingOutcome::Shadowed { .. }
    ));
    assert_ne!(
        pass.traces[0].input_hash, read.traces[0].input_hash,
        "the pass reads the continued text"
    );

    // Recovering the same text from a canonical snapshot replaces the
    // document's pending update and changes no text: nothing more is owed.
    vault
        .with_write_txn(|txn| {
            let row = crate::entity_doc::capture_canonical(&vault, txn, *message.as_bytes())?
                .expect("a document to capture");
            crate::entity_doc::restore_canonical(&vault, txn, &row)
        })
        .expect("recover");
    assert_eq!(
        count(&vault, AttemptState::Queued),
        0,
        "recovering the same text owes nothing"
    );
}

/// Restoring a MESSAGE's document over a lost head makes readable text that
/// could not be read without it, so the restore owes the turn a pass.
#[cfg(feature = "sync")]
#[test]
fn restoring_a_lost_message_document_marks_its_turn_again() {
    use crate::entity_doc::{DocAuthorization, TextField};
    use crate::write_envelope::WriteActor;

    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let writer = speaker(&vault);
    let mut first = message(0, "Ada sailed north");
    first.id = Some("6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c".into());
    let receipt = vault
        .memory(writer, EdgeActorClass::Human)
        .witness(&turn(None, vec![first.clone()]))
        .expect("witness");
    let tagged = receipt_turn(&receipt);
    let message = EntityId::from_hex(first.id.as_deref().expect("id")).expect("message id");
    let tagger = Scripted::new(Answer::Good);
    let reconciler = reconciler(&vault, &tagger);
    assert_eq!(reconciler.drain_once().expect("drain").traces.len(), 1);
    let owner = vault
        .authenticate_owner(
            writer,
            "principal:tagging-test",
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner");
    vault
        .migrate_entity_text(
            &message,
            &TextField::MapField("content".into()),
            WriteActor::new(writer, EdgeActorClass::Human),
            &DocAuthorization::Owner(&owner),
        )
        .expect("migrate");
    let row = {
        let txn = vault.store.env.read_txn().expect("read");
        crate::entity_doc::capture_canonical(&vault, &txn, *message.as_bytes())
            .expect("capture")
            .expect("a document to capture")
    };
    vault
        .with_write_txn(|txn| crate::entity_doc::erase_in_txn(&vault.store, txn, &message))
        .expect("lose the document head");
    assert_eq!(count(&vault, AttemptState::Queued), 0);

    vault
        .with_write_txn(|txn| crate::entity_doc::restore_canonical(&vault, txn, &row))
        .expect("restore");
    let owed: Vec<_> = markers(&vault)
        .into_iter()
        .filter(|record| record.state == AttemptState::Queued)
        .collect();
    assert_eq!(owed.len(), 1);
    assert_eq!(
        owed[0].dedupe_key.as_deref(),
        Some(format!("{}@{CHECKPOINT}", tagged.to_hex()).as_str())
    );
    let pass = reconciler.drain_once().expect("drain");
    assert_eq!(pass.traces.len(), 1);
    assert!(matches!(
        pass.traces[0].outcome,
        TaggingOutcome::Shadowed { .. }
    ));
}

/// Settling a fork that changes a MESSAGE's text marks its turn, and the
/// marker moves no clock floor: given the same writes and the same ticks, the
/// tagged vault persists the untagged vault's clock floor.
#[cfg(feature = "sync")]
#[test]
fn a_settled_message_fork_marks_its_turn_and_moves_no_clock_floor() {
    use crate::entity_doc::{
        AnchoredEdit, DocAuthorization, EditVerb, ForkRequest, SettleVerb, TextField,
    };
    use crate::write_envelope::WriteActor;

    const PROPOSAL: [u8; 16] = [0x6b; 16];
    let arms = Arms::new();
    let (tagged, plain) = arms.open();
    let mut first = message(0, "Ada sailed north");
    first.id = Some("69696969696969696969696969696969".into());
    let message = EntityId::from_hex(first.id.as_deref().expect("id")).expect("message id");
    let writer = speaker(&tagged);
    let actor = WriteActor::new(writer, EdgeActorClass::Human);
    let mut owners = Vec::new();
    for vault in [&tagged, &plain] {
        vault
            .memory(writer, EdgeActorClass::Human)
            .witness(&turn(None, vec![first.clone()]))
            .expect("witness");
        let owner = vault
            .authenticate_owner(
                writer,
                "principal:tagging-test",
                true,
                crate::store::GateDecisionId::now(),
            )
            .expect("owner");
        vault
            .migrate_entity_text(
                &message,
                &TextField::MapField("content".into()),
                actor,
                &DocAuthorization::Owner(&owner),
            )
            .expect("migrate");
        let end = vault.entity_text(&message).expect("text").chars().count();
        let request = ForkRequest {
            entity: message,
            base: vault.entity_text_frontier(&message).expect("frontier"),
            actor,
            edits: vec![AnchoredEdit {
                actor: Some(actor),
                verb: EditVerb::InsertAfterAnchor {
                    anchor: vault
                        .entity_text_anchor(&message, end, end)
                        .expect("anchor"),
                    text: " and Grace followed".into(),
                },
            }],
            rewrite: None,
        };
        vault
            .open_text_proposal(
                &EntityId::from_bytes(PROPOSAL).expect("proposal id"),
                &[request],
                &DocAuthorization::ProposeOnly,
                NOW,
            )
            .expect("proposal");
        owners.push(owner);
    }
    let tagger = Scripted::new(Answer::Good);
    assert_eq!(
        reconciler(&tagged, &tagger)
            .drain_once()
            .expect("drain")
            .traces
            .len(),
        1
    );
    arms.tick(NOW + 30);
    for (vault, owner) in [&tagged, &plain].into_iter().zip(&owners) {
        vault
            .settle_text_proposal(
                &EntityId::from_bytes(PROPOSAL).expect("proposal id"),
                SettleVerb::Merge,
                &DocAuthorization::Owner(owner),
                actor,
                NOW + 30,
            )
            .expect("merge");
        assert_eq!(
            vault.entity_text(&message).expect("text"),
            "Ada sailed north and Grace followed"
        );
    }
    assert_eq!(count(&tagged, AttemptState::Queued), 1);
    let floor = |vault: &Vault| {
        let txn = vault.store.env.read_txn().expect("read");
        crate::ports::authorization_floor_in_txn(&vault.store, &txn).expect("clock floor")
    };
    assert_eq!(floor(&tagged), floor(&plain));
}

/// Promoting an off-record turn into base is a turn admission: the marker
/// commits with the promotion, an aborted promotion leaves none, and a retried
/// promotion, answered from its receipt, owes nothing more.
#[test]
fn a_promoted_off_record_turn_owes_one_marker_committed_with_the_promotion() {
    const SESSION: &str = "sess-tagging-promote";
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let session = vault
        .off_record_session_vault()
        .enter(SESSION, OffRecordBackendClass::Local)
        .expect("enter session");
    let receipt = vault
        .memory(speaker(&vault), EdgeActorClass::Human)
        .witness_into_session(
            &session,
            &WitnessTurn {
                // The room's own shell is the conversation.
                conversation_ref: String::new(),
                ..turn(None, vec![message(0, "Ada sailed north off the record")])
            },
            None,
        )
        .expect("session witness");
    let promoted = receipt_turn(&receipt);
    assert!(
        markers(&vault).is_empty(),
        "an off-record turn owes nothing"
    );

    let plan = session
        .overlay()
        .snapshot()
        .expect("overlay snapshot")
        .plan_promotion(promoted)
        .expect("promotion plan");
    let aborted = vault.with_write_txn(|wtxn| {
        FloorWrites::new(&vault.store).promote(&vault, wtxn, SESSION, &plan, NOW)?;
        Err::<(), _>(crate::Error::InvalidConfig("fixture abort".into()))
    });
    assert!(aborted.is_err());
    assert!(
        markers(&vault).is_empty(),
        "an aborted promotion owes nothing"
    );

    session.promote_turn(&promoted).expect("promote");
    let owed = markers(&vault);
    assert_eq!(owed.len(), 1);
    assert_eq!(owed[0].state, AttemptState::Queued);
    assert_eq!(
        owed[0].dedupe_key.as_deref(),
        Some(format!("{}@{CHECKPOINT}", promoted.to_hex()).as_str())
    );
    let tagger = Scripted::new(Answer::Good);
    let pass = reconciler(&vault, &tagger).drain_once().expect("drain");
    assert_eq!(pass.traces.len(), 1);
    assert_eq!(pass.traces[0].turn, Some(promoted));
    assert!(matches!(
        pass.traces[0].outcome,
        TaggingOutcome::Shadowed { .. }
    ));
    session.promote_turn(&promoted).expect("promote retry");
    assert!(
        markers(&vault).is_empty(),
        "a retried promotion owes nothing"
    );
    assert_eq!(settled(&vault, &promoted), 1);
    session.close().expect("close session");
}

#[test]
fn a_turn_edited_during_the_call_is_tagged_again_on_its_new_text() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let memory_vault = Arc::clone(&vault);
    let turn_ref = Some("64646464646464646464646464646464".to_owned());
    vault
        .memory(speaker(&vault), EdgeActorClass::Human)
        .witness(&turn(
            turn_ref.clone(),
            vec![message(0, "Ada sailed north")],
        ))
        .expect("witness");
    let tagger = Scripted::new(Answer::Good);
    *tagger.during_call.lock().expect("hook") = Some(Box::new(move || {
        memory_vault
            .memory(speaker(&memory_vault), EdgeActorClass::Human)
            .witness(&turn(turn_ref, vec![message(1, "then Grace followed")]))
            .expect("append during the call");
    }));
    let reconciler = reconciler(&vault, &tagger);
    // The superseded try is retried at once, in the same pass, on the new text.
    let pass = reconciler.drain_once().expect("drain");
    assert_eq!(pass.traces.len(), 2);
    assert!(matches!(
        pass.traces[0].outcome,
        TaggingOutcome::Superseded { .. }
    ));
    assert!(matches!(
        pass.traces[1].outcome,
        TaggingOutcome::Shadowed { .. }
    ));
    assert_ne!(pass.traces[0].input_hash, pass.traces[1].input_hash);
    assert_eq!(tagger.calls(), 2);
    assert!(markers(&vault).is_empty());
}

/// A retry owed at once is ready at once: superseded text is tagged again in
/// the same pass, even when the clock reads earlier at the next claim than it
/// did when the retry was scheduled.
#[test]
fn a_superseded_retry_is_ready_at_once_after_the_clock_rolls_back() {
    let dir = tempfile::tempdir().expect("dir");
    let clock = ManualClock::new(NOW);
    let vault = {
        let mut config = config(true);
        config.store_clock = clock.bundle();
        Arc::new(Vault::open(dir.path(), config).expect("open vault"))
    };
    let turn_ref = Some("6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d".to_owned());
    vault
        .memory(speaker(&vault), EdgeActorClass::Human)
        .witness(&turn(
            turn_ref.clone(),
            vec![message(0, "Ada sailed north")],
        ))
        .expect("witness");
    let tagger = Scripted::new(Answer::Good);
    {
        let writer = Arc::clone(&vault);
        let clock = Arc::clone(&clock);
        *tagger.during_call.lock().expect("hook") = Some(Box::new(move || {
            writer
                .memory(speaker(&writer), EdgeActorClass::Human)
                .witness(&turn(turn_ref, vec![message(1, "then Grace followed")]))
                .expect("append during the call");
            // The clock moves on before the retry is scheduled.
            clock.set(NOW + 30);
        }));
    }
    let reconciler = reconciler(&vault, &tagger);
    let rollback = Arc::clone(&clock);
    let pass = reconciler
        .drain_once_with(|trace| {
            // And reads earlier again before the next claim.
            if matches!(trace.outcome, TaggingOutcome::Superseded { .. }) {
                rollback.set(NOW + 10);
            }
        })
        .expect("drain");
    assert_eq!(pass.traces.len(), 2);
    assert!(matches!(
        pass.traces[0].outcome,
        TaggingOutcome::Superseded { .. }
    ));
    assert!(matches!(
        pass.traces[1].outcome,
        TaggingOutcome::Shadowed { .. }
    ));
    assert!(markers(&vault).is_empty());
}

#[test]
fn text_that_appears_after_an_empty_read_is_tagged_before_the_marker_settles() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let writer = Arc::clone(&vault);
    let turn_ref = Some("65656565656565656565656565656565".to_owned());
    vault
        .memory(speaker(&vault), EdgeActorClass::Human)
        .witness(&turn(turn_ref.clone(), vec![message(0, "")]))
        .expect("witness");
    // Visible text lands after the worker read the turn as empty and before
    // the transaction that settles the marker; the leased marker absorbs it.
    super::reconciler::set_after_turn_read_hook(move || {
        writer
            .memory(speaker(&writer), EdgeActorClass::Human)
            .witness(&turn(turn_ref, vec![message(1, "then Grace followed")]))
            .expect("text between the read and the settle");
    });
    let tagger = Scripted::new(Answer::Good);
    let pass = reconciler(&vault, &tagger).drain_once().expect("drain");
    assert_eq!(pass.traces.len(), 2);
    assert!(matches!(
        pass.traces[0].outcome,
        TaggingOutcome::Superseded { .. }
    ));
    assert!(matches!(
        pass.traces[1].outcome,
        TaggingOutcome::Shadowed { .. }
    ));
    assert_eq!(tagger.calls(), 1);
    assert!(markers(&vault).is_empty());
}

/// A long retry history of one turn, all in one second, takes none of the
/// ids the turn's markers need: each retry's id names the try it retries. The
/// history leaves the worker able to claim the turn, and a write that adds
/// text to it still lands.
#[test]
fn a_long_retry_history_in_one_second_leaves_the_turn_its_ids() {
    const OWNER: &str = "oneironer-tagging";
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let turn_ref = Some("6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e".to_owned());
    let memory = vault.memory(speaker(&vault), EdgeActorClass::Human);
    memory
        .witness(&turn(
            turn_ref.clone(),
            vec![message(0, "Ada sailed north")],
        ))
        .expect("witness");
    let first = markers(&vault).remove(0);
    let key = first.dedupe_key.expect("dedupe key");
    let queue = AttemptQueue::from_store(&vault.store);
    // Each try is claimed and retried at once, every one at the second NOW,
    // through the door the worker retries by.
    vault
        .with_write_txn(|txn| {
            for _ in 0..4_100 {
                let next = queue
                    .pending_dedupe_in_txn(txn, TAGGING_MARKER_KIND, &key)?
                    .expect("a pending try");
                let ClaimOutcome::Claimed(leased) = queue.claim_id_storage_in_txn(
                    txn,
                    next.id,
                    ClaimAttempt {
                        lease_owner: OWNER.into(),
                        now: NOW,
                    },
                    NOW,
                )?
                else {
                    panic!("the retry is ready at once");
                };
                super::marker::retry_marker_in_txn(
                    &vault,
                    txn,
                    RetryAttempt {
                        id: leased.id,
                        lease_owner: OWNER.into(),
                        attempt_count: leased.attempt_count,
                        backoff_until: 0,
                        last_error: Some("call_failed".into()),
                        now: NOW,
                    },
                )?;
            }
            Ok(())
        })
        .expect("a long retry history");
    memory
        .witness(&turn(turn_ref, vec![message(1, "then Grace followed")]))
        .expect("text added to the turn lands");
    let tagger = Scripted::new(Answer::Good);
    let pass = reconciler(&vault, &tagger).drain_once().expect("drain");
    assert_eq!(pass.traces.len(), 1);
    assert!(matches!(
        pass.traces[0].outcome,
        TaggingOutcome::Shadowed { .. }
    ));
    // The settled marker left the job ledger with all 4,100 tries it retried.
    assert!(markers(&vault).is_empty());
}

#[test]
fn a_stale_lease_release_passes_over_other_owners_and_undecodable_rows() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    witness(&vault, "Ada sailed north");
    witness(&vault, "Grace stayed behind");
    let queue = AttemptQueue::new(&vault);
    for owner in ["oneironer-tagging", "another-worker"] {
        let claimed = queue
            .claim_kind(
                TAGGING_MARKER_KIND,
                ClaimAttempt {
                    lease_owner: owner.into(),
                    now: u64::MAX,
                },
            )
            .expect("claim");
        assert!(matches!(claimed, ClaimOutcome::Claimed(_)));
    }
    // A job row of no kind this build can read.
    vault
        .try_with_write_txn(|txn| {
            vault
                .store
                .attempt_records
                .put(txn, &[0xee; 16], b"not an attempt record")?;
            Ok::<(), crate::Error>(())
        })
        .expect("undecodable row");
    let tagger = Scripted::new(Answer::Good);
    let reconciler = reconciler(&vault, &tagger);
    assert_eq!(reconciler.release_stale_leases().expect("release"), 1);
    // The full listing decodes every row, so the bad one goes first.
    vault
        .try_with_write_txn(|txn| {
            vault.store.attempt_records.delete(txn, &[0xee; 16])?;
            Ok::<(), crate::Error>(())
        })
        .expect("drop the undecodable row");
    // This owner's lease is a retried try with a new scheduled row; the
    // other owner's stays leased.
    assert_eq!(count(&vault, AttemptState::Failed), 1);
    assert_eq!(count(&vault, AttemptState::Scheduled), 1);
    assert_eq!(count(&vault, AttemptState::Leased), 1);
}

#[test]
fn a_gone_or_empty_turn_settles_with_no_call() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    vault
        .memory(speaker(&vault), EdgeActorClass::Human)
        .witness(&turn(None, vec![message(0, "")]))
        .expect("witness");
    let tagger = Scripted::new(Answer::Good);
    let pass = reconciler(&vault, &tagger).drain_once().expect("drain");
    assert_eq!(tagger.calls(), 0);
    assert!(matches!(
        pass.traces[0].outcome,
        TaggingOutcome::Skipped {
            reason: SkipReason::NoText
        }
    ));
    assert!(markers(&vault).is_empty());
    assert_eq!(
        pass.traces[0].turn.map(|turn| settled(&vault, &turn)),
        Some(1)
    );
}

#[test]
fn a_marker_for_another_checkpoint_moves_onto_the_active_one() {
    let dir = tempfile::tempdir().expect("dir");
    let turn = {
        let mut config = config(true);
        config.tagging = Some(TaggingMarkerConfig::new(OTHER_CHECKPOINT).expect("checkpoint"));
        let vault = Vault::open(dir.path(), config).expect("open");
        witness(&vault, "Ada sailed north")
    };
    let vault = open(dir.path(), true);
    let tagger = Scripted::new(Answer::Good);
    let reconciler = reconciler(&vault, &tagger);
    let pass = reconciler.drain_once().expect("drain");
    let outcomes: Vec<_> = pass.traces.iter().map(|trace| &trace.outcome).collect();
    assert!(matches!(outcomes[0], TaggingOutcome::Rekeyed));
    assert!(matches!(outcomes[1], TaggingOutcome::Shadowed { .. }));
    assert_eq!(pass.traces[1].checkpoint, CHECKPOINT);
    assert_eq!(pass.traces[1].turn, Some(turn));
    assert_eq!(tagger.calls(), 1);
}

/// An importer's held tags complete a marker in shadow, while the store
/// clock runs, without writing outside the job state, and a write after the
/// clock rolls back is the same in both arms.
#[test]
fn held_tags_complete_a_marker_writing_only_the_job_tables() {
    let arms = Arms::new();
    let (tagged, plain) = arms.open();
    let turn = witness_both(&tagged, &plain, "Ada sailed north");
    arms.tick(NOW + 30);
    assert!(matches!(
        tagged
            .complete_tagging_with_held_tags(&turn, &held(3))
            .expect("held tags"),
        HeldTagsOutcome::Completed(_)
    ));
    assert_only_job_tables_differ(&tagged, &plain);
    arms.tick(NOW + 10);
    witness_both(&tagged, &plain, "Grace stayed behind");
    assert_only_job_tables_differ(&tagged, &plain);
}

/// A claim stamps its lease once it holds the write lock: time that passes
/// while it waits for the lock is not charged to the lease. A seam moves the
/// clock the moment the claim's write transaction is open, so a lease sweep
/// at that second, during the call, finds the lease fresh, and the answer
/// settles; a stamp taken before the transaction opened would be stale.
#[test]
fn a_claim_stamps_its_lease_once_it_holds_the_write_lock() {
    let dir = tempfile::tempdir().expect("dir");
    let clock = ManualClock::new(NOW);
    let vault = {
        let mut config = config(true);
        config.store_clock = clock.bundle();
        Arc::new(Vault::open(dir.path(), config).expect("open vault"))
    };
    let turn = witness(&vault, "Ada sailed north");
    let requeued = Arc::new(AtomicU64::new(u64::MAX));
    let tagger = Scripted::new(Answer::Good);
    {
        let vault = Arc::clone(&vault);
        let requeued = Arc::clone(&requeued);
        *tagger.during_call.lock().expect("hook") = Some(Box::new(move || {
            let swept = AttemptQueue::new(&vault)
                .cleanup_leases(CleanupAttemptLeases {
                    now: NOW + 10,
                    lease_timeout_secs: 5,
                })
                .expect("sweep");
            requeued.store(swept.stale_requeued, Ordering::SeqCst);
        }));
    }
    let reconciler = reconciler(&vault, &tagger);
    assert_eq!(reconciler.release_stale_leases().expect("release"), 0);
    {
        let clock = Arc::clone(&clock);
        vault
            .test_hooks()
            .install_after_tagging_claim_writer(move || clock.set(NOW + 10));
    }
    let pass = reconciler.drain_once().expect("drain");
    assert_eq!(
        requeued.load(Ordering::SeqCst),
        0,
        "the fresh lease is not stale"
    );
    assert_eq!(pass.traces.len(), 1);
    assert_eq!(pass.traces[0].turn, Some(turn));
    assert!(matches!(
        pass.traces[0].outcome,
        TaggingOutcome::Shadowed { .. }
    ));
}

/// A lease is stamped no lower than the clock floor the vault has committed,
/// even one another handle on the vault committed while this store's clock
/// never saw it and its source has fallen behind: a lease sweep at that
/// floor, during the call, finds the lease fresh, and the answer settles.
#[test]
fn a_lease_is_stamped_at_least_at_the_committed_clock_floor() {
    let dir = tempfile::tempdir().expect("dir");
    let clock = ManualClock::new(NOW);
    let vault = {
        let mut config = config(true);
        config.store_clock = clock.bundle();
        Arc::new(Vault::open(dir.path(), config).expect("open vault"))
    };
    let turn = witness(&vault, "Ada sailed north");
    // Another handle on the vault commits a later floor.
    vault
        .with_write_txn(|txn| {
            vault.store.vault_meta.put(
                txn,
                crate::ports::CLOCK_FLOOR,
                &(NOW + 30).to_be_bytes(),
            )?;
            Ok(())
        })
        .expect("a later committed floor");
    clock.set(NOW + 10);
    let requeued = Arc::new(AtomicU64::new(u64::MAX));
    let tagger = Scripted::new(Answer::Good);
    {
        let vault = Arc::clone(&vault);
        let requeued = Arc::clone(&requeued);
        *tagger.during_call.lock().expect("hook") = Some(Box::new(move || {
            let swept = AttemptQueue::new(&vault)
                .cleanup_leases(CleanupAttemptLeases {
                    now: NOW + 30,
                    lease_timeout_secs: 5,
                })
                .expect("sweep");
            requeued.store(swept.stale_requeued, Ordering::SeqCst);
        }));
    }
    let pass = reconciler(&vault, &tagger).drain_once().expect("drain");
    assert_eq!(
        requeued.load(Ordering::SeqCst),
        0,
        "the fresh lease is not stale"
    );
    assert_eq!(pass.traces.len(), 1);
    assert_eq!(pass.traces[0].turn, Some(turn));
    assert!(matches!(
        pass.traces[0].outcome,
        TaggingOutcome::Shadowed { .. }
    ));
}

#[test]
fn an_importer_completes_a_marker_with_held_tags_and_no_call() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let turn = witness(&vault, "Ada sailed north");
    assert_eq!(
        vault
            .complete_tagging_with_held_tags(&turn, &held(400))
            .expect("refused"),
        HeldTagsOutcome::Refused(OutputRefusal::BadOffsets)
    );
    assert_eq!(count(&vault, AttemptState::Queued), 1);
    let HeldTagsOutcome::Completed(trace) = vault
        .complete_tagging_with_held_tags(&turn, &held(3))
        .expect("completed")
    else {
        panic!("held tags complete the marker");
    };
    assert!(matches!(
        trace.outcome,
        TaggingOutcome::Imported {
            spans: 1,
            links: 0,
            mood: true
        }
    ));
    assert_eq!(trace.try_number, 1);
    assert!(markers(&vault).is_empty());
    assert_eq!(history(&vault, &turn), vec![trace.outcome]);
    assert_eq!(
        vault
            .complete_tagging_with_held_tags(&turn, &held(3))
            .expect("again"),
        HeldTagsOutcome::NoMarker
    );
    let tagger = Scripted::new(Answer::Good);
    assert!(
        reconciler(&vault, &tagger)
            .drain_once()
            .expect("drain")
            .traces
            .is_empty()
    );
    assert_eq!(tagger.calls(), 0);
}

/// Held tags that complete a retried marker report its place in the retry
/// chain: here the worker's call failed, and the retry it then claimed lost
/// its lease to a sweep before an importer completed it, as the second try.
#[test]
fn held_tags_completing_a_retried_marker_report_its_try() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let turn = witness(&vault, "Ada sailed north");
    let tagger = Scripted::new(Answer::Fail);
    let pass = reconciler(&vault, &tagger).drain_once().expect("drain");
    assert!(matches!(
        pass.traces[0].outcome,
        TaggingOutcome::Failed { .. }
    ));
    let claimed = AttemptQueue::new(&vault)
        .claim_kind(
            TAGGING_MARKER_KIND,
            ClaimAttempt {
                lease_owner: "oneironer-tagging".into(),
                now: u64::MAX,
            },
        )
        .expect("claim the retry");
    assert!(matches!(claimed, ClaimOutcome::Claimed(_)));
    let swept = AttemptQueue::new(&vault)
        .cleanup_leases(CleanupAttemptLeases {
            now: NOW + 100,
            lease_timeout_secs: 1,
        })
        .expect("sweep");
    assert_eq!(swept.stale_requeued, 1);
    let HeldTagsOutcome::Completed(trace) = vault
        .complete_tagging_with_held_tags(&turn, &held(3))
        .expect("held tags")
    else {
        panic!("held tags complete the requeued retry");
    };
    assert_eq!(trace.try_number, 2);
}

#[test]
fn a_marker_the_worker_holds_is_not_completed_by_an_importer() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let turn = witness(&vault, "Ada sailed north");
    let claimed = AttemptQueue::new(&vault)
        .claim_kind(
            TAGGING_MARKER_KIND,
            ClaimAttempt {
                lease_owner: "oneironer-tagging".into(),
                now: u64::MAX,
            },
        )
        .expect("claim");
    assert!(matches!(claimed, ClaimOutcome::Claimed(_)));
    let tags = held(3);
    assert_eq!(
        vault
            .complete_tagging_with_held_tags(&turn, &tags)
            .expect("held"),
        HeldTagsOutcome::WorkerOwned
    );
    assert_eq!(count(&vault, AttemptState::Leased), 1);
}

#[test]
fn a_checkpoint_that_is_not_sixteen_lowercase_hex_digits_is_refused_at_open() {
    for bad in [
        "0123456789ABCDEF",
        "0123456789abcde",
        "0123456789abcdefa",
        "",
    ] {
        let dir = tempfile::tempdir().expect("dir");
        let mut config = config(false);
        config.tagging = Some(TaggingMarkerConfig {
            checkpoint: bad.into(),
            ..TaggingMarkerConfig::new(CHECKPOINT).expect("checkpoint")
        });
        assert!(matches!(
            Vault::open(dir.path(), config),
            Err(crate::Error::InvalidConfig(_))
        ));
    }
}

#[test]
fn an_off_device_tagger_and_an_unarmed_vault_are_refused() {
    struct Remote;
    impl ExtractionEncoder for Remote {
        fn model_id(&self) -> &ModelId {
            unreachable!("never called")
        }
        fn locality(&self) -> crate::embed::EmbedderLocality {
            crate::embed::EmbedderLocality::OwnerServer
        }
        fn infer(&self, _: &EncoderInput) -> crate::Result<EncoderOutput> {
            unreachable!("never called")
        }
    }
    let dir = tempfile::tempdir().expect("dir");
    let armed = open(dir.path(), true);
    assert!(TaggingReconciler::new(Arc::clone(&armed), Arc::new(Remote)).is_err());
    drop(armed);
    let unarmed = open(dir.path(), false);
    assert!(TaggingReconciler::new(unarmed, Scripted::new(Answer::Good)).is_err());
}

/// Plants `count` settled markers the way a build that kept every settled
/// marker left them: Completed rows of the job ledger that hold no index
/// entry. The first settles through the queue's own doors; the rest are its
/// copies under further ids.
fn plant_settled_markers(vault: &Vault, count: u64, settled_at: u64) {
    use crate::attempt_queue::{AttemptId, CompleteAttempt};
    const OWNER: &str = "earlier-build";
    let queue = AttemptQueue::new(vault);
    let mut txn = vault.store.env.write_txn().expect("write txn");
    let turn = EntityId::from_bytes([0x5e; 16]).expect("turn id");
    super::marker::enqueue_marker_in_txn(vault, &mut txn, turn, CHECKPOINT, settled_at)
        .expect("marker");
    let ClaimOutcome::Claimed(leased) = queue
        .claim_kind_storage_in_txn(
            &mut txn,
            Some(TAGGING_MARKER_KIND),
            ClaimAttempt {
                lease_owner: OWNER.into(),
                now: settled_at,
            },
            settled_at,
        )
        .expect("claim")
    else {
        panic!("the planted marker is ready");
    };
    queue
        .complete_storage_in_txn(
            &mut txn,
            CompleteAttempt {
                id: leased.id,
                lease_owner: OWNER.into(),
                attempt_count: leased.attempt_count,
                now: settled_at,
            },
        )
        .expect("complete");
    let template = queue
        .get_in_write_txn(&txn, leased.id)
        .expect("read")
        .expect("settled row");
    for n in 1..count {
        let mut row = template.clone();
        // The marker's own id layout: its range and second, then a count.
        let mut id = *template.id.as_bytes();
        id[8..].copy_from_slice(&n.to_be_bytes());
        row.id = AttemptId::from_bytes(&id).expect("id");
        let encoded = crate::attempt_queue::encode_signal_record(&row).expect("encode");
        vault
            .store
            .attempt_records
            .put(&mut txn, row.id.as_bytes(), &encoded)
            .expect("plant");
    }
    txn.commit().expect("commit");
}

fn ledger_rows(vault: &Vault) -> u64 {
    let txn = vault.store.env.read_txn().expect("read txn");
    vault
        .store
        .attempt_records
        .len(&txn)
        .expect("ledger length")
}

/// Binds the seeded team lead as a resident woken by human messages, as the
/// resident dispatch tests do, and returns its agent id.
fn bind_resident(vault: &Vault) -> EntityId {
    use crate::agent_dispatch::{ResidentAgentSpec, ResidentGoalRecord, ResidentWakeMode};
    use crate::task_verb::ConsultPayloadRef;
    let owner = EntityId::now();
    vault
        .put_entity(
            &owner,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )
        .expect("owner");
    let (lead, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")
        .expect("seeded definitions")
        .expect("team lead");
    let inbox = EntityId::now();
    vault
        .create_own_app_channel_identity(&inbox, lead, 1)
        .expect("inbox identity");
    let room = EntityId::now();
    let node = EntityId::now();
    let goal = EntityId::now();
    vault
        .put_entity(
            &goal,
            crate::registry::ENTITY_TYPE_TURN,
            TimeRange { start: 1, end: 1 },
            1,
            &[0x80],
        )
        .expect("goal");
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: None,
            occurred_at: 2,
            messages: vec![WitnessMessage {
                id: Some(node.to_hex()),
                ..message(0, "room")
            }],
        })
        .expect("room");
    let auth = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner auth");
    let spec = ResidentAgentSpec {
        agent_def_ref: lead,
        inbox_identity_ref: inbox,
        home_conversation_ref: room,
        home_message_ref: node,
        goal: ResidentGoalRecord {
            goal: ConsultPayloadRef::Turn(goal),
            why: ConsultPayloadRef::Turn(goal),
            axes: vec![],
        },
        wake: ResidentWakeMode::HumanMessages,
    };
    vault
        .bind_resident_agent(&auth, &spec, 3)
        .expect("resident");
    lead
}

/// A vault holding more settled tagging markers than the ledger's all-kinds
/// scan cap still serves the inbox lens and resident dispatch: a scan for
/// another kind passes tagging rows over, uncounted.
#[test]
fn a_vault_past_100k_settled_tagging_markers_still_serves_the_inbox_and_resident_dispatch() {
    let config = VaultConfig {
        store_clock: ManualClock::new(NOW).bundle(),
        tagging: Some(TaggingMarkerConfig::new(CHECKPOINT).expect("checkpoint")),
        ..VaultConfig::default()
    };
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    let lead = bind_resident(&vault);
    let cap = crate::receipt::MAX_RECEIPT_QUERY_SCAN as u64;
    plant_settled_markers(&vault, cap + 1, NOW);
    assert!(ledger_rows(&vault) > cap);
    let lens = vault.agent_inbox_lens(crate::agent_inbox_lens::AgentInboxLensQuery {
        identity_ref: None,
        limit: 16,
        before: None,
    });
    assert!(lens.is_ok(), "the inbox lens fails closed: {lens:?}");
    let dispatched =
        crate::agent_dispatch::AgentDispatcher::new(&vault).dispatch_resident_inbox(lead, 16, 4);
    assert!(
        dispatched.is_ok(),
        "resident dispatch fails closed: {:?}",
        dispatched.err()
    );
}

/// Completes one job of another kind at `NOW`, as cleanup's own tests do.
fn complete_other_job(vault: &Vault) -> crate::attempt_queue::AttemptId {
    use crate::attempt_queue::{CompleteAttempt, EnqueueAttempt};
    let queue = AttemptQueue::new(vault);
    queue
        .enqueue(EnqueueAttempt {
            kind: "test.retained".into(),
            payload: vec![1, 2, 3],
            dedupe_key: None,
            run_id: None,
            now: NOW,
        })
        .expect("enqueue");
    let ClaimOutcome::Claimed(other) = queue
        .claim_kind(
            "test.retained",
            ClaimAttempt {
                lease_owner: "test".into(),
                now: NOW,
            },
        )
        .expect("claim")
    else {
        panic!("the other job is ready");
    };
    queue
        .complete(CompleteAttempt {
            id: other.id,
            lease_owner: "test".into(),
            attempt_count: other.attempt_count,
            now: NOW,
        })
        .expect("complete");
    other.id
}

/// A vault on `clock`, armed.
fn open_on(path: &std::path::Path, clock: &Arc<ManualClock>) -> Arc<Vault> {
    let mut config = config(true);
    config.store_clock = clock.bundle();
    Arc::new(Vault::open(path, config).expect("open vault"))
}

/// Runs a cleanup pass past the 90-day horizon and returns the ids it proposed.
fn cleanup_proposals(vault: &Vault, clock: &ManualClock) -> Vec<[u8; 16]> {
    clock.set(NOW + 91 * 86_400);
    vault.set_task_retention_days(Some(90)).expect("retention");
    crate::vault_cleanup::run_vault_cleanup(vault, &crate::attempt_queue::AttemptId::now())
        .expect("cleanup")
        .candidates
        .iter()
        .map(|candidate| *candidate.entity.as_bytes())
        .collect()
}

/// Settled tagging markers are job state: a cleanup pass past the retention
/// horizon proposes none of them, so they mint no proposal id. A completed
/// job of another kind beside them is still proposed.
#[test]
fn vault_cleanup_proposes_nothing_from_tagging_markers() {
    let dir = tempfile::tempdir().expect("dir");
    let clock = ManualClock::new(NOW);
    let vault = open_on(dir.path(), &clock);
    plant_settled_markers(&vault, 3, NOW);
    let other = complete_other_job(&vault);
    assert_eq!(
        cleanup_proposals(&vault, &clock),
        vec![*other.as_bytes()],
        "only the other job is proposed"
    );
}

/// Witnesses `content` as a fresh turn of the fixture room at `occurred_at`.
fn witness_at(vault: &Vault, content: &str, occurred_at: u64) -> EntityId {
    let receipt = vault
        .memory(speaker(vault), EdgeActorClass::Human)
        .witness(&WitnessTurn {
            occurred_at,
            ..turn(None, vec![message(0, content)])
        })
        .expect("witness");
    receipt_turn(&receipt)
}

/// The turns of a window, each as its turn id and its message texts.
fn window(input: &EncoderInput) -> Vec<(String, Vec<String>)> {
    input
        .context
        .iter()
        .map(|turn| {
            (
                turn.turn.clone(),
                turn.messages
                    .iter()
                    .map(|message| message.text.clone())
                    .collect(),
            )
        })
        .collect()
}

/// A live turn is tagged with the earlier text of its conversation, oldest
/// first, and never with a later turn, even one witnessed before the worker
/// read it. The window is bounded by its configured size: past the bound
/// the oldest text is cut from the left, and a size of zero sends the turn
/// alone. The window enters the input digest.
#[test]
fn a_live_turn_reads_the_earlier_window_and_never_a_later_turn() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let first = witness_at(&vault, "Ada sailed north", NOW);
    let second = witness_at(&vault, "Grace stayed behind", NOW + 1);
    let third = witness_at(&vault, "they wrote letters", NOW + 2);
    let tagger = Scripted::new(Answer::Good);
    let pass = reconciler(&vault, &tagger)
        .with_batch_size(3)
        .drain_once()
        .expect("drain");
    assert_eq!(pass.traces.len(), 3);
    let inputs = tagger.inputs.lock().expect("inputs").clone();
    let input = |turn: &EntityId| {
        inputs
            .iter()
            .find(|input| input.turn == turn.to_hex())
            .expect("the turn was tagged")
            .clone()
    };
    let line = |turn: &EntityId, text: &str| (turn.to_hex(), vec![text.to_owned()]);
    assert!(input(&first).context.is_empty());
    assert_eq!(
        window(&input(&second)),
        vec![line(&first, "Ada sailed north")]
    );
    assert_eq!(
        window(&input(&third)),
        vec![
            line(&first, "Ada sailed north"),
            line(&second, "Grace stayed behind")
        ]
    );
    for input in &inputs {
        assert_eq!(input.messages.len(), 1, "a window's turns are not tagged");
    }
    let hashes: Vec<_> = pass
        .traces
        .iter()
        .map(|trace| trace.input_hash.clone())
        .collect();
    assert!(hashes.iter().all(Option::is_some));
    drop(vault);

    // Two tokens' worth of window: the newest 32 characters of earlier text,
    // the oldest turn cut from the left. Zero: the turn alone.
    for (tokens, expected) in [
        (
            2,
            vec![
                line(&first, " sailed north"),
                line(&second, "Grace stayed behind"),
            ],
        ),
        (0, Vec::new()),
    ] {
        let mut config = config(true);
        config.tagging = Some(
            TaggingMarkerConfig::new(CHECKPOINT)
                .expect("checkpoint")
                .with_live_window_tokens(tokens),
        );
        let vault = Arc::new(Vault::open(dir.path(), config).expect("reopen"));
        let read = vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)
            .and_then(|txn| super::input::turn_input_in_txn(&vault, &txn, &third))
            .expect("read the third turn");
        let super::input::TurnInput::Ready {
            input,
            hash,
            text_hash,
        } = read
        else {
            panic!("the third turn has text");
        };
        assert_eq!(window(&input), expected, "window of {tokens} tokens");
        // The window enters the input's digest; the turn's own text has its
        // own, the one a settlement compares.
        assert_eq!(hash != text_hash, !expected.is_empty());
    }
}

/// The trace history keeps exactly what its bounds say: a turn's newest
/// traces up to the per-turn bound, and, once a pass has run, none past the
/// age bound. The job ledger keeps no settled marker and no try it retried.
#[test]
fn pruning_keeps_exactly_the_configured_trace_history() {
    let dir = tempfile::tempdir().expect("dir");
    let clock = ManualClock::new(NOW);
    let vault = {
        let mut config = config(true);
        config.store_clock = clock.bundle();
        config.tagging = Some(
            TaggingMarkerConfig::new(CHECKPOINT)
                .expect("checkpoint")
                .with_trace_history(TaggingTraceHistory {
                    per_turn: 3,
                    max_age_secs: 100,
                }),
        );
        Arc::new(Vault::open(dir.path(), config).expect("open vault"))
    };
    let tagger = Scripted::new(Answer::Good);
    let reconciler = reconciler(&vault, &tagger);
    let old = witness(&vault, "the oldest turn");
    reconciler.drain_once().expect("drain");
    assert_eq!(history(&vault, &old).len(), 1);

    // One turn tagged five times, the first a failed call: its traces past
    // the newest three are dropped, the failed one first.
    clock.set(NOW + 50);
    let turn_ref = Some("6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f".to_owned());
    let busy = EntityId::from_hex(turn_ref.as_deref().expect("ref")).expect("turn id");
    let memory = vault.memory(speaker(&vault), EdgeActorClass::Human);
    memory
        .witness(&turn(
            turn_ref.clone(),
            vec![message(0, "Ada sailed north")],
        ))
        .expect("witness");
    tagger.set(Answer::Fail);
    reconciler.drain_once().expect("drain");
    tagger.set(Answer::Good);
    reconciler.drain_once().expect("drain");
    for order in 1..=3_u32 {
        clock.set(NOW + 50 + u64::from(order));
        memory
            .witness(&turn(
                turn_ref.clone(),
                vec![message(order, "and then some more")],
            ))
            .expect("more text");
        reconciler.drain_once().expect("drain");
    }
    let kept = vault.tagging_trace_history(Some(&busy)).expect("history");
    assert_eq!(
        kept.iter()
            .map(|record| record.recorded_at)
            .collect::<Vec<_>>(),
        vec![NOW + 51, NOW + 52, NOW + 53]
    );
    assert!(
        kept.iter()
            .all(|record| matches!(record.trace.outcome, TaggingOutcome::Shadowed { .. }))
    );
    assert!(markers(&vault).is_empty(), "no settled marker or try stays");

    // Past the age bound a trace stays until a pass prunes it; then only
    // the traces within the bound are left.
    clock.set(NOW + 101);
    assert_eq!(history(&vault, &old).len(), 1);
    assert!(reconciler.drain_once().expect("drain").traces.is_empty());
    assert!(history(&vault, &old).is_empty());
    assert_eq!(history(&vault, &busy).len(), 3);
    clock.set(NOW + 153);
    reconciler.drain_once().expect("drain");
    assert_eq!(history(&vault, &busy).len(), 1);
    clock.set(NOW + 154);
    reconciler.drain_once().expect("drain");
    assert!(history(&vault, &busy).is_empty());
}

/// A scan for another job kind never reads the tagging range: not a settled
/// marker, not a live one, not even a row there it could not decode.
#[test]
fn a_scan_for_another_kind_never_reads_a_tagging_row() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    witness(&vault, "Ada sailed north");
    plant_settled_markers(&vault, 3, NOW);
    let mut undecodable = *markers(&vault)[0].id.as_bytes();
    undecodable[8..].copy_from_slice(&u64::MAX.to_be_bytes());
    undecodable[15] = 0xfe;
    vault
        .try_with_write_txn(|txn| {
            vault
                .store
                .attempt_records
                .put(txn, &undecodable, b"not an attempt record")?;
            Ok::<(), crate::Error>(())
        })
        .expect("undecodable row");
    let view = AttemptQueue::new(&vault)
        .list_kind_bounded(crate::surface_event::SURFACE_EVENT_ATTEMPT_KIND, 1);
    assert!(
        view.as_ref().is_ok_and(Vec::is_empty),
        "another kind's view reads no tagging row: {view:?}"
    );
}

/// A tagging backlog larger than the cleanup arm's scan budget leaves
/// cleanup as a vault with no tagger leaves it: the arm proposes another
/// kind's completed job in the same pass, the backlog taking none of its
/// budget.
#[test]
fn a_tagging_backlog_past_the_cleanup_scan_leaves_cleanup_as_without_one() {
    let dir = tempfile::tempdir().expect("dir");
    let clock = ManualClock::new(NOW);
    let vault = open_on(dir.path(), &clock);
    plant_settled_markers(
        &vault,
        crate::vault_cleanup::MAX_CLEANUP_SCAN_ROWS as u64 + 1,
        NOW,
    );
    let other = complete_other_job(&vault);
    assert_eq!(cleanup_proposals(&vault, &clock), vec![*other.as_bytes()]);
}

/// A marker whose payload this build cannot read, left leased by a stopped
/// worker, is settled by the restarted one as a pass settles it: failed, its
/// trace recorded, then gone from the job ledger.
#[test]
fn an_unreadable_marker_a_stopped_worker_left_is_traced_before_it_leaves_the_ledger() {
    let dir = tempfile::tempdir().expect("dir");
    {
        let vault = open(dir.path(), true);
        witness(&vault, "Ada sailed north");
        let ClaimOutcome::Claimed(mut leased) = AttemptQueue::new(&vault)
            .claim_kind(
                TAGGING_MARKER_KIND,
                ClaimAttempt {
                    lease_owner: "oneironer-tagging".into(),
                    now: u64::MAX,
                },
            )
            .expect("claim")
        else {
            panic!("the marker is ready");
        };
        // A payload a later build cannot read, under the stopped worker's lease.
        leased.payload = b"not a marker payload".to_vec();
        let encoded = crate::attempt_queue::encode_signal_record(&leased).expect("encode");
        vault
            .try_with_write_txn(|txn| {
                vault
                    .store
                    .attempt_records
                    .put(txn, leased.id.as_bytes(), &encoded)?;
                Ok::<(), crate::Error>(())
            })
            .expect("unreadable payload");
    }
    let vault = open(dir.path(), true);
    let tagger = Scripted::new(Answer::Good);
    assert_eq!(
        reconciler(&vault, &tagger)
            .release_stale_leases()
            .expect("release"),
        1
    );
    assert!(markers(&vault).is_empty(), "the marker left the job ledger");
    let traces = vault.tagging_trace_history(None).expect("history");
    assert_eq!(traces.len(), 1, "its trace was recorded first");
    assert!(matches!(
        traces[0].trace.outcome,
        TaggingOutcome::Unreadable
    ));
    assert_eq!(traces[0].trace.try_number, 1);
    assert_eq!(tagger.calls(), 0);
}

/// A pass prunes every expired trace before it claims, however many: past
/// the size of one prune transaction, none is left once a pass has started.
#[test]
fn a_pass_prunes_every_expired_trace_before_it_claims() {
    const TURNS: u64 = 300;
    let dir = tempfile::tempdir().expect("dir");
    let clock = ManualClock::new(NOW);
    let vault = {
        let mut config = config(true);
        config.store_clock = clock.bundle();
        config.tagging = Some(
            TaggingMarkerConfig::new(CHECKPOINT)
                .expect("checkpoint")
                .with_live_window_tokens(0)
                .with_trace_history(TaggingTraceHistory {
                    per_turn: 1,
                    max_age_secs: 10,
                }),
        );
        Arc::new(Vault::open(dir.path(), config).expect("open vault"))
    };
    let turns: Vec<EntityId> = (0..TURNS)
        .map(|n| witness(&vault, &format!("turn {n} where Ada met Grace")))
        .collect();
    let tagger = Scripted::new(Answer::Good);
    let reconciler = reconciler(&vault, &tagger).with_batch_size(TURNS as usize);
    assert_eq!(
        reconciler.drain_once().expect("drain").traces.len(),
        turns.len()
    );
    assert!(turns.iter().all(|turn| history(&vault, turn).len() == 1));
    clock.set(NOW + 11);
    assert!(reconciler.drain_once().expect("drain").traces.is_empty());
    assert!(turns.iter().all(|turn| history(&vault, turn).is_empty()));
}

/// A DAG turn reads its retained ancestry, even once a hard erasure took its
/// own Parent edge, and never a turn of another branch. A DAG root reads
/// alone, even beside a descendant that occurred before it.
#[test]
fn a_dag_turn_reads_its_retained_ancestry_and_a_root_reads_alone() {
    use crate::WriteActor;
    use crate::conversation_dag::AppendRecord;
    use crate::conversation_dag::fixtures::{grant, input};
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    vault
        .put_entity(
            &actor.entity_ref(),
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({"name": "fixture author"}))
                .expect("author body"),
        )
        .expect("author");
    grant(&vault, actor, true);
    let room = EntityId::now();
    vault
        .create_conversation(
            room,
            &crate::conversation::ConversationBody {
                member_ids: vec![actor.entity_ref()],
                ..Default::default()
            },
            actor,
            1,
        )
        .expect("room");
    let append = |record: AppendRecord| vault.append_dag_record(&record).expect("append").id;
    let root = append(input(room, None, true, actor));
    let fork = append(input(room, Some(root), false, actor));
    let trunk = append(input(room, Some(root), true, actor));
    let tip = append(input(room, Some(trunk), true, actor));
    append(AppendRecord {
        occurred: TimeRange { start: 10, end: 10 },
        learned_at: 10,
        ..input(room, Some(tip), true, actor)
    });
    let earlier = |turn: &EntityId| {
        let txn = vault.store.env.read_txn().expect("read txn");
        super::input::earlier_turns_in_txn(&vault, &txn, turn, 256).expect("earlier turns")
    };
    assert_eq!(earlier(&tip), vec![trunk, root]);
    assert!(earlier(&root).is_empty(), "a root reads alone");
    vault
        .delete_room_record(room, trunk, actor, crate::DeleteReason::PolicyDelete)
        .expect("erase");
    assert!(vault.get(&trunk).expect("read").is_none());
    assert_eq!(
        earlier(&tip),
        vec![trunk, root],
        "the erasure pin keeps the ancestry, and no other branch enters"
    );
    assert!(!earlier(&tip).contains(&fork));
}

/// The settling write reads the turn's own text, never its window: an
/// earlier turn edited while the tagger reads a later one leaves that
/// answer standing.
#[test]
fn an_earlier_turn_edited_during_the_call_leaves_the_answer_standing() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let first_ref = Some("70707070707070707070707070707070".to_owned());
    vault
        .memory(speaker(&vault), EdgeActorClass::Human)
        .witness(&turn(
            first_ref.clone(),
            vec![message(0, "Ada sailed north")],
        ))
        .expect("first");
    let tagger = Scripted::new(Answer::Good);
    let reconciler = reconciler(&vault, &tagger).with_batch_size(1);
    reconciler.drain_once().expect("the first turn");
    let second = witness_at(&vault, "Grace stayed behind", NOW + 1);
    let writer = Arc::clone(&vault);
    *tagger.during_call.lock().expect("hook") = Some(Box::new(move || {
        writer
            .memory(speaker(&writer), EdgeActorClass::Human)
            .witness(&turn(first_ref, vec![message(1, "and then turned east")]))
            .expect("the earlier turn gains text during the call");
    }));
    let pass = reconciler.drain_once().expect("the second turn");
    assert_eq!(pass.traces.len(), 1);
    assert_eq!(pass.traces[0].turn, Some(second));
    assert!(
        matches!(pass.traces[0].outcome, TaggingOutcome::Shadowed { .. }),
        "the answer stands: {:?}",
        pass.traces[0].outcome
    );
}

/// The window keeps the nearest earlier turns when the conversation holds
/// more than it takes.
#[test]
fn the_window_keeps_the_nearest_earlier_turns() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let turns: Vec<EntityId> = (0..5_u64)
        .map(|at| witness_at(&vault, "Ada sailed north", NOW + at))
        .collect();
    let txn = vault.store.env.read_txn().expect("read txn");
    assert_eq!(
        super::input::earlier_turns_in_txn(&vault, &txn, &turns[4], 2).expect("earlier"),
        vec![turns[3], turns[2]]
    );
}

/// A same-second re-mark of a settled turn draws a new id: pruning the
/// settled marker frees no id, so the old one never names the new pass, and
/// the two passes' traces name distinct attempts.
#[test]
fn a_settled_marker_s_id_is_never_drawn_again() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let turn_ref = Some("72727272727272727272727272727272".to_owned());
    let tagged = EntityId::from_hex(turn_ref.as_deref().expect("ref")).expect("turn id");
    let memory = vault.memory(speaker(&vault), EdgeActorClass::Human);
    memory
        .witness(&turn(
            turn_ref.clone(),
            vec![message(0, "Ada sailed north")],
        ))
        .expect("witness");
    let first = markers(&vault).remove(0).id;
    let tagger = Scripted::new(Answer::Good);
    let reconciler = reconciler(&vault, &tagger);
    reconciler.drain_once().expect("drain");
    // The same store-clock second: new text owes the turn a new pass.
    memory
        .witness(&turn(turn_ref, vec![message(1, "and then turned east")]))
        .expect("more text");
    let second = markers(&vault).remove(0).id;
    assert_ne!(first, second, "a pruned marker's id is not drawn again");
    assert!(
        AttemptQueue::new(&vault)
            .get(first)
            .expect("read")
            .is_none(),
        "the old id names nothing"
    );
    reconciler.drain_once().expect("drain");
    let attempts: Vec<String> = vault
        .tagging_trace_history(Some(&tagged))
        .expect("history")
        .into_iter()
        .map(|record| record.trace.attempt)
        .collect();
    assert_eq!(attempts.len(), 2);
    assert_ne!(attempts[0], attempts[1]);
}

/// A tagging marker landed through the generic queue doors is not handed
/// off: a minted successor would sit outside the tagging range, where other
/// kinds' scans read. The hand-off is refused and writes no successor.
#[test]
fn a_landing_hand_off_of_a_tagging_marker_is_refused() {
    use crate::attempt_queue::{
        AcceptAttemptLanding, AttemptResumePoint, FinishAttemptLanding, LandingOutcome,
        LandingTrigger, RecordAttemptResumePoint,
    };
    const OWNER: &str = "worker-a";
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    witness(&vault, "Ada sailed north");
    let queue = AttemptQueue::new(&vault);
    let ClaimOutcome::Claimed(leased) = queue
        .claim_kind(
            TAGGING_MARKER_KIND,
            ClaimAttempt {
                lease_owner: OWNER.into(),
                now: NOW,
            },
        )
        .expect("claim")
    else {
        panic!("the marker is ready");
    };
    let LandingOutcome::Landing(_) = queue
        .accept_landing(AcceptAttemptLanding {
            id: leased.id,
            lease_owner: OWNER.into(),
            attempt_count: leased.attempt_count,
            trigger: LandingTrigger::BudgetWarning,
            status: Some("landing".into()),
            resume_point: None,
            request_sequence: None,
            now: NOW,
        })
        .expect("landing")
    else {
        panic!("a fresh landing");
    };
    queue
        .record_resume_point(RecordAttemptResumePoint {
            id: leased.id,
            lease_owner: OWNER.into(),
            attempt_count: leased.attempt_count,
            resume_point: AttemptResumePoint::new("step-1", NOW),
            now: NOW,
        })
        .expect("resume point");
    let handed_off = queue.finish_landing(FinishAttemptLanding {
        id: leased.id,
        lease_owner: OWNER.into(),
        attempt_count: leased.attempt_count,
        hand_off: true,
        scheduled_at: None,
        now: NOW,
    });
    assert!(handed_off.is_err(), "the hand-off is refused");
    let rows = markers(&vault);
    assert_eq!(rows.len(), 1, "no successor was written");
    assert!(crate::attempt_queue::owner_retained_id(&rows[0].id));
}

/// A try a stopped worker left leased, and a try whose settling write
/// failed, are each handed back with their trace recorded, so every try that
/// leaves the job ledger has a trace.
#[test]
fn a_handed_back_try_is_traced_before_it_leaves_the_ledger() {
    let dir = tempfile::tempdir().expect("dir");
    let restarted = {
        let vault = open(dir.path(), true);
        let turn = witness(&vault, "Ada sailed north");
        let claimed = AttemptQueue::new(&vault)
            .claim_kind(
                TAGGING_MARKER_KIND,
                ClaimAttempt {
                    lease_owner: "oneironer-tagging".into(),
                    now: u64::MAX,
                },
            )
            .expect("claim");
        assert!(matches!(claimed, ClaimOutcome::Claimed(_)));
        turn
    };
    let vault = open(dir.path(), true);
    let tagger = Scripted::new(Answer::Good);
    let reconciler = reconciler(&vault, &tagger);
    reconciler.drain_once().expect("drain");
    let failed = witness(&vault, "Grace stayed behind");
    vault.test_hooks().arm_fail_next_tagging_settlement();
    reconciler
        .drain_once()
        .expect_err("the settling write fails");
    reconciler.drain_once().expect("drain");
    assert!(markers(&vault).is_empty());
    for (turn, reason) in [
        (restarted, HandBackReason::WorkerRestarted),
        (failed, HandBackReason::SettlementFailed),
    ] {
        let outcomes = history(&vault, &turn);
        assert_eq!(outcomes.len(), 2, "{reason:?}: {outcomes:?}");
        assert!(
            matches!(outcomes[0], TaggingOutcome::HandedBack { reason: found, .. } if found == reason)
        );
        assert!(matches!(outcomes[1], TaggingOutcome::Shadowed { .. }));
    }
}

/// History kept under a larger per-turn bound reads within a smaller one at
/// once, and the next worker trims it to that bound before it claims.
#[test]
fn a_smaller_per_turn_bound_trims_the_history_kept_under_a_larger_one() {
    let dir = tempfile::tempdir().expect("dir");
    let open_with = |per_turn: u32| {
        let mut config = config(true);
        config.tagging = Some(
            TaggingMarkerConfig::new(CHECKPOINT)
                .expect("checkpoint")
                .with_trace_history(TaggingTraceHistory {
                    per_turn,
                    ..TaggingTraceHistory::default()
                }),
        );
        Arc::new(Vault::open(dir.path(), config).expect("open vault"))
    };
    let turn_ref = Some("73737373737373737373737373737373".to_owned());
    let tagged = EntityId::from_hex(turn_ref.as_deref().expect("ref")).expect("turn id");
    {
        let vault = open_with(3);
        let memory = vault.memory(speaker(&vault), EdgeActorClass::Human);
        let tagger = Scripted::new(Answer::Good);
        let reconciler = reconciler(&vault, &tagger);
        for order in 0..3_u32 {
            memory
                .witness(&turn(
                    turn_ref.clone(),
                    vec![message(order, "Ada sailed north")],
                ))
                .expect("witness");
            reconciler.drain_once().expect("drain");
        }
        assert_eq!(history(&vault, &tagged).len(), 3);
    }
    for (per_turn, kept) in [(1, 1), (0, 0)] {
        let vault = open_with(per_turn);
        assert_eq!(
            history(&vault, &tagged).len(),
            kept,
            "read within {per_turn}"
        );
        let tagger = Scripted::new(Answer::Good);
        reconciler(&vault, &tagger).drain_once().expect("drain");
        drop(vault);
        // What the trim left, read under the larger bound again.
        let vault = open_with(3);
        assert_eq!(
            history(&vault, &tagged).len(),
            kept,
            "trimmed to {per_turn}"
        );
    }
}

/// A turn whose ChildOf owner is not a conversation reads alone, however
/// many turns share that owner.
#[test]
fn a_turn_under_a_parent_that_is_not_a_conversation_reads_alone() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let owner = speaker(&vault);
    let body = rmp_serde::to_vec_named(&serde_json::json!({"speaker": "user"})).expect("body");
    let mut turns = Vec::new();
    for at in [NOW, NOW + 1] {
        let turn = EntityId::now();
        vault
            .put_entity(
                &turn,
                crate::registry::ENTITY_TYPE_TURN,
                TimeRange { start: at, end: at },
                at,
                &body,
            )
            .expect("turn");
        vault
            .put_edge(&turn, crate::edge::EdgeKind::ChildOf, &owner, 1.0)
            .expect("owner");
        turns.push(turn);
    }
    let txn = vault.store.env.read_txn().expect("read txn");
    assert!(
        super::input::earlier_turns_in_txn(&vault, &txn, &turns[1], 256)
            .expect("earlier")
            .is_empty()
    );
}

/// An earlier turn with more messages than the window reads ends the window
/// before it, rather than failing the later turn: that turn is read alone
/// and its answer settles.
#[test]
fn an_earlier_turn_past_the_message_bound_ends_the_window_and_the_turn_settles() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let messages = (0..=256_u32)
        .map(|order| message(order, "a long run of short messages"))
        .collect();
    vault
        .memory(speaker(&vault), EdgeActorClass::Human)
        .witness(&turn(None, messages))
        .expect("a long earlier turn");
    let later = witness_at(&vault, "Grace stayed behind", NOW + 1);
    let tagger = Scripted::new(Answer::Good);
    let pass = reconciler(&vault, &tagger)
        .with_batch_size(2)
        .drain_once()
        .expect("drain");
    assert_eq!(pass.traces.len(), 2);
    let input = tagger
        .inputs
        .lock()
        .expect("inputs")
        .iter()
        .find(|input| input.turn == later.to_hex())
        .expect("the later turn was tagged")
        .clone();
    assert!(
        input.context.is_empty(),
        "the window ends before the long turn"
    );
    assert_eq!(settled(&vault, &later), 1);
}

/// A room whose turns carry DAG topology this replica has not adopted, a
/// received Parent among them, is not ordered by time: its root reads alone,
/// not a descendant that occurred before it.
#[test]
fn a_received_dag_root_reads_alone_before_the_room_adopts_the_dag() {
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let root = witness_at(&vault, "Ada sailed north", NOW + 100);
    let descendant = witness_at(&vault, "and Grace followed", NOW + 10);
    // The replicated edge shape a sync peer's Parent lands in; the public
    // edge door refuses the kind.
    vault
        .batch_in()
        .edge_with_value_fields(
            &descendant,
            crate::edge::EdgeKind::Parent,
            &root,
            crate::batch::EdgeValueFields {
                weight: 1.0,
                created_at: NOW,
                vad: crate::affect::Vad::NEUTRAL,
                provenance: None,
            },
        )
        .commit()
        .expect("a received Parent");
    let txn = vault.store.env.read_txn().expect("read txn");
    assert!(
        super::input::earlier_turns_in_txn(&vault, &txn, &root, 256)
            .expect("earlier")
            .is_empty()
    );
    assert_eq!(
        super::input::earlier_turns_in_txn(&vault, &txn, &descendant, 256).expect("earlier"),
        vec![root],
        "the descendant reads its ancestry"
    );
}

/// A tagging claim never reads another kind's ready backlog: ordinary jobs
/// ready at the same instant, one of them a row this build cannot decode,
/// stand before the marker in the readiness index, and the marker is
/// claimed and settled all the same.
#[test]
fn a_tagging_claim_never_reads_another_kinds_ready_backlog() {
    use crate::attempt_queue::EnqueueAttempt;
    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let queue = AttemptQueue::new(&vault);
    for n in 0..50_u8 {
        queue
            .enqueue(EnqueueAttempt {
                kind: "test.backlog".into(),
                payload: vec![n],
                dedupe_key: None,
                run_id: None,
                now: NOW,
            })
            .expect("an ordinary ready job");
    }
    // A ready row of another kind that no build can decode, ready at once.
    let id = [0x10_u8; 16];
    let mut ready = [0_u8; 24];
    ready[8..].copy_from_slice(&id);
    vault
        .try_with_write_txn(|txn| {
            vault
                .store
                .attempt_records
                .put(txn, &id, b"not an attempt record")?;
            vault.store.attempt_ready.put(txn, &ready, &id)?;
            Ok::<(), crate::Error>(())
        })
        .expect("an undecodable ready row");
    let turn = witness(&vault, "Ada sailed north");
    let tagger = Scripted::new(Answer::Good);
    let pass = reconciler(&vault, &tagger).drain_once().expect("drain");
    assert_eq!(pass.traces.len(), 1);
    assert_eq!(pass.traces[0].turn, Some(turn));
    assert!(matches!(
        pass.traces[0].outcome,
        TaggingOutcome::Shadowed { .. }
    ));
}

/// A marker an earlier build left waiting below the id range markers now
/// take, where claims never look, is moved onto a new marker in the range
/// when the worker starts, and its turn is tagged.
#[test]
fn a_marker_an_earlier_build_left_below_the_range_is_moved_into_it() {
    use crate::attempt_queue::EnqueueAttempt;
    let dir = tempfile::tempdir().expect("dir");
    let turn = {
        let vault = open(dir.path(), false);
        let turn = witness(&vault, "Ada sailed north");
        let queue = AttemptQueue::new(&vault);
        queue
            .enqueue(EnqueueAttempt {
                kind: "test.legacy".into(),
                payload: Vec::new(),
                dedupe_key: None,
                run_id: None,
                now: NOW,
            })
            .expect("a row under a minted id");
        // What an earlier build stored: a waiting marker under that id.
        let mut row = queue
            .list()
            .expect("rows")
            .into_iter()
            .find(|row| row.kind == "test.legacy")
            .expect("the row");
        row.kind = TAGGING_MARKER_KIND.into();
        row.payload = rmp_serde::to_vec_named(&super::marker::MarkerPayload {
            turn,
            checkpoint: CHECKPOINT.into(),
        })
        .expect("payload");
        let encoded = crate::attempt_queue::encode_signal_record(&row).expect("encode");
        vault
            .try_with_write_txn(|txn| {
                vault
                    .store
                    .attempt_records
                    .put(txn, row.id.as_bytes(), &encoded)?;
                Ok::<(), crate::Error>(())
            })
            .expect("an earlier build's marker");
        assert!(!crate::attempt_queue::owner_retained_id(&row.id));
        turn
    };
    let vault = open(dir.path(), true);
    let tagger = Scripted::new(Answer::Good);
    reconciler(&vault, &tagger).drain_once().expect("drain");
    assert!(markers(&vault).is_empty(), "the old marker left the ledger");
    let outcomes = history(&vault, &turn);
    assert!(matches!(outcomes[0], TaggingOutcome::Rekeyed));
    assert!(matches!(outcomes[1], TaggingOutcome::Shadowed { .. }));
    assert_eq!(tagger.calls(), 1);
}

/// An earlier message is read only as far as the window keeps it, from its
/// end: with the first byte of a long message made unreadable, a reader that
/// decoded the whole text would drop the message, and the window still holds
/// its newest characters.
#[test]
fn an_earlier_message_is_read_only_as_far_as_the_window_keeps() {
    let dir = tempfile::tempdir().expect("dir");
    let mut config = config(true);
    config.tagging = Some(
        TaggingMarkerConfig::new(CHECKPOINT)
            .expect("checkpoint")
            .with_live_window_tokens(2),
    );
    let vault = Arc::new(Vault::open(dir.path(), config).expect("open vault"));
    // Within the 64 KiB entity payload cap.
    let text = format!("{}Ada sailed north", "ab ".repeat(20_000));
    let mut long = message(0, &text);
    long.id = Some("67676767676767676767676767676767".into());
    let earlier = receipt_turn(
        &vault
            .memory(speaker(&vault), EdgeActorClass::Human)
            .witness(&turn(None, vec![long.clone()]))
            .expect("a long earlier message"),
    );
    let later = witness_at(&vault, "Grace stayed behind", NOW + 1);
    let id = EntityId::from_hex(long.id.as_deref().expect("id")).expect("message id");
    vault
        .try_with_write_txn(|txn| {
            let mut raw = vault
                .store
                .entities
                .get(txn, id.as_bytes())?
                .expect("the message row")
                .to_vec();
            let at = raw
                .windows(9)
                .position(|bytes| bytes == b"ab ab ab ")
                .expect("the long text");
            raw[at] = 0xff;
            vault.store.entities.put(txn, id.as_bytes(), &raw)?;
            Ok::<(), crate::Error>(())
        })
        .expect("an unreadable first byte");
    let read = vault
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)
        .and_then(|txn| super::input::turn_input_in_txn(&vault, &txn, &later))
        .expect("read the later turn");
    let super::input::TurnInput::Ready { input, .. } = read else {
        panic!("the later turn has text");
    };
    let newest: String = text.chars().skip(text.chars().count() - 32).collect();
    assert_eq!(window(&input), vec![(earlier.to_hex(), vec![newest])]);
}

/// A message whose text lives in an entity document ends the window with it:
/// the nearer turns' text is kept, and nothing older than the document is
/// read.
#[cfg(feature = "sync")]
#[test]
fn an_earlier_message_in_an_entity_document_ends_the_window() {
    use crate::entity_doc::{DocAuthorization, TextField};
    use crate::write_envelope::WriteActor;

    let dir = tempfile::tempdir().expect("dir");
    let vault = open(dir.path(), true);
    let writer = speaker(&vault);
    let mut first = message(0, "Ada sailed north");
    first.id = Some("68686868686868686868686868686868".into());
    vault
        .memory(writer, EdgeActorClass::Human)
        .witness(&turn(None, vec![first.clone()]))
        .expect("witness");
    let second = witness_at(&vault, "Grace stayed behind", NOW + 1);
    let third = witness_at(&vault, "they wrote letters", NOW + 2);
    let owner = vault
        .authenticate_owner(
            writer,
            "principal:tagging-test",
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner");
    vault
        .migrate_entity_text(
            &EntityId::from_hex(first.id.as_deref().expect("id")).expect("message id"),
            &TextField::MapField("content".into()),
            WriteActor::new(writer, EdgeActorClass::Human),
            &DocAuthorization::Owner(&owner),
        )
        .expect("migrate");
    let read = vault
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)
        .and_then(|txn| super::input::turn_input_in_txn(&vault, &txn, &third))
        .expect("read the third turn");
    let super::input::TurnInput::Ready { input, .. } = read else {
        panic!("the third turn has text");
    };
    assert_eq!(
        window(&input),
        vec![(second.to_hex(), vec!["Grace stayed behind".to_owned()])]
    );
}

/// A MESSAGE body is walked to its keys without decoding any string, and its
/// text is read back from the end only as far as it is kept.
#[test]
fn a_message_body_is_walked_to_its_text_and_read_back_from_the_end() {
    use super::body::{message_fields, newest_chars};
    use rmpv::Value;
    let encode = |value: &Value| {
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, value).expect("encode");
        out
    };
    for len in [5, 100, 300, 70_000] {
        let text = format!("{}Ada", "x".repeat(len));
        let body = encode(&Value::Map(vec![
            (Value::from("role"), Value::from("user")),
            (
                Value::from("metadata"),
                Value::Map(vec![(
                    Value::from("tags"),
                    Value::Array(vec![
                        Value::from(1),
                        Value::from(-40),
                        Value::from(2.5),
                        Value::Nil,
                        Value::Binary(vec![0; 300]),
                        Value::Ext(7, vec![1, 2, 3]),
                        Value::Ext(8, vec![0; 4]),
                    ]),
                )]),
            ),
            (Value::from(9), Value::from(u64::MAX)),
            (Value::from("content"), Value::from(text.as_str())),
            (Value::from("is_visible"), Value::from(true)),
            (Value::from("stale"), Value::from("no")),
            (Value::from("order"), Value::from(7)),
        ]));
        let fields = message_fields(&body).expect("a map");
        assert_eq!(fields.content, text.as_bytes());
        assert!(fields.is_visible);
        assert!(!fields.stale);
        assert_eq!(fields.order, 7);
        assert_eq!(newest_chars(fields.content, 4), Some(("xAda", 4)));
    }
    assert_eq!(newest_chars("añ日本🎉".as_bytes(), 3), Some(("日本🎉", 3)));
    assert_eq!(newest_chars("añ".as_bytes(), 10), Some(("añ", 2)));
    assert_eq!(newest_chars(b"\xffAda", 3), Some(("Ada", 3)));
    assert_eq!(newest_chars(b"Ad\xff", 3), None);
    let stale = encode(&Value::Map(vec![(Value::from("stale"), Value::from(true))]));
    assert!(message_fields(&stale).expect("a map").stale);
    let visibility = encode(&Value::Map(vec![(
        Value::from("is_visible"),
        Value::from(1),
    )]));
    assert!(message_fields(&visibility).is_none());
    for (order, read) in [
        (Value::from(70_000), Some(70_000)),
        (Value::from(i64::from(u32::MAX)), Some(u32::MAX)),
        (Value::from(u64::from(u32::MAX) + 1), None),
        (Value::from(-1), None),
        (Value::from("7"), None),
    ] {
        let body = encode(&Value::Map(vec![(Value::from("order"), order)]));
        assert_eq!(message_fields(&body).map(|fields| fields.order), read);
    }
    assert!(message_fields(&encode(&Value::Array(Vec::new()))).is_none());
    let body = encode(&Value::Map(vec![(
        Value::from("content"),
        Value::from("Ada"),
    )]));
    assert!(message_fields(&body[..body.len() - 1]).is_none());
}

/// Trimming history to the per-turn bound reads it outside the writer: a
/// restart over a history within the bound commits no write, and history
/// past a lowered bound, over more turns than one read covers, is trimmed a
/// bounded read a pass, each turn keeping its newest traces.
#[test]
fn trimming_history_reads_outside_the_writer_a_bounded_part_a_pass() {
    const TURNS: u32 = 5_000;
    let dir = tempfile::tempdir().expect("dir");
    let open_with = |per_turn: u32| {
        let mut config = config(true);
        config.tagging = Some(
            TaggingMarkerConfig::new(CHECKPOINT)
                .expect("checkpoint")
                .with_trace_history(TaggingTraceHistory {
                    per_turn,
                    ..TaggingTraceHistory::default()
                }),
        );
        Arc::new(Vault::open(dir.path(), config).expect("open vault"))
    };
    let turns: Vec<EntityId> = (0..TURNS)
        .map(|n| {
            let mut id = [0x7a; 16];
            id[12..].copy_from_slice(&n.to_be_bytes());
            EntityId::from_bytes(id).expect("turn id")
        })
        .collect();
    let tries = |vault: &Vault, turn: &EntityId| -> Vec<u32> {
        vault
            .tagging_trace_history(Some(turn))
            .expect("history")
            .into_iter()
            .map(|record| record.trace.try_number)
            .collect()
    };
    {
        let vault = open_with(3);
        vault
            .try_with_write_txn(|txn| {
                for turn in &turns {
                    for try_number in [1, 2] {
                        let trace = TaggingTrace {
                            attempt: String::new(),
                            turn: Some(*turn),
                            checkpoint: CHECKPOINT.into(),
                            model: None,
                            input_hash: None,
                            try_number,
                            call_micros: None,
                            outcome: TaggingOutcome::Rekeyed,
                        };
                        super::history::record_in_txn(&vault, txn, &trace, NOW)?;
                    }
                }
                Ok::<(), crate::Error>(())
            })
            .expect("a recorded history");
    }
    {
        let vault = open_with(3);
        let tagger = Scripted::new(Answer::Good);
        // A write through the vault's door notifies the queue's observers.
        #[cfg(feature = "sync")]
        let mut commits = AttemptQueue::new(&vault).subscribe();
        reconciler(&vault, &tagger).drain_once().expect("drain");
        #[cfg(feature = "sync")]
        assert!(
            commits.try_recv().is_err(),
            "a history within the bound commits no write"
        );
    }
    let over_bound = || {
        let vault = open_with(3);
        turns
            .iter()
            .filter(|turn| tries(&vault, turn).len() > 1)
            .count()
    };
    {
        let vault = open_with(1);
        let tagger = Scripted::new(Answer::Good);
        let reconciler = reconciler(&vault, &tagger);
        reconciler.drain_once().expect("drain");
        drop(reconciler);
        drop(vault);
    }
    let left = over_bound();
    assert!(
        left > 0 && left < TURNS as usize,
        "one pass trims one bounded read: {left} turns left"
    );
    {
        let vault = open_with(1);
        let tagger = Scripted::new(Answer::Good);
        let reconciler = reconciler(&vault, &tagger);
        for _ in 0..4 {
            reconciler.drain_once().expect("drain");
        }
    }
    assert_eq!(over_bound(), 0);
    let vault = open_with(3);
    for turn in &turns {
        assert_eq!(tries(&vault, turn), vec![2], "the newest trace is kept");
    }
}
