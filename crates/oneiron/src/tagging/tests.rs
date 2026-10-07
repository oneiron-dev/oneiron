//! Laws of the tagging marker and its drain, observed through the job tables,
//! the traces and the vault's stored rows.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::*;
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome, CleanupAttemptLeases,
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
    /// Runs inside the call, outside every write transaction.
    during_call: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Scripted {
    fn new(answer: Answer) -> Arc<Self> {
        Arc::new(Self {
            model: "fixture/tagger@v1".parse().expect("model id"),
            answer: Mutex::new(answer),
            calls: AtomicUsize::new(0),
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

/// Every content database matches; the job tables, left out by name, are
/// where the tagged run differs.
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
    assert_eq!(count(&vault, AttemptState::Completed), 1);
    // A settled turn: the exact retry stages nothing and owes nothing.
    memory
        .witness(&turn(turn_ref.clone(), vec![first]))
        .expect("exact retry after settlement");
    assert_eq!(markers(&vault).len(), 1);
    // New text in the same turn owes a new pass.
    memory
        .witness(&turn(turn_ref, vec![message(1, "and a second message")]))
        .expect("append");
    assert_eq!(markers(&vault).len(), 2);
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
    assert_eq!(count(&vault, AttemptState::Completed), 1);

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
    assert_eq!(markers(&vault).len(), 1);
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

/// Shadow writes nothing outside the three job tables, through the paths that
/// retry a marker too (a failed call, a refused answer, a lease a stopped
/// worker left) and while the store clock runs, an empty pass included. A
/// write after them allocates the same entity ids in both arms, even after
/// the clock rolls back: no retry drew from the vault's id source, and no
/// pass moved the vault's clock floor, on disk or in memory.
#[test]
fn shadow_leaves_every_content_database_as_a_run_with_no_tagger_leaves_it() {
    let arms = Arms::new();
    let tagger = Scripted::new(Answer::Fail);
    {
        let (tagged, plain) = arms.open();
        assert_eq!(content_digests(&tagged), content_digests(&plain));
        for text in [
            "Ada sailed north",
            "Grace stayed behind",
            "they wrote letters",
        ] {
            witness_both(&tagged, &plain, text);
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
    // Two retried tries and the restarted lease; every turn settled once.
    assert_eq!(count(&tagged, AttemptState::Failed), 3);
    assert_eq!(count(&tagged, AttemptState::Completed), 3);
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
    // Three retried tries and the one that settled; nothing left owed.
    assert_eq!(count(&vault, AttemptState::Failed), 3);
    assert_eq!(count(&vault, AttemptState::Completed), 1);
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
    // One settled marker per turn; the abandoned lease is a retried try.
    assert_eq!(count(&vault, AttemptState::Completed), 2);
    assert_eq!(count(&vault, AttemptState::Failed), 1);
    assert_eq!(count(&vault, AttemptState::Queued), 0);
    assert_eq!(count(&vault, AttemptState::Leased), 0);
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
    for (call, text) in [
        (Answer::Good, "Ada sailed north"),
        (Answer::Fail, "Grace stayed behind"),
    ] {
        let turn = witness(&vault, text);
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
    assert_eq!(count(&vault, AttemptState::Completed), 2);
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
    assert_eq!(count(&vault, AttemptState::Completed), 1);
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
    assert_eq!(markers(&vault).len(), 1, "a retried promotion owes nothing");
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
    assert_eq!(count(&vault, AttemptState::Completed), 1);
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
    assert_eq!(count(&vault, AttemptState::Completed), 1);
    assert_eq!(count(&vault, AttemptState::Queued), 0);
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
    assert_eq!(count(&vault, AttemptState::Completed), 1);
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
/// clock runs, without writing outside the job tables, and a write after the
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
    assert_eq!(count(&vault, AttemptState::Completed), 1);
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
