//! [SCORECARD-WORLD-SCOPED-ARM]: `scorecard run --arm world-scoped` replays a
//! slice as an agent whose one Grant reads the base world. A seeded share of
//! the records lands as the owner's claims in a second world, the rest in the
//! base world; the agent is never served a second-world record, and the run is
//! graded on the readable records alone: a hidden relevant record leaves the
//! qrels, and a query left with no readable relevant record is dropped.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::path::Path;
use std::process::Command;

use oneiron_contracts::fingerprint::purposes::bench_scorecard::{
    WORLD_SCOPED_PARAMS, WORLD_SCOPED_PARTITION,
};
use oneiron_contracts::fingerprint::{ContentHash, Fingerprint, Fingerprinter};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// A 40-hex engine commit for the fixtures.
const ENGINE_COMMIT: &str = "0123456789012345678901234567890123456789";

/// The fixture's partition: seed 0, half the records hidden.
const SEED: u32 = 0;
const HIDDEN_SHARE: u32 = 500;

/// Whether the arm puts `record_id` in the second world
/// (`scorecard/world_scoped/partition.rs`): the first 8 bytes of the
/// fingerprint `WORLD_SCOPED_PARTITION` of (seed as 4 little-endian bytes,
/// record id), read big-endian, modulo 1000, fall below the share.
fn hidden(record_id: &str) -> bool {
    let draw = Fingerprint::of_parts(
        WORLD_SCOPED_PARTITION,
        &[&SEED.to_le_bytes(), record_id.as_bytes()],
    );
    u64::from_be_bytes(draw.prefix::<8>()) % 1000 < u64::from(HIDDEN_SHARE)
}

/// The first `count` ids `rec-<n>` the partition puts in (`want_hidden`) or
/// out of the second world.
fn pick(count: usize, want_hidden: bool) -> Vec<String> {
    let picked: Vec<String> = (0..1000)
        .map(|n| format!("rec-{n}"))
        .filter(|id| hidden(id) == want_hidden)
        .take(count)
        .collect();
    assert_eq!(
        picked.len(),
        count,
        "FIXTURE: enough record ids on each side"
    );
    picked
}

/// sha256 of bytes as lowercase hex.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Run `oneiron-bench scorecard` with the given arguments.
fn scorecard(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_oneiron-bench"))
        .arg("scorecard")
        .args(args)
        .output()
        .expect("scorecard CLI fixture")
}

/// The one stdout line of a run, as JSON.
fn summary(output: &std::process::Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim()).expect("one JSON summary line")
}

/// The record ids of the fixture pack, by role.
struct Ids {
    /// Readable, holds the query words, graded 2.
    readable_match: String,
    /// Hidden, holds the query words, graded 1.
    hidden_match: String,
    /// Hidden, holds the query words, not graded.
    hidden_other: String,
    /// Readable, no query word.
    readable_fillers: [String; 2],
    /// Hidden, the only relevant record of the second query.
    hidden_only: String,
    /// Readable, no query word, in the second corpus.
    readable_other: String,
}

/// One turn record of the fixture pack.
fn record(id: &str, text: &str) -> Value {
    json!({
        "record_id": id,
        "kind": "turn",
        "speaker": "user",
        "text": text,
        "source_ref": format!("{id}#0"),
    })
}

/// Write an unembedded `search` slice: corpus `harbour` holds three records
/// with the words "harbour crossing" (one readable, two hidden) and two
/// readable fillers; corpus `mountain`'s only relevant record is hidden.
fn write_pack(dir: &Path) -> Ids {
    let readable = pick(4, false);
    let hidden_ids = pick(3, true);
    let ids = Ids {
        readable_match: readable[0].clone(),
        hidden_match: hidden_ids[0].clone(),
        hidden_other: hidden_ids[1].clone(),
        readable_fillers: [readable[1].clone(), readable[2].clone()],
        hidden_only: hidden_ids[2].clone(),
        readable_other: readable[3].clone(),
    };
    let manifest = json!({
        "contract": "oneiron.retrieval_pack.v1",
        "pack_id": "world-scoped-fixture",
        "revision": "r1",
        "slice": "search",
        "source": {
            "dataset": "LongMemEval-S",
            "dataset_sha256": sha256_hex(b"fixture-dataset"),
            "license": "MIT",
            "split_sha256": sha256_hex(b"fixture-split"),
        },
        "embedding": Value::Null,
        "records": [
            record(&ids.readable_match, "harbour crossing at dawn"),
            record(&ids.hidden_match, "harbour crossing at night"),
            record(&ids.hidden_other, "harbour crossing ferry timetable"),
            record(&ids.readable_fillers[0], "grocery list for market day"),
            record(&ids.readable_fillers[1], "quiet evening reading nook"),
            record(&ids.hidden_only, "mountain trail snowfall"),
            record(&ids.readable_other, "city bus schedule"),
        ],
        "corpora": [
            {"corpus_id": "corpus-harbour", "sessions": [
                {"session_id": "sess-harbour", "time": "2026-01-01T00:00:00Z", "record_ids": [
                    ids.readable_match, ids.hidden_match, ids.hidden_other,
                    ids.readable_fillers[0], ids.readable_fillers[1],
                ]},
            ]},
            {"corpus_id": "corpus-mountain", "sessions": [
                {"session_id": "sess-mountain", "time": "2026-01-01T00:00:00Z", "record_ids": [
                    ids.hidden_only, ids.readable_other,
                ]},
            ]},
        ],
        "queries": [
            {"query_id": "query-harbour", "slice": "search", "corpus_id": "corpus-harbour", "category": "single-session-user", "text": "harbour crossing", "now": "2026-01-02T00:00:00Z", "qrels": {ids.readable_match.clone(): 2, ids.hidden_match.clone(): 1}, "expect_empty": false},
            {"query_id": "query-mountain", "slice": "search", "corpus_id": "corpus-mountain", "category": "single-session-user", "text": "mountain snowfall", "now": "2026-01-02T00:00:00Z", "qrels": {ids.hidden_only.clone(): 2}, "expect_empty": false},
        ],
    });
    let mut pretty = serde_json::to_vec_pretty(&manifest).expect("manifest JSON");
    pretty.push(b'\n');
    std::fs::write(dir.join("search.json"), pretty).expect("manifest write");
    ids
}

/// Run the world-scoped arm over the fixture pack in `dir` into `card`,
/// with `hidden_share` per mille hidden under [`SEED`].
fn run_arm(dir: &Path, card: &Path, hidden_share: u32) -> std::process::Output {
    let pack_dir = dir.to_str().expect("fixture dir");
    let out = card.to_str().expect("scorecard path");
    let share = hidden_share.to_string();
    let seed = SEED.to_string();
    scorecard(&[
        "run",
        "--arm",
        "world-scoped",
        "--pack-dir",
        pack_dir,
        "--slice",
        "search",
        "--engine-commit",
        ENGINE_COMMIT,
        "--hidden-share",
        &share,
        "--partition-seed",
        &seed,
        "--out",
        out,
    ])
}

#[test]
fn world_scoped_arm_serves_and_grades_readable_records_only() {
    let dir = tempfile::tempdir().expect("scorecard fixture dir");
    let ids = write_pack(dir.path());
    let card_path = dir.path().join("world-scoped.json");
    let result = run_arm(dir.path(), &card_path, HIDDEN_SHARE);
    let stderr = String::from_utf8_lossy(&result.stderr);
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        result.status.success(),
        "the world-scoped arm runs (on main the arm and its flags are unknown, exit 2), and a \
         second-world record served to the agent would fail it: stdout {stdout} stderr {stderr}"
    );
    let line = summary(&result);
    assert_eq!(line["arm"], "world-scoped");
    assert_eq!(line["retriever"], "world-scoped-text");
    assert_eq!(line["hidden_share_permille"], HIDDEN_SHARE);
    assert_eq!(line["partition_seed"], SEED);
    assert_eq!(
        line["params_digest"],
        Fingerprinter::new(WORLD_SCOPED_PARAMS)
            .part(b"world-scoped-text")
            .u64(u64::from(HIDDEN_SHARE))
            .u64(u64::from(SEED))
            .finish()
            .to_hex(),
        "the params digest is the fingerprint of the retriever, the share and the seed"
    );
    assert_eq!(
        line["records_hidden"], 3,
        "three records sit in the second world"
    );
    assert_eq!(line["records_readable"], 4);
    assert_eq!(
        line["records_written"], 7,
        "every record lands as a claim, the corpus whose one query is dropped included"
    );
    let mut hidden_ids = vec![
        ids.hidden_match.clone(),
        ids.hidden_other.clone(),
        ids.hidden_only.clone(),
    ];
    hidden_ids.sort();
    assert_eq!(
        line["partition_digest"],
        ContentHash::of(&serde_json::to_vec(&hidden_ids).expect("hidden ids JSON")).to_hex(),
        "the partition pin is the content hash of the sorted hidden ids as a JSON array: an \
         id holding a newline cannot make two partitions hash alike"
    );
    assert_eq!(
        line["queries_dropped"], 1,
        "the query whose only relevant record is hidden is not graded"
    );
    assert_ne!(
        line["pack_digest"], line["source_pack_digest"],
        "the card grades the readable view, not the source slice"
    );

    let card: Value =
        serde_json::from_slice(&std::fs::read(&card_path).expect("scorecard file reads"))
            .expect("scorecard file is JSON");
    assert_eq!(card["model_id"], "world-scoped-text");
    assert_eq!(card["pack_digest"], line["pack_digest"]);
    assert_eq!(card["query_count"], 1);
    assert_eq!(card["repeat_digest_equal"], true);
    let per_query = card["per_query"].as_array().expect("per-query scores");
    assert_eq!(per_query.len(), 1);
    assert_eq!(per_query[0]["query_id"], "query-harbour");
    assert_eq!(
        per_query[0]["returned"], 1,
        "of the three records holding the query words the agent is served the readable one \
         ({}), never {} or {}",
        ids.readable_match, ids.hidden_match, ids.hidden_other
    );
    assert_eq!(
        per_query[0]["ndcg_at_10"], 1.0,
        "the hidden relevant record left the qrels: the readable one alone is ideal"
    );
    assert_eq!(per_query[0]["recall_at_5"], 1.0);

    let again_path = dir.path().join("world-scoped-again.json");
    let again = run_arm(dir.path(), &again_path, HIDDEN_SHARE);
    assert!(again.status.success(), "the second run succeeds");
    let again_line = summary(&again);
    assert_eq!(
        again_line["pack_digest"], line["pack_digest"],
        "the partition is reproducible: the same view digest"
    );
    assert_eq!(again_line["params_digest"], line["params_digest"]);
    assert_eq!(again_line["partition_digest"], line["partition_digest"]);
    let again_card: Value =
        serde_json::from_slice(&std::fs::read(&again_path).expect("second scorecard reads"))
            .expect("second scorecard is JSON");
    assert_eq!(
        again_card["per_query"][0]["ranked_digest"], per_query[0]["ranked_digest"],
        "a second fresh vault ranks the same: two builds' cards compare ranking for ranking"
    );
}

/// The positive control: with no hidden share the same pack's claims all
/// sit in the base world, so the agent is served every record holding the
/// query words. The two second-world claims the first test keeps out are
/// searchable claims, not rows that never reached the text index.
#[test]
fn world_scoped_arm_with_no_hidden_share_serves_every_match() {
    let dir = tempfile::tempdir().expect("scorecard fixture dir");
    write_pack(dir.path());
    let card_path = dir.path().join("world-scoped-open.json");
    let result = run_arm(dir.path(), &card_path, 0);
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(result.status.success(), "the open run succeeds: {stdout}");
    let line = summary(&result);
    assert_eq!(line["records_hidden"], 0);
    assert_eq!(line["records_readable"], 7);
    assert_eq!(line["records_written"], 7);
    assert_eq!(line["queries_dropped"], 0);
    assert_eq!(
        line["pack_digest"], line["source_pack_digest"],
        "nothing hidden: the view is the source slice"
    );
    let card: Value =
        serde_json::from_slice(&std::fs::read(&card_path).expect("scorecard file reads"))
            .expect("scorecard file is JSON");
    assert_eq!(card["query_count"], 2);
    let per_query = card["per_query"].as_array().expect("per-query scores");
    assert_eq!(per_query[0]["query_id"], "query-harbour");
    assert_eq!(
        per_query[0]["returned"], 3,
        "all three records holding the query words are served once readable"
    );
    assert_eq!(per_query[1]["query_id"], "query-mountain");
    assert_eq!(per_query[1]["returned"], 1);
}

/// Write an unembedded `search` slice of one corpus whose one query's only
/// relevant record the partition hides, beside one readable filler. Returns
/// the hidden record's id.
fn write_hidden_answer_pack(dir: &Path) -> String {
    let hidden_only = pick(1, true).remove(0);
    let filler = pick(1, false).remove(0);
    let manifest = json!({
        "contract": "oneiron.retrieval_pack.v1",
        "pack_id": "world-scoped-hidden-answer-fixture",
        "revision": "r1",
        "slice": "search",
        "source": {
            "dataset": "LongMemEval-S",
            "dataset_sha256": sha256_hex(b"fixture-dataset"),
            "license": "MIT",
            "split_sha256": sha256_hex(b"fixture-split"),
        },
        "embedding": Value::Null,
        "records": [
            record(&hidden_only, "mountain trail snowfall"),
            record(&filler, "city bus schedule"),
        ],
        "corpora": [
            {"corpus_id": "corpus-mountain", "sessions": [
                {"session_id": "sess-mountain", "time": "2026-01-01T00:00:00Z", "record_ids": [hidden_only, filler]},
            ]},
        ],
        "queries": [
            {"query_id": "query-mountain", "slice": "search", "corpus_id": "corpus-mountain", "category": "single-session-user", "text": "mountain snowfall", "now": "2026-01-02T00:00:00Z", "qrels": {hidden_only.clone(): 2}, "expect_empty": false},
        ],
    });
    let mut pretty = serde_json::to_vec_pretty(&manifest).expect("manifest JSON");
    pretty.push(b'\n');
    std::fs::write(dir.join("search.json"), pretty).expect("manifest write");
    hidden_only
}

/// A partition that leaves no query a readable relevant record still runs
/// (REVIEW-10085 round 2): every record lands as a claim and its landing is
/// checked, and the card grades no query. Before, the arm refused the
/// partition and wrote nothing.
#[test]
fn world_scoped_arm_with_every_query_dropped_still_writes_every_record() {
    let dir = tempfile::tempdir().expect("scorecard fixture dir");
    let hidden_only = write_hidden_answer_pack(dir.path());
    let card_path = dir.path().join("world-scoped-hidden-answer.json");
    let result = run_arm(dir.path(), &card_path, HIDDEN_SHARE);
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        result.status.success(),
        "a partition that hides the only relevant record ({hidden_only}) of every query still          runs: stdout {stdout} stderr {stderr}"
    );
    let line = summary(&result);
    assert_eq!(line["records_hidden"], 1);
    assert_eq!(line["records_readable"], 1);
    assert_eq!(
        line["records_written"], 2,
        "both records land as claims though no query is graded"
    );
    assert_eq!(line["queries_dropped"], 1);
    let card: Value =
        serde_json::from_slice(&std::fs::read(&card_path).expect("scorecard file reads"))
            .expect("scorecard file is JSON");
    assert_eq!(card["query_count"], 0);
    assert_eq!(
        card["per_query"].as_array().map(Vec::len),
        Some(0),
        "the card grades no query"
    );
}

/// Write an unembedded `search` slice of one corpus: the relevant record
/// "orchard harvest" from 2020 and the newer "orchard harvest notes" from
/// 2025, plus a filler, queried the day after the newer session.
fn write_age_pack(dir: &Path) -> (String, String) {
    let ids = pick(3, false);
    let (old, new, filler) = (ids[0].clone(), ids[1].clone(), ids[2].clone());
    let manifest = json!({
        "contract": "oneiron.retrieval_pack.v1",
        "pack_id": "world-scoped-age-fixture",
        "revision": "r1",
        "slice": "search",
        "source": {
            "dataset": "LongMemEval-S",
            "dataset_sha256": sha256_hex(b"fixture-dataset"),
            "license": "MIT",
            "split_sha256": sha256_hex(b"fixture-split"),
        },
        "embedding": Value::Null,
        "records": [
            record(&old, "orchard harvest"),
            record(&new, "orchard harvest notes"),
            record(&filler, "city bus schedule"),
        ],
        "corpora": [
            {"corpus_id": "corpus-orchard", "sessions": [
                {"session_id": "sess-2020", "time": "2020-01-01T00:00:00Z", "record_ids": [old, filler]},
                {"session_id": "sess-2025", "time": "2025-06-01T00:00:00Z", "record_ids": [new]},
            ]},
        ],
        "queries": [
            {"query_id": "query-orchard", "slice": "search", "corpus_id": "corpus-orchard", "category": "single-session-user", "text": "orchard harvest", "now": "2025-06-02T00:00:00Z", "qrels": {old.clone(): 2}, "expect_empty": false},
        ],
    });
    let mut pretty = serde_json::to_vec_pretty(&manifest).expect("manifest JSON");
    pretty.push(b'\n');
    std::fs::write(dir.join("search.json"), pretty).expect("manifest write");
    (old, new)
}

/// The arm ranks by text alone: claim age moves no record. The older record
/// is the shorter match, so BM25 puts it first; were each claim stamped at
/// its own session, the access-factor decay of a five-year-old claim (down
/// to its 0.05 floor) would put the newer one ahead of it.
#[test]
fn world_scoped_arm_ranks_by_text_not_claim_age() {
    let dir = tempfile::tempdir().expect("scorecard fixture dir");
    let (old, new) = write_age_pack(dir.path());
    let card_path = dir.path().join("world-scoped-age.json");
    let result = run_arm(dir.path(), &card_path, 0);
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        result.status.success(),
        "the age run succeeds: stdout {stdout} stderr {stderr}"
    );
    let card: Value =
        serde_json::from_slice(&std::fs::read(&card_path).expect("scorecard file reads"))
            .expect("scorecard file is JSON");
    let per_query = card["per_query"].as_array().expect("per-query scores");
    assert_eq!(per_query.len(), 1);
    assert_eq!(
        per_query[0]["returned"], 2,
        "both records holding the query words are served"
    );
    assert_eq!(
        per_query[0]["mrr"], 1.0,
        "the shorter, relevant match {old} ranks first, ahead of the newer {new}: no claim \
         age decay reorders a text-only arm"
    );
}

#[test]
fn world_scoped_arm_flags_are_gated() {
    let dir = tempfile::tempdir().expect("scorecard fixture dir");
    write_pack(dir.path());
    let pack_dir = dir.path().to_str().expect("fixture dir").to_owned();
    let out = dir.path().join("card.json");
    let out_arg = out.to_str().expect("scorecard path").to_owned();
    let base = [
        "run",
        "--pack-dir",
        pack_dir.as_str(),
        "--slice",
        "search",
        "--engine-commit",
        ENGINE_COMMIT,
        "--out",
        out_arg.as_str(),
    ];
    let refused = |extra: &[&str], words: &str| {
        let mut args: Vec<&str> = base.to_vec();
        args.extend_from_slice(extra);
        let result = scorecard(&args);
        assert_eq!(result.status.code(), Some(2), "{extra:?} is bad input");
        let error = summary(&result)["error"]
            .as_str()
            .expect("an error line")
            .to_owned();
        assert!(error.contains(words), "{extra:?}: {error}");
    };
    refused(
        &["--hidden-share", "500"],
        "--hidden-share needs --arm world-scoped",
    );
    refused(
        &["--partition-seed", "7"],
        "--partition-seed needs --arm world-scoped",
    );
    refused(
        &["--arm", "world-scoped", "--params", "params.json"],
        "--params needs --arm pipeline",
    );
    refused(
        &["--arm", "world-scoped", "--rank-profile", "bm25f"],
        "--rank-profile needs --arm keyword",
    );
    refused(
        &["--arm", "world-scoped", "--hidden-share", "1000"],
        "--hidden-share",
    );
    let sealed = scorecard(&["run", "--arm", "world-scoped", "--slice", "sealed"]);
    assert_eq!(sealed.status.code(), Some(2), "the sealed slice is refused");
    let error = summary(&sealed)["error"]
        .as_str()
        .expect("an error line")
        .to_owned();
    assert!(
        error.contains("search and held_out slices only"),
        "sealed: {error}"
    );
}
