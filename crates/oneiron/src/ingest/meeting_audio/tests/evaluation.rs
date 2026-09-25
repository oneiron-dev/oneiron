//! Fixture scorer checks only: no audio, model, or corpus runs here.
//!
//! These tests pin the pure WER/E3 scorers and the strict receipt/cohort
//! parsers over in-repo literal fixtures. A green run proves the scorer
//! arithmetic and parser refusals, never that an engine default won a bake-off
//! or that any real E1/E3 evaluation ran.

use std::collections::HashMap;

use super::super::{CohortManifest, E1SelectionReceipt, aggregate_wer, e3_score, wer_counts};

fn words<const N: usize>(tokens: [&str; N]) -> HashMap<String, String> {
    tokens
        .into_iter()
        .enumerate()
        .map(|(i, cluster)| (format!("w{i}"), cluster.to_string()))
        .collect()
}

fn labels<const N: usize>(principals: [&str; N]) -> HashMap<String, String> {
    principals
        .into_iter()
        .enumerate()
        .map(|(i, principal)| (format!("w{i}"), principal.to_string()))
        .collect()
}

#[test]
fn wer_counts_split_substitution_deletion_insertion_over_fixture_tokens() {
    // One of each operation: "bravo"->"BRAVO" substitutes, "charlie" deletes,
    // "XRAY" inserts. Caller tokenization is used verbatim (no case folding).
    let reference = ["alpha", "bravo", "charlie", "delta"];
    let hypothesis = ["alpha", "BRAVO", "delta", "XRAY"];
    let counts = wer_counts(&reference, &hypothesis);
    assert_eq!(counts.reference_len, 4);
    assert_eq!(wer_counts(&["old"], &["new"]).substitutions, 1);
    assert_eq!(wer_counts(&["old"], &[]).deletions, 1);
    assert_eq!(wer_counts(&[], &["new"]).insertions, 1);
    assert_eq!(counts.errors(), 3);
    let empty = wer_counts(&[], &[]);
    assert_eq!(empty.errors(), 0);
    assert_eq!(empty.reference_len, 0);
    // Aggregate keeps exact integer counts across two language arms.
    let total = aggregate_wer(&[counts, empty]);
    assert_eq!(total.reference_len, 4);
    assert_eq!(total.errors(), 3);
}

#[test]
fn e3_score_uses_one_global_mapping_and_penalizes_chunk_flips() {
    let expected = labels(["a", "a", "b", "b"]);
    let correct = words(["cluster2", "cluster2", "cluster1", "cluster1"]);
    let score = e3_score(&correct, &expected).unwrap();
    assert_eq!(score.correct, 4);
    assert_eq!(score.wrong_speaker, 0);
    let flipped = words(["cluster2", "cluster1", "cluster1", "cluster2"]);
    let score = e3_score(&flipped, &expected).unwrap();
    assert_eq!(score.correct, 2);
    assert_eq!(score.wrong_speaker, 2);
    let missing = words(["cluster2"]);
    assert_eq!(e3_score(&missing, &expected).unwrap().missing_words, 3);
    assert_eq!(e3_score(&correct, &HashMap::new()).unwrap().extra_words, 4);
}

#[test]
fn e1_receipt_and_cohort_manifest_parse_and_reject_fixture_documents() {
    let corpus_sha = "a".repeat(64);
    let cohort_sha = "b".repeat(64);
    let audio_sha = "c".repeat(64);
    let ref_sha = "d".repeat(64);
    let mut receipt = serde_json::json!({
        "corpus_id": "fixture-corpus",
        "corpus_sha256": corpus_sha,
        "arms": [
            {
                "model_id": "fixture-asr-a", "model_revision": "fixture-rev", "model_sha256": "a".repeat(64), "runtime_sha256": "b".repeat(64),
                "wer_by_lang": {
                    "en": {
                        "substitutions": 1,
                        "deletions": 1,
                        "insertions": 1,
                        "reference_len": 4
                    }
                }
            },
            {
                "model_id": "fixture-asr-b", "model_revision": "fixture-rev", "model_sha256": "c".repeat(64), "runtime_sha256": "b".repeat(64),
                "wer_by_lang": {
                    "en": {
                        "substitutions": 0,
                        "deletions": 0,
                        "insertions": 0,
                        "reference_len": 4
                    }
                }
            }
        ],
        "winner": "fixture-asr-b"
    });
    let parsed = E1SelectionReceipt::parse(&receipt.to_string()).unwrap();
    assert_eq!(parsed.winner, "fixture-asr-b");
    let totals = parsed.winner_totals().unwrap();
    assert_eq!(totals.reference_len, 4);
    assert_eq!(totals.errors(), 0);
    // Winner naming no arm is refused; parsing never selects a default.
    let mut bad_winner = receipt.clone();
    bad_winner["winner"] = serde_json::json!("no-such-model");
    assert!(E1SelectionReceipt::parse(&bad_winner.to_string()).is_err());
    // Unknown fields are refused so a producer cannot smuggle authority.
    let mut extra = receipt.clone();
    extra["authority"] = serde_json::json!("self-declared");
    assert!(E1SelectionReceipt::parse(&extra.to_string()).is_err());
    let mut manifest = serde_json::json!({
        "corpus_id": "fixture-corpus",
        "cohort_sha256": cohort_sha,
        "files": [
            {
                "file_id": "f1",
                "audio_sha256": audio_sha,
                "reference_sha256": ref_sha,
                "consent_ref": "host-consent-ledger:001"
            }
        ]
    });
    let shape: CohortManifest = serde_json::from_value(manifest.clone()).unwrap();
    manifest["cohort_sha256"] = serde_json::json!(shape.computed_hash().unwrap());
    let cohort = CohortManifest::parse(&manifest.to_string()).unwrap();
    assert!(parsed.validate_for_cohort(&cohort).is_err());
    receipt["corpus_sha256"] = serde_json::json!(cohort.cohort_sha256);
    E1SelectionReceipt::parse(&receipt.to_string())
        .unwrap()
        .validate_for_cohort(&cohort)
        .unwrap();
    let mut changed = manifest.clone();
    changed["files"][0]["audio_sha256"] = serde_json::json!("e".repeat(64));
    assert!(CohortManifest::parse(&changed.to_string()).is_err());
    let mut nested_extra = receipt.clone();
    nested_extra["arms"][0]["authorized"] = serde_json::json!(true);
    assert!(E1SelectionReceipt::parse(&nested_extra.to_string()).is_err());
    assert_eq!(cohort.files.len(), 1);
    assert_eq!(cohort.files[0].consent_ref, "host-consent-ledger:001");
    // Blank file id is refused; hashes bind, consent stays host-side.
    let mut bad_file = manifest.clone();
    bad_file["files"][0]["file_id"] = serde_json::json!("  ");
    assert!(CohortManifest::parse(&bad_file.to_string()).is_err());
}
