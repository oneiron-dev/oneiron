//! Corpus honesty: every case emits exactly one row, probes never score.
//!
//! Runs the full pinned 834-case fixture through the unchanged engine and
//! asserts the report shape laws. It does NOT assert a pass rate: the score
//! is evidence for the step-20 decision, not a test threshold, and it is
//! meaningless before the Excel goldens and the same-corpus LibreOffice
//! baseline both exist.

use std::collections::BTreeMap;
use std::path::PathBuf;

use oneiron_xlsx_formula::engine::ENGINE_STAMP;
use oneiron_xlsx_formula::measure::{MeasureOptions, measure_corpus, read_corpus_cases};

fn fixture() -> (PathBuf, String) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../oneiron-docedit/tests/fixtures/spreadsheet-compat");
    let provenance: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("provenance.json")).expect("provenance readable"),
    )
    .expect("provenance parses");
    let sha = provenance
        .get("normalized_cases_sha256")
        .and_then(serde_json::Value::as_str)
        .expect("provenance pins cases")
        .to_owned();
    (dir.join("cases.json"), sha)
}

#[test]
fn every_case_reports_exactly_once_with_a_stable_status() {
    let (cases_path, sha) = fixture();
    let cases = read_corpus_cases(&cases_path, &sha).expect("pinned corpus loads");
    assert_eq!(cases.len(), 834, "upstream holds 834 cases, not 604");
    let report = measure_corpus(&cases, &sha, &MeasureOptions::default());
    assert_eq!(report.engine_stamp, ENGINE_STAMP);
    assert_eq!(report.corpus_sha256, sha);
    assert_eq!(report.cases.len(), cases.len());
    let allowed = ["ok", "engine-error", "unsupported", "probe"];
    for case in &cases {
        let row = report.cases.get(&case.id).expect("one row per case");
        assert!(
            allowed.contains(&row.status.as_str()),
            "stable status for {}",
            case.id
        );
        if case.expected.is_null() {
            assert_eq!(row.status, "probe", "null-expected cases are probes");
            assert_eq!(row.matches_upstream, None, "probes never score");
        } else if row.status == "ok" {
            assert!(
                row.matches_upstream.is_some(),
                "scored cases carry a verdict"
            );
        } else {
            assert_eq!(
                row.matches_upstream, None,
                "unscored cases carry no verdict"
            );
            assert!(
                row.detail.as_ref().is_some_and(|detail| !detail.is_empty()),
                "unscored cases name why"
            );
        }
    }
    let counted: usize = report.status_counts.values().sum();
    assert_eq!(counted, cases.len(), "status counts cover every case");
    let mut by_status: BTreeMap<&str, usize> = BTreeMap::new();
    for row in report.cases.values() {
        *by_status.entry(row.status.as_str()).or_insert(0) += 1;
    }
    for (status, count) in &by_status {
        assert_eq!(
            report.status_counts.get(*status),
            Some(count),
            "counts match rows"
        );
    }
}

#[test]
fn tampered_corpus_refuses_to_measure() {
    let dir = std::env::temp_dir().join("oneiron-xlsx-formula-tamper.json");
    std::fs::write(&dir, b"[]").expect("temp writable");
    let error = read_corpus_cases(&dir, "not-the-pinned-sha").expect_err("hash must fail");
    assert_eq!(error.code(), "invalid-corpus");
    let _ = std::fs::remove_file(&dir);
}
