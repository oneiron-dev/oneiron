//! Vector bench contract and end-to-end tests.

// ─── Tests ───────────────────────────────────────────────────────────────

use super::*;

/// End-to-end at a tiny operating point (n=100 < ef_search=128, so the
/// search beam covers the whole graph): recall must be exactly 1.0 in
/// every phase, churn counts must match, and the post-delete phase must
/// produce zero structural violations (no tombstone leaks).
#[test]
fn run_bench_tiny_end_to_end() {
    let settings = BenchSettings {
        n: 100,
        dim: 16,
        seed: 42,
        queries: 20,
        churn: ChurnMode::Both,
        churn_pct: 10,
        churn_ops: None,
        assert_recall: true,
    };
    let report = run_bench(&settings).expect("tiny bench run");

    assert_eq!(report.insert_new.count, 100);
    assert_eq!(report.baseline.recall_k, 10);
    assert!(report.baseline.violations.is_empty());
    assert_eq!(report.baseline.recall, 1.0);

    let refresh = report.refresh.as_ref().expect("refresh phase ran");
    assert_eq!(refresh.churned, 10);
    assert_eq!(refresh.live_after, 100);
    assert!(refresh.search.violations.is_empty());
    assert_eq!(refresh.search.recall, 1.0);

    let delete = report.delete.as_ref().expect("delete phase ran");
    assert_eq!(delete.churned, 10);
    assert_eq!(delete.live_after, 90);
    assert!(delete.search.violations.is_empty());
    assert_eq!(delete.search.recall, 1.0);

    assert_eq!(report.ram.vectors_raw_bytes, 100 * 16 * 4);
    assert!(report.ram.data_mdb_disk_bytes.is_some_and(|b| b > 0));
}
