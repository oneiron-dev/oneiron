//! `oneiron maintain` on a stopped vault: every housekeeping sweep runs now,
//! the typed report prints as JSON, and a healthy vault exits 0.
use serde_json::Value;

use super::reopen_after_restart::{oneiron, stdout};

const ENGINE_SWEEPS: [&str; 10] = [
    "secret_lease_expiry",
    "critical_confirm_expiry",
    "symbol_lease_expiry",
    "voice_print_retention",
    "esign_expiry",
    "esign_seal_backstop",
    "commitment_lapse",
    "gate_decision_retention",
    "hard_erase_sweep",
    "ppr_cache_eviction",
];

fn outcomes(report: &Value) -> Vec<(String, String)> {
    report["housekeeping"]["sweeps"]
        .as_array()
        .expect("one row per sweep")
        .iter()
        .map(|row| {
            (
                row["sweep"].as_str().expect("sweep code").to_owned(),
                row["outcome"].as_str().expect("outcome").to_owned(),
            )
        })
        .collect()
}

#[test]
fn maintain_runs_every_sweep_and_the_named_repairs_on_a_healthy_vault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = dir.path().join("vault");
    let vault = vault.to_str().expect("UTF-8 path");
    let config = dir.path().join("oneiron.toml");
    stdout(oneiron(&["init", vault, "--embedder", "none"], &config));

    let report: Value = serde_json::from_str(&stdout(oneiron(
        &["maintain", "--vault-path", vault],
        &config,
    )))
    .expect("one JSON report");
    let outcomes = outcomes(&report);
    assert_eq!(outcomes.len(), 16, "{report:#}");
    for (sweep, outcome) in &outcomes {
        let expected = if ENGINE_SWEEPS.contains(&sweep.as_str()) {
            "ran"
        } else {
            "host_only"
        };
        assert_eq!(outcome, expected, "{sweep}: {report:#}");
    }
    assert!(report.get("repairs").is_none(), "{report:#}");

    let report: Value = serde_json::from_str(&stdout(oneiron(
        &[
            "maintain",
            "--vault-path",
            vault,
            "--recompute-short-ids",
            "--reindex-text",
        ],
        &config,
    )))
    .expect("one JSON report");
    assert!(report["repairs"]["short_ids"].is_object(), "{report:#}");
    assert!(report["repairs"]["text_index"].is_object(), "{report:#}");
    assert!(
        report["repairs"].get("vector_graph").is_none(),
        "{report:#}"
    );
}
