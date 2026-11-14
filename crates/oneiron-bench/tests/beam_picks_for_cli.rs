//! `oneiron-bench beam measure --picks-for` (census L9-32; Engine ruling
//! L9-32-PICK-WRITER, Sat 14 Nov 07:43): the shipped binary prints the
//! argument of `vault.agents.optional_memory.set` from a saved measure
//! report's reader picks, so the owner applies a bench pick in one reviewed
//! step. On a tree without the flag the binary answers "unknown BEAM
//! invocation" and exits non-zero.
//!
//! `cargo test --locked -p oneiron-bench --test beam_picks_for_cli`.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Output};

use serde_json::{Value, json};

const AGENT: &str = "0123456789abcdef0123456789abcdef";

/// One saved reader pick, in the shape `beam measure` prints.
fn pick(regime: &str, family: &str, arm: &str, tokens: Option<u64>) -> Value {
    json!({
        "regime": regime,
        "answerer": "local/reader@1",
        "answerer_params_sha256": "aa",
        "task_family": family,
        "arm": arm,
        "effort": tokens.map(|_| "light"),
        "optional_memory_tokens": tokens,
        "tier": tokens.filter(|_| arm == "deterministic").map(|_| "standard"),
        "paired_difference": {"int-cast-saw-question": 0.25, "beam-fixed": 0.25},
    })
}

fn picks_for(report: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_oneiron-bench"))
        .args([
            "beam",
            "measure",
            "--picks-for",
            AGENT,
            "--expected-version",
            "1",
        ])
        .args(extra)
        .arg(report)
        .output()
        .expect("the bench binary runs")
}

fn saved(dir: &Path, picks: &[Value]) -> std::path::PathBuf {
    let path = dir.join("report.json");
    std::fs::write(&path, json!({"picks": picks, "rows": []}).to_string()).unwrap();
    path
}

#[test]
fn the_printed_argument_lists_each_family_whose_pick_takes_memory() {
    let dir = tempfile::tempdir().unwrap();
    let report = saved(
        dir.path(),
        &[
            pick("fixed_answer_cap", "event_ordering", "backbone_solo", None),
            pick(
                "fixed_answer_cap",
                "multi_session",
                "deterministic",
                Some(2048),
            ),
            pick(
                "fixed_total_tokens",
                "event_ordering",
                "backbone_solo",
                None,
            ),
            pick(
                "fixed_total_tokens",
                "multi_session",
                "deterministic",
                Some(2048),
            ),
        ],
    );
    let out = picks_for(&report, &[]);
    assert!(
        out.status.success(),
        "picks-for exits 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let argument: Value = serde_json::from_slice(&out.stdout).expect("stdout is the argument");
    assert_eq!(
        argument,
        json!({
            "agent_def_ref": AGENT,
            "expected_version": "1",
            "default": {"kind": "none"},
            "families": {
                "multi_session": {"kind": "budget", "tokens": 2048, "view": "standard"},
            },
        })
    );
}

#[test]
fn regimes_that_disagree_print_only_with_one_named() {
    let dir = tempfile::tempdir().unwrap();
    let report = saved(
        dir.path(),
        &[
            pick(
                "fixed_answer_cap",
                "multi_session",
                "deterministic",
                Some(2048),
            ),
            pick("fixed_total_tokens", "multi_session", "backbone_solo", None),
        ],
    );
    let refused = picks_for(&report, &[]);
    assert!(!refused.status.success(), "no regime named");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--regime"),
        "the refusal names the way out: {}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let capped = picks_for(&report, &["--regime", "fixed_answer_cap"]);
    assert!(
        capped.status.success(),
        "{}",
        String::from_utf8_lossy(&capped.stderr)
    );
    let argument: Value = serde_json::from_slice(&capped.stdout).unwrap();
    assert_eq!(
        argument.pointer("/families/multi_session/tokens"),
        Some(&json!(2048))
    );
}

#[test]
fn a_recalling_pick_that_served_no_engine_pack_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let report = saved(
        dir.path(),
        &[pick(
            "fixed_answer_cap",
            "multi_session",
            "vanilla_rag",
            Some(2048),
        )],
    );
    let refused = picks_for(&report, &[]);
    assert!(
        !refused.status.success(),
        "no pack setting matches the pick"
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("served no engine pack"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(refused.stdout.is_empty(), "nothing to apply is printed");
}
