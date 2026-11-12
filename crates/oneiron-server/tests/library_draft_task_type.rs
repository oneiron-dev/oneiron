//! FIX 10508: a `self.browser.library.draft` call whose caller records its
//! task type and names its checks gives the code-mode run's solved-run
//! capture its span, so the unfiled run joins the solved-run groups under
//! its site, origin, type and subgoal. Before the fix the draft arm refused
//! every draft: "a draft names its checks but no recorded task type". A
//! draft that records no type still captures nothing (kept).
//!
//! Reaches the capture's span reader through `oneiron_server::test_doors`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --test library_draft_task_type`.
#![cfg(oneiron_test_support)]

use oneiron::browser_library::SolvedSource;
use oneiron::learning::TypeRef;
use oneiron_server::test_doors::solved_runs::{CheckedSpanView, draft_checked_span};
use serde_json::json;

fn vault() -> (tempfile::TempDir, oneiron::Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap();
    (dir, vault)
}

#[test]
fn draft_with_recorded_type_builds_checked_span() {
    let (_dir, vault) = vault();
    let input = json!({
        "subgoal": "file the expense report",
        "postcondition": [{ "role": "heading", "name": "Report filed" }],
        "after_seq": 3,
        "type_ref": { "node_id": "expenses.file", "tree_version": 2 },
    });
    let found = draft_checked_span(&vault, &input, &json!({}), Some(5));
    assert_eq!(
        found,
        Ok(Some(CheckedSpanView {
            subgoal: "file the expense report".to_owned(),
            checks: 1,
            type_ref: TypeRef {
                node_id: "expenses.file".to_owned(),
                tree_version: 2,
            },
            source: SolvedSource::UnfiledDraft,
            after_seq: Some(3),
        })),
        "a draft with its recorded type and checks names its capture span"
    );
}

#[test]
fn draft_without_recorded_type_captures_nothing() {
    let (_dir, vault) = vault();
    let input = json!({
        "subgoal": "file the expense report",
        "postcondition": [{ "role": "heading", "name": "Report filed" }],
        "after_seq": 3,
    });
    let found = draft_checked_span(&vault, &input, &json!({}), Some(5));
    assert!(
        found.is_err(),
        "a draft that records no task type names no capture: {found:?}"
    );
}
