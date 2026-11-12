//! FIX 10508: a `self.browser.library.draft` call whose caller records its
//! task type and names its checks gives the code-mode run's solved-run
//! capture its span, so the unfiled run joins the solved-run groups under
//! its site, origin, type and subgoal. Before the fix the draft arm refused
//! every draft: "a draft names its checks but no recorded task type". A
//! draft that records no type still captures nothing (kept). A draft's
//! capture ends where the draft's own span ends (review round 1 of #7236).
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
            through_seq: None,
        })),
        "a draft with its recorded type and checks names its capture span"
    );
}

/// Review round 1 of #7236 (P1): a draft that ends its span before the
/// page's latest entry (seq 1 opens a form headed "Ready", seq 2 types
/// "Alice", seq 3 replaces it with "Bob"; the draft runs after 0 through 2)
/// gives its capture that end, so the capture keeps steps 1..2, not 1..3.
/// Before the fix the span kept only `after_seq`, and the capture ran to
/// the latest entry, "Bob" included.
#[test]
fn draft_capture_ends_at_its_through_seq() {
    let (_dir, vault) = vault();
    let input = json!({
        "subgoal": "fill the form",
        "postcondition": [{ "role": "heading", "name": "Ready" }],
        "after_seq": 0,
        "through_seq": 2,
        "type_ref": { "node_id": "forms.fill", "tree_version": 1 },
    });
    let found = draft_checked_span(&vault, &input, &json!({}), Some(3))
        .expect("a typed draft with checks names a capture")
        .expect("a draft call names a span");
    assert_eq!(
        (found.after_seq, found.through_seq),
        (Some(0), Some(2)),
        "the capture's span is the drafted span, after 0 through 2"
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
