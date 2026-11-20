//! A test that waits on a product door runs nightly without failing it until
//! its deadline; past the deadline the nightly fails on it: door or delete.

use std::path::{Path, PathBuf};
use std::process::Command;

use oneiron_testkit::pending_door::{PendingDoors, REGISTER_ENV};
use oneiron_testkit::quarantine::Date;

const REGISTER: &str = r#"
{"module": "crates/oneiron/src/skill_hub", "crate": "oneiron", "file": "crates/oneiron/src/skill_hub/admission_tests.rs", "test": "every_hub_tier_requires_human_consent", "door": "POST /v1/owner/packs", "deadline": "2026-12-01", "fix_row": "[NO-DOOR ND-001]", "status": "WAIT", "row": "ND-001"}
{"module": "crates/oneiron-server/tests", "crate": "oneiron-server", "file": "crates/oneiron-server/tests/it/booking.rs", "test": "a_token_is_single_use", "door": "booking", "deadline": "2026-12-01", "fix_row": "[NO-DOOR ND-050]", "status": "WAIT", "row": "ND-050"}
{"module": "crates/oneiron/src/memory/chat", "crate": "oneiron", "file": "crates/oneiron/src/memory/chat.rs", "test": "chat_keeps_order", "door": null, "deadline": "2026-11-30", "fix_row": "[NO-DOOR ND-090]", "status": "DELETE-UNLESS", "row": "ND-090"}
{"module": "tests/e2e", "crate": "e2e", "file": "tests/e2e/gate.test.ts", "test": "GATE-05", "door": "x", "deadline": "2026-12-01", "fix_row": "[NO-DOOR ND-124]", "status": "WAIT", "row": "ND-124"}
{"module": "crates/oneiron/src/image", "crate": "oneiron", "file": null, "test": null, "door": "vault.image.*", "deadline": "2026-12-01", "fix_row": "[NO-DOOR ND-128]", "status": "DOOR-ROW", "row": "ND-128", "moves": []}
"#;

fn date(text: &str) -> Date {
    Date::parse(text).expect("a date")
}

#[test]
fn waiting_tests_are_pending_until_their_deadline_and_expired_after_it() {
    let before = PendingDoors::parse(REGISTER, date("2026-11-30")).expect("parse");
    assert_eq!(
        before.pending.len(),
        3,
        "E2E cases and door rows are not nextest tests"
    );
    assert!(
        before.expired.is_empty(),
        "on its deadline a test still waits"
    );
    assert_eq!(before.expired_filter(), "none()");

    let after = PendingDoors::parse(REGISTER, date("2026-12-01")).expect("parse");
    assert_eq!(after.pending.len(), 2);
    assert_eq!(after.expired.len(), 1);
    assert_eq!(
        after.expired_report(),
        [
            "door or delete: ND-090 crates/oneiron/src/memory/chat.rs::chat_keeps_order (DELETE-UNLESS, deadline 2026-11-30)"
        ]
    );

    let gone = PendingDoors::parse(REGISTER, date("2026-12-02")).expect("parse");
    assert!(gone.pending.is_empty());
    assert_eq!(gone.expired.len(), 3);
}

#[test]
fn each_waiting_test_is_selected_by_package_binary_or_module_and_name() {
    let doors = PendingDoors::parse(REGISTER, date("2026-11-01")).expect("parse");
    let filters: Vec<String> = doors.pending.iter().map(|test| test.filter()).collect();
    assert_eq!(
        filters,
        [
            "(package(=oneiron) & test(/^skill_hub::(.+::)?every_hub_tier_requires_human_consent$/))",
            "(package(=oneiron-server) & binary(=it) & test(/(^|::)a_token_is_single_use$/))",
            "(package(=oneiron) & test(/^memory::(.+::)?chat_keeps_order$/))",
        ]
    );
    assert_eq!(doors.pending_filter(), filters.join(" | "));
}

#[test]
fn an_empty_register_waits_on_nothing() {
    let doors = PendingDoors::parse("\n", date("2026-11-10")).expect("parse");
    assert_eq!(doors.pending_filter(), "none()");
    assert_eq!(doors.expired_filter(), "none()");
    assert!(PendingDoors::parse("{not json", date("2026-11-10")).is_err());
}

/// Rows naming integration test files as the register did before a fold wave
/// (FIX NIGHTLY-PENDING-DOOR-FILTER-MOVED-TEST-FILE): one the wave moved into
/// the `it` harness, one still in place, one whose file is gone, one whose
/// file name sits in two harness areas, and a source-file row whose file is
/// gone.
const MOVED_REGISTER: &str = r#"
{"module": "crates/oneiron/tests/code_memory", "crate": "oneiron", "file": "crates/oneiron/tests/code_memory.rs", "test": "deleting_a_payload_clears_its_refs", "door": "vault.code.memory.attach", "deadline": "2026-12-01", "fix_row": "[NO-DOOR ND-105]", "status": "WAIT", "row": "ND-105"}
{"module": "crates/oneiron/tests/kept", "crate": "oneiron", "file": "crates/oneiron/tests/kept.rs", "test": "a_kept_test", "door": "x", "deadline": "2026-12-01", "fix_row": "[NO-DOOR ND-901]", "status": "WAIT", "row": "ND-901"}
{"module": "crates/oneiron/tests/gone", "crate": "oneiron", "file": "crates/oneiron/tests/gone.rs", "test": "a_gone_test", "door": "x", "deadline": "2026-12-01", "fix_row": "[NO-DOOR ND-902]", "status": "WAIT", "row": "ND-902"}
{"module": "crates/oneiron/tests/twice", "crate": "oneiron", "file": "crates/oneiron/tests/twice.rs", "test": "a_twice_test", "door": "x", "deadline": "2026-12-01", "fix_row": "[NO-DOOR ND-903]", "status": "WAIT", "row": "ND-903"}
{"module": "crates/oneiron/src/skill_hub", "crate": "oneiron", "file": "crates/oneiron/src/skill_hub/gone_tests.rs", "test": "a_module_test", "door": "x", "deadline": "2026-12-01", "fix_row": "[NO-DOOR ND-904]", "status": "WAIT", "row": "ND-904"}
"#;

/// The tree after the fold wave: `code_memory.rs` and two `twice.rs` in the
/// harness, `kept.rs` at the top level, no `gone.rs` anywhere.
const MOVED_TREE: [&str; 5] = [
    "crates/oneiron/tests/it/main.rs",
    "crates/oneiron/tests/it/authority/code_memory.rs",
    "crates/oneiron/tests/it/authority/twice.rs",
    "crates/oneiron/tests/it/sync/twice.rs",
    "crates/oneiron/tests/kept.rs",
];

/// A workspace tree of empty files in the temp dir, removed on drop.
struct Tree(PathBuf);

impl Tree {
    fn new(label: &str, files: &[&str]) -> Self {
        let root = std::env::temp_dir().join(format!(
            "oneiron-testkit-pending-door-{}-{label}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        for file in files {
            let path = root.join(file);
            std::fs::create_dir_all(path.parent().expect("a parent dir")).expect("make the dir");
            std::fs::write(&path, "").expect("write the file");
        }
        Self(root)
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The pending-door tool run at `tree`'s root with `register` on `day`, as the
/// nightly runs it from the workspace root: its exit code and its JSON.
fn run_tool(tree: &Path, register: &str, day: &str) -> (Option<i32>, serde_json::Value) {
    let file = tree.join("register.jsonl");
    std::fs::write(&file, register).expect("write the register");
    let output = Command::new(env!("CARGO_BIN_EXE_oneiron-testkit-pending-door"))
        .arg(day)
        .current_dir(tree)
        .env(REGISTER_ENV, &file)
        .output()
        .expect("run the pending-door tool");
    let json = serde_json::from_slice(&output.stdout).expect("the tool prints one JSON object");
    (output.status.code(), json)
}

#[test]
fn a_test_a_fold_moved_is_selected_in_its_harness_and_a_gone_file_names_no_binary() {
    let tree = Tree::new("moved", &MOVED_TREE);
    let (code, json) = run_tool(&tree.0, MOVED_REGISTER, "2026-11-18");
    assert_eq!(
        json["pending_filter"],
        "(package(=oneiron) & binary(=it) & test(/(^|::)deleting_a_payload_clears_its_refs$/)) \
         | (package(=oneiron) & binary(=kept) & test(/(^|::)a_kept_test$/)) \
         | (package(=oneiron) & test(/^skill_hub::(.+::)?a_module_test$/))",
        "a filter that names a test binary the build lacks makes nextest refuse the whole night"
    );
    assert_eq!(code, Some(0));
    assert_eq!(json["pending"], 3);
    assert_eq!(
        json["moved"],
        serde_json::json!([
            "ND-105 crates/oneiron/tests/code_memory.rs::deleting_a_payload_clears_its_refs -> crates/oneiron/tests/it/authority/code_memory.rs"
        ])
    );
    assert_eq!(
        json["unlocated"],
        serde_json::json!([
            "ND-902 crates/oneiron/tests/gone.rs::a_gone_test",
            "ND-903 crates/oneiron/tests/twice.rs::a_twice_test"
        ]),
        "a file gone from the tree, or found in two places, leaves the filters"
    );
}

#[test]
fn a_test_past_its_date_whose_file_is_gone_still_fails_the_night_and_names_no_binary() {
    let tree = Tree::new("expired", &MOVED_TREE);
    let (code, json) = run_tool(&tree.0, MOVED_REGISTER, "2026-12-02");
    assert_eq!(
        json["expired_filter"],
        "(package(=oneiron) & binary(=it) & test(/(^|::)deleting_a_payload_clears_its_refs$/)) \
         | (package(=oneiron) & binary(=kept) & test(/(^|::)a_kept_test$/)) \
         | (package(=oneiron) & test(/^skill_hub::(.+::)?a_module_test$/))"
    );
    assert_eq!(
        code,
        Some(1),
        "door or delete: the night fails past the date"
    );
    assert_eq!(json["expired"], 5);
    let report = json["expired_report"].as_array().expect("a report list");
    assert!(
        report.contains(&serde_json::json!(
            "door or delete: ND-902 crates/oneiron/tests/gone.rs::a_gone_test (WAIT, deadline 2026-12-01, file gone from the tree)"
        )),
        "{report:?}"
    );
    assert_eq!(report.len(), 5);
}
