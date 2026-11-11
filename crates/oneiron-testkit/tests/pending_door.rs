//! A test that waits on a product door runs nightly without failing it until
//! its deadline; past the deadline the nightly fails on it: door or delete.

use oneiron_testkit::pending_door::PendingDoors;
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
