//! The app's action table offers no verb-table row whose answer an invocation
//! never keeps (FIX ACTION-REPLAY-SERVES-UNKEPT-VERB-ANSWERS). An action keeps
//! its row's answer in its replay record and answers the same key from that
//! record again, and no row door judges the caller anew. So, as an action, a
//! starter whose workload approval was revoked would read the old workload
//! again, and a personal booking link's raw token would be held and answered
//! again. Those rows stay callable as direct rows; a row whose answer is kept
//! stays an action.
//!
//! Run on the fleet, never on a workstation:
//! cargo test --locked -p oneiron-server --all-features --test action_table_unkept_replies

use std::collections::BTreeSet;

use oneiron_server::actions::SharedActionExecutor;

/// The rows whose answer an invocation never keeps
/// (`api::facade::invocations::UNKEPT_REPLY_VERBS` at this test's writing).
const UNKEPT_REPLY_ROWS: [&str; 7] = [
    "vault.inquire",
    "vault.inquiry.edge.prepare_join",
    "vault.members.accept_with_inquiry_edge",
    "vault.members.inquiry_edge.attach",
    "vault.booking.personal_link.mint",
    "vault.jobs.workloads.get",
    "vault.jobs.workloads.list",
];

/// A verb-table row whose answer is kept, which a REST route runs as an action
/// (`execute_facade_row_held`).
const KEPT_ROW: &str = "vault.artifacts.create";

#[test]
fn the_action_table_offers_no_row_whose_answer_is_never_kept() {
    let app = SharedActionExecutor::app().expect("the app's action table builds");
    let offered: BTreeSet<&str> = app
        .definitions()
        .map(|definition| definition.id.as_str())
        .collect();
    let still_offered: Vec<&str> = UNKEPT_REPLY_ROWS
        .iter()
        .copied()
        .filter(|row| offered.contains(row))
        .collect();
    assert!(
        still_offered.is_empty(),
        "rows whose answer is never kept are still offered as actions: {still_offered:?}"
    );
    assert!(
        offered.contains(KEPT_ROW),
        "{KEPT_ROW}, a kept row, is no longer an action"
    );
}
