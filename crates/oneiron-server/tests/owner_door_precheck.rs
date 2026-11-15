//! The host-door rows whose door proves the vault owner first check the
//! owner before the row's pre hooks (FIX-LIST
//! HOST-DOOR-UNNAMED-OWNER-HOOKS-FIRE; UC-01 PR 0b; FIX 1763). Each of the
//! 37 rows below named `"proof": "in_door"`, so the check before its hooks
//! (`row_door_admits`) admitted every caller, and a non-owner's pre hooks
//! fired on a call its door then refused: each door runs `facade_owner`
//! before anything else (read door by door, UC-01 0b census). With rule
//! `owner` the check refuses the agent and the unbound caller FORBIDDEN, as
//! the door does; the owner passes, as before.
//!
//! On the proof table without 0b's rows the agent and the unbound caller pass
//! the check: red.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --test owner_door_precheck`.
#![cfg(oneiron_test_support)]

#[path = "support/door_rule_fixture.rs"]
mod door_rule_fixture;

use door_rule_fixture::{TestResult, admits, setup};
use oneiron::memory::MEMORY_CODE_FORBIDDEN;

/// The rows whose door admits exactly the callers `facade_owner` admits.
const OWNER_DOOR_ROWS: [&str; 37] = [
    "ai.streams.release",
    "vault.budgets.resident_shares",
    "vault.budgets.resident_shares.set",
    "vault.code.snapshots.capture",
    "vault.code.symbols.neighbors",
    "vault.commitments.ledger",
    "vault.connectors.read_grants.grant",
    "vault.connectors.read_grants.revoke",
    "vault.connectors.replies.retry_failed",
    "vault.connectors.web.usage",
    "vault.decisions.asks.confirm_grant",
    "vault.dreamer.follower.keyframe",
    "vault.files.sources.exclude",
    "vault.inbox.groups.resolve",
    "vault.model_pack.revert",
    "vault.models.trials.resend_arm",
    "vault.outbox.diverged.answer",
    "vault.outbox.diverged.list",
    "vault.proactivity.digest.get",
    "vault.roots.requests.cancel",
    "vault.secrets.lift_history",
    "vault.settings.model_pack",
    "vault.settings.model_pack.replace",
    "vault.settings.snapshot_read.replace",
    "vault.settings.web_connector",
    "vault.settings.web_connector.replace",
    "vault.shape.groups",
    "vault.shape.groups.resolve",
    "vault.skill_hubs.clawhub.import",
    "vault.skill_hubs.clawhub.search",
    "vault.skills.optimize.tradeoff_asks.resolve",
    "vault.skills.proposal.settle",
    "vault.step_up.totp.reset",
    "vault.sync.documents.copy_edit.review",
    "vault.sync.documents.copy_edit.settle",
    "vault.sync.repo_manifests.conflict.discard",
    "vault.sync.repo_manifests.conflict.review",
];

/// The agent and the unbound caller are refused FORBIDDEN before the hooks
/// of every row. A mismatch lists every wrong answer at once.
#[test]
fn a_non_owner_is_refused_before_the_hooks_of_an_owner_door_row() -> TestResult {
    let fixture = setup()?;
    let forbidden = format!("{MEMORY_CODE_FORBIDDEN}: ");
    let mut wrong = Vec::new();
    for verb in OWNER_DOOR_ROWS {
        for (who, credential) in [("agent", &fixture.agent), ("unbound", &fixture.unbound)] {
            match admits(&fixture, credential, verb)? {
                Err(refusal) if refusal.starts_with(&forbidden) => {}
                answer => wrong.push(format!("  {verb}: {who}: {answer:?}")),
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} answers are no FORBIDDEN refusal before the hooks:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    Ok(())
}

/// The owner passes the check of every row.
#[test]
fn the_owner_passes_the_check_of_an_owner_door_row() -> TestResult {
    let fixture = setup()?;
    let mut wrong = Vec::new();
    for verb in OWNER_DOOR_ROWS {
        if let Err(refusal) = admits(&fixture, &fixture.owner, verb)? {
            wrong.push(format!("  {verb}: {refusal}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "the owner is refused on {} rows:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    Ok(())
}
