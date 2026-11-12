//! FIX 22437 [GOAL-PRIVACY]: a project goal's text never leaves its
//! project's audience through the skill judge. A skill joined to a project
//! goal is judged on one live axis by the serve replay judge; the judgment's
//! journaled state (which the Coach re-reads into new prompts and the owner
//! route serves) carries the goal's axes by name and kind, and none of the
//! goal's text, why, measure or bound. Before the fix the goal brief that
//! rides every case state copied all four.
//!
//! The ladder is unstaffed here (no model), so the judgment abstains; its
//! question and state are journaled before its answer is read.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --test skill_judge_goal_privacy`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::skill_optimize::{HeldOutReplayNotes, set_skill_goal_project};
use oneiron::test_doors::coach::{coach, write_root_goal};
use oneiron::test_doors::steward::{
    STEWARD_READ_VERB, open_owner_carrier_vault, owner, stand_steward_grant,
};
use oneiron::{EntityId, TimeRange};
use oneiron_server::config::SyncServerConfig;
use oneiron_server::replay_judge::{ServeReplayJudge, journal};
use oneiron_server::server::SyncServer;
use serde_json::json;

/// The engine's call depth under a judgment, as the served-door tests give it.
const STACK_BYTES: usize = 64 * 1024 * 1024;

/// `write_root_goal`'s goal text, why and measures: none may reach a journal
/// row.
const GOAL_TEXT: [&str; 4] = [
    "Answer customer requests correctly",
    "Reduce repeat support tickets",
    "resolved requests per week from receipts",
    "held-out unsafe answer count",
];

#[test]
fn judge_journal_holds_no_project_goal_text() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(STACK_BYTES)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::task::spawn_blocking(judged_skill_journals_no_goal_text)
            .await
            .expect("the test body passes");
    });
}

fn judged_skill_journals_no_goal_text() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(open_owner_carrier_vault(dir.path()).unwrap());
    let owner_proof = owner(&vault).unwrap();
    let project = write_root_goal(&vault, &owner_proof).unwrap();
    // The Coach reads the goal through its own `read` grant (S66-2 = A).
    stand_steward_grant(&vault, coach(&vault).unwrap(), &[STEWARD_READ_VERB]).unwrap();

    let skill = EntityId::now();
    let record = SkillRecord::new(
        "goal-privacy-fixture",
        "fixture",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("goal-privacy"),
        )]),
    );
    let now = vault.now_recorded_at();
    vault
        .put_skill_record(
            &skill,
            &record,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .unwrap();
    set_skill_goal_project(&vault, &owner_proof, &skill, Some(project)).unwrap();

    let server = SyncServer::new(Arc::clone(&vault), SyncServerConfig::default()).unwrap();
    let judge = ServeReplayJudge::new(&server, None).unwrap();
    let criterion = json!({"name": "unsafe_answers", "kind": "floor"});
    // An unstaffed ladder abstains, which fails the pull; the judgment is
    // journaled either way.
    let _ = (&judge as &dyn HeldOutReplayNotes).live_axis_met(
        skill,
        &record,
        "fixture-receipt",
        &criterion,
    );

    let rows = journal(&vault, 100).unwrap();
    assert!(
        rows.iter()
            .any(|row| row.state.contains("confirmed_answers")),
        "the judgment's journaled state carries the joined goal's axes: {:?}",
        rows.iter().map(|row| &row.state).collect::<Vec<_>>()
    );
    let leaked: Vec<(&str, &str)> = rows
        .iter()
        .flat_map(|row| {
            GOAL_TEXT
                .iter()
                .filter(|text| row.state.contains(*text))
                .map(|text| (*text, row.state.as_str()))
        })
        .collect();
    assert!(
        leaked.is_empty(),
        "no journaled judgment state holds the project goal's text: {leaked:?}"
    );
}
