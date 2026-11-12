//! A holder or reader door takes no owner by actor id (review of #6999,
//! round 2). The substrate reads behind a grant answered a reader whose
//! actor id was the vault owner's, with no owner proof. A server sends a
//! caller to these doors exactly when its owner proof failed, so an owner
//! credential that was attenuated or handed to another key read the owner's
//! rows through them.
//!
//! Now each of these doors admits by the Steward grant alone, and the owner
//! reads through the owner door under its proof.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test reader_doors_take_no_owner_actor_id`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::EdgeActorClass;
use oneiron::learning_setting_doors::{
    LearningSettingsRequest, learning_settings_as_holder, learning_settings_as_owner,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::snapshot_read::snapshot_read_settings_as_holder;
use oneiron::task_verb::sdk::{
    RetrievalRunsRequest, project_goal_get_as_owner, project_goal_get_as_reader,
    retrieval_runs_as_reader,
};
use oneiron::test_doors::coach::{define_agent, write_root_goal};
use oneiron::test_doors::steward::{
    STEWARD_READ_VERB, open_owner_carrier_vault, owner, stand_steward_grant,
};
use oneiron::write_envelope::WriteActor;

fn assert_refused<T>(answer: MemoryResult<T>, verb: &str) {
    let Err(error) = answer else {
        panic!("{verb}: the owner's actor id, with no proof and no grant, is refused");
    };
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{verb}: {error:?}");
}

#[test]
fn the_reader_doors_refuse_the_owners_actor_id_without_a_grant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner_proof = owner(&vault).expect("owner proof");
    let project = write_root_goal(&vault, &owner_proof).expect("goal");
    let owner_id = vault.ensure_embedded_owner_actor().expect("owner");
    // The caller a server hands these doors when an owner credential failed
    // the owner proof: the owner's actor id, and nothing else of the owner.
    let unproven = WriteActor::new(owner_id, EdgeActorClass::Human);
    let handle = vault.memory(owner_id, EdgeActorClass::Human);

    assert_refused(
        learning_settings_as_holder(&vault, unproven, &LearningSettingsRequest::default()),
        "vault.settings.learning",
    );
    assert_refused(
        snapshot_read_settings_as_holder(&vault, unproven),
        "vault.settings.snapshot_read",
    );
    assert_refused(
        retrieval_runs_as_reader(&handle, RetrievalRunsRequest::default()),
        "vault.retrieval.runs",
    );
    assert_refused(
        project_goal_get_as_reader(&handle, project),
        "vault.projects.goal.get",
    );

    // The owner reads under its proof, through the owner doors.
    learning_settings_as_owner(&vault, &owner_proof, &LearningSettingsRequest::default())
        .expect("the owner reads the dials");
    let goal =
        project_goal_get_as_owner(&vault, &owner_proof, project).expect("the owner reads the goal");
    assert!(goal.goal_claim.is_some(), "the owner sees the goal");

    // A holder of the grant reads, as before.
    let agent = define_agent(&vault).expect("an agent");
    stand_steward_grant(&vault, agent, &[STEWARD_READ_VERB]).expect("a read grant");
    let granted = project_goal_get_as_reader(&vault.memory(agent, EdgeActorClass::Agent), project)
        .expect("a `read` holder reads the goal");
    assert!(granted.goal_claim.is_some(), "the holder sees the goal");
}
