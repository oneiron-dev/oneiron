#![cfg(oneiron_test_support)]
//! The owner's restore installs the owner side policies live (SIDE-2b).
//!
//! Public doors only; neutral fixtures; vaults in tempdirs. Each destination
//! opens at least one wall-clock second after its source (sleep 1100 ms), as
//! in `archive_import_retained_side_rows.rs`.
//!
//! * `the_owner_restore_installs_the_owner_policies_and_the_actorless_import_does_not`:
//!   the owner import installs one PROJECT_HISTORY_POLICY row, one
//!   MERGE_QUEUE_REVIEW_POLICY row and one owner LEARNING_SETTING pin live
//!   and reports one installed row for each; a repeat owner import reports
//!   one unchanged live row for each; the actorless import of the same
//!   archive leaves every read at its default and installs nothing.
//! * `a_restored_drafter_policy_that_turns_drafting_off_returns_the_destination_bindings_to_stock`:
//!   the owner import installs the source DRAFTER_POLICY row that turns
//!   drafting off with its revision, and no version binding stays served.
//!   No public door mints a serving version binding (that needs a qualified
//!   version with a sealed artifact from the training pipeline), so the
//!   Stock repair of a live binding has no public-path fixture here.
//! * `a_holder_learning_row_over_the_destination_owner_cap_is_held_back`:
//!   a holder seed above the destination owner's pin cap stays out of force
//!   and reports one held-back row with reason `local_authority_mismatch`,
//!   while the destination keeps its own row.
//! * `a_path_policy_for_an_absent_repo_is_held_back`: a source
//!   ORIGIN_LFS_PATH_POLICY row for a repo the destination never registered
//!   reports one held-back row with reason `missing_live_entity` and is
//!   still retained byte for byte. Registering the served origin needs
//!   bridged git, which the fleet host contract provides.
//!
//! The message-stream policy and the retrieval pins are Setting keys
//! (`memory.message_stream.*`, `retrieval.policy_pins`), which the archive
//! carries in no section yet (FIX ARCHIVE-SETTING-CATALOGUE-KEYS-NOT-CARRIED),
//! so no test here restores them.
//!
//! New report counts are read through `serde_json::to_value` of the SIDE-1
//! summary, so this file compiles on 24ed2deead79; an absent field fails its
//! assertion as a missing outcome, never as a setup panic.
//! `cargo test --locked -p oneiron --all-features --test archive_import_owner_installs_side_policies`.

#[path = "archive_import_retained_side_rows.rs"]
mod retained_side_rows;

use std::collections::BTreeSet;
use std::io::Cursor;

use oneiron::critic::LensCatalog;
use oneiron::drafter::{
    DrafterPolicySetRequest, DrafterStatusRequest, drafter_status_as_owner,
    set_drafter_policy_as_owner,
};
use oneiron::federation::EngineControlClass;
use oneiron::learning_setting::{
    SettingMode, SettingRow, SettingScope, setting_spec, setting_value,
};
use oneiron::learning_setting_doors::{
    LearningSettingMode, LearningSettingPut, LearningSettingsRequest, learning_settings_as_owner,
    put_learning_setting_as_owner,
};
use oneiron::memory::merge_queue_doors::{
    QueueReviewPolicyInput, QueueReviewPolicyProof, QueueReviewPolicySetRequest,
    QueueReviewPolicyState,
};
use oneiron::memory::origin_doors::OriginLfsPathPolicySetRequest;
use oneiron::merge_queue::QueueReviewThresholds;
use oneiron::origin::lfs::{LfsAssetClass, OriginLfsPathMatch, OriginLfsPathRule};
use oneiron::workspace_roster::ProjectHistoryPolicy;
use oneiron::{EdgeActorClass, EntityId};
use retained_side_rows::{
    export_whole, open_later_vault, open_source_vault, owner_proof, retained_rows, rows_for,
};

/// The learned knob the learning tests steer: the question call budget, the
/// one work-budget dial a holder may tune.
const CALL_BUDGET_KEY: &str = "question_call_budget_ms";

/// A fixed entity id from one repeated byte. The banned bytes (00, 11, 42,
/// 47, A1..A6, D7, E1, FF) belong to other fixtures.
fn fixed_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("a non-reserved repeated byte is a valid entity id")
}

/// The `field` count for `table` in a `retained_side_rows` JSON summary, when
/// the table entry and the field are both present.
fn table_count(summary: &serde_json::Value, table: &str, field: &str) -> Option<u64> {
    summary
        .get("tables")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("source_table").and_then(|name| name.as_str()) == Some(table))?
        .get(field)?
        .as_u64()
}

/// The held-back list for `table` in a `retained_side_rows` JSON summary,
/// when the table entry and the list are both present.
fn held_back_for_table(summary: &serde_json::Value, table: &str) -> Option<serde_json::Value> {
    summary
        .get("tables")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("source_table").and_then(|name| name.as_str()) == Some(table))?
        .get("held_back")
        .cloned()
}

/// The three owner-policy tables the first test carries through the archive.
const OWNER_POLICY_TABLES: [&str; 3] = [
    "PROJECT_HISTORY_POLICY",
    "MERGE_QUEUE_REVIEW_POLICY",
    "LEARNING_SETTING",
];

/// The owner restore installs the three owner policies live; the actorless
/// import leaves every read at its default.
#[test]
fn the_owner_restore_installs_the_owner_policies_and_the_actorless_import_does_not() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let source_actor = source
        .ensure_embedded_owner_actor()
        .expect("the source names its embedded owner actor");
    let source_memory = source.memory(source_actor, EdgeActorClass::Human);

    let history = ProjectHistoryPolicy {
        max_revisions: 500,
        cycle_worlds_max: 8,
    };
    source
        .set_project_history_policy(&source_owner, history)
        .expect("the owner stores the source history budget");
    assert_eq!(
        source
            .project_history_policy()
            .expect("read the source history budget"),
        history,
        "the source holds the history row"
    );

    let catalog = LensCatalog::of366_seed().expect("the seed lens catalog reads");
    let source_review = source_memory
        .merge_queue_review_policy_set_as(
            &QueueReviewPolicyProof::Owner(source_owner.clone()),
            QueueReviewPolicySetRequest {
                policy: Some(QueueReviewPolicyInput {
                    catalog,
                    thresholds: QueueReviewThresholds {
                        critics: 3,
                        votes: 70,
                    },
                }),
            },
        )
        .expect("the owner stores the source review policy");
    assert_eq!(
        source_review.state,
        QueueReviewPolicyState::Set,
        "the source review policy is set"
    );
    let source_review_policy = source_review
        .policy
        .clone()
        .expect("a set review policy reads back");

    let spec = setting_spec(CALL_BUDGET_KEY).expect("the catalog names the call-budget knob");
    let pinned = 12_000.0;
    put_learning_setting_as_owner(
        &source,
        &source_owner,
        LearningSettingPut {
            key: CALL_BUDGET_KEY.to_owned(),
            mode: LearningSettingMode::Pin,
            value: Some(pinned),
            choice: None,
            weight_runs: None,
            why: "the owner pins the call budget for the archive".to_owned(),
            goal: None,
            project: None,
            task_type: None,
        },
    )
    .expect("the owner pins the source call budget");
    assert_eq!(
        setting_value(&source, spec).expect("read the source call budget"),
        pinned,
        "the source pin fixes the value in force"
    );
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let dest_actor = dest
        .ensure_embedded_owner_actor()
        .expect("the destination names its embedded owner actor");
    let dest_memory = dest.memory(dest_actor, EdgeActorClass::Human);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        dest.project_history_policy()
            .expect("read the restored history budget"),
        history,
        "the owner import installs the history row live"
    );
    let dest_review = dest_memory
        .merge_queue_review_policy_get_as(&QueueReviewPolicyProof::Owner(dest_owner.clone()))
        .expect("read the restored review policy");
    assert_eq!(
        dest_review.state,
        QueueReviewPolicyState::Set,
        "the owner import installs the review row live"
    );
    assert_eq!(
        dest_review.policy,
        Some(source_review_policy.clone()),
        "the owner import keeps the review row byte for byte"
    );
    assert_eq!(
        setting_value(&dest, spec).expect("read the restored call budget"),
        pinned,
        "the owner import installs the learning pin live"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    for table in OWNER_POLICY_TABLES {
        assert_eq!(
            table_count(&summary, table, "installed_rows"),
            Some(1),
            "the owner import reports one installed {table} row; an absent field means it installed nothing: {summary}"
        );
    }

    let repeat = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the repeat owner import succeeds");
    let repeat_summary =
        serde_json::to_value(&repeat.retained_side_rows).expect("the repeat summary serializes");
    for table in OWNER_POLICY_TABLES {
        assert_eq!(
            table_count(&repeat_summary, table, "unchanged_live_rows"),
            Some(1),
            "the repeat owner import reports one unchanged live {table} row; an absent field means it counted no live outcome: {repeat_summary}"
        );
        assert_eq!(
            table_count(&repeat_summary, table, "installed_rows"),
            Some(0),
            "the repeat owner import installs no {table} row; an absent field means it counted no live outcome: {repeat_summary}"
        );
    }

    let (_bare_dir, bare) = open_later_vault();
    let bare_owner = owner_proof(&bare);
    let bare_actor = bare
        .ensure_embedded_owner_actor()
        .expect("the actorless vault names its embedded owner actor");
    let bare_memory = bare.memory(bare_actor, EdgeActorClass::Human);
    let bare_receipt = bare
        .import_whole_vault_archive_from(Cursor::new(&archive))
        .expect("the actorless import succeeds");
    assert_eq!(
        bare.project_history_policy()
            .expect("read the actorless history budget"),
        ProjectHistoryPolicy::default(),
        "the actorless import leaves the history budget at its default"
    );
    let bare_review = bare_memory
        .merge_queue_review_policy_get_as(&QueueReviewPolicyProof::Owner(bare_owner))
        .expect("read the actorless review policy");
    assert_eq!(
        bare_review.state,
        QueueReviewPolicyState::Absent,
        "the actorless import leaves the review policy absent"
    );
    assert_eq!(
        setting_value(&bare, spec).expect("read the actorless call budget"),
        spec.seed,
        "the actorless import leaves the call budget at its seed"
    );
    let bare_summary =
        serde_json::to_value(&bare_receipt.retained_side_rows).expect("the summary serializes");
    for table in OWNER_POLICY_TABLES {
        assert!(
            matches!(
                table_count(&bare_summary, table, "installed_rows"),
                None | Some(0)
            ),
            "the actorless import installs no {table} row: {bare_summary}"
        );
    }
}

/// A restored drafter policy that turns drafting off installs with its
/// revision, and no version binding stays served.
#[test]
fn a_restored_drafter_policy_that_turns_drafting_off_returns_the_destination_bindings_to_stock() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let excluded = fixed_id(0x5C);
    let stored = set_drafter_policy_as_owner(
        &source,
        &source_owner,
        &DrafterPolicySetRequest {
            expected_revision: 0,
            enabled: false,
            excluded_worlds: BTreeSet::from([excluded]),
            recipe: None,
        },
    )
    .expect("the owner turns drafting off on the source");
    assert!(
        !stored.enabled,
        "the source policy turns drafting off: {stored:?}"
    );
    assert_eq!(
        stored.revision, 1,
        "the first set lands at revision one: {stored:?}"
    );
    let source_status =
        drafter_status_as_owner(&source, &source_owner, &DrafterStatusRequest::default())
            .expect("read the source drafter status");
    assert_eq!(
        source_status.policy, stored,
        "the source status reads the stored policy"
    );
    assert!(
        source_status.bindings.is_empty(),
        "the source serves no version binding: {:?}",
        source_status.bindings
    );
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let restored = drafter_status_as_owner(&dest, &dest_owner, &DrafterStatusRequest::default())
        .expect("read the restored drafter status");
    assert_eq!(
        restored.policy, stored,
        "the owner import installs the off policy with its revision"
    );
    assert!(
        !restored.policy.enabled,
        "the restored policy keeps drafting off: {:?}",
        restored.policy
    );
    assert_eq!(
        restored.policy.revision, 1,
        "the restored policy keeps its revision: {:?}",
        restored.policy
    );
    assert!(
        restored.bindings.is_empty(),
        "no version binding stays served once drafting is off: {:?}",
        restored.bindings
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "DRAFTER_POLICY", "installed_rows"),
        Some(1),
        "the owner import reports one installed DRAFTER_POLICY row; an absent field means it installed nothing: {summary}"
    );
}

/// A holder seed above the destination owner's pin cap stays out of force
/// and is held back.
#[test]
fn a_holder_learning_row_over_the_destination_owner_cap_is_held_back() {
    const CAP: f64 = 4_000.0;
    const OVER: f64 = 50_000.0;
    let spec = setting_spec(CALL_BUDGET_KEY).expect("the catalog names the call-budget knob");
    assert!(
        CAP >= spec.min && OVER <= spec.max && CAP < OVER,
        "the cap {CAP} and the over-cap value {OVER} sit inside the knob bounds [{}, {}]",
        spec.min,
        spec.max
    );

    let (_source_dir, source) = open_source_vault();
    // The engine-controls Grant is an owner act this install carries
    // (`ActSurface::ThisInstall`): root the source, give it a keystore and
    // serve its machine profile first, in the order
    // `test_doors::steward::open_owner_carrier_vault` uses.
    let issuer = oneiron::test_support::provision_engine_machines(&source);
    source
        .ensure_embedded_owner_actor()
        .expect("the source's embedded owner");
    source.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    source
        .ensure_serving_install_profile(&issuer, oneiron::authority::MachineRole::Unanswered)
        .expect("this install carries the owner's acts");
    let source_owner = owner_proof(&source);
    let holder = fixed_id(0x3A);
    source
        .grant_engine_controls(
            &source_owner,
            holder,
            &BTreeSet::from([EngineControlClass::WorkBudget]),
        )
        .expect("the owner grants the holder the work-budget class");
    source
        .put_setting_row_as_holder(
            holder,
            &SettingScope::Vault,
            &SettingRow {
                key: CALL_BUDGET_KEY.to_owned(),
                mode: SettingMode::Seed,
                value: OVER,
                weight_runs: Some(1.0),
                at: 1_700_000_001,
                why: "a holder seed above the destination cap".to_owned(),
            },
        )
        .expect("the holder seeds the call budget above the cap");
    assert_eq!(
        setting_value(&source, spec).expect("read the source call budget"),
        OVER,
        "the holder seed fixes the source value in force"
    );
    let archive = export_whole(&source);
    let source_tuple = rows_for(&retained_rows(&archive), "LEARNING_SETTING");
    assert_eq!(
        source_tuple.len(),
        1,
        "the source archive holds one learning tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    put_learning_setting_as_owner(
        &dest,
        &dest_owner,
        LearningSettingPut {
            key: CALL_BUDGET_KEY.to_owned(),
            mode: LearningSettingMode::Pin,
            value: Some(CAP),
            choice: None,
            weight_runs: None,
            why: "the destination caps the call budget".to_owned(),
            goal: None,
            project: None,
            task_type: None,
        },
    )
    .expect("the destination owner pins its cap");
    assert_eq!(
        setting_value(&dest, spec).expect("read the destination call budget"),
        CAP,
        "the destination holds its cap before the import"
    );
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        setting_value(&dest, spec).expect("read the destination call budget after the import"),
        CAP,
        "the over-cap holder row stays out of force"
    );
    let view = learning_settings_as_owner(
        &dest,
        &dest_owner,
        &LearningSettingsRequest {
            key: Some(CALL_BUDGET_KEY.to_owned()),
        },
    )
    .expect("list the destination rows");
    assert_eq!(
        view.rows.len(),
        1,
        "the destination keeps its one owner row: {:?}",
        view.rows
    );
    assert_eq!(
        view.rows[0].mode,
        LearningSettingMode::Pin,
        "the kept row is the owner pin: {:?}",
        view.rows[0]
    );
    assert_eq!(
        view.rows[0].value,
        Some(CAP),
        "the kept row is the owner cap: {:?}",
        view.rows[0]
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        held_back_for_table(&summary, "LEARNING_SETTING"),
        Some(serde_json::json!([{"reason": "local_authority_mismatch", "rows": 1}])),
        "the owner import holds back one learning row as local_authority_mismatch; an absent field means it counted no held-back outcome: {summary}"
    );
    assert_eq!(
        rows_for(&retained_rows(&export_whole(&dest)), "LEARNING_SETTING").len(),
        2,
        "the destination keeps its live row and the retained holder tuple"
    );
}

/// A path policy for a repo the destination never registered is held back
/// and retained byte for byte.
#[test]
fn a_path_policy_for_an_absent_repo_is_held_back() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let source_actor = source
        .ensure_embedded_owner_actor()
        .expect("the source names its embedded owner actor");
    let source_memory = source.memory(source_actor, EdgeActorClass::Human);
    let repo = "field-notes";
    let repo_id = source
        .register_served_origin_as_owner(&source_owner, repo, "main")
        .expect("the owner registers the source served origin");
    let rules = vec![OriginLfsPathRule {
        path_match: OriginLfsPathMatch::Exact("models/large.bin".to_owned()),
        class: LfsAssetClass::BuildRequired,
    }];
    let stored = source_memory
        .origin_lfs_path_policy_set_as(
            &source_owner,
            OriginLfsPathPolicySetRequest {
                repo: repo.to_owned(),
                expected_revision: 0,
                rules: rules.clone(),
            },
        )
        .expect("the owner stores the source path rules");
    assert_eq!(
        stored.revision, 1,
        "the first set lands at revision one: {stored:?}"
    );
    assert_eq!(stored.rules, rules, "the source holds its path rules");
    assert_eq!(
        stored.repo_id, repo_id,
        "the view names the registered repo: {stored:?}"
    );
    let archive = export_whole(&source);
    let source_tuple = rows_for(&retained_rows(&archive), "ORIGIN_LFS_PATH_POLICY");
    assert_eq!(
        source_tuple.len(),
        1,
        "the source archive holds one path-policy tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        held_back_for_table(&summary, "ORIGIN_LFS_PATH_POLICY"),
        Some(serde_json::json!([{"reason": "missing_live_entity", "rows": 1}])),
        "the owner import holds back one path-policy row as missing_live_entity; an absent field means it counted no held-back outcome: {summary}"
    );
    assert_eq!(
        rows_for(
            &retained_rows(&export_whole(&dest)),
            "ORIGIN_LFS_PATH_POLICY"
        ),
        source_tuple,
        "the destination retains the held-back path tuple byte for byte"
    );
}
