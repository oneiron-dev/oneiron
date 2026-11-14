#![cfg(oneiron_test_support)]
//! The owner's restore installs the held shared-policy side tables live (SIDE-4c).
//!
//! Public doors only; neutral fixtures (`owen`, `yuki`); vaults in tempdirs. Each destination
//! opens at least one wall-clock second after its source (sleep 1100 ms), as
//! in `archive_import_retained_side_rows.rs`.
//!
//! * `the_owner_restore_installs_the_shared_policies_and_the_actorless_import_does_not`:
//!   the owner import installs one EDIT_DISTANCE_ESCALATION_POLICY row (N agreeing
//!   rulings proposed), one OWNER_POLICY_WORLD_PRIVACY_UNANIMITY row (vault on with
//!   one world override) and one OWNER_POLICY_WORLD_PRIVACY_UNANIMITY_OFF row (the
//!   applied turn-off) live and reports one installed row for each; a repeat owner
//!   import reports one unchanged live row for each; the actorless import of the same
//!   archive leaves every read at its default and installs nothing. The actorless
//!   guard passes the base on its own; this test fails there by its owner
//!   installed==1 assertions.
//! * `an_org_admin_policy_naming_a_missing_person_is_held_back`: a source
//!   ORG_ADMIN_POLICY row naming an admin PERSON the destination never held reports
//!   one held-back row with reason `missing_live_entity` and is still retained byte
//!   for byte.
//!
//! New report counts are read through `serde_json::to_value` of the SIDE-1
//! summary, so this file compiles on 56a501392094; an absent field fails its
//! assertion as a missing outcome, never as a setup panic.
//! `cargo test --locked -p oneiron --all-features --test archive_import_owner_installs_side_shared_policies`.

#[path = "archive_import_retained_side_rows.rs"]
mod retained_side_rows;

use std::collections::BTreeSet;
use std::io::Cursor;

use oneiron::EntityId;
use oneiron::edit_distance::escalation::{
    EscalationReceipt, EscalationRuling, EscalationTrigger, StandingPolicyStatus,
    escalation_standing_n, maybe_propose_standing_policy, record_escalation, standing_policy_for,
};
use oneiron::federation::{OrgAdminError, OrgAdminPolicy, OrgAdminPower};
use oneiron::policy_model::{WidenUnanimity, WidenUnanimityOutcome};
use retained_side_rows::{
    export_whole, open_later_vault, open_source_vault, owner_proof, retained_rows, rows_for,
};

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

/// The three shared-policy tables the first test carries through the archive.
const SHARED_POLICY_TABLES: [&str; 3] = [
    "EDIT_DISTANCE_ESCALATION_POLICY",
    "OWNER_POLICY_WORLD_PRIVACY_UNANIMITY",
    "OWNER_POLICY_WORLD_PRIVACY_UNANIMITY_OFF",
];

/// The owner restore installs the three shared policies live; the actorless
/// import leaves every read at its default.
#[test]
fn the_owner_restore_installs_the_shared_policies_and_the_actorless_import_does_not() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);

    // The escalation row: N agreeing approve rulings earn one proposed standing row.
    let scope = "owen review scope";
    let trigger = EscalationTrigger::Unsure;
    let standing_n = escalation_standing_n(&source).expect("read the standing threshold");
    assert!(standing_n > 0, "the threshold names at least one ruling");
    for _ in 0..standing_n {
        record_escalation(
            &source,
            EscalationReceipt {
                task_ref: fixed_id(0x2E),
                scope: scope.to_owned(),
                trigger,
                question: "may owen proceed".to_owned(),
                ruling: EscalationRuling::Approve,
                rationale: "yuki agrees for the archive".to_owned(),
                budget_band: None,
            },
        )
        .expect("record one agreeing ruling");
    }
    let proposed = maybe_propose_standing_policy(&source, scope, trigger)
        .expect("propose the standing row")
        .expect("N agreeing rulings earn a proposal");
    let source_policy = standing_policy_for(&source, scope, trigger)
        .expect("read the source standing row")
        .expect("the source holds the standing row");
    assert_eq!(
        source_policy.row_ref, proposed,
        "the read names the proposal"
    );
    assert_eq!(source_policy.scope, scope, "the source holds the scope");
    assert_eq!(
        source_policy.trigger, trigger,
        "the source holds the trigger"
    );
    assert_eq!(
        source_policy.status,
        StandingPolicyStatus::Proposed,
        "the source row is proposed"
    );
    assert_eq!(
        source_policy.ruling,
        EscalationRuling::Approve,
        "the source holds the agreeing ruling"
    );

    // Unanimity on, then one world's turn-off, which lands at once with one owner.
    let world = fixed_id(0x6C);
    let turned_on = source
        .set_widen_needs_every_owner(&source_owner, None, Some(true))
        .expect("the owner turns unanimity on");
    match turned_on {
        WidenUnanimityOutcome::Set(row) => {
            assert!(row.vault, "turning on lands vault on");
        }
        other => panic!("turning on lands at once: {other:?}"),
    }
    let turned_off = source
        .set_widen_needs_every_owner(&source_owner, Some(world), Some(false))
        .expect("the owner turns one world off");
    match turned_off {
        WidenUnanimityOutcome::Set(_) => {}
        other => panic!("one owner's turn-off lands at once: {other:?}"),
    }
    let source_unanimity = source
        .widen_needs_every_owner()
        .expect("read the source unanimity row");
    assert!(source_unanimity.vault, "the source holds unanimity on");
    assert_eq!(
        source_unanimity.worlds.get(&world.to_hex()),
        Some(&false),
        "the source holds the world's override"
    );
    let source_offs = source
        .widen_unanimity_off_requests(false)
        .expect("read the source turn-off rows");
    assert_eq!(source_offs.len(), 1, "the source holds one turn-off row");
    assert_eq!(
        source_offs[0].world,
        Some(world.to_hex()),
        "the turn-off names the world"
    );
    assert_eq!(
        source_offs[0].on,
        Some(false),
        "the turn-off clears the world"
    );
    let archive = export_whole(&source);
    let source_rows = retained_rows(&archive);
    for table in SHARED_POLICY_TABLES {
        assert_eq!(
            rows_for(&source_rows, table).len(),
            1,
            "the source archive holds one {table} tuple"
        );
    }

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        standing_policy_for(&dest, scope, trigger).expect("read the restored standing row"),
        Some(source_policy.clone()),
        "the owner import installs the escalation row live"
    );
    assert_eq!(
        dest.widen_needs_every_owner()
            .expect("read the restored unanimity row"),
        source_unanimity,
        "the owner import installs unanimity on live"
    );
    assert_eq!(
        dest.widen_unanimity_off_requests(false)
            .expect("read the restored turn-off rows"),
        source_offs,
        "the owner import installs the applied turn-off live"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    for table in SHARED_POLICY_TABLES {
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
    for table in SHARED_POLICY_TABLES {
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

    // The actorless guard passes the base on its own; this test fails there by the owner
    // installed==1 assertions above.
    let (_bare_dir, bare) = open_later_vault();
    let bare_receipt = bare
        .import_whole_vault_archive_from(Cursor::new(&archive))
        .expect("the actorless import succeeds");
    assert_eq!(
        standing_policy_for(&bare, scope, trigger).expect("read the actorless standing row"),
        None,
        "the actorless import leaves the escalation row absent"
    );
    assert_eq!(
        bare.widen_needs_every_owner()
            .expect("read the actorless unanimity row"),
        WidenUnanimity::default(),
        "the actorless import leaves unanimity off"
    );
    assert!(
        bare.widen_unanimity_off_requests(false)
            .expect("read the actorless turn-off rows")
            .is_empty(),
        "the actorless import leaves no turn-off row"
    );
    let bare_summary =
        serde_json::to_value(&bare_receipt.retained_side_rows).expect("the summary serializes");
    for table in SHARED_POLICY_TABLES {
        assert!(
            matches!(
                table_count(&bare_summary, table, "installed_rows"),
                None | Some(0)
            ),
            "the actorless import installs no {table} row: {bare_summary}"
        );
    }
    let bare_carried = retained_rows(&export_whole(&bare));
    for table in SHARED_POLICY_TABLES {
        assert_eq!(
            rows_for(&bare_carried, table).len(),
            1,
            "the actorless vault still carries one {table} tuple"
        );
    }
}

/// An org setup naming a PERSON the destination never held is held back with
/// `missing_live_entity` and retained byte for byte.
#[test]
fn an_org_admin_policy_naming_a_missing_person_is_held_back() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let org = fixed_id(0x6A);
    let missing = fixed_id(0x3B);
    let policy = OrgAdminPolicy::new(
        org,
        BTreeSet::from([missing]),
        BTreeSet::from([OrgAdminPower::AddMember]),
    )
    .expect("the org policy builds");
    source
        .configure_org_admin_as_owner(&source_owner, &policy)
        .expect("the owner stores the source org row");
    assert_eq!(
        source
            .org_admin_policy(org)
            .expect("read the source org row"),
        policy,
        "the source holds the org row"
    );
    let archive = export_whole(&source);
    let source_tuple = rows_for(&retained_rows(&archive), "ORG_ADMIN_POLICY");
    assert_eq!(
        source_tuple.len(),
        1,
        "the source archive holds one org tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        held_back_for_table(&summary, "ORG_ADMIN_POLICY"),
        Some(serde_json::json!([{"reason": "missing_live_entity", "rows": 1}])),
        "the owner import holds back one org row as missing_live_entity; an absent field means it counted no held-back outcome: {summary}"
    );
    assert!(
        matches!(dest.org_admin_policy(org), Err(OrgAdminError::Denied)),
        "the held-back org row stays out of force"
    );
    assert_eq!(
        rows_for(&retained_rows(&export_whole(&dest)), "ORG_ADMIN_POLICY"),
        source_tuple,
        "the destination retains the held-back org tuple byte for byte"
    );
}
