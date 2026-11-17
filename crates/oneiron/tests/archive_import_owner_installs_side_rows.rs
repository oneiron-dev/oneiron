#![cfg(oneiron_test_support)]
//! The owner's restore installs retained side rows live (SIDE-2a).
//!
//! Public doors only; neutral fixtures (`agent-a`, `owen`, `yuki`); vaults in
//! tempdirs. Each destination opens at least one wall-clock second after its
//! source (sleep 1100 ms), as in `archive_import_retained_side_rows.rs`.
//!
//! * `the_owner_restore_installs_the_setting_and_power_grant_and_the_actorless_import_does_not`:
//!   the owner import installs one BACKUP_POLICY row and one
//!   AGENT_DEF_POWER_GRANT row live and reports one installed row for each; a
//!   repeat owner import reports one unchanged live row for each; the
//!   actorless import of the same archive leaves both reads at their absent
//!   values and installs nothing.
//! * `a_different_destination_setting_stays_live_and_is_reported_kept`: a
//!   destination that already holds another backup choice keeps it, the
//!   report counts one kept-live row, and its next archive holds both tuples.
//! * `a_power_grant_for_an_absent_agent_is_held_back_and_the_other_rows_install`:
//!   a grant whose agent was never created stays absent, reports one
//!   held-back row with reason `missing_live_entity`, and is still retained
//!   byte for byte, while the backup row installs.
//! * `restored_customization_events_keep_their_keys_and_the_next_event_follows_them`:
//!   two source customization events restore with their sequences, and the
//!   next event the destination owner writes follows with sequence three.
//!
//! New report counts are read through `serde_json::to_value` of the SIDE-1
//! summary, so this file compiles on df2ecf9d4376; an absent field fails its
//! assertion as a missing outcome, never as a setup panic.
//! `cargo test --locked -p oneiron --all-features --test archive_import_owner_installs_side_rows`.

#[path = "archive_import_retained_side_rows.rs"]
mod retained_side_rows;

use std::io::Cursor;

use oneiron::agent_def::{
    AgentCeiling, AgentDefinition, AgentPowerTarget, AgentPowers, AgentScope,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::settings::backup::BackupPolicy;
use oneiron::settings::{AccentLayer, CustomizationLayerValue, ModeLayer, TypeLayer};
use oneiron::{EntityId, TimeRange};
use retained_side_rows::{
    export_whole, open_later_vault, open_source_vault, owner_proof, retained_rows, rows_for,
};

/// The source backup choice: enabled, every six hours, keep three.
fn source_backup_policy() -> BackupPolicy {
    BackupPolicy {
        enabled: true,
        every_hours: 6,
        keep: 3,
    }
}

/// A different valid backup choice the destination holds first.
fn dest_backup_policy() -> BackupPolicy {
    BackupPolicy {
        enabled: true,
        every_hours: 12,
        keep: 5,
    }
}

/// Both powers off: what the installed grant holds.
fn restricted_powers() -> AgentPowers {
    AgentPowers {
        spawn: false,
        save_agent: false,
    }
}

/// A model-free agent definition with neutral names.
fn agent_definition() -> AgentDefinition {
    AgentDefinition::new(
        "agent-a",
        "Archive power-grant fixture",
        "1.0.0",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![
            (
                rmpv::Value::from("definedVia"),
                rmpv::Value::from("define_agent"),
            ),
            (rmpv::Value::from("seed"), rmpv::Value::from(1u64)),
        ]),
        None,
        true,
        None,
    )
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

#[test]
fn the_owner_restore_installs_the_setting_and_power_grant_and_the_actorless_import_does_not() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let policy = source_backup_policy();
    source
        .set_backup_policy(&source_owner, policy)
        .expect("the owner stores the source backup choice");
    assert_eq!(
        source
            .backup_policy()
            .expect("read the source backup choice"),
        Some(policy),
        "the source holds the backup row"
    );
    let agent_id = EntityId::now();
    source
        .create_agent_definition_as(
            &source_owner,
            &agent_id,
            &agent_definition(),
            TimeRange { start: 10, end: 10 },
            11,
        )
        .expect("the owner creates the source agent");
    assert!(
        source
            .get_agent_definition(&agent_id)
            .expect("read the source agent")
            .is_some(),
        "the source holds the agent definition"
    );
    let restricted = restricted_powers();
    source
        .set_agent_powers_as(
            &source_owner,
            AgentPowerTarget::Agent(agent_id),
            AgentPowers::ALL,
            restricted,
        )
        .expect("the owner restricts the source grant");
    assert_eq!(
        source
            .agent_powers(AgentPowerTarget::Agent(agent_id))
            .expect("read the source grant"),
        restricted,
        "the source holds the restricted grant"
    );
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        dest.backup_policy()
            .expect("read the destination backup choice"),
        Some(policy),
        "the owner import installs the backup row live"
    );
    assert_eq!(
        dest.agent_powers(AgentPowerTarget::Agent(agent_id))
            .expect("read the destination grant"),
        restricted,
        "the owner import installs the power grant live"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "BACKUP_POLICY", "installed_rows"),
        Some(1),
        "the owner import reports one installed BACKUP_POLICY row; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        table_count(&summary, "AGENT_DEF_POWER_GRANT", "installed_rows"),
        Some(1),
        "the owner import reports one installed AGENT_DEF_POWER_GRANT row; an absent field means it installed nothing: {summary}"
    );

    let repeat = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the repeat owner import succeeds");
    let repeat_summary =
        serde_json::to_value(&repeat.retained_side_rows).expect("the repeat summary serializes");
    for table in ["BACKUP_POLICY", "AGENT_DEF_POWER_GRANT"] {
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
    let bare_receipt = bare
        .import_whole_vault_archive_from(Cursor::new(&archive))
        .expect("the actorless import succeeds");
    assert_eq!(
        bare.backup_policy()
            .expect("read the actorless backup choice"),
        None,
        "the actorless import retains the backup row without making it live"
    );
    assert_eq!(
        bare.agent_powers(AgentPowerTarget::Agent(agent_id))
            .expect("read the actorless grant"),
        AgentPowers::ALL,
        "the actorless import retains the grant without making it live"
    );
    let bare_summary =
        serde_json::to_value(&bare_receipt.retained_side_rows).expect("the summary serializes");
    for table in ["BACKUP_POLICY", "AGENT_DEF_POWER_GRANT"] {
        assert!(
            matches!(
                table_count(&bare_summary, table, "installed_rows"),
                None | Some(0)
            ),
            "the actorless import installs no {table} row: {bare_summary}"
        );
    }
}

#[test]
fn a_different_destination_setting_stays_live_and_is_reported_kept() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let source_policy = source_backup_policy();
    source
        .set_backup_policy(&source_owner, source_policy)
        .expect("the owner stores the source backup choice");
    let archive = export_whole(&source);
    let source_rows = retained_rows(&archive);
    let source_backup = rows_for(&source_rows, "BACKUP_POLICY");
    assert_eq!(
        source_backup.len(),
        1,
        "the source archive holds one backup tuple: {source_rows:?}"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let dest_policy = dest_backup_policy();
    assert_ne!(
        dest_policy, source_policy,
        "the two backup choices differ before the import"
    );
    dest.set_backup_policy(&dest_owner, dest_policy)
        .expect("the destination owner stores its own backup choice");
    assert_eq!(
        dest.backup_policy()
            .expect("read the destination backup choice"),
        Some(dest_policy),
        "the destination holds its own backup row before the import"
    );
    let pre_backup = rows_for(&retained_rows(&export_whole(&dest)), "BACKUP_POLICY");
    assert_eq!(
        pre_backup.len(),
        1,
        "the destination archive holds its live tuple before the import"
    );

    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        dest.backup_policy()
            .expect("read the destination backup choice"),
        Some(dest_policy),
        "the owner import keeps the different destination row live"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "BACKUP_POLICY", "kept_live_rows"),
        Some(1),
        "the owner import reports one kept-live BACKUP_POLICY row; an absent field means it counted no live outcome: {summary}"
    );
    let post_backup = rows_for(&retained_rows(&export_whole(&dest)), "BACKUP_POLICY");
    assert_eq!(
        post_backup.len(),
        2,
        "the destination keeps both backup values after a kept-live import"
    );
    assert!(
        post_backup.contains(&source_backup[0]) && post_backup.contains(&pre_backup[0]),
        "the destination archive holds its live tuple and the retained source tuple byte for byte: {post_backup:?}"
    );
}

#[test]
fn a_power_grant_for_an_absent_agent_is_held_back_and_the_other_rows_install() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let policy = source_backup_policy();
    source
        .set_backup_policy(&source_owner, policy)
        .expect("the owner stores the source backup choice");
    let missing_agent = EntityId::now();
    assert!(
        source
            .get_agent_definition(&missing_agent)
            .expect("read the absent agent")
            .is_none(),
        "the source holds no definition for the missing agent"
    );
    let restricted = restricted_powers();
    source
        .set_agent_powers_as(
            &source_owner,
            AgentPowerTarget::Agent(missing_agent),
            AgentPowers::ALL,
            restricted,
        )
        .expect("the vault setter stages a grant without a holder lookup");
    assert_eq!(
        source
            .agent_powers(AgentPowerTarget::Agent(missing_agent))
            .expect("read the source grant"),
        restricted,
        "the source holds the restricted grant for the absent agent"
    );
    let archive = export_whole(&source);
    let source_power = rows_for(&retained_rows(&archive), "AGENT_DEF_POWER_GRANT");
    assert_eq!(
        source_power.len(),
        1,
        "the source archive holds one power-grant tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        dest.agent_powers(AgentPowerTarget::Agent(missing_agent))
            .expect("read the destination grant"),
        AgentPowers::ALL,
        "the grant for the absent agent stays absent on the destination"
    );
    assert!(
        dest.get_agent_definition(&missing_agent)
            .expect("read the absent agent on the destination")
            .is_none(),
        "the import creates no phantom agent definition"
    );
    assert_eq!(
        dest.backup_policy()
            .expect("read the destination backup choice"),
        Some(policy),
        "the other row still installs while one row is held back"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        held_back_for_table(&summary, "AGENT_DEF_POWER_GRANT"),
        Some(serde_json::json!([{"reason": "missing_live_entity", "rows": 1}])),
        "the owner import holds back one power-grant row as missing_live_entity; an absent field means it counted no held-back outcome: {summary}"
    );
    assert_eq!(
        table_count(&summary, "BACKUP_POLICY", "installed_rows"),
        Some(1),
        "the owner import reports one installed BACKUP_POLICY row beside the held-back row: {summary}"
    );
    assert_eq!(
        rows_for(
            &retained_rows(&export_whole(&dest)),
            "AGENT_DEF_POWER_GRANT"
        ),
        source_power,
        "the destination retains the held-back power tuple byte for byte"
    );
}

#[test]
fn restored_customization_events_keep_their_keys_and_the_next_event_follows_them() {
    let (_source_dir, source) = open_source_vault();
    let first = source
        .set_customization_layer(CustomizationLayerValue::Accent(
            AccentLayer::new("owen").expect("owen is a valid palette token"),
        ))
        .expect("the first layer write lands");
    assert!(
        first.event.is_some(),
        "the first layer write emits a change event"
    );
    let second = source
        .set_customization_layer(CustomizationLayerValue::Mode(
            ModeLayer::new("yuki").expect("yuki is a valid mode token"),
        ))
        .expect("the second layer write lands");
    assert!(
        second.event.is_some(),
        "the second layer write emits a change event"
    );
    let source_events = source
        .customization_events_after(0, 10)
        .expect("read the source events");
    assert_eq!(
        source_events.len(),
        2,
        "the source holds two customization events"
    );
    assert_eq!(
        source_events[0].sequence, 1,
        "the first source event keeps sequence one"
    );
    assert_eq!(
        source_events[1].sequence, 2,
        "the second source event keeps sequence two"
    );
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let restored = dest
        .customization_events_after(0, 10)
        .expect("read the restored events");
    assert_eq!(
        restored.len(),
        2,
        "the owner import restores two customization events"
    );
    assert_eq!(
        restored, source_events,
        "the restored events match the source events unchanged"
    );

    let third = dest
        .set_customization_layer(CustomizationLayerValue::Type(
            TypeLayer::new("owen-type").expect("owen-type is a valid typeface token"),
        ))
        .expect("the next layer write lands");
    assert!(
        third.event.is_some(),
        "the next layer write emits a change event"
    );
    assert_eq!(
        third.event.as_ref().map(|event| event.sequence),
        Some(3),
        "the next event follows the restored keys with sequence three"
    );
    let all = dest
        .customization_events_after(0, 10)
        .expect("read all destination events");
    assert_eq!(
        all.len(),
        3,
        "the destination holds three events after the next write"
    );
    assert_eq!(
        &all[..2],
        &source_events[..],
        "the restored two stay unchanged after the next write"
    );
    assert_eq!(
        all[2].sequence, 3,
        "the third event follows the restored keys with sequence three"
    );
    assert!(
        all[0] != all[1] && all[1] != all[2] && all[0] != all[2],
        "the three events are distinct: {all:?}"
    );
}
