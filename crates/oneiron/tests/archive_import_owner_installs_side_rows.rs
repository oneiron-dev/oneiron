#![cfg(oneiron_test_support)]
//! The owner's restore installs retained side rows live (SIDE-2a).
//!
//! Public doors only; neutral fixtures (`agent-a`); vaults in
//! tempdirs. Each destination opens at least one wall-clock second after its
//! source (sleep 1100 ms), as in `archive_import_retained_side_rows.rs`.
//!
//! * `the_owner_restore_installs_the_setting_and_power_grant_and_the_actorless_import_does_not`:
//!   the owner import installs one SNAPSHOT_READ_SETTINGS row and one
//!   AGENT_DEF_POWER_GRANT row live and reports one installed row for each; a
//!   repeat owner import reports one unchanged live row for each; the
//!   actorless import of the same archive leaves both reads at their absent
//!   values and installs nothing.
//! * `a_different_destination_setting_stays_live_and_is_reported_kept`: a
//!   destination that already holds other snapshot bounds keeps them, the
//!   report counts one kept-live row, and its next archive holds both tuples.
//! * `a_power_grant_for_an_absent_agent_is_held_back_and_the_other_rows_install`:
//!   a grant whose agent was never created stays absent, reports one
//!   held-back row with reason `missing_live_entity`, and is still retained
//!   byte for byte, while the snapshot bounds row installs.
//! * `an_inert_copy_never_displaces_the_source_live_setting`: a middle vault
//!   holds its own snapshot bounds live and, after an owner import, an older
//!   choice as an inert copy whose tuple files first in its archive. The
//!   owner's restore of that archive into a fresh vault installs the live
//!   choice and keeps the copy inert (REVIEW-7771 round 1).
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
use oneiron::settings::snapshot_read::SnapshotReadSettings;
use oneiron::{EntityId, TimeRange};
use retained_side_rows::{
    export_whole, open_later_vault, open_source_vault, other_snapshot_bounds, owner_proof,
    retained_rows, rows_for, source_snapshot_bounds,
};

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
    let bounds = source_snapshot_bounds();
    source
        .replace_snapshot_read_settings_as_owner(&source_owner, bounds)
        .expect("the owner stores the source snapshot bounds");
    assert_eq!(
        source
            .snapshot_read_settings()
            .expect("read the source snapshot bounds"),
        bounds,
        "the source holds the snapshot bounds row"
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
        dest.snapshot_read_settings()
            .expect("read the destination snapshot bounds"),
        bounds,
        "the owner import installs the snapshot bounds row live"
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
        table_count(&summary, "SNAPSHOT_READ_SETTINGS", "installed_rows"),
        Some(1),
        "the owner import reports one installed SNAPSHOT_READ_SETTINGS row; an absent field means it installed nothing: {summary}"
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
    for table in ["SNAPSHOT_READ_SETTINGS", "AGENT_DEF_POWER_GRANT"] {
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
        bare.snapshot_read_settings()
            .expect("read the actorless snapshot bounds"),
        SnapshotReadSettings::DEFAULT,
        "the actorless import retains the snapshot bounds row without making it live"
    );
    assert_eq!(
        bare.agent_powers(AgentPowerTarget::Agent(agent_id))
            .expect("read the actorless grant"),
        AgentPowers::ALL,
        "the actorless import retains the grant without making it live"
    );
    let bare_summary =
        serde_json::to_value(&bare_receipt.retained_side_rows).expect("the summary serializes");
    for table in ["SNAPSHOT_READ_SETTINGS", "AGENT_DEF_POWER_GRANT"] {
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
    let source_bounds = source_snapshot_bounds();
    source
        .replace_snapshot_read_settings_as_owner(&source_owner, source_bounds)
        .expect("the owner stores the source snapshot bounds");
    let archive = export_whole(&source);
    let source_rows = retained_rows(&archive);
    let source_tuples = rows_for(&source_rows, "SNAPSHOT_READ_SETTINGS");
    assert_eq!(
        source_tuples.len(),
        1,
        "the source archive holds one snapshot bounds tuple: {source_rows:?}"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let dest_bounds = other_snapshot_bounds();
    assert_ne!(
        dest_bounds, source_bounds,
        "the two snapshot bounds differ before the import"
    );
    dest.replace_snapshot_read_settings_as_owner(&dest_owner, dest_bounds)
        .expect("the destination owner stores its own snapshot bounds");
    assert_eq!(
        dest.snapshot_read_settings()
            .expect("read the destination snapshot bounds"),
        dest_bounds,
        "the destination holds its own snapshot bounds row before the import"
    );
    let pre_tuples = rows_for(
        &retained_rows(&export_whole(&dest)),
        "SNAPSHOT_READ_SETTINGS",
    );
    assert_eq!(
        pre_tuples.len(),
        1,
        "the destination archive holds its live tuple before the import"
    );

    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        dest.snapshot_read_settings()
            .expect("read the destination snapshot bounds"),
        dest_bounds,
        "the owner import keeps the different destination row live"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "SNAPSHOT_READ_SETTINGS", "kept_live_rows"),
        Some(1),
        "the owner import reports one kept-live SNAPSHOT_READ_SETTINGS row; an absent field means it counted no live outcome: {summary}"
    );
    let post_tuples = rows_for(
        &retained_rows(&export_whole(&dest)),
        "SNAPSHOT_READ_SETTINGS",
    );
    assert_eq!(
        post_tuples.len(),
        2,
        "the destination keeps both snapshot bounds values after a kept-live import"
    );
    assert!(
        post_tuples.contains(&source_tuples[0]) && post_tuples.contains(&pre_tuples[0]),
        "the destination archive holds its live tuple and the retained source tuple byte for byte: {post_tuples:?}"
    );
}

#[test]
fn a_power_grant_for_an_absent_agent_is_held_back_and_the_other_rows_install() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let bounds = source_snapshot_bounds();
    source
        .replace_snapshot_read_settings_as_owner(&source_owner, bounds)
        .expect("the owner stores the source snapshot bounds");
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
        dest.snapshot_read_settings()
            .expect("read the destination snapshot bounds"),
        bounds,
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
        table_count(&summary, "SNAPSHOT_READ_SETTINGS", "installed_rows"),
        Some(1),
        "the owner import reports one installed SNAPSHOT_READ_SETTINGS row beside the held-back row: {summary}"
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

/// The physical key the archive files a retained tuple under, as
/// `retained_side_row_key` derives it: BLAKE3 over the domain and the
/// length-framed table name, source key and source value hash.
fn retained_tuple_key((table, source_key, source_value): &(String, Vec<u8>, Vec<u8>)) -> [u8; 32] {
    let value_hash = blake3::hash(source_value);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.archive.retained_side_row.v1");
    for part in [
        table.as_bytes(),
        source_key.as_slice(),
        value_hash.as_bytes().as_slice(),
    ] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// The one SNAPSHOT_READ_SETTINGS tuple of `vault`'s whole archive.
fn snapshot_bounds_tuple(vault: &oneiron::Vault) -> (String, Vec<u8>, Vec<u8>) {
    let rows = rows_for(
        &retained_rows(&export_whole(vault)),
        "SNAPSHOT_READ_SETTINGS",
    );
    assert_eq!(
        rows.len(),
        1,
        "the archive holds one snapshot bounds tuple: {rows:?}"
    );
    rows[0].clone()
}

#[test]
fn an_inert_copy_never_displaces_the_source_live_setting() {
    // The first vault stores nine choices in turn to read each one's tuple.
    // The choice whose tuple files last is the live one and the choice whose
    // tuple files first is the older one, so the older copy files before the
    // live tuple whatever the hashes give. The first vault then holds the
    // older choice.
    let (_first_dir, first) = open_source_vault();
    let first_owner = owner_proof(&first);
    let mut candidates = Vec::new();
    for open_per_actor in [2, 3, 4] {
        for page_rows in [50, 100, 150] {
            let choice = SnapshotReadSettings {
                open_per_actor,
                page_rows,
                ..SnapshotReadSettings::DEFAULT
            };
            first
                .replace_snapshot_read_settings_as_owner(&first_owner, choice)
                .expect("the first owner stores a candidate choice");
            candidates.push((choice, snapshot_bounds_tuple(&first)));
        }
    }
    candidates.sort_by_key(|(_, tuple)| retained_tuple_key(tuple));
    let (older, older_tuple) = candidates.first().cloned().expect("nine candidate choices");
    let (live, live_tuple) = candidates.last().cloned().expect("nine candidate choices");
    assert!(
        retained_tuple_key(&older_tuple) < retained_tuple_key(&live_tuple),
        "the older choice's tuple files before the live one: {candidates:?}"
    );
    first
        .replace_snapshot_read_settings_as_owner(&first_owner, older)
        .expect("the first owner stores the older choice");
    assert_eq!(
        snapshot_bounds_tuple(&first),
        older_tuple,
        "the first vault holds the older choice"
    );
    let first_archive = export_whole(&first);

    let (_middle_dir, middle) = open_later_vault();
    let middle_owner = owner_proof(&middle);
    middle
        .replace_snapshot_read_settings_as_owner(&middle_owner, live)
        .expect("the middle owner stores the live choice");
    middle
        .import_whole_vault_archive_from_as_owner(Cursor::new(&first_archive), &middle_owner)
        .expect("the middle owner import succeeds");
    assert_eq!(
        middle
            .snapshot_read_settings()
            .expect("read the middle snapshot bounds"),
        live,
        "the middle vault keeps its own choice live"
    );
    let middle_archive = export_whole(&middle);
    let middle_tuples = rows_for(&retained_rows(&middle_archive), "SNAPSHOT_READ_SETTINGS");
    assert!(
        middle_tuples.len() == 2
            && middle_tuples.contains(&live_tuple)
            && middle_tuples.contains(&older_tuple),
        "the middle archive holds the live tuple and the older inert copy: {middle_tuples:?}"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&middle_archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        dest.snapshot_read_settings()
            .expect("read the destination snapshot bounds"),
        live,
        "the source's live choice installs, not the older inert copy {older:?}"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "SNAPSHOT_READ_SETTINGS", "installed_rows"),
        Some(1),
        "the owner import installs one snapshot bounds row: {summary}"
    );
    let dest_tuples = rows_for(
        &retained_rows(&export_whole(&dest)),
        "SNAPSHOT_READ_SETTINGS",
    );
    assert!(
        dest_tuples.len() == 2
            && dest_tuples.contains(&live_tuple)
            && dest_tuples.contains(&older_tuple),
        "the destination archive holds the live tuple and keeps the older copy inert: {dest_tuples:?}"
    );
}
