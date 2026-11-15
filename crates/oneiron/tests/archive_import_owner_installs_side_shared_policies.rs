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
//! * `a_restored_pending_widen_ask_keeps_no_ask_number`: a Pending
//!   OWNER_POLICY_WORLD_PRIVACY_REQUEST row installs without the source's decision
//!   ask number (the ask queue does not travel and numbers from 1 on every vault),
//!   and the owner's answer to the restored request leaves another pending
//!   request's ask open.
//! * `the_owner_restore_installs_the_world_privacy_receipt_live`: one
//!   OWNER_POLICY_WORLD_PRIVACY_RECEIPT row installs and the destination's change
//!   log reads it with its settings revision and log entry.
//! * `the_owner_restore_installs_the_shared_act_policy_change_live`: one applied
//!   SHARED_ACT_POLICY_CHANGE row installs on a destination shared under the same
//!   vault id and reads back whole.
//! * `the_owner_restore_installs_an_org_admin_policy_whose_admin_is_live`: one
//!   ORG_ADMIN_POLICY row whose admin PERSON travels with the archive installs and
//!   the destination reads it.
//! * `the_owner_restore_installs_the_mail_compliance_setting`: one
//!   MAIL_PACK_COMPLIANCE_SETTING row installs and the destination reads compliance
//!   search on where it read off before the import.
//!
//! POLICY_HOLD_QUEUE has no landing and no test: no production route queues a hold
//! (FIX-LIST ARCHIVE-POLICY-HOLD-QUEUE-NOT-RESTORED). SOURCE_AUDIENCE_POLICY has no
//! landing and no test: no archive carries the source and record rows that name a
//! policy (FIX-LIST ARCHIVE-SOURCE-AUDIENCE-POLICY-NOT-RESTORED).
//!
//! New report counts are read through `serde_json::to_value` of the SIDE-1
//! summary, so this file compiles on 56a501392094; an absent field fails its
//! assertion as a missing outcome, never as a setup panic.
//! `cargo test --locked -p oneiron --all-features --test archive_import_owner_installs_side_shared_policies`.

#[path = "archive_import_retained_side_rows.rs"]
mod retained_side_rows;

use std::collections::BTreeSet;
use std::io::Cursor;
use std::sync::Arc;

use oneiron::EdgeActorClass;
use oneiron::EntityId;
use oneiron::WriteActor;
use oneiron::authority::{
    ActSurface, HostSlipIssuer, MachineRole, ModelOrder, ReadLocation, WorldPrivacy,
};
use oneiron::edit_distance::escalation::{
    EscalationReceipt, EscalationRuling, EscalationTrigger, StandingPolicyStatus,
    escalation_standing_n, maybe_propose_standing_policy, record_escalation, standing_policy_for,
};
use oneiron::federation::{
    FederationGrantRole, OrgAdminError, OrgAdminPolicy, OrgAdminPower, SharedActPolicyChangeState,
    SharedVaultPreset,
};
use oneiron::mail_pack::{
    MailComplianceSetRequest, MailComplianceSettingView, install_mail_calendar_pack_embedded,
};
use oneiron::policy_model::{
    WidenUnanimity, WidenUnanimityOutcome, WorldPrivacyAnswer, WorldPrivacyOutcome,
    WorldPrivacyRequestStatus,
};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentDefinitionSpec, create_agent_definition_as,
};
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

/// A restored pending widen ask keeps no ask number: the decision ask queue
/// does not travel, so the landing installs the request with `ask: None`.
/// Part 2: answering the restored request leaves the other request's ask
/// open.
#[test]
fn a_restored_pending_widen_ask_keeps_no_ask_number() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let agent = fixed_id(0x5A);
    let definition: AgentDefinitionSpec = serde_json::from_value(serde_json::json!({
        "agent_id": "widen-ask-agent",
        "desc": "World privacy widen agent",
        "version": "1",
        "ceiling": "auto",
        "enabled": true,
    }))
    .expect("the agent definition parses");
    create_agent_definition_as(
        &source,
        &source_owner,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition,
        },
    )
    .expect("the owner creates the agent");
    let world = source
        .create_world(&source_owner, "widen ask world", source.now_recorded_at())
        .expect("the owner creates a world");
    // Any model-order change widens a world at its default settings.
    let widen = WorldPrivacy {
        models: ModelOrder::Ordered(vec!["r1".to_owned()]),
        ..WorldPrivacy::default()
    };
    let writer = WriteActor::new(agent, EdgeActorClass::Agent);
    let source_request = match source
        .agent_world_privacy(&writer, Vec::new(), world, widen.clone(), None)
        .expect("the agent's widen asks")
    {
        WorldPrivacyOutcome::Asked(request) => request,
        other => panic!("the agent's widen asks, not {other:?}"),
    };
    assert_eq!(
        source_request.status,
        WorldPrivacyRequestStatus::Pending,
        "the source's request is pending"
    );
    assert!(
        source_request.ask.is_some(),
        "the source's request keeps its ask number"
    );
    let archive = export_whole(&source);
    assert_eq!(
        rows_for(
            &retained_rows(&archive),
            "OWNER_POLICY_WORLD_PRIVACY_REQUEST"
        )
        .len(),
        1,
        "the source archive holds one OWNER_POLICY_WORLD_PRIVACY_REQUEST tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(
            &summary,
            "OWNER_POLICY_WORLD_PRIVACY_REQUEST",
            "installed_rows"
        ),
        Some(1),
        "the owner import reports one installed OWNER_POLICY_WORLD_PRIVACY_REQUEST row; \
         an absent field means it installed nothing: {summary}"
    );
    let restored = dest
        .world_privacy_requests(false)
        .expect("read the restored requests");
    assert_eq!(restored.len(), 1, "the destination holds one request");
    assert_eq!(
        restored[0].status,
        WorldPrivacyRequestStatus::Pending,
        "the restored request is pending"
    );
    assert_eq!(
        restored[0].ask, None,
        "a restored pending request names no ask of this vault"
    );
    assert!(
        dest.decision_asks(None, 8, true)
            .expect("read the destination asks")
            .is_empty(),
        "the destination's ask queue holds no ask after the restore"
    );

    // Part 2: a second widen on the destination takes the number the
    // source's ask had, and answering the restored request leaves it open.
    let dest_writer = WriteActor::new(agent, EdgeActorClass::Agent);
    let second = match dest
        .agent_world_privacy(&dest_writer, Vec::new(), world, widen, None)
        .expect("the second widen asks")
    {
        WorldPrivacyOutcome::Asked(request) => request,
        other => panic!("the second widen asks, not {other:?}"),
    };
    assert_eq!(
        second.ask, source_request.ask,
        "the second ask takes the number the source's ask had"
    );
    let second_seq = second.ask.expect("the second ask is queued");
    let restored_id = restored[0].id().expect("the restored request has its id");
    match dest
        .answer_world_privacy_request(&dest_owner, ActSurface::ThisInstall, restored_id, false)
        .expect("the owner declines the restored request")
    {
        WorldPrivacyAnswer::Declined(_) => {}
        other => panic!("the decline declines, not {other:?}"),
    }
    let reread = dest
        .world_privacy_requests(false)
        .expect("read the requests again");
    let live_second = reread
        .iter()
        .find(|request| request.request_id == second.request_id)
        .expect("the second request is still listed");
    assert_eq!(
        live_second.status,
        WorldPrivacyRequestStatus::Pending,
        "the second request is still pending"
    );
    assert!(
        dest.decision_ask(second_seq)
            .expect("read the second ask")
            .is_some_and(|ask| ask.is_open()),
        "the restored request's answer leaves the other request's ask open"
    );
}

/// The owner restore installs the world's privacy receipt live: the restored change log
/// holds the receipt naming the world with its stored settings revision and log entry.
#[test]
fn the_owner_restore_installs_the_world_privacy_receipt_live() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let issuer = HostSlipIssuer::from_secret(b"side-4c world privacy receipt host")
        .expect("the fixture issuer derives");
    source
        .ensure_host_root_slip(&issuer)
        .expect("the source takes a host root");
    source.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    source
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("the source enrolls its install");
    let world = source
        .create_world(&source_owner, "owen world", source.now_recorded_at())
        .expect("the owner creates the source world");
    let change = source
        .set_world_privacy_as(
            &source_owner,
            ActSurface::ThisInstall,
            world,
            WorldPrivacy {
                read: ReadLocation::MyMachines,
                ..WorldPrivacy::default()
            },
            None,
        )
        .expect("the owner keeps the world on their machines");
    let source_log = source
        .world_privacy_change_log()
        .expect("read the source receipt log");
    assert_eq!(source_log.len(), 1, "the source holds one receipt");
    assert_eq!(source_log[0].revision, 1, "the first receipt is revision 1");
    assert_eq!(
        source_log[0].world,
        world.to_hex(),
        "the receipt names the world"
    );
    assert_eq!(
        source_log[0].receipt_id, change.receipt_id,
        "the log holds the change"
    );
    let archive = export_whole(&source);
    assert_eq!(
        rows_for(
            &retained_rows(&archive),
            "OWNER_POLICY_WORLD_PRIVACY_RECEIPT"
        )
        .len(),
        1,
        "the source archive holds one receipt tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    assert!(
        dest.world_privacy_change_log()
            .expect("read the bare log")
            .is_empty(),
        "the bare destination holds no receipt"
    );
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(
            &summary,
            "OWNER_POLICY_WORLD_PRIVACY_RECEIPT",
            "installed_rows"
        ),
        Some(1),
        "one installed receipt row; an absent field means it installed nothing: {summary}"
    );
    let dest_log = dest
        .world_privacy_change_log()
        .expect("read the restored receipt log");
    assert_eq!(
        dest_log.len(),
        1,
        "the destination holds one restored receipt"
    );
    assert_eq!(
        dest_log[0].revision, 1,
        "the restored receipt is revision 1"
    );
    assert_eq!(
        dest_log[0].world,
        world.to_hex(),
        "the restored receipt names the world"
    );
    assert_eq!(
        dest_log[0].revision_after, source_log[0].revision_after,
        "the restored receipt keeps its settings revision"
    );
    assert_eq!(
        dest_log[0].entry_hash, source_log[0].entry_hash,
        "the restored receipt keeps its log entry"
    );
}

/// The owner restore installs the shared-act policy change live: the sole editor's
/// applied change reads back whole on a destination shared under the same vault id.
#[test]
fn the_owner_restore_installs_the_shared_act_policy_change_live() {
    const SHARED_VAULT_ID: u64 = 7;
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    source
        .initialize_shared_vault(
            &source_owner,
            SHARED_VAULT_ID,
            Some(SharedVaultPreset::Team),
            &[],
            source.now_recorded_at(),
        )
        .expect("the owner shares the source vault");
    let view = source
        .shared_act_policies(&source_owner, SHARED_VAULT_ID)
        .expect("read the source act rows");
    let mut row = view
        .effective
        .get("add_owner")
        .expect("the shared kind ships add_owner")
        .clone();
    row.wait_secs = 3600;
    row.objector_roles = vec![FederationGrantRole::Owner];
    let change = source
        .propose_shared_act_policy_change(
            &source_owner,
            SHARED_VAULT_ID,
            "add_owner",
            Some(row),
            &view.policy_hash,
        )
        .expect("the sole editor proposes the tighter row");
    assert_eq!(
        change.state,
        SharedActPolicyChangeState::Applied,
        "the sole editor's change applies at once: {change:?}"
    );
    assert!(
        change.awaiting.is_empty(),
        "the applied change waits on no one"
    );
    assert_eq!(
        source
            .shared_act_policy_change(&source_owner, &change.id)
            .expect("read the source change"),
        change,
        "the source reads its applied change"
    );
    let archive = export_whole(&source);
    assert_eq!(
        rows_for(&retained_rows(&archive), "SHARED_ACT_POLICY_CHANGE").len(),
        1,
        "the source archive holds one change tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    dest.initialize_shared_vault(
        &dest_owner,
        SHARED_VAULT_ID,
        Some(SharedVaultPreset::Team),
        &[],
        dest.now_recorded_at(),
    )
    .expect("the destination shares its vault under the same id");
    assert!(
        dest.shared_act_policy_change(&dest_owner, &change.id)
            .is_err(),
        "the destination holds no change before the import"
    );
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "SHARED_ACT_POLICY_CHANGE", "installed_rows"),
        Some(1),
        "one installed change row; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        dest.shared_act_policy_change(&dest_owner, &change.id)
            .expect("read the restored change"),
        change,
        "the owner import installs the applied change live"
    );
}

/// The owner restore installs an org admin policy whose admin is live.
#[test]
fn the_owner_restore_installs_an_org_admin_policy_whose_admin_is_live() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let admin = source
        .ensure_embedded_owner_actor()
        .expect("the embedded owner PERSON");
    let org = fixed_id(0x6A);
    let policy = OrgAdminPolicy::new(
        org,
        BTreeSet::from([admin]),
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
    assert_eq!(
        rows_for(&retained_rows(&archive), "ORG_ADMIN_POLICY").len(),
        1,
        "the source archive holds one org tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    assert!(
        matches!(dest.org_admin_policy(org), Err(OrgAdminError::Denied)),
        "the bare destination holds no org row"
    );
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "ORG_ADMIN_POLICY", "installed_rows"),
        Some(1),
        "the owner import installs one org row; absent means none: {summary}"
    );
    assert_eq!(
        dest.org_admin_policy(org)
            .expect("read the restored org row"),
        policy,
        "the owner import installs the org row live"
    );
}

/// The owner restore installs the mail compliance setting live.
#[test]
fn the_owner_restore_installs_the_mail_compliance_setting() {
    let (_source_dir, source) = open_source_vault();
    let owner = source
        .ensure_embedded_owner_actor()
        .expect("the embedded owner PERSON");
    // The pack installs as the embedded owner, as a server starts it; the
    // same steps as `tests/mail_active_sources.rs`.
    let issuer = HostSlipIssuer::from_secret(b"mail compliance setting test host")
        .expect("the host issuer builds");
    source.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    source
        .ensure_host_root_slip(&issuer)
        .expect("the host roots the vault");
    source
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("the serving install enrols");
    let memory = source.memory(owner, EdgeActorClass::Human);
    install_mail_calendar_pack_embedded(&memory).expect("the pack installs");
    let source_setting: MailComplianceSettingView = memory
        .mail_compliance_set(&MailComplianceSetRequest {
            enabled: true,
            purpose: "owen audits the shared mailbox".to_owned(),
        })
        .expect("the owner turns compliance search on");
    assert!(source_setting.enabled, "the source reads the setting on");
    assert_eq!(
        source_setting.set_by_ref,
        Some(owner.to_hex()),
        "the source names the setter"
    );
    assert!(
        source_setting.set_at.is_some(),
        "the source stamps the change"
    );
    let archive = export_whole(&source);
    assert_eq!(
        rows_for(&retained_rows(&archive), "MAIL_PACK_COMPLIANCE_SETTING").len(),
        1,
        "the source archive holds one compliance tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_actor = dest
        .ensure_embedded_owner_actor()
        .expect("the destination embedded owner");
    let dest_memory = dest.memory(dest_actor, EdgeActorClass::Human);
    assert!(
        !dest_memory
            .mail_compliance_setting()
            .expect("read the bare setting")
            .enabled,
        "the bare destination reads compliance search off"
    );
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "MAIL_PACK_COMPLIANCE_SETTING", "installed_rows"),
        Some(1),
        "the owner import installs one compliance row; absent means none: {summary}"
    );
    assert_eq!(
        dest_memory
            .mail_compliance_setting()
            .expect("read the restored setting"),
        source_setting,
        "the owner import installs the setting live"
    );
}
