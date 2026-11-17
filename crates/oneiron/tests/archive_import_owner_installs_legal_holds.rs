#![cfg(oneiron_test_support)]
//! The owner's restore installs customer legal holds live.
//!
//! Public doors only; neutral fixtures; vaults in tempdirs. Each destination
//! opens at least one wall-clock second after its source (sleep 1100 ms), as
//! in `archive_import_retained_side_rows.rs`.
//!
//! The five customer tables are `LEGAL_HOLD_ROW`, `LEGAL_HOLD_TARGET`,
//! `LEGAL_HOLD_USE_LIMIT`, `LEGAL_HOLD_ERASE_LINK` and `LEGAL_HOLD_EVENT`;
//! `LEGAL_HOLD_PENDING_ERASE` stays retained-only. All five install here.
//!
//! * `the_owner_restore_installs_a_standing_hold_that_refuses_deleting_its_record`:
//!   the owner import installs one ROW row, one TARGET row and one EVENT row
//!   live and reports one installed row for each, and the restored hold
//!   refuses its record's delete; a repeat owner import reports one unchanged
//!   live row for each; the actorless import of the same archive lists no
//!   hold and its delete succeeds.
//! * `the_next_hold_act_after_a_restore_follows_the_restored_log`: a restored
//!   hold's next widen adds its second record, the log keeps its restored
//!   prefix then its scope change, and the new record's delete is refused.
//! * `a_lifted_hold_restores_as_history_and_starts_no_erase`: a hold the
//!   owner lifted in a shared vault's veto window restores lifted with its
//!   erase link and three events, its waiting erase stays retained byte for
//!   byte, and the record stays live; no erase starts.
//! * `a_use_limit_restores_only_beside_its_standing_hold`: a hosted privacy
//!   erase mints its use limit beside its standing hold, the destination
//!   preseeds the same record its export withholds, and the owner import
//!   restores the limit with its marker beside the hold.
//!
//! New report counts are read through `serde_json::to_value` of the SIDE-1
//! summary, using only public items present at 13fb2c3d88f6. An absent field
//! fails its assertion as a missing outcome, never as a setup panic.
//! `cargo test --locked -p oneiron --all-features --test
//! archive_import_owner_installs_legal_holds`.

#[path = "archive_import_retained_side_rows.rs"]
mod retained_side_rows;

use std::io::Cursor;

use oneiron::deletion::{
    ErasePendingReason, LEGAL_HOLD_REFUSAL, LegalHoldEventKind, LegalHoldReason, LegalHoldTarget,
    LiftAndEraseStatus,
};
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};
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

/// The three live tables a standing hold installs.
const STANDING_TABLES: [&str; 3] = ["LEGAL_HOLD_ROW", "LEGAL_HOLD_TARGET", "LEGAL_HOLD_EVENT"];

/// The shared vault id the lifted test shares.
const SHARED_VAULT_ID: u64 = 42;

/// The owner restore installs the standing hold live and its delete stays
/// refused; the actorless import lists no hold and its delete succeeds.
#[test]
fn the_owner_restore_installs_a_standing_hold_that_refuses_deleting_its_record() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let record = fixed_id(0x29);
    source
        .put_entity(
            &record,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 10 },
            10,
            b"held record",
        )
        .expect("the source stores the held record");
    assert_eq!(
        source.get(&record).expect("read the source record"),
        Some(b"held record".to_vec()),
        "the source holds the record"
    );
    let matter = "matter-001".to_owned();
    let hold = source
        .place_legal_hold(
            &source_owner,
            vec![LegalHoldTarget::Record(record)],
            Some(matter.clone()),
        )
        .expect("the owner places the source hold");
    assert!(hold.stands(), "the source hold stands: {hold:?}");
    assert_eq!(
        hold.targets,
        vec![LegalHoldTarget::Record(record)],
        "the source hold names its record"
    );
    assert_eq!(
        hold.matter_ref,
        Some(matter.clone()),
        "the source hold carries its matter"
    );
    let source_holds = source
        .legal_holds(&source_owner)
        .expect("list the source holds");
    assert_eq!(
        source_holds,
        vec![hold.clone()],
        "the source lists its one hold"
    );
    let source_log = source
        .legal_hold_log(&source_owner)
        .expect("read the source log");
    assert_eq!(
        source_log.len(),
        1,
        "the source log holds its placement: {source_log:?}"
    );
    assert_eq!(
        source_log[0].event,
        LegalHoldEventKind::Placed,
        "the source log starts with its placement"
    );
    assert_eq!(
        source_log[0].reason,
        LegalHoldReason::OwnerPlaced,
        "the source placement names its reason"
    );
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        dest.legal_holds(&dest_owner)
            .expect("list the restored holds"),
        source_holds,
        "the owner import installs the standing hold live"
    );
    assert_eq!(
        dest.legal_hold_log(&dest_owner)
            .expect("read the restored log"),
        source_log,
        "the owner import installs the hold log live"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    for table in STANDING_TABLES {
        assert_eq!(
            table_count(&summary, table, "installed_rows"),
            Some(1),
            "the owner import reports one installed {table} row; an absent field means it installed nothing: {summary}"
        );
    }
    let refused = dest
        .delete_entity(&record)
        .expect_err("the restored hold refuses its record");
    assert!(
        format!("{refused:?}").contains(LEGAL_HOLD_REFUSAL),
        "the restored refusal names the hold: {refused:?}"
    );
    assert!(
        dest.get(&record)
            .expect("read the held restored record")
            .is_some(),
        "the refused restored delete keeps the record"
    );

    let repeat = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the repeat owner import succeeds");
    let repeat_summary =
        serde_json::to_value(&repeat.retained_side_rows).expect("the repeat summary serializes");
    for table in STANDING_TABLES {
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
    // A delete signs its receipt with this install's device key. A held
    // delete is refused before that step; this unheld one reaches it.
    bare.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    let bare_receipt = bare
        .import_whole_vault_archive_from(Cursor::new(&archive))
        .expect("the actorless import succeeds");
    let bare_owner = owner_proof(&bare);
    assert!(
        bare.legal_holds(&bare_owner)
            .expect("list the actorless holds")
            .is_empty(),
        "the actorless import installs no hold"
    );
    assert!(
        bare.legal_hold_log(&bare_owner)
            .expect("read the actorless log")
            .is_empty(),
        "the actorless import installs no log"
    );
    let bare_summary =
        serde_json::to_value(&bare_receipt.retained_side_rows).expect("the summary serializes");
    for table in STANDING_TABLES {
        assert!(
            matches!(
                table_count(&bare_summary, table, "installed_rows"),
                None | Some(0)
            ),
            "the actorless import installs no {table} row: {bare_summary}"
        );
    }
    assert_eq!(
        bare.delete_entity(&record)
            .expect("the actorless delete succeeds"),
        true,
        "without the hold the record deletes"
    );
    assert_eq!(
        bare.get(&record).expect("read the deleted record"),
        Some(Vec::new()),
        "the actorless delete keeps only the empty tombstone shell"
    );
}

/// The next widen after a restore keeps the restored log prefix, appends its
/// scope change, and refuses its new record's delete.
#[test]
fn the_next_hold_act_after_a_restore_follows_the_restored_log() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let first = fixed_id(0x2E);
    let second = fixed_id(0x31);
    source
        .put_entity(
            &first,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 10 },
            10,
            b"first record",
        )
        .expect("the source stores the first record");
    source
        .put_entity(
            &second,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 11, end: 11 },
            11,
            b"second record",
        )
        .expect("the source stores the second record");
    let hold = source
        .place_legal_hold(
            &source_owner,
            vec![LegalHoldTarget::Record(first)],
            Some("matter-002".to_owned()),
        )
        .expect("the owner places the source hold");
    let source_log = source
        .legal_hold_log(&source_owner)
        .expect("read the source log");
    assert_eq!(
        source_log.len(),
        1,
        "the source log holds its placement: {source_log:?}"
    );
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        dest.legal_hold_log(&dest_owner)
            .expect("read the restored log"),
        source_log,
        "the owner import installs the log before the next act"
    );

    let widened = dest
        .widen_legal_hold(
            &dest_owner,
            hold.hold_id,
            vec![LegalHoldTarget::Record(second)],
        )
        .expect("the owner widens the restored hold");
    assert!(
        widened.targets.contains(&LegalHoldTarget::Record(first))
            && widened.targets.contains(&LegalHoldTarget::Record(second)),
        "the widened hold names both records: {widened:?}"
    );
    let dest_log = dest
        .legal_hold_log(&dest_owner)
        .expect("read the widened log");
    assert_eq!(
        dest_log.len(),
        source_log.len() + 1,
        "the widen appends one event: {dest_log:?}"
    );
    assert_eq!(
        &dest_log[..source_log.len()],
        &source_log[..],
        "the widen keeps the restored prefix"
    );
    let last = dest_log.last().expect("the widened log has its new event");
    assert_eq!(
        last.event,
        LegalHoldEventKind::ScopeChanged,
        "the widen logs a scope change"
    );
    assert_eq!(
        last.reason,
        LegalHoldReason::ScopeWidened,
        "the widen names its reason"
    );
    assert_eq!(
        last.targets,
        vec![LegalHoldTarget::Record(second)],
        "the widen logs its added record"
    );
    let refused = dest
        .delete_entity(&second)
        .expect_err("the widened hold refuses its new record");
    assert!(
        format!("{refused:?}").contains(LEGAL_HOLD_REFUSAL),
        "the new record refusal names the hold: {refused:?}"
    );
}

/// A hold lifted in the shared veto window restores lifted with its link and
/// history, keeps its waiting erase retained, and starts no erase.
#[test]
fn a_lifted_hold_restores_as_history_and_starts_no_erase() {
    let (_source_dir, source) = open_source_vault();
    let source_owner = owner_proof(&source);
    let second_id = fixed_id(0x33);
    source
        .put_entity(
            &second_id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"second owner",
        )
        .expect("the source stores the second owner");
    let second_proof = source
        .authenticate_owner(second_id, &second_id.to_hex(), true, GateDecisionId::now())
        .expect("the second owner proves");
    source
        .initialize_shared_vault(
            &source_owner,
            SHARED_VAULT_ID,
            None,
            &[InitialSharedMember {
                member_ref: second_id,
                role: Some(FederationGrantRole::Owner),
            }],
            1,
        )
        .expect("the owner shares the vault");
    let invitations = source
        .shared_invitations(&second_proof, SHARED_VAULT_ID)
        .expect("the second owner lists its invitation");
    assert_eq!(
        invitations.len(),
        1,
        "the second owner has one invitation: {invitations:?}"
    );
    source
        .accept_shared_invitation(&second_proof, SHARED_VAULT_ID, &invitations[0].id)
        .expect("the second owner joins");

    let record = fixed_id(0x36);
    source
        .put_entity(
            &record,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 10 },
            10,
            b"lifted record",
        )
        .expect("the source stores the lifted record");
    let hold = source
        .place_legal_hold(
            &source_owner,
            vec![LegalHoldTarget::Record(record)],
            Some("matter-003".to_owned()),
        )
        .expect("the owner places the source hold");
    let shown = source
        .lift_and_erase_shown_state(&source_owner, &[record], false)
        .expect("the confirm shows its state");
    let outcome = source
        .confirm_lift_legal_hold_and_erase(&source_owner, &[record], false, &shown)
        .expect("the owner confirms lift and erase");
    assert!(
        outcome.changed.is_none(),
        "the confirm matches what was shown: {outcome:?}"
    );
    assert_eq!(
        outcome.holds,
        vec![hold.hold_id],
        "the confirm lifts its hold: {outcome:?}"
    );
    assert_eq!(
        outcome.records.len(),
        1,
        "the confirm names its record: {outcome:?}"
    );
    assert_eq!(
        outcome.records[0].0, record,
        "the confirm names the lifted record"
    );
    assert!(
        matches!(
            outcome.records[0].1,
            LiftAndEraseStatus::CompletionPending {
                reason: Some(ErasePendingReason::VetoWindow),
                ..
            }
        ),
        "the shared erase waits out its veto window: {:?}",
        outcome.records[0].1
    );

    let source_holds = source
        .legal_holds(&source_owner)
        .expect("list the source holds");
    assert_eq!(
        source_holds.len(),
        1,
        "the source keeps its lifted hold: {source_holds:?}"
    );
    let lifted = &source_holds[0];
    assert!(!lifted.stands(), "the confirm lifts the hold: {lifted:?}");
    assert!(
        lifted.lifted_at.is_some(),
        "the lifted hold names its release: {lifted:?}"
    );
    assert_eq!(
        lifted.targets,
        vec![LegalHoldTarget::Record(record)],
        "a fully lifted hold keeps its last scope: {lifted:?}"
    );
    assert!(
        source
            .get(&record)
            .expect("read the lifted source record")
            .is_some(),
        "the veto keeps the source record live"
    );
    let source_log = source
        .legal_hold_log(&source_owner)
        .expect("read the source log");
    assert_eq!(
        source_log.len(),
        3,
        "the source log holds placement, confirm and lift: {source_log:?}"
    );
    assert_eq!(
        source_log[0].event,
        LegalHoldEventKind::Placed,
        "the lifted log starts with its placement"
    );
    assert_eq!(
        source_log[1].event,
        LegalHoldEventKind::LiftAndEraseConfirmed,
        "the lifted log names its confirm"
    );
    assert_eq!(
        source_log[2].event,
        LegalHoldEventKind::Lifted,
        "the lifted log ends with its lift"
    );
    let archive = export_whole(&source);
    let source_pending = rows_for(&retained_rows(&archive), "LEGAL_HOLD_PENDING_ERASE");
    assert_eq!(
        source_pending.len(),
        1,
        "the source archive carries its waiting erase: {source_pending:?}"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        dest.legal_holds(&dest_owner)
            .expect("list the restored holds"),
        source_holds,
        "the owner import restores the lifted hold as history"
    );
    assert_eq!(
        dest.legal_hold_log(&dest_owner)
            .expect("read the restored log"),
        source_log,
        "the owner import restores the hold history"
    );
    assert!(
        dest.get(&record)
            .expect("read the restored record")
            .is_some(),
        "the restore starts no erase"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "LEGAL_HOLD_ROW", "installed_rows"),
        Some(1),
        "the owner import reports one installed LEGAL_HOLD_ROW row; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        table_count(&summary, "LEGAL_HOLD_ERASE_LINK", "installed_rows"),
        Some(1),
        "the owner import reports one installed LEGAL_HOLD_ERASE_LINK row; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        table_count(&summary, "LEGAL_HOLD_EVENT", "installed_rows"),
        Some(3),
        "the owner import reports three installed LEGAL_HOLD_EVENT rows; an absent field means it installed nothing: {summary}"
    );
    assert!(
        matches!(
            table_count(&summary, "LEGAL_HOLD_TARGET", "installed_rows"),
            None | Some(0)
        ),
        "a lifted hold installs no target: {summary}"
    );
    assert!(
        matches!(
            table_count(&summary, "LEGAL_HOLD_PENDING_ERASE", "installed_rows"),
            None | Some(0)
        ),
        "the waiting erase stays retained: {summary}"
    );
    assert_eq!(
        table_count(&summary, "LEGAL_HOLD_PENDING_ERASE", "inserted_rows"),
        Some(1),
        "the owner import retains one waiting erase envelope: {summary}"
    );
    assert_eq!(
        rows_for(
            &retained_rows(&export_whole(&dest)),
            "LEGAL_HOLD_PENDING_ERASE"
        ),
        source_pending,
        "the destination retains the waiting erase byte for byte"
    );
}

/// A hosted use limit restores beside its standing hold onto its preseeded
/// record, with its marker equal. The destination preseed is public setup:
/// the whole export withholds the use-limited payload, and the landing
/// needs destination liveness, so the same id and body are stored first.
#[test]
fn a_use_limit_restores_only_beside_its_standing_hold() {
    let source_dir = tempfile::tempdir().expect("temp dir for the hosted source vault");
    let mut source_config = VaultConfig::default();
    source_config.privacy.posture = HostingPrivacyPosture::Hosted;
    let source =
        Vault::open_owned(source_dir.path(), source_config).expect("open the hosted source vault");
    let source_owner = owner_proof(&source);
    let record = fixed_id(0x3B);
    source
        .put_entity(
            &record,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 10 },
            10,
            b"limited record",
        )
        .expect("the source stores the limited record");
    assert_eq!(
        source.get(&record).expect("read the source record"),
        Some(b"limited record".to_vec()),
        "the source holds the record"
    );
    let hold = source
        .place_legal_hold(
            &source_owner,
            vec![LegalHoldTarget::Record(record)],
            Some("matter-004".to_owned()),
        )
        .expect("the owner places the source hold");
    assert!(hold.stands(), "the source hold stands: {hold:?}");
    let source_actor = source
        .ensure_embedded_owner_actor()
        .expect("the source names its embedded owner actor");
    let source_memory = source.memory(source_actor, EdgeActorClass::Human);
    let preview = source_memory
        .preview_entity_delete(&record)
        .expect("preview the limited record");
    let outcome = source_memory
        .confirm_entity_erase(
            &preview,
            EraseOptions {
                reason: EraseReason::GdprDelete,
                also_same_bytes: false,
                veto_starter: None,
            },
        )
        .expect("the hosted privacy erase runs");
    assert_eq!(
        outcome.first.reason.as_str(),
        "privacy_erase_kept",
        "the held privacy erase is kept: {outcome:?}"
    );
    assert!(
        outcome.first.receipt_ref.is_none(),
        "a kept erase writes no receipt: {outcome:?}"
    );
    assert!(
        outcome.same_bytes.is_empty(),
        "without the flag no other record is named: {outcome:?}"
    );
    let source_limit = source
        .legal_hold_use_limit(&record)
        .expect("read the source use limit")
        .expect("the hosted privacy erase mints its marker");
    assert_eq!(source_limit.record, record, "the marker names its record");
    assert_eq!(
        source_limit.reason,
        LegalHoldReason::PrivacyEraseKept,
        "the marker names its reason"
    );
    let source_holds = source
        .legal_holds(&source_owner)
        .expect("list the source holds");
    assert_eq!(
        source_holds.len(),
        1,
        "the source keeps its standing hold: {source_holds:?}"
    );
    assert!(
        source_holds[0].stands(),
        "the kept hold stands: {:?}",
        source_holds[0]
    );
    let source_log = source
        .legal_hold_log(&source_owner)
        .expect("read the source log");
    assert_eq!(
        source_log.len(),
        2,
        "the source log holds placement and kept refusal: {source_log:?}"
    );
    assert_eq!(
        source_log[0].event,
        LegalHoldEventKind::Placed,
        "the limited log starts with its placement"
    );
    assert_eq!(
        source_log[1].event,
        LegalHoldEventKind::DeleteRefused,
        "the kept erase logs its refusal"
    );
    assert_eq!(
        source_log[1].reason,
        LegalHoldReason::PrivacyEraseKept,
        "the kept refusal names its reason"
    );
    let archive = export_whole(&source);
    assert_eq!(
        rows_for(&retained_rows(&archive), "LEGAL_HOLD_USE_LIMIT").len(),
        1,
        "the source archive carries its limit row"
    );

    // The whole export withholds the use-limited payload, so the destination
    // stores the same id and body first through the public entity door. The
    // landing still checks destination liveness and its standing hold, so the
    // preseed is required setup, not a bypass of its validation.
    let (_dest_dir, dest) = open_later_vault();
    dest.put_entity(
        &record,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 10, end: 10 },
        10,
        b"limited record",
    )
    .expect("the destination preseeds the same record");
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds");
    assert_eq!(
        dest.legal_holds(&dest_owner)
            .expect("list the restored holds"),
        source_holds,
        "the owner import installs the standing hold beside its limit"
    );
    assert_eq!(
        dest.legal_hold_log(&dest_owner)
            .expect("read the restored log"),
        source_log,
        "the owner import installs the hold log beside its limit"
    );
    assert_eq!(
        dest.legal_hold_use_limit(&record)
            .expect("read the restored use limit"),
        Some(source_limit.clone()),
        "the owner import restores the use limit with its marker; baseline reads None"
    );
    assert!(
        dest.get(&record)
            .expect("read the use-limited record")
            .is_none(),
        "the restored use limit hides the record from normal reads"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "LEGAL_HOLD_ROW", "installed_rows"),
        Some(1),
        "the owner import reports one installed LEGAL_HOLD_ROW row; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        table_count(&summary, "LEGAL_HOLD_TARGET", "installed_rows"),
        Some(1),
        "the owner import reports one installed LEGAL_HOLD_TARGET row; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        table_count(&summary, "LEGAL_HOLD_EVENT", "installed_rows"),
        Some(2),
        "the owner import reports two installed LEGAL_HOLD_EVENT rows; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        table_count(&summary, "LEGAL_HOLD_USE_LIMIT", "installed_rows"),
        Some(1),
        "the owner import reports one installed LEGAL_HOLD_USE_LIMIT row; an absent field means it installed nothing: {summary}"
    );
    let refused = dest
        .delete_entity(&record)
        .expect_err("the restored hold refuses its limited record");
    assert!(
        format!("{refused:?}").contains(LEGAL_HOLD_REFUSAL),
        "the limited refusal names the hold: {refused:?}"
    );
}
