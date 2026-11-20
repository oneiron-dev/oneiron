#![cfg(oneiron_test_support)]
//! The owner's restore installs the room membership ledger live.
//!
//! Public doors only; neutral fixtures (`owen`, `yuki`); vaults in tempdirs. Each destination
//! opens at least one wall-clock second after its source (sleep 1100 ms), as in
//! `archive_import_retained_side_rows.rs`.
//!
//! * `the_owner_restore_seats_a_room_and_installs_its_admin_grant_on_a_fresh_vault`: a fresh owner restore
//!   succeeds; the destination holds exactly two ledger rows, its current members read
//!   `owen` and `yuki`, its ledger equals the source ledger, the report counts two installed
//!   `CONVERSATION_MEMBERSHIP_ROW` rows, one installed `CONVERSATION_MEMBERSHIP_SEQ` row and
//!   one installed `CONVERSATION_ROLE_GRANT` row, and yuki's Admin-only act succeeds while
//!   owen's stays refused.
//! * `a_repeat_owner_restore_reports_the_ledger_unchanged`: a repeat owner restore
//!   of the same archive installs nothing and reports two unchanged live
//!   `CONVERSATION_MEMBERSHIP_ROW` rows, one unchanged live `CONVERSATION_MEMBERSHIP_SEQ`
//!   row and one unchanged live `CONVERSATION_ROLE_GRANT` row; the ledger and members stay
//!   the source's.
//! * `a_member_who_left_stays_out_after_the_owner_restore`: the source seats owen and
//!   yuki and yuki leaves, so its ledger holds Join owen, Join yuki and Leave yuki; the
//!   owner restore installs three `CONVERSATION_MEMBERSHIP_ROW` rows and one
//!   `CONVERSATION_MEMBERSHIP_SEQ` row, the destination ledger equals the source ledger and
//!   only owen reads current.
//! * `a_destination_that_seats_the_room_itself_keeps_its_own_ledger`: the source and the
//!   destination seat the same room and persons with the same entity stamps but different
//!   ledger times, so the room put meets byte-identical rows and never refuses; the owner
//!   import keeps the destination ledger live, reports two kept-live
//!   `CONVERSATION_MEMBERSHIP_ROW` rows and one kept-live `CONVERSATION_MEMBERSHIP_SEQ`
//!   row, and the destination ledger and members stay its own.
//! * `a_whole_vault_export_withholds_the_ledger_and_roles_of_a_use_limited_room`
//!   (REVIEW-9446 P1-1): on a hosted source, a customer hold refuses the room's privacy
//!   erase and use-limits the room; the export then carries no `CONVERSATION_MEMBERSHIP_ROW`,
//!   `CONVERSATION_MEMBERSHIP_SEQ` or `CONVERSATION_ROLE_GRANT` row of that room, where the
//!   export before the hold carried two, one and one.
//! * `a_room_whose_member_is_no_live_person_here_stays_out_of_the_owner_restore`
//!   (REVIEW-9446 P1-2): the source user-deletes yuki, so its archive carries the room and its
//!   ledger but no yuki record. An owner restore into a vault without yuki, and one into a
//!   vault that holds yuki's soft-deleted shell, each goes on, keeps the room out under
//!   `RoomNotSeatedHere`, lands no ledger row and counts the three ledger envelopes held back
//!   as `missing_live_entity`; owen still lands. (Round 2: a use-limited yuki now keeps the
//!   whole ledger out of the archive, test 10, so this fixture deletes her instead.)
//! * `an_incomplete_room_ledger_keeps_the_room_out_of_the_owner_restore` (REVIEW-9446 P1-3;
//!   door `test_doors::archive_room_ledger`): the source's ledger lost its revision row, so
//!   the archive carries two ledger rows and no `CONVERSATION_MEMBERSHIP_SEQ`; the owner
//!   restore goes on, keeps the room out under `RoomNotSeatedHere` and counts the two rows
//!   held back as `missing_companion`.
//! * `a_join_visible_after_its_time_keeps_the_room_out_of_the_owner_restore` (REVIEW-9446
//!   P1-4; same door): owen's archived Join opens his window ten units after his join, which
//!   the membership door never writes; the owner restore goes on, keeps the room out and
//!   counts the three ledger envelopes held back as `invalid_value`.
//! * `a_whole_vault_export_withholds_the_ledger_of_a_deleted_room` (REVIEW-9446 round 2 P1-1):
//!   the source holds the room's ledger live and, after an actorless import of its own
//!   archive, inert as well; once the room is user-deleted the export carries no
//!   `CONVERSATION_MEMBERSHIP_ROW` or `CONVERSATION_MEMBERSHIP_SEQ` row of it, where it
//!   carried two and one before.
//! * `a_whole_vault_export_withholds_a_ledger_that_names_a_use_limited_member`
//!   (round 2 P1-2): on a hosted source yuki joins and leaves, then a customer hold refuses her
//!   privacy erase; the export still carries the room but no row or revision of its ledger,
//!   where it carried three and one before the hold.
//! * `an_identical_ledger_of_a_deleted_room_is_held_back_not_unchanged` (round 2 P1-3; door
//!   `copy_room_ledger`): a carrier vault holds the source room's ledger with no room record,
//!   so its archive carries that ledger alone; the owner restore into the source after the
//!   room's user delete counts both ledger tables held back as `missing_live_entity`, none
//!   unchanged live, and a repeat counts the inert copies unchanged.
//! * `an_intermediate_join_window_keeps_the_room_out_of_the_owner_restore` (round 2 P1-4;
//!   door `set_room_ledger_row_visible_from`): owen's plain Join at 20 opens his window at 10,
//!   between the room's origin and his join, with no speaker handoff; the owner restore goes
//!   on, keeps the room out and counts the three ledger envelopes held back as
//!   `invalid_value`.
//! * `an_unbound_leader_chat_stays_out_of_the_owner_restore` (round 2 P1-5; door
//!   `open_bound_leader_chat`): the source's leader chat room carries its binding, which the
//!   destination's project door never made; the owner restore goes on, keeps the room out
//!   under `RoomNotSeatedHere` and counts its ledger envelopes held back as
//!   `missing_live_entity`; owen and yuki land.
//! * `a_whole_vault_export_withholds_the_role_grant_of_a_deleted_room` (Engine ANSWER
//!   RETAINED-ROOM-ROWS-WITHHELD Q1 = A): yuki holds the Admin grant, the source keeps the
//!   grant live and, after an actorless import of its own archive, inert; once the room is
//!   user-deleted the export carries no `CONVERSATION_ROLE_GRANT` row of it, where it carried
//!   one before.
//! * `a_whole_vault_export_withholds_the_role_grant_of_a_use_limited_grantee` (Q1 = A): on a
//!   hosted source a customer hold refuses the Admin grantee yuki's privacy erase; the export
//!   still carries the room but no role grant naming yuki, where it carried one before.
//! * `a_malformed_inert_ledger_copy_is_withheld_alone` (REVIEW-9739 P1-2; door
//!   `retain_inert_side_row`): the source keeps two inert copies an archive could carry, its
//!   room's revision row under a key one byte too long and one of its ledger rows with a value
//!   that reads as no ledger row; the export carries neither copy and still carries the room's
//!   two live ledger rows and its revision.
//! * `an_inert_ledger_copy_naming_a_use_limited_person_is_withheld_alone` (REVIEW-9739 round 2
//!   P1-1; door `retain_inert_side_row`): on a hosted source the room keeps an inert copy of
//!   yuki's ledger row that names another person, held, in her place; a customer hold then
//!   refuses held's privacy erase. The export carries no such copy and still carries the
//!   room's two live ledger rows and its revision.
//!
//! Tests 5 and 6 use public doors only and run red at the review test commit (the round-1
//! head with #9721 merged, plus tests 5 and 6), where tests 1-4 pass. Tests 7 and 8 use the
//! door the fix commit adds and run green only. Tests 9 to 13 run red at the round-2 test
//! commit (the round-2 head with these tests and the round-2 doors, no fix), where tests 1 to
//! 8 pass. Tests 14 and 15 run red at the round-2 head (1adbb2714bf), which withholds a role
//! grant only for a room the export keeps out, where tests 1 to 13 pass.
//! Test 16 runs red at the review-1 test commit (ec7407c4e2a with this test and its door, no
//! fix), whose export withholds the room's whole ledger for either copy, where tests 1 to 15
//! pass. Test 17 runs red at f71253a24a9 (the round-1 fix), where an inert copy that reads
//! as a ledger row and names a kept-out person still withholds the room's whole ledger.
//!
//! New report counts are read through `serde_json::to_value` of the SIDE-1 summary, so this
//! file compiles where the landing is absent; an absent field fails its assertion as a
//! missing outcome, never as a setup panic. The semantic role read goes through the public
//! Admin-only act (`Vault::erase_room_person`), never through the body's roles map alone.
//! `cargo test --locked -p oneiron --all-features --test archive_import_owner_installs_room_membership`.

#[path = "archive_import_retained_side_rows.rs"]
mod retained_side_rows;

use std::io::Cursor;

use oneiron::batch::export::WholeVaultImportReceipt;
use oneiron::conversation::{
    ConversationBody, ConversationKind, HistoryChoice, MembershipAction, RoomRole,
};
use oneiron::deletion::LegalHoldTarget;
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::archive_room_ledger;
use oneiron::{
    EdgeActorClass, EntityId, HostingPrivacyPosture, TimeRange, Vault, VaultConfig, WriteActor,
};
use retained_side_rows::{
    export_whole, open_later_vault, open_source_vault, owner_proof, retained_rows, rows_for,
};
use std::collections::BTreeSet;

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

/// Puts a PERSON row for `id` holding `name`, at `occurred`/`learned_at`.
fn put_person_at(vault: &Vault, id: EntityId, name: &[u8], occurred: TimeRange, learned_at: u64) {
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, occurred, learned_at, name)
        .expect("the vault stores the fixture person");
}

/// Asserts yuki's Admin grant semantically on `vault`: yuki manages owen's room records (the
/// Admin-only act the room policy opens to Admin and shuts for Member), while owen's matching
/// act stays refused.
fn assert_admin_semantics(
    vault: &Vault,
    room: EntityId,
    owen: EntityId,
    yuki: EntityId,
    side: &str,
) {
    let manages = vault.erase_room_person(room, owen, WriteActor::new(yuki, EdgeActorClass::Human));
    assert!(
        manages.is_ok(),
        "the Admin grant lets yuki manage owen's room records on {side}: {manages:?}"
    );
    let refused = vault.erase_room_person(room, yuki, WriteActor::new(owen, EdgeActorClass::Human));
    assert!(
        refused.is_err(),
        "a Member cannot manage another member's room records on {side}: {refused:?}"
    );
}

/// Seats owen and yuki in a group room at `occurred`/`learned_at`, with no role granted: the
/// vault owner creates the room empty (so the creator's implicit Owner never falls on owen,
/// and no initial member's entry mints a reserved TASK fact, which the actorless import
/// refuses and whose id two vaults would share), then joins owen and yuki. Returns the room,
/// owen and yuki.
fn seat_room(
    vault: &Vault,
    occurred: TimeRange,
    learned_at: u64,
) -> (EntityId, EntityId, EntityId) {
    seat_room_with_join_at(vault, occurred, learned_at, occurred.start)
}

/// Builds the room seating owen and yuki ([`seat_room`]) with yuki holding the Admin grant,
/// at `occurred`/`learned_at`. Returns the room, owen and yuki. Asserts the grant's semantic
/// effect on the source.
fn build_admin_grant_room(
    source: &Vault,
    occurred: TimeRange,
    learned_at: u64,
) -> (EntityId, EntityId, EntityId) {
    let (room, owen, yuki) = seat_room(source, occurred, learned_at);
    let owner = source
        .ensure_embedded_owner_actor()
        .expect("the source names its embedded owner actor");
    source
        .set_room_role(
            room,
            yuki,
            RoomRole::Admin,
            WriteActor::new(owner, EdgeActorClass::Human),
        )
        .expect("the owner grants yuki the Admin role");
    assert_admin_semantics(source, room, owen, yuki, "the source");
    (room, owen, yuki)
}

/// Seats owen and yuki as [`seat_room`] does but joins at `join_at` while the PERSON rows
/// and the room keep `occurred`/`learned_at`: the entity bytes stay the caller's stamps
/// while the ledger rows carry `join_at`. Test 4 seats the source and the destination with
/// the same entity stamps and different `join_at`, so the room put meets byte-identical
/// rows and only the ledger times differ.
fn seat_room_with_join_at(
    vault: &Vault,
    occurred: TimeRange,
    learned_at: u64,
    join_at: u64,
) -> (EntityId, EntityId, EntityId) {
    let room = fixed_id(0x6B);
    let owen = fixed_id(0x6C);
    let yuki = fixed_id(0x6D);
    put_person_at(vault, owen, b"owen", occurred, learned_at);
    put_person_at(vault, yuki, b"yuki", occurred, learned_at);
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault names its embedded owner actor");
    vault
        .create_conversation_with_text(
            room,
            &ConversationBody {
                kind: ConversationKind::Group,
                member_ids: vec![],
                ..Default::default()
            },
            WriteActor::new(owner, EdgeActorClass::Human),
            occurred,
            learned_at,
            &[],
        )
        .expect("the owner creates the empty group room");
    for (member, name) in [(owen, "owen"), (yuki, "yuki")] {
        vault
            .join_member(
                room,
                member,
                WriteActor::new(owner, EdgeActorClass::Human),
                join_at,
                HistoryChoice::Share,
            )
            .unwrap_or_else(|err| panic!("{name} joins the room: {err:?}"));
    }
    (room, owen, yuki)
}

/// The shared entity stamps for the independently seated room: the source and the
/// destination write the room and its persons at these, so each destination row is the row
/// the archive carries and the import never refuses it.
const ENTITY_OCCURRED: TimeRange = TimeRange { start: 10, end: 10 };
const ENTITY_LEARNED_AT: u64 = 10;

/// The ledger times for the independently seated room: the source joins at the first, the
/// destination at the second, so the ledgers differ by `at` alone.
const SOURCE_JOIN_AT: u64 = 100;
const DEST_JOIN_AT: u64 = 200;

#[test]
fn the_owner_restore_seats_a_room_and_installs_its_admin_grant_on_a_fresh_vault() {
    let (_source_dir, source) = open_source_vault();
    let now = source.now_recorded_at();
    let (room, owen, yuki) = build_admin_grant_room(
        &source,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    );
    let source_ledger = source
        .membership_ledger(room)
        .expect("read the source ledger");
    assert_eq!(
        source_ledger.len(),
        2,
        "the source ledger holds two join rows"
    );
    let source_members = source.members(room).expect("read the source members");
    assert_eq!(
        source_members,
        vec![owen, yuki],
        "owen and yuki read current on the source"
    );
    let archive = export_whole(&source);
    let source_rows = retained_rows(&archive);
    let source_row_tuples = rows_for(&source_rows, "CONVERSATION_MEMBERSHIP_ROW");
    let source_seq_tuples = rows_for(&source_rows, "CONVERSATION_MEMBERSHIP_SEQ");
    let source_grant_tuples = rows_for(&source_rows, "CONVERSATION_ROLE_GRANT");
    assert_eq!(
        source_grant_tuples.len(),
        1,
        "the source archive holds one role-grant tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds into a fresh vault");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "CONVERSATION_MEMBERSHIP_ROW", "installed_rows"),
        Some(2),
        "the owner import reports two installed CONVERSATION_MEMBERSHIP_ROW rows; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        table_count(&summary, "CONVERSATION_MEMBERSHIP_SEQ", "installed_rows"),
        Some(1),
        "the owner import reports one installed CONVERSATION_MEMBERSHIP_SEQ row; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        table_count(&summary, "CONVERSATION_ROLE_GRANT", "installed_rows"),
        Some(1),
        "the owner import reports one installed CONVERSATION_ROLE_GRANT row; an absent field means it installed nothing: {summary}"
    );

    let dest_ledger = dest
        .membership_ledger(room)
        .expect("read the restored ledger");
    assert_eq!(
        dest_ledger.len(),
        2,
        "the restored ledger holds exactly two rows"
    );
    assert_eq!(
        dest_ledger, source_ledger,
        "the restored ledger equals the source ledger"
    );
    assert_eq!(
        dest.members(room).expect("read the restored members"),
        source_members,
        "the restored members equal the source members"
    );
    assert_eq!(
        dest.members(room).expect("read the restored members"),
        vec![owen, yuki],
        "owen and yuki read current on the destination"
    );
    assert_admin_semantics(&dest, room, owen, yuki, "the destination");
    assert_eq!(
        dest.conversation_body(room)
            .expect("read the restored room")
            .roles
            .get(&yuki.to_hex()),
        Some(&RoomRole::Admin),
        "the restored twin entry names yuki's Admin grant"
    );
    let dest_rows = retained_rows(&export_whole(&dest));
    assert_eq!(
        rows_for(&dest_rows, "CONVERSATION_MEMBERSHIP_ROW"),
        source_row_tuples,
        "the destination archive carries the installed row tuples byte for byte"
    );
    assert_eq!(
        rows_for(&dest_rows, "CONVERSATION_MEMBERSHIP_SEQ"),
        source_seq_tuples,
        "the destination archive carries the installed seq tuple byte for byte"
    );
    assert_eq!(
        rows_for(&dest_rows, "CONVERSATION_ROLE_GRANT"),
        source_grant_tuples,
        "the destination archive carries the installed grant tuple byte for byte"
    );
}

#[test]
fn a_repeat_owner_restore_reports_the_ledger_unchanged() {
    let (_source_dir, source) = open_source_vault();
    let now = source.now_recorded_at();
    let (room, owen, yuki) = build_admin_grant_room(
        &source,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    );
    let source_ledger = source
        .membership_ledger(room)
        .expect("read the source ledger");
    let source_members = source.members(room).expect("read the source members");
    let archive = export_whole(&source);

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the first owner import succeeds");
    assert_eq!(
        dest.membership_ledger(room)
            .expect("read the restored ledger"),
        source_ledger,
        "the first restore lands the source ledger"
    );

    let repeat = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the repeat owner import succeeds");
    let repeat_summary =
        serde_json::to_value(&repeat.retained_side_rows).expect("the repeat summary serializes");
    for (table, unchanged) in [
        ("CONVERSATION_MEMBERSHIP_ROW", 2),
        ("CONVERSATION_MEMBERSHIP_SEQ", 1),
        ("CONVERSATION_ROLE_GRANT", 1),
    ] {
        assert_eq!(
            table_count(&repeat_summary, table, "unchanged_live_rows"),
            Some(unchanged),
            "the repeat owner import reports {unchanged} unchanged live {table} rows; an absent field means it counted no live outcome: {repeat_summary}"
        );
        assert_eq!(
            table_count(&repeat_summary, table, "installed_rows"),
            Some(0),
            "the repeat owner import installs no {table} row; an absent field means it counted no live outcome: {repeat_summary}"
        );
    }
    assert_eq!(
        dest.membership_ledger(room)
            .expect("read the ledger after the repeat"),
        source_ledger,
        "the repeat keeps the two-row ledger"
    );
    assert_eq!(
        dest.members(room)
            .expect("read the members after the repeat"),
        source_members,
        "the repeat keeps owen and yuki current"
    );
    assert_eq!(
        dest.members(room)
            .expect("read the members after the repeat"),
        vec![owen, yuki],
        "owen and yuki stay current after the repeat"
    );
    assert_admin_semantics(&dest, room, owen, yuki, "the destination after the repeat");
}

#[test]
fn a_member_who_left_stays_out_after_the_owner_restore() {
    let (_source_dir, source) = open_source_vault();
    let now = source.now_recorded_at();
    let (room, owen, yuki) = seat_room(
        &source,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    );
    let owner = source
        .ensure_embedded_owner_actor()
        .expect("the source names its embedded owner actor");
    source
        .leave_member(
            room,
            yuki,
            WriteActor::new(owner, EdgeActorClass::Human),
            now + 1,
        )
        .expect("yuki leaves the room");
    let source_ledger = source
        .membership_ledger(room)
        .expect("read the source ledger");
    assert_eq!(
        source_ledger.len(),
        3,
        "the source ledger holds two joins and one leave"
    );
    assert_eq!(
        source_ledger
            .iter()
            .map(|row| (row.person, row.action))
            .collect::<Vec<_>>(),
        vec![
            (owen, MembershipAction::Join),
            (yuki, MembershipAction::Join),
            (yuki, MembershipAction::Leave),
        ],
        "the source ledger joins owen and yuki, then leaves yuki"
    );
    assert_eq!(
        source.members(room).expect("read the source members"),
        vec![owen],
        "only owen reads current on the source"
    );
    let archive = export_whole(&source);
    let source_rows = retained_rows(&archive);
    let source_row_tuples = rows_for(&source_rows, "CONVERSATION_MEMBERSHIP_ROW");
    let source_seq_tuples = rows_for(&source_rows, "CONVERSATION_MEMBERSHIP_SEQ");
    assert!(
        rows_for(&source_rows, "CONVERSATION_ROLE_GRANT").is_empty(),
        "the grant-free source archive holds no role-grant tuple"
    );

    let (_dest_dir, dest) = open_later_vault();
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds into a fresh vault");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "CONVERSATION_MEMBERSHIP_ROW", "installed_rows"),
        Some(3),
        "the owner import reports three installed CONVERSATION_MEMBERSHIP_ROW rows; an absent field means it installed nothing: {summary}"
    );
    assert_eq!(
        table_count(&summary, "CONVERSATION_MEMBERSHIP_SEQ", "installed_rows"),
        Some(1),
        "the owner import reports one installed CONVERSATION_MEMBERSHIP_SEQ row; an absent field means it installed nothing: {summary}"
    );
    assert!(
        matches!(
            table_count(&summary, "CONVERSATION_ROLE_GRANT", "installed_rows"),
            None | Some(0)
        ),
        "the grant-free import installs no CONVERSATION_ROLE_GRANT row: {summary}"
    );

    let dest_ledger = dest
        .membership_ledger(room)
        .expect("read the restored ledger");
    assert_eq!(
        dest_ledger.len(),
        3,
        "the restored ledger preserves all three rows"
    );
    assert_eq!(
        dest_ledger, source_ledger,
        "the restored ledger equals the source ledger"
    );
    assert_eq!(
        dest.members(room).expect("read the restored members"),
        vec![owen],
        "only owen reads current on the destination"
    );
    assert_eq!(
        dest.conversation_body(room)
            .expect("read the restored room")
            .member_ids,
        vec![owen],
        "the restored body lists only owen"
    );
    let dest_rows = retained_rows(&export_whole(&dest));
    assert_eq!(
        rows_for(&dest_rows, "CONVERSATION_MEMBERSHIP_ROW"),
        source_row_tuples,
        "the destination archive carries the three row tuples byte for byte"
    );
    assert_eq!(
        rows_for(&dest_rows, "CONVERSATION_MEMBERSHIP_SEQ"),
        source_seq_tuples,
        "the destination archive carries the seq tuple byte for byte"
    );
}

#[test]
fn a_destination_that_seats_the_room_itself_keeps_its_own_ledger() {
    let (_source_dir, source) = open_source_vault();
    let (room, owen, yuki) =
        seat_room_with_join_at(&source, ENTITY_OCCURRED, ENTITY_LEARNED_AT, SOURCE_JOIN_AT);
    let source_ledger = source
        .membership_ledger(room)
        .expect("read the source ledger");
    assert_eq!(
        source_ledger.len(),
        2,
        "the source ledger holds two join rows"
    );
    assert!(
        source_ledger.iter().all(|row| row.at == SOURCE_JOIN_AT),
        "the source ledger joins at its own time"
    );
    let archive = export_whole(&source);
    let source_rows = retained_rows(&archive);
    let source_row_tuples = rows_for(&source_rows, "CONVERSATION_MEMBERSHIP_ROW");
    let source_seq_tuples = rows_for(&source_rows, "CONVERSATION_MEMBERSHIP_SEQ");

    let (_dest_dir, dest) = open_later_vault();
    let (dest_room, dest_owen, dest_yuki) =
        seat_room_with_join_at(&dest, ENTITY_OCCURRED, ENTITY_LEARNED_AT, DEST_JOIN_AT);
    assert_eq!(dest_room, room, "the destination seats the same room id");
    assert_eq!(dest_owen, owen, "the destination seats the same owen id");
    assert_eq!(dest_yuki, yuki, "the destination seats the same yuki id");
    let dest_pre_ledger = dest
        .membership_ledger(room)
        .expect("read the destination ledger before the import");
    assert_eq!(
        dest_pre_ledger.len(),
        2,
        "the destination ledger holds two join rows before the import"
    );
    assert!(
        dest_pre_ledger.iter().all(|row| row.at == DEST_JOIN_AT),
        "the destination ledger joins at its own later time"
    );
    assert_ne!(
        dest_pre_ledger, source_ledger,
        "the two ledgers differ by their join times before the import"
    );
    assert_eq!(
        dest.members(room).expect("read the destination members"),
        vec![owen, yuki],
        "owen and yuki read current on the destination before the import"
    );
    let dest_pre_rows = retained_rows(&export_whole(&dest));
    let dest_pre_row_tuples = rows_for(&dest_pre_rows, "CONVERSATION_MEMBERSHIP_ROW");

    // The room put meets byte-identical rows (same entity stamps, same body), so it never
    // refuses; only the ledger times differ. Keep the strong success assertion.
    let dest_owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &dest_owner)
        .expect("the owner import succeeds over byte-identical room rows");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "CONVERSATION_MEMBERSHIP_ROW", "kept_live_rows"),
        Some(2),
        "the owner import reports two kept-live CONVERSATION_MEMBERSHIP_ROW rows; an absent field means it counted no live outcome: {summary}"
    );
    assert_eq!(
        table_count(&summary, "CONVERSATION_MEMBERSHIP_ROW", "installed_rows"),
        Some(0),
        "the kept-live import installs no CONVERSATION_MEMBERSHIP_ROW row; an absent field means it counted no live outcome: {summary}"
    );
    // A differing ledger is kept as a whole, including its byte-identical row count.
    assert_eq!(
        table_count(&summary, "CONVERSATION_MEMBERSHIP_SEQ", "kept_live_rows"),
        Some(1),
        "the owner import reports one kept-live CONVERSATION_MEMBERSHIP_SEQ row: {summary}"
    );
    assert_eq!(
        table_count(&summary, "CONVERSATION_MEMBERSHIP_SEQ", "installed_rows"),
        Some(0),
        "the kept-live import installs no CONVERSATION_MEMBERSHIP_SEQ row; an absent field means it counted no live outcome: {summary}"
    );

    assert_eq!(
        dest.membership_ledger(room)
            .expect("read the destination ledger after the import"),
        dest_pre_ledger,
        "the destination keeps its own two-row ledger"
    );
    assert_ne!(
        dest.membership_ledger(room)
            .expect("read the destination ledger after the import"),
        source_ledger,
        "the destination ledger is not the source ledger"
    );
    assert_eq!(
        dest.members(room)
            .expect("read the destination members after the import"),
        vec![owen, yuki],
        "owen and yuki stay current on the destination"
    );
    let dest_post_rows = retained_rows(&export_whole(&dest));
    let dest_post_row_tuples = rows_for(&dest_post_rows, "CONVERSATION_MEMBERSHIP_ROW");
    assert_eq!(
        dest_post_row_tuples.len(),
        4,
        "the destination keeps both live and retained row values after a kept-live import"
    );
    assert!(
        dest_post_row_tuples.contains(&source_row_tuples[0])
            && dest_post_row_tuples.contains(&source_row_tuples[1])
            && dest_post_row_tuples.contains(&dest_pre_row_tuples[0])
            && dest_post_row_tuples.contains(&dest_pre_row_tuples[1]),
        "the destination archive holds its live tuples and the retained source tuples byte for byte"
    );
    assert_eq!(
        rows_for(&dest_post_rows, "CONVERSATION_MEMBERSHIP_SEQ"),
        source_seq_tuples,
        "the seq tuple stays byte-identical after a kept-live import"
    );
}

/// A source vault opened as the owner's own where Oneiron hosts the bytes, so a privacy erase
/// that a standing customer hold refuses keeps its record use-limited.
fn open_hosted_source_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir for the hosted source vault");
    let mut config = VaultConfig::default();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let vault = Vault::open_owned(dir.path(), config).expect("open the hosted source vault");
    (dir, vault)
}

/// Places a customer hold on `record` and runs its privacy erase, which the hold refuses: the
/// record stays stored and use-limited, and a whole-vault export keeps it out.
fn use_limit(vault: &Vault, record: EntityId) {
    let hold = vault
        .place_legal_hold(
            &owner_proof(vault),
            vec![LegalHoldTarget::Record(record)],
            Some("matter-9446".to_owned()),
        )
        .expect("FIXTURE: place the customer hold");
    assert!(hold.stands(), "FIXTURE: the customer hold stands: {hold:?}");
    let actor = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault names its embedded owner actor");
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let preview = memory
        .preview_entity_delete(&record)
        .expect("FIXTURE: preview the privacy erase");
    let outcome = memory
        .confirm_entity_erase(
            &preview,
            EraseOptions {
                reason: EraseReason::GdprDelete,
                also_same_bytes: false,
                veto_starter: None,
            },
        )
        .expect("FIXTURE: the privacy erase runs");
    assert_eq!(
        outcome.first.reason.as_str(),
        "privacy_erase_kept",
        "FIXTURE: the held privacy erase is kept: {outcome:?}"
    );
    assert!(
        vault
            .legal_hold_use_limit(&record)
            .expect("FIXTURE: read the use limit")
            .is_some(),
        "FIXTURE: the kept erase use-limits the record"
    );
}

/// The retained tuples of `table` in `rows` whose source key starts with `room`.
fn room_tuples(rows: &[(String, Vec<u8>, Vec<u8>)], table: &str, room: EntityId) -> usize {
    rows_for(rows, table)
        .iter()
        .filter(|(_, key, _)| key.starts_with(room.as_bytes()))
        .count()
}

/// The `held_back` entries for `table` in a `retained_side_rows` JSON summary, as (reason,
/// rows); empty when the table entry or the list is absent.
fn held_back(summary: &serde_json::Value, table: &str) -> Vec<(String, u64)> {
    summary
        .get("tables")
        .and_then(|tables| tables.as_array())
        .and_then(|tables| {
            tables.iter().find(|entry| {
                entry.get("source_table").and_then(|name| name.as_str()) == Some(table)
            })
        })
        .and_then(|entry| entry.get("held_back"))
        .and_then(|held| held.as_array())
        .map(|held| {
            held.iter()
                .map(|count| {
                    (
                        count
                            .get("reason")
                            .and_then(|reason| reason.as_str())
                            .unwrap_or_default()
                            .to_owned(),
                        count
                            .get("rows")
                            .and_then(|rows| rows.as_u64())
                            .unwrap_or_default(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The reason the receipt's `destination_omissions` gives for `id`, by its debug name.
fn omission_reason(receipt: &WholeVaultImportReceipt, id: EntityId) -> Option<String> {
    receipt
        .destination_omissions
        .iter()
        .find(|kept| kept.entity_id == id.to_hex())
        .map(|kept| format!("{:?}", kept.reason))
}

fn stored(vault: &Vault, id: EntityId) -> bool {
    vault
        .get_entity_type(&id)
        .expect("read the destination row")
        .is_some()
}

/// Every delete signs as this install.
fn install_keystore(vault: &Vault) {
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
}

/// Whether whole-vault `archive` carries a record of `id`, read through `reader`.
fn archive_carries(reader: &Vault, archive: &[u8], id: EntityId) -> bool {
    reader
        .read_whole_vault_archive(archive)
        .expect("read the archive")
        .evidence_ledger
        .entities
        .iter()
        .any(|entity| entity.id == id.to_hex())
}

/// `room` stayed archive data on `dest`: no row and no ledger row of it, named under
/// `RoomNotSeatedHere` in `receipt`, and none of its ledger envelopes installed.
fn assert_room_kept_out(
    dest: &Vault,
    receipt: &WholeVaultImportReceipt,
    room: EntityId,
    side: &str,
) {
    assert!(!stored(dest, room), "the room stays archive data on {side}");
    assert_eq!(
        omission_reason(receipt, room).as_deref(),
        Some("RoomNotSeatedHere"),
        "the receipt names the room kept out on {side}: {:?}",
        receipt.destination_omissions
    );
    assert!(
        dest.membership_ledger(room).unwrap_or_default().is_empty(),
        "no ledger row of the room lands on {side}"
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    for table in ["CONVERSATION_MEMBERSHIP_ROW", "CONVERSATION_MEMBERSHIP_SEQ"] {
        assert_eq!(
            table_count(&summary, table, "installed_rows").unwrap_or_default(),
            0,
            "no {table} row installs on {side}: {summary}"
        );
    }
}

#[test]
fn a_whole_vault_export_withholds_the_ledger_and_roles_of_a_use_limited_room() {
    let (_source_dir, source) = open_hosted_source_vault();
    let now = source.now_recorded_at();
    let (room, _owen, _yuki) = build_admin_grant_room(
        &source,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    );
    let tables = [
        ("CONVERSATION_MEMBERSHIP_ROW", 2),
        ("CONVERSATION_MEMBERSHIP_SEQ", 1),
        ("CONVERSATION_ROLE_GRANT", 1),
    ];
    let before = retained_rows(&export_whole(&source));
    for (table, rows) in tables {
        assert_eq!(
            room_tuples(&before, table, room),
            rows,
            "FIXTURE: before the hold the archive carries the room's {table} rows"
        );
    }

    use_limit(&source, room);
    let after = retained_rows(&export_whole(&source));
    for (table, _) in tables {
        assert_eq!(
            room_tuples(&after, table, room),
            0,
            "LEAK: the archive carries no {table} row of the use-limited room"
        );
    }
}

#[test]
fn a_room_whose_member_is_no_live_person_here_stays_out_of_the_owner_restore() {
    let (_source_dir, source) = open_source_vault();
    let now = source.now_recorded_at();
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    let (room, owen, yuki) = seat_room(&source, occurred, now);
    install_keystore(&source);
    assert!(
        source
            .delete_entity(&yuki)
            .expect("FIXTURE: user-delete yuki on the source"),
        "FIXTURE: yuki existed on the source"
    );
    let archive = export_whole(&source);
    assert_eq!(
        room_tuples(
            &retained_rows(&archive),
            "CONVERSATION_MEMBERSHIP_ROW",
            room
        ),
        2,
        "FIXTURE: the archive carries the room's two ledger rows"
    );

    let (_absent_dir, absent) = open_later_vault();
    let receipt = absent
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner_proof(&absent))
        .expect("the owner restore into a vault without yuki goes on past the room");
    assert!(
        !stored(&absent, yuki),
        "FIXTURE: the archive carries no record of the deleted yuki"
    );
    assert_room_kept_out(&absent, &receipt, room, "a destination without yuki");
    assert!(
        stored(&absent, owen),
        "owen lands on a destination without yuki"
    );

    let (_shell_dir, shell) = open_later_vault();
    put_person_at(&shell, yuki, b"yuki", occurred, now);
    install_keystore(&shell);
    assert!(
        shell
            .delete_entity(&yuki)
            .expect("FIXTURE: soft-delete yuki on the destination"),
        "FIXTURE: the destination holds yuki's soft-deleted shell"
    );
    let receipt = shell
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner_proof(&shell))
        .expect("the owner restore into a vault with yuki's shell goes on past the room");
    assert_room_kept_out(
        &shell,
        &receipt,
        room,
        "a destination with yuki's deleted shell",
    );
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    for (table, rows) in [
        ("CONVERSATION_MEMBERSHIP_ROW", 2),
        ("CONVERSATION_MEMBERSHIP_SEQ", 1),
    ] {
        assert_eq!(
            held_back(&summary, table),
            vec![("missing_live_entity".to_owned(), rows)],
            "the {table} envelopes are held back with the room: {summary}"
        );
    }
    assert!(
        stored(&shell, owen),
        "owen lands on a destination with yuki's shell"
    );
}

#[test]
fn an_incomplete_room_ledger_keeps_the_room_out_of_the_owner_restore() {
    let (_source_dir, source) = open_source_vault();
    let now = source.now_recorded_at();
    let (room, owen, yuki) = seat_room(
        &source,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    );
    archive_room_ledger::drop_room_ledger_sequence(&source, room)
        .expect("FIXTURE: drop the source ledger's revision row");
    let archive = export_whole(&source);
    let rows = retained_rows(&archive);
    assert_eq!(
        room_tuples(&rows, "CONVERSATION_MEMBERSHIP_ROW", room),
        2,
        "FIXTURE: the archive carries the room's two ledger rows"
    );
    assert_eq!(
        room_tuples(&rows, "CONVERSATION_MEMBERSHIP_SEQ", room),
        0,
        "FIXTURE: the archive carries no revision row for the room"
    );

    let (_dest_dir, dest) = open_later_vault();
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner_proof(&dest))
        .expect("the owner restore goes on past a room whose ledger is incomplete");
    assert_room_kept_out(&dest, &receipt, room, "the destination");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        held_back(&summary, "CONVERSATION_MEMBERSHIP_ROW"),
        vec![("missing_companion".to_owned(), 2)],
        "the two ledger rows are held back for their missing revision: {summary}"
    );
    assert!(
        stored(&dest, owen) && stored(&dest, yuki),
        "owen and yuki still land"
    );
}

#[test]
fn a_join_visible_after_its_time_keeps_the_room_out_of_the_owner_restore() {
    let (_source_dir, source) = open_source_vault();
    let now = source.now_recorded_at();
    let (room, owen, yuki) = seat_room(
        &source,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    );
    let joined = source
        .membership_ledger(room)
        .expect("FIXTURE: read the source ledger");
    assert_eq!(
        (joined[0].action, joined[0].person),
        (MembershipAction::Join, owen),
        "FIXTURE: row 0 is owen's Join"
    );
    archive_room_ledger::set_room_ledger_row_visible_from(
        &source,
        room,
        0,
        Some(joined[0].at + 10),
    )
    .expect("FIXTURE: open owen's window after his join");
    let archive = export_whole(&source);
    assert_eq!(
        room_tuples(
            &retained_rows(&archive),
            "CONVERSATION_MEMBERSHIP_ROW",
            room
        ),
        2,
        "FIXTURE: the archive carries the room's two ledger rows"
    );

    let (_dest_dir, dest) = open_later_vault();
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner_proof(&dest))
        .expect("the owner restore goes on past a room whose Join the door forbids");
    assert_room_kept_out(&dest, &receipt, room, "the destination");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    for (table, rows) in [
        ("CONVERSATION_MEMBERSHIP_ROW", 2),
        ("CONVERSATION_MEMBERSHIP_SEQ", 1),
    ] {
        assert_eq!(
            held_back(&summary, table),
            vec![("invalid_value".to_owned(), rows)],
            "the {table} envelopes are held back as an invalid ledger: {summary}"
        );
    }
    assert!(
        stored(&dest, owen) && stored(&dest, yuki),
        "owen and yuki still land"
    );
}

#[test]
fn a_whole_vault_export_withholds_the_ledger_of_a_deleted_room() {
    let (_source_dir, source) = open_source_vault();
    let now = source.now_recorded_at();
    let (room, _owen, _yuki) = seat_room(
        &source,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    );
    let tables = [
        ("CONVERSATION_MEMBERSHIP_ROW", 2),
        ("CONVERSATION_MEMBERSHIP_SEQ", 1),
    ];
    let before = export_whole(&source);
    for (table, rows) in tables {
        assert_eq!(
            room_tuples(&retained_rows(&before), table, room),
            rows,
            "FIXTURE: before the delete the archive carries the room's {table} rows"
        );
    }
    // The actorless import keeps every archived ledger envelope as an inert copy beside
    // the live ledger, so both export loops meet the room.
    let receipt = source
        .import_whole_vault_archive_from(Cursor::new(&before))
        .expect("FIXTURE: the actorless import of the source's own archive succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    for (table, rows) in tables {
        assert_eq!(
            table_count(&summary, table, "inserted_rows"),
            Some(rows as u64),
            "FIXTURE: the source keeps an inert copy of each {table} envelope: {summary}"
        );
    }

    install_keystore(&source);
    assert!(
        source
            .delete_entity(&room)
            .expect("FIXTURE: user-delete the room"),
        "FIXTURE: the room existed before its delete"
    );
    assert!(
        source
            .is_deleted_shell(&room)
            .expect("FIXTURE: read the room's shell"),
        "FIXTURE: a user delete keeps the room's shell and its ledger"
    );
    let after = export_whole(&source);
    assert!(
        !archive_carries(&source, &after, room),
        "FIXTURE: the archive carries no record of the deleted room"
    );
    for (table, _) in tables {
        assert_eq!(
            room_tuples(&retained_rows(&after), table, room),
            0,
            "LEAK: the archive carries no live or inert {table} row of the deleted room"
        );
    }
}

#[test]
fn a_whole_vault_export_withholds_a_ledger_that_names_a_use_limited_member() {
    let (_source_dir, source) = open_hosted_source_vault();
    let now = source.now_recorded_at();
    let (room, owen, yuki) = seat_room(
        &source,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    );
    let owner = source
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the source names its embedded owner actor");
    source
        .leave_member(
            room,
            yuki,
            WriteActor::new(owner, EdgeActorClass::Human),
            now + 1,
        )
        .expect("FIXTURE: yuki leaves the room");
    assert_eq!(
        source.members(room).expect("FIXTURE: read the members"),
        vec![owen],
        "FIXTURE: only owen is a current member"
    );
    let tables = [
        ("CONVERSATION_MEMBERSHIP_ROW", 3),
        ("CONVERSATION_MEMBERSHIP_SEQ", 1),
    ];
    let before = retained_rows(&export_whole(&source));
    for (table, rows) in tables {
        assert_eq!(
            room_tuples(&before, table, room),
            rows,
            "FIXTURE: before the hold the archive carries the room's {table} rows"
        );
    }

    use_limit(&source, yuki);
    let archive = export_whole(&source);
    assert!(
        archive_carries(&source, &archive, room),
        "FIXTURE: the archive still carries the unrestricted room"
    );
    assert!(
        !archive_carries(&source, &archive, yuki),
        "FIXTURE: the archive carries no record of the use-limited yuki"
    );
    for (table, _) in tables {
        assert_eq!(
            room_tuples(&retained_rows(&archive), table, room),
            0,
            "LEAK: the archive carries no {table} row of a ledger naming the use-limited yuki"
        );
    }
}

#[test]
fn an_identical_ledger_of_a_deleted_room_is_held_back_not_unchanged() {
    let (_source_dir, source) = open_source_vault();
    let now = source.now_recorded_at();
    let (room, _owen, _yuki) = seat_room(
        &source,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    );
    let source_rows = retained_rows(&export_whole(&source));
    let (_carrier_dir, carrier) = open_later_vault();
    archive_room_ledger::copy_room_ledger(&source, &carrier, room)
        .expect("FIXTURE: copy the room's ledger into the carrier");
    let archive = export_whole(&carrier);
    assert!(
        !archive_carries(&carrier, &archive, room),
        "FIXTURE: the carrier's archive carries no room record"
    );
    let carried = retained_rows(&archive);
    for (table, rows) in [
        ("CONVERSATION_MEMBERSHIP_ROW", 2),
        ("CONVERSATION_MEMBERSHIP_SEQ", 1),
    ] {
        let room_rows = |rows: &[(String, Vec<u8>, Vec<u8>)]| {
            rows_for(rows, table)
                .into_iter()
                .filter(|(_, key, _)| key.starts_with(room.as_bytes()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            room_rows(&carried).len(),
            rows,
            "FIXTURE: the carrier's archive carries the room's {table} rows"
        );
        assert_eq!(
            room_rows(&carried),
            room_rows(&source_rows),
            "FIXTURE: the carried {table} rows are the source's byte for byte"
        );
    }

    install_keystore(&source);
    assert!(
        source
            .delete_entity(&room)
            .expect("FIXTURE: user-delete the room"),
        "FIXTURE: the room existed before its delete"
    );
    for pass in ["first", "repeat"] {
        let receipt = source
            .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner_proof(&source))
            .unwrap_or_else(|err| panic!("the {pass} owner restore succeeds: {err:?}"));
        let summary =
            serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
        for (table, rows) in [
            ("CONVERSATION_MEMBERSHIP_ROW", 2),
            ("CONVERSATION_MEMBERSHIP_SEQ", 1),
        ] {
            assert_eq!(
                held_back(&summary, table),
                vec![("missing_live_entity".to_owned(), rows)],
                "the {pass} restore holds back the deleted room's {table} envelopes: {summary}"
            );
            assert_eq!(
                table_count(&summary, table, "unchanged_live_rows").unwrap_or_default(),
                0,
                "the {pass} restore counts no {table} row unchanged live: {summary}"
            );
            if pass == "repeat" {
                assert_eq!(
                    table_count(&summary, table, "unchanged_rows"),
                    Some(rows),
                    "the repeat finds the inert {table} copies the first restore kept: {summary}"
                );
            }
        }
        assert!(
            source
                .is_deleted_shell(&room)
                .expect("read the room's shell"),
            "the room stays a deleted shell after the {pass} restore"
        );
    }
}

#[test]
fn an_intermediate_join_window_keeps_the_room_out_of_the_owner_restore() {
    let (_source_dir, source) = open_source_vault();
    let now = source.now_recorded_at();
    let (room, owen, yuki) = seat_room_with_join_at(
        &source,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        now + 20,
    );
    let joined = source
        .membership_ledger(room)
        .expect("FIXTURE: read the source ledger");
    assert_eq!(
        (
            joined[0].action,
            joined[0].person,
            joined[0].visible_from,
            joined[0].handoff.is_none()
        ),
        (MembershipAction::Join, owen, Some(0), true),
        "FIXTURE: row 0 is owen's plain Join, visible from the room's origin"
    );
    archive_room_ledger::set_room_ledger_row_visible_from(&source, room, 0, Some(now + 10))
        .expect("FIXTURE: open owen's window between the origin and his join");
    let archive = export_whole(&source);
    assert_eq!(
        room_tuples(
            &retained_rows(&archive),
            "CONVERSATION_MEMBERSHIP_ROW",
            room
        ),
        2,
        "FIXTURE: the archive carries the room's two ledger rows"
    );

    let (_dest_dir, dest) = open_later_vault();
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner_proof(&dest))
        .expect("the owner restore goes on past a room whose Join no door wrote");
    assert_room_kept_out(&dest, &receipt, room, "the destination");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    for (table, rows) in [
        ("CONVERSATION_MEMBERSHIP_ROW", 2),
        ("CONVERSATION_MEMBERSHIP_SEQ", 1),
    ] {
        assert_eq!(
            held_back(&summary, table),
            vec![("invalid_value".to_owned(), rows)],
            "the {table} envelopes are held back as an invalid ledger: {summary}"
        );
    }
    assert!(
        stored(&dest, owen) && stored(&dest, yuki),
        "owen and yuki still land"
    );
}

#[test]
fn an_unbound_leader_chat_stays_out_of_the_owner_restore() {
    let (_source_dir, source) = open_source_vault();
    let now = source.now_recorded_at();
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    let chat = fixed_id(0x6E);
    let owen = fixed_id(0x6C);
    let yuki = fixed_id(0x6D);
    put_person_at(&source, owen, b"owen", occurred, now);
    put_person_at(&source, yuki, b"yuki", occurred, now);
    let owner = source
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the source names its embedded owner actor");
    archive_room_ledger::open_bound_leader_chat(
        &source,
        chat,
        [fixed_id(0x6F), fixed_id(0x70)],
        [owen, yuki],
        WriteActor::new(owner, EdgeActorClass::Human),
        now,
    )
    .expect("FIXTURE: the source opens the leader chat");
    assert_eq!(
        source
            .members(chat)
            .expect("FIXTURE: read the members")
            .into_iter()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([owen, yuki]),
        "FIXTURE: the leader chat seats owen and yuki"
    );
    let archive = export_whole(&source);
    assert!(
        archive_carries(&source, &archive, chat),
        "FIXTURE: the archive carries the leader chat room"
    );
    assert_eq!(
        room_tuples(
            &retained_rows(&archive),
            "CONVERSATION_MEMBERSHIP_ROW",
            chat
        ),
        2,
        "FIXTURE: the archive carries the chat's two ledger rows"
    );

    let (_dest_dir, dest) = open_later_vault();
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner_proof(&dest))
        .expect("the owner restore goes on past a leader chat this vault never bound");
    assert_room_kept_out(&dest, &receipt, chat, "the destination");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    for (table, rows) in [
        ("CONVERSATION_MEMBERSHIP_ROW", 2),
        ("CONVERSATION_MEMBERSHIP_SEQ", 1),
    ] {
        assert_eq!(
            held_back(&summary, table),
            vec![("missing_live_entity".to_owned(), rows)],
            "the chat's {table} envelopes are held back with the room: {summary}"
        );
    }
    assert!(
        stored(&dest, owen) && stored(&dest, yuki),
        "owen and yuki still land"
    );
}

#[test]
fn a_whole_vault_export_withholds_the_role_grant_of_a_deleted_room() {
    let (_source_dir, source) = open_source_vault();
    let now = source.now_recorded_at();
    let (room, _owen, _yuki) = build_admin_grant_room(
        &source,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    );
    let before = export_whole(&source);
    assert_eq!(
        room_tuples(&retained_rows(&before), "CONVERSATION_ROLE_GRANT", room),
        1,
        "FIXTURE: before the delete the archive carries yuki's role grant"
    );
    // The actorless import keeps the archived grant as an inert copy beside the live grant,
    // so both export loops meet it.
    let receipt = source
        .import_whole_vault_archive_from(Cursor::new(&before))
        .expect("FIXTURE: the actorless import of the source's own archive succeeds");
    let summary =
        serde_json::to_value(&receipt.retained_side_rows).expect("the summary serializes");
    assert_eq!(
        table_count(&summary, "CONVERSATION_ROLE_GRANT", "inserted_rows"),
        Some(1),
        "FIXTURE: the source keeps an inert copy of the grant envelope: {summary}"
    );

    install_keystore(&source);
    assert!(
        source
            .delete_entity(&room)
            .expect("FIXTURE: user-delete the room"),
        "FIXTURE: the room existed before its delete"
    );
    let after = export_whole(&source);
    assert!(
        !archive_carries(&source, &after, room),
        "FIXTURE: the archive carries no record of the deleted room"
    );
    assert_eq!(
        room_tuples(&retained_rows(&after), "CONVERSATION_ROLE_GRANT", room),
        0,
        "LEAK: the archive carries no live or inert role grant of the deleted room"
    );
}

#[test]
fn a_whole_vault_export_withholds_the_role_grant_of_a_use_limited_grantee() {
    let (_source_dir, source) = open_hosted_source_vault();
    let now = source.now_recorded_at();
    let (room, _owen, yuki) = build_admin_grant_room(
        &source,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    );
    assert_eq!(
        room_tuples(
            &retained_rows(&export_whole(&source)),
            "CONVERSATION_ROLE_GRANT",
            room
        ),
        1,
        "FIXTURE: before the hold the archive carries yuki's role grant"
    );

    use_limit(&source, yuki);
    let archive = export_whole(&source);
    assert!(
        archive_carries(&source, &archive, room),
        "FIXTURE: the archive still carries the unrestricted room"
    );
    assert!(
        !archive_carries(&source, &archive, yuki),
        "FIXTURE: the archive carries no record of the use-limited yuki"
    );
    assert_eq!(
        room_tuples(&retained_rows(&archive), "CONVERSATION_ROLE_GRANT", room),
        0,
        "LEAK: the archive carries no role grant naming the use-limited yuki"
    );
}

#[test]
fn a_malformed_inert_ledger_copy_is_withheld_alone() {
    let (_source_dir, source) = open_source_vault();
    let now = source.now_recorded_at();
    let (room, _owen, _yuki) = seat_room(
        &source,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    );
    let before = retained_rows(&export_whole(&source));
    let live_row = |table: &str| {
        rows_for(&before, table)
            .into_iter()
            .find(|(_, key, _)| key.starts_with(room.as_bytes()))
            .unwrap_or_else(|| panic!("FIXTURE: the archive carries a {table} row of the room"))
    };
    let (_, sequence_key, sequence_value) = live_row("CONVERSATION_MEMBERSHIP_SEQ");
    let (_, row_key, _) = live_row("CONVERSATION_MEMBERSHIP_ROW");
    let mut long_key = sequence_key.clone();
    long_key.push(0);
    archive_room_ledger::retain_inert_side_row(
        &source,
        "CONVERSATION_MEMBERSHIP_SEQ",
        long_key,
        sequence_value,
    )
    .expect("FIXTURE: keep an inert revision copy whose key is one byte too long");
    archive_room_ledger::retain_inert_side_row(
        &source,
        "CONVERSATION_MEMBERSHIP_ROW",
        row_key,
        b"no ledger row".to_vec(),
    )
    .expect("FIXTURE: keep an inert ledger row copy whose value reads as no ledger row");

    let after = retained_rows(&export_whole(&source));
    for (table, rows) in [
        ("CONVERSATION_MEMBERSHIP_ROW", 2),
        ("CONVERSATION_MEMBERSHIP_SEQ", 1),
    ] {
        assert_eq!(
            room_tuples(&after, table, room),
            rows,
            "the export carries the room's live {table} rows and no malformed copy"
        );
    }
}

/// `bytes` with every run of `from` replaced by `to`, of the same length.
fn replace_bytes(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let mut at = 0;
    while let Some(found) = out[at..].windows(from.len()).position(|run| run == from) {
        out[at + found..at + found + from.len()].copy_from_slice(to);
        at += found + from.len();
    }
    out
}

#[test]
fn an_inert_ledger_copy_naming_a_use_limited_person_is_withheld_alone() {
    let (_source_dir, source) = open_hosted_source_vault();
    let now = source.now_recorded_at();
    let at = TimeRange {
        start: now,
        end: now,
    };
    let (room, _owen, yuki) = seat_room(&source, at, now);
    let held = fixed_id(0x5C);
    put_person_at(&source, held, b"held", at, now);
    let before = retained_rows(&export_whole(&source));
    let yuki_hex = yuki.to_hex();
    let (_, row_key, row_value) = rows_for(&before, "CONVERSATION_MEMBERSHIP_ROW")
        .into_iter()
        .find(|(_, key, value)| {
            key.starts_with(room.as_bytes())
                && value
                    .windows(yuki_hex.len())
                    .any(|run| run == yuki_hex.as_bytes())
        })
        .expect("FIXTURE: the archive carries yuki's ledger row of the room");
    let copy = replace_bytes(&row_value, yuki_hex.as_bytes(), held.to_hex().as_bytes());
    assert_ne!(
        copy, row_value,
        "FIXTURE: the copy names held in yuki's place"
    );
    archive_room_ledger::retain_inert_side_row(
        &source,
        "CONVERSATION_MEMBERSHIP_ROW",
        row_key,
        copy,
    )
    .expect("FIXTURE: keep an inert ledger row copy that names held");

    use_limit(&source, held);
    let after = retained_rows(&export_whole(&source));
    for (table, rows) in [
        ("CONVERSATION_MEMBERSHIP_ROW", 2),
        ("CONVERSATION_MEMBERSHIP_SEQ", 1),
    ] {
        assert_eq!(
            room_tuples(&after, table, room),
            rows,
            "the export carries the room's live {table} rows and no copy naming the held person"
        );
    }
}
