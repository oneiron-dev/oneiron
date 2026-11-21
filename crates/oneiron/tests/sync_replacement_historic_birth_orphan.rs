//! A legitimate full-history window snapshot can fail replacement
//! admission after a hard delete (SYNC-REPLACEMENT-HISTORIC-BIRTH-ORPHAN).
//!
//! A hard delete takes a row's entity carrier and its `row_births` carrier
//! out of the live maps, but a full-history snapshot still holds the birth
//! insertion that was written while the row lived. Window admission judges
//! every retained birth insertion, so it must judge that insertion against
//! a state that carried the row (the range's starting state or an entity
//! insertion in the range), not only against the final map the delete
//! emptied. That excuse reaches only a birth the final state no longer
//! carries: a birth still live at the end must find its row live beside
//! it, because a live birth carrier waits to be stamped when its row
//! lands. A birth whose owner no inspected state carries, and a birth
//! that does not decode, are still refused. For an update the starting
//! state is the state at the range's start, so the same bytes keep their
//! verdict after they have been imported, and after a concurrent local
//! delete of the row they birth and delete.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test sync_replacement_historic_birth_orphan`
#![cfg(feature = "sync")]

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, ExportMode, LoroDoc, LoroValue, VersionVector};
use oneiron::EntityId;
use oneiron::provenance::birth::RowBirth;
use oneiron::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::validate_window_update_locality;
use oneiron::write_envelope::provenance::made_by::{MadeBy, MadeByClass, MadeByProcess};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const WINDOW: &str = "2026-03";

fn window_doc(peer_id: u64) -> TestResult<LoroDoc> {
    let key = WindowKey::new(WINDOW);
    let doc = create_window_doc("fixture", &key);
    doc.set_peer_id(peer_id)?;
    Ok(doc)
}

fn window_at() -> TestResult<u64> {
    let key = WindowKey::new(WINDOW);
    Ok(key.start_timestamp().ok_or("window start")? + 60)
}

/// An entity row from literal parts: type u8, then occurred start and end,
/// learned-at and row version, each a big-endian u64, then the body.
fn entity_blob(at: u64, body: &[u8]) -> Vec<u8> {
    let mut blob = vec![ENTITY_TYPE_BLOB_ARTIFACT];
    for part in [at, at, at, 0] {
        blob.extend_from_slice(&part.to_be_bytes());
    }
    blob.extend_from_slice(body);
    blob
}

/// One canonical row birth envelope, as the `row_births` map carries it.
fn birth_bytes() -> Vec<u8> {
    let birth = RowBirth {
        made_by: MadeBy {
            inputs: Vec::new(),
            process: MadeByProcess {
                actor: EntityId::now(),
                class: MadeByClass::Stated,
                identity: "historic-birth-fixture".to_owned(),
                version: "1".to_owned(),
                params_hash: "0".repeat(64),
            },
            at: 1,
            trigger: None,
        },
        content_hash: String::new(),
        withheld: Vec::new(),
        room_evidence: None,
    };
    rmp_serde::to_vec_named(&birth).expect("a row birth encodes")
}

fn insert_bytes(doc: &LoroDoc, map: &str, key: &str, bytes: &[u8]) -> TestResult {
    doc.get_map(map).insert(key, bytes)?;
    doc.commit();
    Ok(())
}

fn delete_key(doc: &LoroDoc, map: &str, key: &str) -> TestResult {
    doc.get_map(map).delete(key)?;
    doc.commit();
    Ok(())
}

/// One row in `doc` with its birth beside it, as a mirrored window holds it.
fn put_born_row(doc: &LoroDoc, owner: &EntityId, at: u64, birth: &[u8]) -> TestResult {
    insert_bytes(
        doc,
        "entities",
        &owner.to_hex(),
        &entity_blob(at, b"artifact row"),
    )?;
    insert_bytes(doc, "row_births", &owner.to_hex(), birth)
}

/// The live-map part of a hard delete: the row's entity carrier and its
/// birth carrier both leave, and the insertions stay in the history.
fn delete_born_row(doc: &LoroDoc, owner: &EntityId) -> TestResult {
    delete_key(doc, "entities", &owner.to_hex())?;
    delete_key(doc, "row_births", &owner.to_hex())
}

fn carries(doc: &LoroDoc, map: &str, owner: &EntityId) -> bool {
    doc.get_map(map).get(&owner.to_hex()).is_some()
}

/// Whether `doc`'s retained history inserts `birth` for `owner`.
fn birth_inserted_in_history(doc: &LoroDoc, owner: &EntityId, birth: &[u8]) -> bool {
    let births = ContainerID::new_root("row_births", ContainerType::Map);
    doc.export_json_updates(&VersionVector::default(), &doc.oplog_vv())
        .changes
        .into_iter()
        .flat_map(|change| change.ops)
        .filter(|op| op.container == births)
        .any(|op| {
            matches!(
                op.content,
                JsonOpContent::Map(MapOp::Insert {
                    key,
                    value: LoroValue::Binary(bytes),
                }) if key == owner.to_hex() && bytes.as_slice() == birth
            )
        })
}

/// The row's scenario in its smallest form: a full snapshot retains the
/// birth insertion of a row it later deletes, beside a row that stays live.
#[test]
fn a_full_history_snapshot_that_deletes_a_born_row_passes_admission() -> TestResult {
    let source = window_doc(1)?;
    let receiver = window_doc(2)?;
    let at = window_at()?;
    let owner = EntityId::now();
    let survivor = EntityId::now();
    let birth = birth_bytes();
    put_born_row(&source, &owner, at, &birth)?;
    put_born_row(&source, &survivor, at, &birth_bytes())?;
    delete_born_row(&source, &owner)?;
    assert!(
        !carries(&source, "entities", &owner) && !carries(&source, "row_births", &owner),
        "FIXTURE: the delete took the row and its birth out of the live maps"
    );
    assert!(
        carries(&source, "entities", &survivor),
        "FIXTURE: the other row stays live"
    );

    let snapshot = source.export(ExportMode::Snapshot)?;
    let shown = LoroDoc::from_snapshot(&snapshot)?;
    assert!(
        !carries(&shown, "entities", &owner),
        "FIXTURE: the snapshot's latest state does not carry the deleted row"
    );
    assert!(
        birth_inserted_in_history(&shown, &owner, &birth),
        "FIXTURE: the snapshot's history retains the birth insertion"
    );

    let result = validate_window_update_locality(&receiver, &snapshot);
    assert!(
        result.is_ok(),
        "a full-history snapshot whose only orphan is a deleted row's earlier \
         birth must pass admission: {result:?}"
    );
    Ok(())
}

/// The same delete in a shallow snapshot rooted while the row lived but
/// before its birth was inserted: the row is in the root state, and the
/// birth insertion and the delete are the retained operations past it.
#[test]
fn a_shallow_snapshot_rooted_before_a_born_rows_delete_passes_admission() -> TestResult {
    let source = window_doc(1)?;
    let receiver = window_doc(2)?;
    let at = window_at()?;
    let owner = EntityId::now();
    insert_bytes(
        &source,
        "entities",
        &owner.to_hex(),
        &entity_blob(at, b"artifact row"),
    )?;
    let root = source.oplog_frontiers();
    insert_bytes(&source, "row_births", &owner.to_hex(), &birth_bytes())?;
    delete_born_row(&source, &owner)?;

    let snapshot = source.export(ExportMode::shallow_snapshot(&root))?;
    let shown = LoroDoc::from_snapshot(&snapshot)?;
    assert!(shown.is_shallow(), "FIXTURE: the snapshot is shallow");
    assert!(
        !carries(&shown, "entities", &owner),
        "FIXTURE: the snapshot's latest state does not carry the deleted row"
    );

    let result = validate_window_update_locality(&receiver, &snapshot);
    assert!(
        result.is_ok(),
        "a birth inserted past a root that carries its row, and deleted after \
         it, must pass admission: {result:?}"
    );
    Ok(())
}

/// The same shape as an ordinary update: the receiver already holds the
/// row, and the update range carries its birth insertion and then its
/// delete, so no entity insertion in the range evidences the owner.
#[test]
fn an_update_that_births_then_deletes_a_held_row_passes_admission() -> TestResult {
    let source = window_doc(1)?;
    let receiver = window_doc(2)?;
    let at = window_at()?;
    let owner = EntityId::now();
    insert_bytes(
        &source,
        "entities",
        &owner.to_hex(),
        &entity_blob(at, b"artifact row"),
    )?;
    receiver.import(&source.export(ExportMode::all_updates())?)?;
    assert!(
        carries(&receiver, "entities", &owner),
        "FIXTURE: the receiver already holds the row"
    );
    let before = receiver.oplog_vv();
    insert_bytes(&source, "row_births", &owner.to_hex(), &birth_bytes())?;
    delete_born_row(&source, &owner)?;

    let update = source.export(ExportMode::updates(&before))?;
    let result = validate_window_update_locality(&receiver, &update);
    assert!(
        result.is_ok(),
        "an update that births a held row and then deletes it must pass \
         admission: {result:?}"
    );
    Ok(())
}

/// Birth admission is not disabled: a birth for a row no inspected state
/// carries is still refused.
#[test]
fn a_birth_for_a_row_the_sender_never_carried_is_still_refused() -> TestResult {
    let source = window_doc(1)?;
    let receiver = window_doc(2)?;
    let owner = EntityId::now();
    insert_bytes(&source, "row_births", &owner.to_hex(), &birth_bytes())?;

    let snapshot = source.export(ExportMode::Snapshot)?;
    let result = validate_window_update_locality(&receiver, &snapshot);
    assert!(
        result.is_err(),
        "a birth whose row the sender never carried must be refused: {result:?}"
    );
    Ok(())
}

/// And its envelope is still checked: a deleted row's birth insertion
/// passes only when the birth itself is a canonical envelope.
#[test]
fn a_malformed_birth_for_a_deleted_row_is_still_refused() -> TestResult {
    let source = window_doc(1)?;
    let receiver = window_doc(2)?;
    let at = window_at()?;
    let owner = EntityId::now();
    put_born_row(&source, &owner, at, b"not a canonical row birth")?;
    delete_born_row(&source, &owner)?;

    let snapshot = source.export(ExportMode::Snapshot)?;
    let result = validate_window_update_locality(&receiver, &snapshot);
    assert!(
        result.is_err(),
        "a birth that does not decode must be refused, deleted row or not: {result:?}"
    );
    Ok(())
}

/// The throwaway-carrier shape: the row is shipped, its birth is inserted,
/// and then only the row is deleted, so the birth stays live with no live
/// owner. The starting states above may excuse only a birth that leaves
/// with its row; a live one would wait in the window and stamp whatever
/// row later lands under its key, so it is refused.
#[test]
fn a_snapshot_that_leaves_a_birth_live_without_its_row_is_refused() -> TestResult {
    let source = window_doc(1)?;
    let receiver = window_doc(2)?;
    let at = window_at()?;
    let owner = EntityId::now();
    let survivor = EntityId::now();
    let birth = birth_bytes();
    put_born_row(&source, &owner, at, &birth)?;
    put_born_row(&source, &survivor, at, &birth_bytes())?;
    delete_key(&source, "entities", &owner.to_hex())?;
    assert!(
        !carries(&source, "entities", &owner) && carries(&source, "row_births", &owner),
        "FIXTURE: only the row left, so the birth stays live without it"
    );
    assert!(
        carries(&source, "entities", &survivor),
        "FIXTURE: the other row stays live"
    );

    let snapshot = source.export(ExportMode::Snapshot)?;
    let shown = LoroDoc::from_snapshot(&snapshot)?;
    assert!(
        !carries(&shown, "entities", &owner) && carries(&shown, "row_births", &owner),
        "FIXTURE: the snapshot's latest state carries the birth but not its row"
    );
    assert!(
        birth_inserted_in_history(&shown, &owner, &birth),
        "FIXTURE: the snapshot's history retains the birth insertion"
    );

    let result = validate_window_update_locality(&receiver, &snapshot);
    assert!(
        result.is_err(),
        "a birth left live after its row is deleted must be refused: {result:?}"
    );
    Ok(())
}

/// The same shape past a shallow root that carries the row: the root is a
/// starting state for a birth that leaves with its row, not for one left
/// live without it.
#[test]
fn a_shallow_snapshot_that_leaves_a_birth_live_without_its_root_row_is_refused() -> TestResult {
    let source = window_doc(1)?;
    let receiver = window_doc(2)?;
    let at = window_at()?;
    let owner = EntityId::now();
    insert_bytes(
        &source,
        "entities",
        &owner.to_hex(),
        &entity_blob(at, b"artifact row"),
    )?;
    let root = source.oplog_frontiers();
    insert_bytes(&source, "row_births", &owner.to_hex(), &birth_bytes())?;
    delete_key(&source, "entities", &owner.to_hex())?;

    let snapshot = source.export(ExportMode::shallow_snapshot(&root))?;
    let shown = LoroDoc::from_snapshot(&snapshot)?;
    assert!(shown.is_shallow(), "FIXTURE: the snapshot is shallow");
    assert!(
        !carries(&shown, "entities", &owner) && carries(&shown, "row_births", &owner),
        "FIXTURE: the snapshot's latest state carries the birth but not its row"
    );

    let result = validate_window_update_locality(&receiver, &snapshot);
    assert!(
        result.is_err(),
        "a birth left live after its root row is deleted must be refused: {result:?}"
    );
    Ok(())
}

/// The same shape as an ordinary update over a held row: the state the
/// range starts from carries the row, but the birth it leaves live does
/// not leave with the row, so that starting state does not excuse it.
#[test]
fn an_update_that_leaves_a_birth_live_without_its_held_row_is_refused() -> TestResult {
    let source = window_doc(1)?;
    let receiver = window_doc(2)?;
    let at = window_at()?;
    let owner = EntityId::now();
    insert_bytes(
        &source,
        "entities",
        &owner.to_hex(),
        &entity_blob(at, b"artifact row"),
    )?;
    receiver.import(&source.export(ExportMode::all_updates())?)?;
    assert!(
        carries(&receiver, "entities", &owner),
        "FIXTURE: the receiver already holds the row"
    );
    let before = receiver.oplog_vv();
    insert_bytes(&source, "row_births", &owner.to_hex(), &birth_bytes())?;
    delete_key(&source, "entities", &owner.to_hex())?;
    assert!(
        !carries(&source, "entities", &owner) && carries(&source, "row_births", &owner),
        "FIXTURE: only the row left, so the birth stays live without it"
    );

    let update = source.export(ExportMode::updates(&before))?;
    let result = validate_window_update_locality(&receiver, &update);
    assert!(
        result.is_err(),
        "a birth left live after its held row is deleted must be refused: {result:?}"
    );
    Ok(())
}

/// Redelivery of the births-then-deletes update: once the receiver has imported
/// it, the receiver no longer holds the row, but the state the range
/// starts from has not changed, so the same bytes are admitted again
/// (the import itself would absorb them as a no-op).
#[test]
fn an_update_that_births_then_deletes_a_held_row_passes_admission_on_redelivery() -> TestResult {
    let source = window_doc(1)?;
    let receiver = window_doc(2)?;
    let at = window_at()?;
    let owner = EntityId::now();
    insert_bytes(
        &source,
        "entities",
        &owner.to_hex(),
        &entity_blob(at, b"artifact row"),
    )?;
    receiver.import(&source.export(ExportMode::all_updates())?)?;
    assert!(
        carries(&receiver, "entities", &owner),
        "FIXTURE: the receiver already holds the row"
    );
    let before = receiver.oplog_vv();
    insert_bytes(&source, "row_births", &owner.to_hex(), &birth_bytes())?;
    delete_born_row(&source, &owner)?;

    let update = source.export(ExportMode::updates(&before))?;
    let first = validate_window_update_locality(&receiver, &update);
    assert!(
        first.is_ok(),
        "FIXTURE: the update passes admission on first delivery: {first:?}"
    );
    receiver.import(&update)?;
    assert!(
        !carries(&receiver, "entities", &owner) && !carries(&receiver, "row_births", &owner),
        "FIXTURE: the import took the row and its birth out of the receiver"
    );

    let result = validate_window_update_locality(&receiver, &update);
    assert!(
        result.is_ok(),
        "the same update must keep its verdict after it has been imported: {result:?}"
    );
    Ok(())
}

/// A concurrent local delete of the held row is not part of the state the
/// update's range starts from either: that state still carries the row
/// the update births and then deletes, so the delete does not stall it.
#[test]
fn an_update_that_births_then_deletes_a_row_the_receiver_deleted_locally_passes() -> TestResult {
    let source = window_doc(1)?;
    let receiver = window_doc(2)?;
    let at = window_at()?;
    let owner = EntityId::now();
    insert_bytes(
        &source,
        "entities",
        &owner.to_hex(),
        &entity_blob(at, b"artifact row"),
    )?;
    receiver.import(&source.export(ExportMode::all_updates())?)?;
    assert!(
        carries(&receiver, "entities", &owner),
        "FIXTURE: the receiver already holds the row"
    );
    let before = receiver.oplog_vv();
    insert_bytes(&source, "row_births", &owner.to_hex(), &birth_bytes())?;
    delete_born_row(&source, &owner)?;
    let update = source.export(ExportMode::updates(&before))?;

    delete_key(&receiver, "entities", &owner.to_hex())?;
    assert!(
        !carries(&receiver, "entities", &owner),
        "FIXTURE: the receiver deleted the row locally before validating"
    );

    let result = validate_window_update_locality(&receiver, &update);
    assert!(
        result.is_ok(),
        "the update must pass despite the concurrent local delete of its row: {result:?}"
    );
    Ok(())
}
