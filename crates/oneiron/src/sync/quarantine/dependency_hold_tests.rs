use std::sync::Arc;

use super::*;
use crate::Vault;
use crate::config::VaultConfig;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::habit::TaskRole;
use crate::ports::ManualClock;
use crate::registry::ENTITY_TYPE_TASK;
use crate::sync::bridge::{Materializer, encode_edge_value_for_crdt, format_edge_key};
use crate::sync::loro_support::map_insert_bytes;
use crate::sync::schema::create_window_doc;
use crate::sync::window::forward_rematerialize;
use crate::temporal::TimeRange;
use crate::test_util::log_capture::LogCapture;
use crate::workspace_roster::ProjectRecord;
use loro::LoroDoc;

/// `learned_at` inside the 2026-03 window used throughout.
const LEARNED_AT: u64 = 1_772_400_000;
const T0: u64 = LEARNED_AT;
const DEFAULT_HOLD_MAX_SECS: u64 = 86_400;
const WINDOW: &str = "2026-03";
const WINDOW2: &str = "2026-04";

/// The aggregate breach ERROR this leg classifies, prefix-matched.
const BREACH: &str = "forward remat: rm: markers still pending after tombstone pass";
/// The dependency-hold WARN, prefix-matched.
const HOLD_WARN: &str = "forward remat: rm: markers still pending: each one waits";
const DRAIN_BREACH: &str = "rm drain: tombstone purge still failing";
const DOCTOR_BREACH: &str = "sync doctor: rm: markers pending — hard-deleted";
const DOCTOR_HOLD: &str = "sync doctor: rm: markers pending: each one waits";

/// Small map_size + tempdir held for the vault's lifetime — macOS LMDB
/// flake isolation. One vault at a time per test; each case below drops
/// its vault before the next opens.
fn test_vault_with_dir() -> (tempfile::TempDir, Arc<Vault>, Arc<ManualClock>) {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    let clock = ManualClock::new(T0);
    cfg.store_clock = clock.bundle();
    let vault = Arc::new(Vault::open(dir.path(), cfg).unwrap());
    // A receiver loads its install signer at boot (serve's keystore
    // install); every hard purge signs its deletion receipt with it.
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    (dir, vault, clock)
}

/// 33-byte envelope: type u8 + occurred_start/end + learned_at + row_version u64 BE.
fn entity_blob(entity_type: u8, occurred: TimeRange, learned_at: u64, data: &[u8]) -> Vec<u8> {
    // Fresh test carrier: row_version 0, the value base writes for a new row.
    crate::test_util::entity_record(entity_type, occurred, learned_at, 0, data)
}

fn task_body() -> Vec<u8> {
    crate::habit::task_body_for_test(TaskRole::Task)
}

fn valid_time_range() -> TimeRange {
    TimeRange { start: 1, end: 2 }
}

/// A child project whose parent this replica does not hold, with the
/// carrier blobs a window delivers for each.
struct ProjectHold {
    child: EntityId,
    parent: EntityId,
    waiting: ProjectRecord,
    child_blob: Vec<u8>,
    parent_blob: Vec<u8>,
}

fn project_hold_fixture(vault: &Vault) -> ProjectHold {
    let root_id = vault.root_project().unwrap();
    let root = vault.project(root_id).unwrap().unwrap();
    let leader = EntityId::from_hex(&root.leader).unwrap();
    let kind = vault.project_type_byte().unwrap();
    let child = EntityId::now();
    let parent = EntityId::now();
    let waiting = ProjectRecord::new(child, Some(parent), root_id, leader).expect("fixture");
    let parent_body = ProjectRecord::new(parent, Some(root_id), root_id, leader).expect("fixture");
    let child_blob = entity_blob(
        kind,
        valid_time_range(),
        LEARNED_AT,
        &rmp_serde::to_vec_named(&waiting).unwrap(),
    );
    let parent_blob = entity_blob(
        kind,
        valid_time_range(),
        LEARNED_AT,
        &rmp_serde::to_vec_named(&parent_body).unwrap(),
    );
    ProjectHold {
        child,
        parent,
        waiting,
        child_blob,
        parent_blob,
    }
}

/// A fresh vault whose window holds one child for its missing parent,
/// with the carrier already in the window doc.
struct HeldWindow {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    clock: Arc<ManualClock>,
    hold: ProjectHold,
    window_key: WindowKey,
    doc: LoroDoc,
}

fn held_window() -> HeldWindow {
    let (dir, vault, clock) = test_vault_with_dir();
    let hold = project_hold_fixture(&vault);
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("test-user", &window_key);
    let entities = doc.get_map("entities");
    map_insert_bytes(&entities, &hold.child.to_hex(), &hold.child_blob).unwrap();
    doc.commit();
    HeldWindow {
        _dir: dir,
        vault,
        clock,
        hold,
        window_key,
        doc,
    }
}

impl HeldWindow {
    fn forward(&self, materializer: &Materializer) -> crate::error::Result<u32> {
        forward_rematerialize(&self.vault, &self.doc, materializer, &self.window_key)
    }

    fn hold_start_key(&self) -> String {
        format!("rmh:w:{WINDOW}:{}", self.hold.child.to_hex())
    }

    fn hold_start(&self) -> Option<u64> {
        raw_row(&self.vault, &self.hold_start_key())
            .map(|row| u64::from_le_bytes(row.try_into().expect("eight-byte hold start")))
    }
}

/// Captured lines holding the breach ERROR.
fn breach_errors(lines: &[String]) -> Vec<&String> {
    lines
        .iter()
        .filter(|line| line.starts_with("event ERROR") && line.contains(BREACH))
        .collect()
}

/// Captured lines holding the dependency-hold WARN.
fn hold_warns(lines: &[String]) -> Vec<&String> {
    lines
        .iter()
        .filter(|line| {
            line.starts_with("event WARN")
                && line.contains(HOLD_WARN)
                && line.contains("reason=ProjectDependencyPending")
        })
        .collect()
}

fn drain_breach_errors(lines: &[String]) -> Vec<&String> {
    lines
        .iter()
        .filter(|line| line.starts_with("event ERROR") && line.contains(DRAIN_BREACH))
        .collect()
}

fn doctor_breach_errors(lines: &[String]) -> Vec<&String> {
    lines
        .iter()
        .filter(|line| line.starts_with("event ERROR") && line.contains(DOCTOR_BREACH))
        .collect()
}

fn doctor_hold_warns(lines: &[String]) -> Vec<&String> {
    lines
        .iter()
        .filter(|line| line.starts_with("event WARN") && line.contains(DOCTOR_HOLD))
        .collect()
}

/// One raw `sync_state` row, if present.
fn raw_row(vault: &Vault, key: &str) -> Option<Vec<u8>> {
    let rtxn = vault.store.env.read_txn().unwrap();
    vault
        .store
        .sync_state
        .get(&rtxn, key)
        .unwrap()
        .map(std::borrow::Cow::into_owned)
}

/// One entity row as it rests, past the deletion fence that `get` and
/// `get_raw` honor: a failed purge leaves the row stored but fenced.
fn stored_entity_row(vault: &Vault, id: &EntityId) -> Option<Vec<u8>> {
    let rtxn = vault.store.env.read_txn().unwrap();
    crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &rtxn, id).unwrap()
}

/// The raw `rm:` row for one window and id, if present.
fn remat_row(vault: &Vault, window: &str, id: &EntityId) -> Option<Vec<u8>> {
    raw_row(vault, &remat_marker_key(window, id))
}

/// The raw `rmp:` sidecar for one window and id, if present.
fn provenance_row(vault: &Vault, window: &str, id: &EntityId) -> Option<Vec<u8>> {
    raw_row(vault, &replay_remat_marker_provenance_key(window, id))
}

/// Plants one raw `sync_state` row.
fn plant_row(vault: &Vault, key: &str, value: &[u8]) {
    vault
        .with_write_txn(|wtxn| {
            vault.store.sync_state.put(wtxn, key, value)?;
            Ok(())
        })
        .unwrap();
}

/// A window held for a missing project warns and raises no breach
/// signal; once the parent lands, the child heals and both markers clear.
#[test]
fn a_window_held_for_a_missing_project_warns_and_raises_no_breach_signal() {
    let held = held_window();
    let materializer = Materializer::new();
    let refusal_at = held.vault.store.clock.now_recorded_at();

    let capture = LogCapture::default();
    capture
        .with_default(|| held.forward(&materializer))
        .unwrap();
    let lines = capture.lines();
    assert!(
        breach_errors(&lines).is_empty(),
        "a pure project hold raises no breach signal: {lines:?}"
    );
    assert_eq!(
        hold_warns(&lines).len(),
        1,
        "a pure project hold warns once: {lines:?}"
    );
    let records = quarantined_records(&held.vault).unwrap();
    assert!(
        records.iter().any(|(_, record)| {
            record.window_key == WINDOW
                && record.container == QuarantineContainer::Entities
                && record.reason_code == "ProjectDependencyPending"
                && record.crdt_key_hash == xxh3_64(held.hold.child.to_hex().as_bytes())
        }),
        "the held child leaves a ProjectDependencyPending x: row: {records:?}"
    );
    assert_eq!(
        remat_row(&held.vault, WINDOW, &held.hold.child).as_deref(),
        Some([1u8].as_slice()),
        "the held child's rm: marker stays pending"
    );
    assert_eq!(
        provenance_row(&held.vault, WINDOW, &held.hold.child).as_deref(),
        Some([1u8].as_slice()),
        "the held child's marker proves replay origin"
    );
    assert_eq!(
        held.hold_start(),
        Some(refusal_at),
        "the hold start records the clock at refusal"
    );
    assert_eq!(
        pending_remat_windows(&held.vault).unwrap(),
        vec![WINDOW.to_string()],
        "the held window stays flagged"
    );
    assert!(
        held.vault.get(&held.hold.child).unwrap().is_none(),
        "the held child installs nothing"
    );

    // The parent lands in another window; the child window runs again
    // without its carrier being re-sent.
    let window2_key = WindowKey::new(WINDOW2);
    let doc2 = create_window_doc("test-user", &window2_key);
    let entities2 = doc2.get_map("entities");
    map_insert_bytes(
        &entities2,
        &held.hold.parent.to_hex(),
        &held.hold.parent_blob,
    )
    .unwrap();
    doc2.commit();
    forward_rematerialize(&held.vault, &doc2, &materializer, &window2_key).unwrap();
    assert!(
        held.vault.project(held.hold.parent).unwrap().is_some(),
        "the parent lands through its own window"
    );

    let capture = LogCapture::default();
    capture
        .with_default(|| held.forward(&materializer))
        .unwrap();
    let lines = capture.lines();
    assert!(
        breach_errors(&lines).is_empty(),
        "the healed window raises no breach signal: {lines:?}"
    );
    assert!(
        hold_warns(&lines).is_empty(),
        "the healed window warns about nothing: {lines:?}"
    );
    assert_eq!(
        held.vault.project(held.hold.child).unwrap(),
        Some(held.hold.waiting.clone()),
        "the released child is written"
    );
    assert_eq!(
        remat_row(&held.vault, WINDOW, &held.hold.child),
        None,
        "the healing write clears the rm: marker"
    );
    assert_eq!(
        provenance_row(&held.vault, WINDOW, &held.hold.child),
        None,
        "the healing write clears the provenance sidecar"
    );
    assert_eq!(held.hold_start(), None, "the heal clears the hold start");
    assert!(
        pending_remat_windows(&held.vault).unwrap().is_empty(),
        "no window stays flagged after the heal"
    );
}

/// A project waiting for the message it was born from warns without a breach.
/// After the hold bound, it raises the breach signal (GDPR-HOLD-ORIGIN-MESSAGE = B).
#[test]
fn a_window_held_for_a_missing_origin_message_warns_then_breaches_at_the_bound() {
    let (_dir, vault, clock) = test_vault_with_dir();
    let root_id = vault.root_project().unwrap();
    let root = vault.project(root_id).unwrap().unwrap();
    let leader = EntityId::from_hex(&root.leader).unwrap();
    let child = EntityId::now();
    let mut waiting = ProjectRecord::new(child, Some(root_id), root_id, leader).expect("fixture");
    waiting.born_from = Some(EntityId::now().to_hex());
    let child_blob = entity_blob(
        vault.project_type_byte().unwrap(),
        valid_time_range(),
        LEARNED_AT,
        &rmp_serde::to_vec_named(&waiting).unwrap(),
    );
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("test-user", &window_key);
    map_insert_bytes(&doc.get_map("entities"), &child.to_hex(), &child_blob).unwrap();
    doc.commit();
    let materializer = Materializer::new();

    clock.set(T0);
    let capture = LogCapture::default();
    capture
        .with_default(|| forward_rematerialize(&vault, &doc, &materializer, &window_key))
        .unwrap();
    let lines = capture.lines();
    assert!(
        breach_errors(&lines).is_empty(),
        "a missing origin message raises no breach at the start: {lines:?}"
    );
    assert!(
        !hold_warns(&lines).is_empty(),
        "a missing origin message warns at the start: {lines:?}"
    );
    assert_eq!(remat_row(&vault, WINDOW, &child), Some(vec![1]));
    assert_eq!(provenance_row(&vault, WINDOW, &child), Some(vec![1]));
    let hold_start_key = format!("rmh:w:{WINDOW}:{}", child.to_hex());
    assert_eq!(
        raw_row(&vault, &hold_start_key),
        Some(T0.to_le_bytes().to_vec())
    );

    clock.set(T0 + DEFAULT_HOLD_MAX_SECS + 1);
    let capture = LogCapture::default();
    capture
        .with_default(|| forward_rematerialize(&vault, &doc, &materializer, &window_key))
        .unwrap();
    let lines = capture.lines();
    assert_eq!(breach_errors(&lines).len(), 1, "expired hold: {lines:?}");
    assert!(hold_warns(&lines).is_empty(), "expired hold: {lines:?}");
    assert_eq!(remat_row(&vault, WINDOW, &child), Some(vec![1]));
}

/// A held child that the same pass also refuses for good, here through an
/// edge sourced at it whose value is not bytes, raises the breach signal.
/// A hold for a parent project or the message a project was born from that
/// this replica does not hold yet never hides another refusal (review round 1
/// of #10563).
#[test]
fn a_held_child_the_pass_also_refuses_for_good_raises_the_breach_signal() {
    let held = held_window();
    let other = EntityId::now();
    let edge_key = format_edge_key(&held.hold.child, EdgeKind::Mentions, &other);
    held.doc
        .get_map("edges")
        .insert(&edge_key, "string-valued-edge")
        .unwrap();
    held.doc.commit();
    let materializer = Materializer::new();

    let capture = LogCapture::default();
    capture
        .with_default(|| held.forward(&materializer))
        .unwrap();
    let lines = capture.lines();
    assert_eq!(
        breach_errors(&lines).len(),
        1,
        "the edge refusal of the held child breaches: {lines:?}"
    );
    assert!(
        hold_warns(&lines).is_empty(),
        "no project-hold WARN for a child also refused for good: {lines:?}"
    );
    assert!(
        remat_row(&held.vault, WINDOW, &held.hold.child).is_some(),
        "the held child's rm: marker stays pending"
    );
}

/// A held window whose marker outlives the release raises the breach
/// signal: with no refusal in the pass, even a proven marker cannot warn.
#[test]
fn a_held_window_whose_marker_outlives_the_release_raises_the_breach_signal() {
    let held = held_window();
    let materializer = Materializer::new();

    // Hold, then release through the genuine path: the parent lands in
    // another window and the child window heals.
    held.forward(&materializer).unwrap();
    assert_eq!(
        remat_row(&held.vault, WINDOW, &held.hold.child).as_deref(),
        Some([1u8].as_slice()),
        "precondition: the hold leaves a pending marker"
    );
    let window2_key = WindowKey::new(WINDOW2);
    let doc2 = create_window_doc("test-user", &window2_key);
    let entities2 = doc2.get_map("entities");
    map_insert_bytes(
        &entities2,
        &held.hold.parent.to_hex(),
        &held.hold.parent_blob,
    )
    .unwrap();
    doc2.commit();
    forward_rematerialize(&held.vault, &doc2, &materializer, &window2_key).unwrap();
    held.forward(&materializer).unwrap();
    assert!(
        held.vault.project(held.hold.child).unwrap().is_some(),
        "precondition: the hold is released"
    );
    assert_eq!(
        remat_row(&held.vault, WINDOW, &held.hold.child),
        None,
        "precondition: the healing write clears the marker"
    );

    // The stale route: the marker outlives the release, and the next
    // pass on the window refuses nothing. A proven marker then still
    // breaches, since the pass owes it no wait.
    set_replay_remat_marker(&held.vault, WINDOW, &held.hold.child).unwrap();
    let empty = create_window_doc("test-user", &held.window_key);
    let capture = LogCapture::default();
    let result = capture.with_default(|| {
        forward_rematerialize(&held.vault, &empty, &materializer, &held.window_key)
    });
    result.unwrap();
    let lines = capture.lines();
    assert_eq!(
        breach_errors(&lines).len(),
        1,
        "a stale proven marker breaches: {lines:?}"
    );
    assert!(
        hold_warns(&lines).is_empty(),
        "a stale proven marker never warns: {lines:?}"
    );
    assert_eq!(
        remat_row(&held.vault, WINDOW, &held.hold.child).as_deref(),
        Some([1u8].as_slice()),
        "the stale marker stays pending"
    );
    assert_eq!(
        provenance_row(&held.vault, WINDOW, &held.hold.child).as_deref(),
        Some([1u8].as_slice()),
        "the stale sidecar stays pending"
    );

    // The same stale marker without provenance breaches too.
    set_remat_marker(&held.vault, WINDOW, &held.hold.child).unwrap();
    assert_eq!(
        provenance_row(&held.vault, WINDOW, &held.hold.child),
        None,
        "precondition: the strong setter drops the sidecar"
    );
    let capture = LogCapture::default();
    let result = capture.with_default(|| {
        forward_rematerialize(&held.vault, &empty, &materializer, &held.window_key)
    });
    result.unwrap();
    let lines = capture.lines();
    assert_eq!(
        breach_errors(&lines).len(),
        1,
        "a stale unproven marker breaches: {lines:?}"
    );
    assert!(
        hold_warns(&lines).is_empty(),
        "a stale unproven marker never warns: {lines:?}"
    );
    assert_eq!(
        remat_row(&held.vault, WINDOW, &held.hold.child).as_deref(),
        Some([1u8].as_slice()),
        "the unproven marker stays pending"
    );
}

/// A purge failure beside a project hold still raises the breach
/// signal; once the purge succeeds, only the hold WARN remains.
#[test]
fn a_purge_failure_beside_a_project_hold_still_raises_the_breach_signal() {
    let held = held_window();
    let materializer = Materializer::new();

    let other = EntityId::now();
    held.vault
        .put_entity(
            &other,
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &task_body(),
        )
        .unwrap();
    map_insert_bytes(&held.doc.get_map("tombstones"), &other.to_hex(), b"1").unwrap();
    held.doc.commit();

    INJECT_PURGE_FAILURES.with(|cell| cell.set(1));
    let capture = LogCapture::default();
    capture
        .with_default(|| held.forward(&materializer))
        .unwrap();
    let lines = capture.lines();
    assert_eq!(
        breach_errors(&lines).len(),
        1,
        "a purge failure beside a hold breaches: {lines:?}"
    );
    assert!(
        hold_warns(&lines).is_empty(),
        "a purge failure beside a hold never warns: {lines:?}"
    );
    assert!(
        stored_entity_row(&held.vault, &other).is_some(),
        "the failed purge leaves the stored row behind"
    );
    assert!(
        held.vault.get_raw(&other).unwrap().is_none(),
        "the accepted delete's fence hides the row from raw reads"
    );
    assert!(
        held.vault.get(&other).unwrap().is_none(),
        "the accepted delete is fenced while its purge is pending"
    );
    assert_eq!(
        remat_row(&held.vault, WINDOW, &other).as_deref(),
        Some([1u8].as_slice()),
        "the failed purge flags its own marker"
    );
    assert_eq!(
        provenance_row(&held.vault, WINDOW, &other),
        None,
        "a purge failure proves no replay origin"
    );
    assert_eq!(
        remat_row(&held.vault, WINDOW, &held.hold.child).as_deref(),
        Some([1u8].as_slice()),
        "the held child's marker stays pending"
    );

    // Retry without the injection: the purge runs, and only the hold
    // WARN remains.
    let capture = LogCapture::default();
    capture
        .with_default(|| held.forward(&materializer))
        .unwrap();
    let lines = capture.lines();
    assert!(
        breach_errors(&lines).is_empty(),
        "the clean retry breaches nothing: {lines:?}"
    );
    assert_eq!(
        hold_warns(&lines).len(),
        1,
        "the clean retry still warns for the hold: {lines:?}"
    );
    assert!(
        stored_entity_row(&held.vault, &other).is_none(),
        "the retry purges the hard-deleted body"
    );
    assert!(
        raw_row(&held.vault, &crate::deletion::local_hard_delete_key(&other)).is_some(),
        "the retry's purge writes the hard-delete marker"
    );
    assert_eq!(
        remat_row(&held.vault, WINDOW, &other),
        None,
        "the retry clears the purge marker"
    );
    assert_eq!(
        remat_row(&held.vault, WINDOW, &held.hold.child).as_deref(),
        Some([1u8].as_slice()),
        "the held child's marker stays pending"
    );
    assert!(
        held.vault.get(&held.hold.child).unwrap().is_none(),
        "the held child is still absent"
    );
}

/// An unclassified marker beside a project hold raises the breach
/// signal: entity-less rows, non-canonical suffixes, unmatched proven
/// markers, and unproven markers for the held id all fail closed.
#[test]
fn an_unclassified_marker_beside_a_project_hold_raises_the_breach_signal() {
    // An entity-less row beside the hold.
    {
        let held = held_window();
        let materializer = Materializer::new();
        plant_row(&held.vault, &format!("rm:w:{WINDOW}"), &[1u8]);
        let capture = LogCapture::default();
        capture
            .with_default(|| held.forward(&materializer))
            .unwrap();
        let lines = capture.lines();
        assert_eq!(
            breach_errors(&lines).len(),
            1,
            "an entity-less marker breaches: {lines:?}"
        );
        assert!(
            hold_warns(&lines).is_empty(),
            "an entity-less marker never warns: {lines:?}"
        );
        assert_eq!(
            raw_row(&held.vault, &format!("rm:w:{WINDOW}")).as_deref(),
            Some([1u8].as_slice()),
            "the entity-less row stays"
        );
        assert_eq!(
            remat_row(&held.vault, WINDOW, &held.hold.child).as_deref(),
            Some([1u8].as_slice()),
            "the held child's marker stays pending"
        );
        assert_eq!(
            provenance_row(&held.vault, WINDOW, &held.hold.child).as_deref(),
            Some([1u8].as_slice()),
            "the held child's sidecar stays pending"
        );
        assert!(
            held.vault.get(&held.hold.child).unwrap().is_none(),
            "the held child is still absent"
        );
    }

    // Non-canonical suffixes beside the hold: one that never parses
    // and one that parses but is not the canonical spelling.
    {
        let held = held_window();
        let materializer = Materializer::new();
        plant_row(&held.vault, &format!("rm:w:{WINDOW}:zzz-not-hex"), &[1u8]);
        let stranger = EntityId::now();
        let upper = stranger.to_hex().to_uppercase();
        plant_row(&held.vault, &format!("rm:w:{WINDOW}:{upper}"), &[1u8]);
        let capture = LogCapture::default();
        capture
            .with_default(|| held.forward(&materializer))
            .unwrap();
        let lines = capture.lines();
        assert_eq!(
            breach_errors(&lines).len(),
            1,
            "a non-canonical marker breaches: {lines:?}"
        );
        assert!(
            hold_warns(&lines).is_empty(),
            "a non-canonical marker never warns: {lines:?}"
        );
        assert_eq!(
            raw_row(&held.vault, &format!("rm:w:{WINDOW}:zzz-not-hex")).as_deref(),
            Some([1u8].as_slice()),
            "the unparsable row stays"
        );
        assert_eq!(
            raw_row(&held.vault, &format!("rm:w:{WINDOW}:{upper}")).as_deref(),
            Some([1u8].as_slice()),
            "the non-canonical row stays"
        );
        assert_eq!(
            remat_row(&held.vault, WINDOW, &held.hold.child).as_deref(),
            Some([1u8].as_slice()),
            "the held child's marker stays pending"
        );
        assert!(
            held.vault.get(&held.hold.child).unwrap().is_none(),
            "the held child is still absent"
        );
    }

    // A proven marker for an id the pass never refuses.
    {
        let held = held_window();
        let materializer = Materializer::new();
        let stranger = EntityId::now();
        set_replay_remat_marker(&held.vault, WINDOW, &stranger).unwrap();
        let capture = LogCapture::default();
        capture
            .with_default(|| held.forward(&materializer))
            .unwrap();
        let lines = capture.lines();
        assert_eq!(
            breach_errors(&lines).len(),
            1,
            "an unmatched proven marker breaches: {lines:?}"
        );
        assert!(
            hold_warns(&lines).is_empty(),
            "an unmatched proven marker never warns: {lines:?}"
        );
        assert_eq!(
            remat_row(&held.vault, WINDOW, &stranger).as_deref(),
            Some([1u8].as_slice()),
            "the unmatched marker stays pending"
        );
        assert_eq!(
            provenance_row(&held.vault, WINDOW, &stranger).as_deref(),
            Some([1u8].as_slice()),
            "the unmatched sidecar stays pending"
        );
        assert_eq!(
            remat_row(&held.vault, WINDOW, &held.hold.child).as_deref(),
            Some([1u8].as_slice()),
            "the held child's marker stays pending"
        );
        assert!(
            held.vault.get(&held.hold.child).unwrap().is_none(),
            "the held child is still absent"
        );
    }

    // An unproven marker for the held id itself: the quarantine keeps
    // the stronger provenance, and the pass still breaches.
    {
        let held = held_window();
        let materializer = Materializer::new();
        set_remat_marker(&held.vault, WINDOW, &held.hold.child).unwrap();
        let capture = LogCapture::default();
        capture
            .with_default(|| held.forward(&materializer))
            .unwrap();
        let lines = capture.lines();
        assert_eq!(
            breach_errors(&lines).len(),
            1,
            "an unproven marker for the held id breaches: {lines:?}"
        );
        assert!(
            hold_warns(&lines).is_empty(),
            "an unproven marker for the held id never warns: {lines:?}"
        );
        assert_eq!(
            remat_row(&held.vault, WINDOW, &held.hold.child).as_deref(),
            Some([1u8].as_slice()),
            "the unproven marker stays pending"
        );
        assert_eq!(
            provenance_row(&held.vault, WINDOW, &held.hold.child),
            None,
            "the quarantine adds no provenance to the unproven marker"
        );
        assert!(
            held.vault.get(&held.hold.child).unwrap().is_none(),
            "the held child is still absent"
        );
    }
}

#[test]
fn a_re_quarantined_hold_keeps_its_first_start_and_breaches_at_the_bound() {
    let held = held_window();
    let materializer = Materializer::new();
    for now in [
        T0,
        T0 + DEFAULT_HOLD_MAX_SECS - 1,
        T0 + DEFAULT_HOLD_MAX_SECS,
    ] {
        held.clock.set(now);
        let capture = LogCapture::default();
        capture
            .with_default(|| held.forward(&materializer))
            .unwrap();
        let lines = capture.lines();
        assert_eq!(hold_warns(&lines).len(), 1, "hold at {now}: {lines:?}");
        assert!(breach_errors(&lines).is_empty(), "hold at {now}: {lines:?}");
        assert_eq!(held.hold_start(), Some(T0), "hold at {now} keeps its start");
    }

    held.clock.set(T0 + DEFAULT_HOLD_MAX_SECS + 1);
    let capture = LogCapture::default();
    capture
        .with_default(|| held.forward(&materializer))
        .unwrap();
    let lines = capture.lines();
    assert_eq!(breach_errors(&lines).len(), 1, "expired hold: {lines:?}");
    assert!(hold_warns(&lines).is_empty(), "expired hold: {lines:?}");
    assert_eq!(
        remat_row(&held.vault, WINDOW, &held.hold.child),
        Some(vec![1])
    );
    assert_eq!(
        provenance_row(&held.vault, WINDOW, &held.hold.child),
        Some(vec![1])
    );
    assert_eq!(held.hold_start(), Some(T0));
}

#[test]
fn the_hold_start_goes_with_its_marker_on_every_clear_path() {
    let held = held_window();
    let materializer = Materializer::new();
    let vault = &held.vault;
    let id = &held.hold.child;

    held.forward(&materializer).unwrap();
    assert_eq!(held.hold_start(), Some(T0));
    vault
        .with_write_txn(|txn| clear_remat_marker_in_txn(vault, txn, WINDOW, id))
        .unwrap();
    assert_eq!(remat_row(vault, WINDOW, id), None);
    assert_eq!(held.hold_start(), None);

    held.forward(&materializer).unwrap();
    assert_eq!(held.hold_start(), Some(T0));
    let cleared = vault
        .with_write_txn(|txn| clear_replay_remat_marker_in_txn(vault, txn, WINDOW, id))
        .unwrap();
    assert!(cleared);
    assert_eq!(remat_row(vault, WINDOW, id), None);
    assert_eq!(held.hold_start(), None);

    held.forward(&materializer).unwrap();
    assert_eq!(held.hold_start(), Some(T0));
    vault
        .with_write_txn(|txn| set_remat_marker_in_txn(vault, txn, WINDOW, id))
        .unwrap();
    assert_eq!(provenance_row(vault, WINDOW, id), None);
    assert_eq!(
        held.hold_start(),
        Some(T0),
        "the strong setter keeps the start"
    );
    let cleared = vault
        .with_write_txn(|txn| clear_replay_remat_marker_in_txn(vault, txn, WINDOW, id))
        .unwrap();
    assert!(!cleared);
    assert_eq!(remat_row(vault, WINDOW, id), Some(vec![1]));
    assert_eq!(
        held.hold_start(),
        Some(T0),
        "a refused clear keeps the start"
    );
}

#[test]
fn a_held_window_with_no_hold_start_raises_the_breach_signal() {
    let held = held_window();
    let materializer = Materializer::new();
    held.forward(&materializer).unwrap();
    assert_eq!(held.hold_start(), Some(T0));
    let key = held.hold_start_key();
    assert!(
        held.vault
            .with_write_txn(|txn| Ok(held.vault.store.sync_state.delete(txn, &key)?))
            .unwrap()
    );

    let capture = LogCapture::default();
    capture
        .with_default(|| held.forward(&materializer))
        .unwrap();
    let lines = capture.lines();
    assert_eq!(breach_errors(&lines).len(), 1, "missing start: {lines:?}");
    assert!(hold_warns(&lines).is_empty(), "missing start: {lines:?}");
    assert_eq!(
        remat_row(&held.vault, WINDOW, &held.hold.child),
        Some(vec![1])
    );
    assert_eq!(
        held.hold_start(),
        None,
        "re-quarantine must not backfill a start"
    );
}

fn persist_held_window(held: &HeldWindow, materializer: &Arc<Materializer>) {
    let loaded = crate::sync::window::LoadedWindow::from_doc(
        held.doc.clone(),
        held.window_key.clone(),
        &held.vault,
        materializer,
    );
    loaded.persist_state(&held.vault).unwrap();
}

fn drain_held_window(
    held: &HeldWindow,
    materializer: &Arc<Materializer>,
) -> (RematDrainReport, Vec<String>) {
    let capture = LogCapture::default();
    let report = capture
        .with_default(|| crate::sync::drain_remat_markers(&held.vault, "test-user", materializer))
        .unwrap();
    (report, capture.lines())
}

#[test]
fn draining_a_held_window_reports_it_held_and_raises_no_breach_signal() {
    let held = held_window();
    let materializer = Arc::new(Materializer::new());
    held.forward(&materializer).unwrap();
    persist_held_window(&held, &materializer);

    let (report, lines) = drain_held_window(&held, &materializer);
    assert_eq!(report.held, vec![WINDOW.to_string()]);
    assert!(report.still_pending.is_empty());
    assert!(report.drained.is_empty());
    assert_eq!(
        remat_row(&held.vault, WINDOW, &held.hold.child),
        Some(vec![1])
    );
    assert_eq!(held.hold_start(), Some(T0));
    assert_eq!(hold_warns(&lines).len(), 1, "{lines:?}");
    assert!(drain_breach_errors(&lines).is_empty(), "{lines:?}");
    assert!(breach_errors(&lines).is_empty(), "{lines:?}");
}

#[test]
fn draining_a_held_window_past_the_bound_raises_the_breach_signal() {
    let held = held_window();
    let materializer = Arc::new(Materializer::new());
    held.forward(&materializer).unwrap();
    persist_held_window(&held, &materializer);
    held.clock.set(T0 + DEFAULT_HOLD_MAX_SECS + 1);

    let (report, lines) = drain_held_window(&held, &materializer);
    assert_eq!(report.still_pending, vec![WINDOW.to_string()]);
    assert!(report.held.is_empty());
    assert_eq!(drain_breach_errors(&lines).len(), 1, "{lines:?}");
    assert_eq!(breach_errors(&lines).len(), 1, "{lines:?}");
    assert_eq!(
        remat_row(&held.vault, WINDOW, &held.hold.child),
        Some(vec![1])
    );
}

#[test]
fn draining_a_held_window_beside_a_purge_failure_raises_the_breach_signal() {
    let held = held_window();
    let materializer = Arc::new(Materializer::new());

    let other = EntityId::now();
    held.vault
        .put_entity(
            &other,
            ENTITY_TYPE_TASK,
            valid_time_range(),
            LEARNED_AT,
            &task_body(),
        )
        .unwrap();
    map_insert_bytes(&held.doc.get_map("tombstones"), &other.to_hex(), b"1").unwrap();
    held.doc.commit();

    INJECT_PURGE_FAILURES.with(|cell| cell.set(1));
    held.forward(&materializer).unwrap();
    assert_eq!(held.hold_start(), Some(T0));
    assert_eq!(remat_row(&held.vault, WINDOW, &other), Some(vec![1]));
    assert_eq!(provenance_row(&held.vault, WINDOW, &other), None);
    persist_held_window(&held, &materializer);

    // The drain retries the tombstone; keep the purge failure pending.
    INJECT_PURGE_FAILURES.with(|cell| cell.set(1));
    let (report, lines) = drain_held_window(&held, &materializer);
    assert_eq!(report.still_pending, vec![WINDOW.to_string()]);
    assert!(report.held.is_empty());
    assert_eq!(drain_breach_errors(&lines).len(), 1, "{lines:?}");
    assert_eq!(remat_row(&held.vault, WINDOW, &other), Some(vec![1]));
}

#[test]
fn the_doctor_lists_a_held_window_apart_and_raises_no_breach_signal() {
    {
        let held = held_window();
        let materializer = Materializer::new();
        held.forward(&materializer).unwrap();

        let capture = LogCapture::default();
        let report = capture.with_default(|| sync_doctor(&held.vault)).unwrap();
        let lines = capture.lines();
        assert_eq!(report.rm_held_windows, vec![WINDOW.to_string()]);
        assert!(report.rm_pending_windows.is_empty());
        assert_eq!(doctor_hold_warns(&lines).len(), 1, "{lines:?}");
        assert!(doctor_breach_errors(&lines).is_empty(), "{lines:?}");

        held.clock.set(T0 + DEFAULT_HOLD_MAX_SECS + 1);
        let capture = LogCapture::default();
        let report = capture.with_default(|| sync_doctor(&held.vault)).unwrap();
        let lines = capture.lines();
        assert_eq!(report.rm_pending_windows, vec![WINDOW.to_string()]);
        assert!(report.rm_held_windows.is_empty());
        assert_eq!(doctor_breach_errors(&lines).len(), 1, "{lines:?}");
    }

    let held = held_window();
    let materializer = Materializer::new();
    held.forward(&materializer).unwrap();
    let key = held.hold_start_key();
    assert!(
        held.vault
            .with_write_txn(|txn| Ok(held.vault.store.sync_state.delete(txn, &key)?))
            .unwrap()
    );

    let capture = LogCapture::default();
    let report = capture.with_default(|| sync_doctor(&held.vault)).unwrap();
    let lines = capture.lines();
    assert_eq!(report.rm_pending_windows, vec![WINDOW.to_string()]);
    assert!(report.rm_held_windows.is_empty());
    assert_eq!(doctor_breach_errors(&lines).len(), 1, "{lines:?}");
}

/// The T1 pair's shared setup: project A is stored with its old body,
/// parented at the vault root, while the window carries a newer body for the
/// same id whose parent this vault does not hold — with a well-formed
/// ChildOf edge A -> B (B absent) beside it when asked.
struct PresentHeldProject {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    id: EntityId,
    stored: ProjectRecord,
    target: Option<EntityId>,
    window_key: WindowKey,
    doc: LoroDoc,
}

fn present_held_project(with_child_of: bool) -> PresentHeldProject {
    let (dir, vault, _clock) = test_vault_with_dir();
    let root_id = vault.root_project().unwrap();
    let root = vault.project(root_id).unwrap().unwrap();
    let leader = EntityId::from_hex(&root.leader).unwrap();
    let kind = vault.project_type_byte().unwrap();
    let id = EntityId::now();
    let old = ProjectRecord::new(id, Some(root_id), root_id, leader).expect("fixture");
    vault.put_project(id, &old, 1).unwrap();
    let stored = vault.project(id).unwrap().unwrap();
    let missing_parent = EntityId::now();
    let newer = ProjectRecord::new(id, Some(missing_parent), root_id, leader).expect("fixture");
    let newer_blob = entity_blob(
        kind,
        valid_time_range(),
        LEARNED_AT,
        &rmp_serde::to_vec_named(&newer).unwrap(),
    );
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("test-user", &window_key);
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &newer_blob).unwrap();
    let target = if with_child_of {
        let target = EntityId::now();
        let key = format_edge_key(&id, EdgeKind::ChildOf, &target);
        let value =
            encode_edge_value_for_crdt(EdgeKind::ChildOf, 1.0, LEARNED_AT, None, None).unwrap();
        map_insert_bytes(&doc.get_map("edges"), &key, &value).unwrap();
        Some(target)
    } else {
        None
    };
    doc.commit();
    PresentHeldProject {
        _dir: dir,
        vault,
        id,
        stored,
        target,
        window_key,
        doc,
    }
}

/// A present held project with an independent ChildOf wait raises the breach
/// signal: the edge wait the id still owes vetoes the dependency hold
/// (review round 2 of #10565).
#[test]
fn a_present_held_project_with_an_independent_child_of_wait_raises_the_breach_signal() {
    let held = present_held_project(true);
    let materializer = Materializer::new();
    let capture = LogCapture::default();
    capture
        .with_default(|| {
            forward_rematerialize(&held.vault, &held.doc, &materializer, &held.window_key)
        })
        .unwrap();
    let lines = capture.lines();
    assert_eq!(
        held.vault.project(held.id).unwrap(),
        Some(held.stored.clone()),
        "the refused newer body leaves the old A in place"
    );
    let target = held
        .target
        .expect("the ChildOf edge names its absent target");
    assert!(
        raw_row(
            &held.vault,
            &format!("dc:w:{WINDOW}:{}:{}", held.id.to_hex(), target.to_hex())
        )
        .is_some(),
        "the ChildOf edge to the absent target stays owed"
    );
    let rtxn = held.vault.store.env.read_txn().unwrap();
    assert!(
        crate::sync::bridge::has_pending_source_in_txn(&held.vault, &rtxn, WINDOW, &held.id)
            .unwrap(),
        "the owed ChildOf edge is a pending wait sourced at A"
    );
    drop(rtxn);
    assert_eq!(
        breach_errors(&lines).len(),
        1,
        "the independent ChildOf wait breaches: {lines:?}"
    );
    assert!(
        hold_warns(&lines).is_empty(),
        "no project-hold WARN beside the edge wait: {lines:?}"
    );
    assert_eq!(
        classify_window_markers(&held.vault, WINDOW, |_| true).unwrap(),
        WindowMarkerClass::Unclassified,
        "the edge wait vetoes the hold"
    );
    let report = sync_doctor(&held.vault).unwrap();
    assert_eq!(
        report.rm_pending_windows,
        vec![WINDOW.to_string()],
        "the doctor lists the vetoed window as pending"
    );
    assert!(
        report.rm_held_windows.is_empty(),
        "the doctor lists no held window beside the edge wait"
    );
}

/// The same newer body with no ChildOf edge stays a bounded hold: it warns
/// and never breaches, proving the veto above comes from the edge wait.
#[test]
fn a_present_held_project_without_the_child_of_wait_stays_held() {
    let held = present_held_project(false);
    let materializer = Materializer::new();
    let capture = LogCapture::default();
    capture
        .with_default(|| {
            forward_rematerialize(&held.vault, &held.doc, &materializer, &held.window_key)
        })
        .unwrap();
    let lines = capture.lines();
    assert_eq!(
        held.vault.project(held.id).unwrap(),
        Some(held.stored.clone()),
        "the refused newer body leaves the old A in place"
    );
    assert!(
        breach_errors(&lines).is_empty(),
        "the same newer body with no edge wait breaches nothing: {lines:?}"
    );
    assert_eq!(
        hold_warns(&lines).len(),
        1,
        "the same newer body with no edge wait warns once: {lines:?}"
    );
    assert_eq!(
        classify_window_markers(&held.vault, WINDOW, |_| true).unwrap(),
        WindowMarkerClass::AllMatch,
        "with no edge wait the hold stands"
    );
}

/// A new project in an owner-rooted vault that waits for its signed birth
/// raises the breach signal: the birth wait stamps no hold start and never
/// matches the hold (review round 2 of #10565).
#[test]
fn a_project_waiting_for_its_signed_birth_raises_the_breach_signal() {
    let (_dir, vault, _clock) = test_vault_with_dir();
    let _owner = crate::subject_model::tests::authorization::root_host_owner(&vault, 0xA1).unwrap();
    let root_id = vault.root_project().unwrap();
    let root = vault.project(root_id).unwrap().unwrap();
    let leader = EntityId::from_hex(&root.leader).unwrap();
    let child = EntityId::now();
    let record = ProjectRecord::new(child, Some(root_id), root_id, leader).expect("fixture");
    assert!(
        record.born_from.is_none(),
        "the fixture names no origin message"
    );
    assert!(
        record.write_proof.is_none(),
        "the fixture carries no signed spawn"
    );
    let child_blob = entity_blob(
        vault.project_type_byte().unwrap(),
        valid_time_range(),
        LEARNED_AT,
        &rmp_serde::to_vec_named(&record).unwrap(),
    );
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("test-user", &window_key);
    map_insert_bytes(&doc.get_map("entities"), &child.to_hex(), &child_blob).unwrap();
    doc.commit();

    let materializer = Materializer::new();
    let capture = LogCapture::default();
    capture
        .with_default(|| forward_rematerialize(&vault, &doc, &materializer, &window_key))
        .unwrap();
    let lines = capture.lines();
    assert!(
        vault.get(&child).unwrap().is_none(),
        "the birth-waiting child installs nothing"
    );
    let records = quarantined_records(&vault).unwrap();
    assert!(
        records.iter().any(|(_, record)| {
            record.window_key == WINDOW
                && record.container == QuarantineContainer::Entities
                && record.reason_code == "ProjectBirthPending"
                && record.crdt_key_hash == xxh3_64(child.to_hex().as_bytes())
        }),
        "the birth-waiting child leaves a ProjectBirthPending x: row: {records:?}"
    );
    assert_eq!(
        remat_row(&vault, WINDOW, &child).as_deref(),
        Some([1u8].as_slice()),
        "the birth wait keeps its rm: marker"
    );
    assert_eq!(
        provenance_row(&vault, WINDOW, &child).as_deref(),
        Some([1u8].as_slice()),
        "the birth wait proves replay origin"
    );
    assert_eq!(
        raw_row(&vault, &format!("rmh:w:{WINDOW}:{}", child.to_hex())),
        None,
        "the birth wait stamps no hold start"
    );
    assert_eq!(
        breach_errors(&lines).len(),
        1,
        "the birth wait breaches: {lines:?}"
    );
    assert!(
        hold_warns(&lines).is_empty(),
        "no project-hold WARN for a birth wait: {lines:?}"
    );
    let report = sync_doctor(&vault).unwrap();
    assert_eq!(report.rm_pending_windows, vec![WINDOW.to_string()]);
    assert!(report.rm_held_windows.is_empty());

    let materializer = Arc::new(Materializer::new());
    let loaded = crate::sync::window::LoadedWindow::from_doc(
        doc.clone(),
        window_key.clone(),
        &vault,
        &materializer,
    );
    loaded.persist_state(&vault).unwrap();
    let capture = LogCapture::default();
    let report = capture
        .with_default(|| crate::sync::drain_remat_markers(&vault, "test-user", &materializer))
        .unwrap();
    assert_eq!(report.still_pending, vec![WINDOW.to_string()]);
    assert!(report.held.is_empty());
    assert!(report.drained.is_empty());
}

/// An edge settled beside a project hold keeps the hold and its start: only
/// the entity's own settlement discharges them (review round 2 of #10565).
#[test]
fn an_edge_settled_beside_a_project_hold_keeps_the_hold_and_its_start() {
    let held = held_window();
    let materializer = Arc::new(Materializer::new());
    // A well-formed DAG Parent edge C -> B with B absent: the coordinator
    // waits on C's own arrival and owes a pending obligation for C.
    let missing = EntityId::now();
    let parent_key = format_edge_key(&held.hold.child, EdgeKind::Parent, &missing);
    let parent_value =
        encode_edge_value_for_crdt(EdgeKind::Parent, 1.0, LEARNED_AT, None, None).unwrap();
    map_insert_bytes(&held.doc.get_map("edges"), &parent_key, &parent_value).unwrap();
    held.doc.commit();
    let obligation = format!(
        "dp:w:{WINDOW}:{}:{}",
        held.hold.child.to_hex(),
        missing.to_hex()
    );

    // Pass 1: the hold stands, and the edge wait is owed beside it.
    let capture = LogCapture::default();
    capture
        .with_default(|| held.forward(&materializer))
        .unwrap();
    let lines = capture.lines();
    assert_eq!(
        remat_row(&held.vault, WINDOW, &held.hold.child).as_deref(),
        Some([1u8].as_slice()),
        "pass 1 leaves the held child's rm: marker"
    );
    assert_eq!(held.hold_start(), Some(T0), "pass 1 starts the hold at T0");
    assert!(
        raw_row(&held.vault, &obligation).is_some(),
        "pass 1 owes the Parent wait for the held child"
    );
    assert_eq!(
        hold_warns(&lines).len(),
        1,
        "pass 1 warns for the hold: {lines:?}"
    );
    assert!(
        breach_errors(&lines).is_empty(),
        "pass 1 breaches nothing: {lines:?}"
    );

    // Pass 2: the edge value turns to garbage, so its wait settles while the
    // entity still waits on its missing parent.
    map_insert_bytes(&held.doc.get_map("edges"), &parent_key, &[0xffu8]).unwrap();
    held.doc.commit();
    held.clock.set(T0 + 5);
    held.forward(&materializer).unwrap();
    assert_eq!(
        remat_row(&held.vault, WINDOW, &held.hold.child).as_deref(),
        Some([1u8].as_slice()),
        "the settled edge wait keeps the held child's marker"
    );
    assert_eq!(
        held.hold_start(),
        Some(T0),
        "the settled edge wait keeps the hold start, stamping no fresh hold"
    );
    assert_eq!(
        raw_row(&held.vault, &obligation),
        None,
        "pass 2 settles the Parent wait"
    );
    assert!(
        classify_window_markers(&held.vault, WINDOW, |_| true).unwrap()
            != WindowMarkerClass::NonePending,
        "the kept hold still pends the window"
    );
    persist_held_window(&held, &materializer);
    let (report, lines) = drain_held_window(&held, &materializer);
    assert!(
        !report.drained.contains(&WINDOW.to_string()),
        "the kept hold never drains: {report:?}"
    );
    assert_eq!(report.still_pending, vec![WINDOW.to_string()]);
    assert!(report.held.is_empty());
    assert_eq!(drain_breach_errors(&lines).len(), 1, "{lines:?}");
    assert_eq!(breach_errors(&lines).len(), 1, "{lines:?}");

    // The parent arrives and the child lands; the entity's own settlement
    // discharges the hold the edge settlement kept.
    map_insert_bytes(
        &held.doc.get_map("entities"),
        &held.hold.parent.to_hex(),
        &held.hold.parent_blob,
    )
    .unwrap();
    held.doc.commit();
    // Traversal order is not ancestry order: the child may be visited before
    // its newly arrived parent on the first of these passes.
    held.forward(&materializer).unwrap();
    held.forward(&materializer).unwrap();
    assert_eq!(
        held.vault.project(held.hold.child).unwrap(),
        Some(held.hold.waiting.clone()),
        "the released child is written"
    );
    assert_eq!(
        remat_row(&held.vault, WINDOW, &held.hold.child),
        None,
        "the healing write clears the rm: marker"
    );
    assert_eq!(
        held.hold_start(),
        None,
        "the healing write clears the hold start"
    );
}
