use std::sync::Arc;

use super::*;
use crate::Vault;
use crate::config::VaultConfig;
use crate::entity_id::EntityId;
use crate::habit::TaskRole;
use crate::ports::ManualClock;
use crate::registry::ENTITY_TYPE_TASK;
use crate::sync::bridge::Materializer;
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
        held.vault.get_raw(&other).unwrap().is_some(),
        "the failed purge leaves raw bytes behind"
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
        held.vault.get_raw(&other).unwrap().is_none(),
        "the retry purges the hard-deleted body"
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
