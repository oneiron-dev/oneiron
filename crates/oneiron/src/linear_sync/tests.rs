//! Mirror-adapter tests (ONE-1905). Everything here runs on injected fakes:
//! no vault, no network, and no Linear credential exists anywhere in the
//! crate for these tests to need.

use std::cell::Cell;

use super::*;

const TEAM: &str = "team-1";

fn task_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("test entity id")
}

fn task_fields() -> MirroredTaskFields {
    MirroredTaskFields {
        title: "Ship the wave".to_owned(),
        description: Some("first cut".to_owned()),
        priority: Some(2),
        assignee_ref: None,
        status: "todo".to_owned(),
    }
}

#[derive(Debug, Default)]
struct FakeStore {
    snapshots: BTreeMap<EntityId, TaskMirrorSnapshot>,
    links: BTreeMap<EntityId, TaskIssueLink>,
    applies: usize,
    issue_link_lookups: Cell<usize>,
    /// A concurrent link write to commit from INSIDE the store, in the window
    /// between an operation's link read and its link write. That window is the
    /// entire subject of the compare-and-set contract, and it is unreachable
    /// from adapter code — which is exactly why the check cannot live there.
    interleaved_link_write: Option<TaskIssueLink>,
}

impl FakeStore {
    fn with_task(task_ref: EntityId, fields: MirroredTaskFields) -> Self {
        let snapshot = TaskMirrorSnapshot {
            task_ref,
            issue: None,
            revision: 1,
            last_pushed_at_ms: None,
            last_pulled_updated_at_ms: None,
            fields,
        };
        let mut store = Self::default();
        store.snapshots.insert(task_ref, snapshot);
        store
    }

    fn edit(&mut self, task_ref: EntityId, edit: impl FnOnce(&mut MirroredTaskFields)) {
        let snapshot = self.snapshots.get_mut(&task_ref).expect("task snapshot");
        edit(&mut snapshot.fields);
        snapshot.revision += 1;
    }

    fn snapshot(&self, task_ref: EntityId) -> TaskMirrorSnapshot {
        self.snapshots.get(&task_ref).cloned().expect("snapshot")
    }

    fn stored_link(&self, task_ref: EntityId) -> TaskIssueLink {
        self.links.get(&task_ref).cloned().expect("link")
    }
}

impl LinearTaskStore for FakeStore {
    fn task_snapshot(&self, task_ref: EntityId) -> LinearSyncResult<TaskMirrorSnapshot> {
        self.snapshots
            .get(&task_ref)
            .cloned()
            .ok_or(LinearSyncError::Store(crate::error::Error::EntityNotFound))
    }

    fn apply_issue_fields(
        &mut self,
        task_ref: EntityId,
        expected_revision: u64,
        fields: &MirroredTaskFields,
        _now: u64,
    ) -> LinearSyncResult<TaskMirrorSnapshot> {
        let snapshot = self
            .snapshots
            .get_mut(&task_ref)
            .ok_or(LinearSyncError::Store(crate::error::Error::EntityNotFound))?;
        if snapshot.revision != expected_revision {
            return Err(LinearSyncError::Conflict {
                expected_revision,
                found: snapshot.revision,
            });
        }
        snapshot.fields = fields.clone();
        snapshot.revision += 1;
        self.applies += 1;
        Ok(self.snapshots.get(&task_ref).cloned().expect("snapshot"))
    }

    fn link(&self, task_ref: EntityId) -> LinearSyncResult<Option<TaskIssueLink>> {
        Ok(self.links.get(&task_ref).cloned())
    }

    fn link_for_issue(&self, issue: &LinearIssueRef) -> LinearSyncResult<Option<TaskIssueLink>> {
        self.issue_link_lookups
            .set(self.issue_link_lookups.get().saturating_add(1));
        let found = self
            .links
            .values()
            .find(|link| link.issue.issue_id == issue.issue_id);
        Ok(found.cloned())
    }

    fn put_link(
        &mut self,
        expected_link_revision: Option<u64>,
        link: &TaskIssueLink,
    ) -> LinearSyncResult<()> {
        // Commit the injected writer inside the store method, before the
        // atomic compare. An adapter-side preflight read cannot see this race.
        if let Some(interleaved) = self.interleaved_link_write.take() {
            self.links.insert(interleaved.task_ref, interleaved);
        }
        let found = self
            .links
            .get(&link.task_ref)
            .map(|stored| stored.link_revision);
        if found != expected_link_revision {
            return Err(LinearSyncError::LinkConflict {
                expected: expected_link_revision,
                found,
            });
        }
        self.links.insert(link.task_ref, link.clone());
        Ok(())
    }
}

/// Records every operation id and every outbound payload it is handed; holds
/// no credential, no client, and no transport — exactly the shape the host
/// implements behind the outbound door. The payload log is what proves a push
/// carried a pending local edit, and that a barred push carried nothing.
#[derive(Debug, Default)]
struct FakeEgress {
    clock_ms: u64,
    created: usize,
    updated: usize,
    operations: Vec<[u8; 32]>,
    payloads: Vec<MirroredTaskFields>,
}

impl LinearEgress for FakeEgress {
    fn create_issue(
        &mut self,
        operation_id: [u8; 32],
        _task_ref: EntityId,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        self.created += 1;
        self.clock_ms += 1_000;
        self.operations.push(operation_id);
        self.payloads.push(fields.clone());
        Ok(LinearIssueChange {
            event_id: format!("evt-create-{}", self.created),
            issue: issue_ref(self.created),
            updated_at_ms: self.clock_ms,
            fields: fields.clone(),
        })
    }

    fn update_issue(
        &mut self,
        operation_id: [u8; 32],
        issue: &LinearIssueRef,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        self.updated += 1;
        self.clock_ms += 1_000;
        self.operations.push(operation_id);
        self.payloads.push(fields.clone());
        Ok(LinearIssueChange {
            event_id: format!("evt-update-{}", self.updated),
            issue: issue.clone(),
            updated_at_ms: self.clock_ms,
            fields: fields.clone(),
        })
    }
}

#[derive(Debug, Default)]
struct FakeSource {
    pages: BTreeMap<String, LinearChangePage>,
}

impl FakeSource {
    fn with_page(cursor: &str, page: LinearChangePage) -> Self {
        let mut source = Self::default();
        source.pages.insert(cursor.to_owned(), page);
        source
    }
}

impl LinearChangeSource for FakeSource {
    fn changes_since(&mut self, cursor: Option<&str>) -> LinearSyncResult<LinearChangePage> {
        let key = cursor.unwrap_or("start");
        let empty = LinearChangePage {
            changes: Vec::new(),
            next_cursor: None,
        };
        Ok(self.pages.get(key).cloned().unwrap_or(empty))
    }
}

type TestAdapter = LinearSyncAdapter<FakeStore, FakeSource, FakeEgress>;

fn issue_ref(index: usize) -> LinearIssueRef {
    LinearIssueRef {
        issue_id: format!("issue-{index}"),
        team_id: TEAM.to_owned(),
        identifier: format!("ENG-{index}"),
    }
}

fn adapter(store: FakeStore, source: FakeSource) -> TestAdapter {
    LinearSyncAdapter::new(store, source, FakeEgress::default())
}

fn linked_adapter(task_ref: EntityId, source: FakeSource) -> TestAdapter {
    let store = FakeStore::with_task(task_ref, task_fields());
    let mut adapter = adapter(store, source);
    adapter.push_task(task_ref, 10).expect("initial push");
    adapter
}

fn change(event_id: &str, updated_at_ms: u64, fields: MirroredTaskFields) -> LinearIssueChange {
    LinearIssueChange {
        event_id: event_id.to_owned(),
        issue: issue_ref(1),
        updated_at_ms,
        fields,
    }
}

#[test]
fn push_creates_and_links_the_issue() {
    let task_ref = task_id(0x11);
    let store = FakeStore::with_task(task_ref, task_fields());
    let mut adapter = adapter(store, FakeSource::default());

    let receipt = adapter.push_task(task_ref, 10).expect("push");

    assert_eq!(receipt.status, LinearMirrorStatus::Linked);
    assert_eq!(receipt.direction, LinearSyncDirection::TaskToIssue);
    assert_eq!(receipt.issue.identifier, "ENG-1");
    assert!(receipt.conflicts.is_empty());
    let link = adapter.tasks().stored_link(task_ref);
    assert_eq!(link.task_revision, 1);
    assert_eq!(link.issue_updated_at_ms, 1_000);
    assert_eq!(link.base_field_hashes.len(), LINEAR_MIRRORED_FIELDS.len());
}

#[test]
fn push_updates_the_issue_after_a_task_edit() {
    let task_ref = task_id(0x12);
    let mut adapter = linked_adapter(task_ref, FakeSource::default());
    let store = adapter.tasks_mut();
    store.edit(task_ref, |fields| fields.status = "doing".to_owned());

    let receipt = adapter.push_task(task_ref, 20).expect("push update");

    assert_eq!(receipt.status, LinearMirrorStatus::Applied);
    let link = adapter.tasks().stored_link(task_ref);
    assert_eq!(link.task_revision, 2);
    assert_eq!(link.issue_updated_at_ms, 2_000);
    let (_, _, egress) = adapter.into_parts();
    assert_eq!(egress.created, 1);
    assert_eq!(egress.updated, 1);
}

#[test]
fn repeated_push_of_one_revision_is_operation_id_idempotent() {
    let task_ref = task_id(0x13);
    let mut adapter = linked_adapter(task_ref, FakeSource::default());
    let store = adapter.tasks_mut();
    store.edit(task_ref, |fields| fields.title = "Ship now".to_owned());

    let first = adapter.push_task(task_ref, 20).expect("push once");
    let second = adapter.push_task(task_ref, 30).expect("push twice");

    assert_eq!(first.status, LinearMirrorStatus::Applied);
    assert_eq!(second.status, LinearMirrorStatus::Noop);
    assert_eq!(first.operation_id, second.operation_id);
    let (_, _, egress) = adapter.into_parts();
    assert_eq!(egress.updated, 1);
    assert_eq!(egress.operations.len(), 2);
}

#[test]
fn inbound_change_applies_issue_fields_to_the_task() {
    let task_ref = task_id(0x14);
    let mut adapter = linked_adapter(task_ref, FakeSource::default());
    let mut fields = task_fields();
    fields.status = "in_review".to_owned();
    fields.assignee_ref = Some("user-7".to_owned());

    let receipt = adapter
        .apply_issue_change(change("evt-1", 5_000, fields), 40)
        .expect("apply inbound");

    assert_eq!(receipt.status, LinearMirrorStatus::Applied);
    assert_eq!(receipt.direction, LinearSyncDirection::IssueToTask);
    let snapshot = adapter.tasks().snapshot(task_ref);
    assert_eq!(snapshot.fields.status, "in_review");
    assert_eq!(snapshot.fields.assignee_ref.as_deref(), Some("user-7"));
    assert_eq!(snapshot.revision, 2);
    let link = adapter.tasks().stored_link(task_ref);
    assert_eq!(link.issue_updated_at_ms, 5_000);
    assert_eq!(link.task_revision, 2);
}

#[test]
fn inbound_echo_of_our_own_push_is_suppressed() {
    let task_ref = task_id(0x15);
    let mut adapter = linked_adapter(task_ref, FakeSource::default());

    let stale = adapter
        .apply_issue_change(change("evt-echo", 1_000, task_fields()), 40)
        .expect("stale echo");
    let later = adapter
        .apply_issue_change(change("evt-echo-2", 6_000, task_fields()), 41)
        .expect("later echo");

    assert_eq!(stale.status, LinearMirrorStatus::Noop);
    assert_eq!(later.status, LinearMirrorStatus::Noop);
    let store = adapter.tasks();
    assert_eq!(store.applies, 0);
    assert_eq!(store.snapshot(task_ref).revision, 1);
    let link = store.stored_link(task_ref);
    assert_eq!(link.issue_updated_at_ms, 6_000);

    // Preserve the independent store-watermark guard as well as the link
    // watermark exercised above.
    let mut snapshot = store.snapshot(task_ref);
    snapshot.last_pulled_updated_at_ms = Some(9_000);
    let replay = change("evt-behind-store", 8_000, task_fields());
    assert!(inbound_already_seen(&link, &snapshot, &replay, [0_u8; 32]));
}

#[test]
fn outbound_echo_of_an_inbound_apply_is_suppressed() {
    let task_ref = task_id(0x16);
    let mut adapter = linked_adapter(task_ref, FakeSource::default());
    let mut fields = task_fields();
    fields.title = "Renamed in the tracker".to_owned();
    adapter
        .apply_issue_change(change("evt-1", 5_000, fields), 40)
        .expect("apply inbound");

    let receipt = adapter.push_task(task_ref, 50).expect("push after pull");

    assert_eq!(receipt.status, LinearMirrorStatus::Noop);
    let (_, _, egress) = adapter.into_parts();
    assert_eq!(egress.updated, 0);
}

#[test]
fn mixed_conflict_applies_safe_fields_once_and_keeps_the_field_barrier() {
    let task_ref = task_id(0x17);
    let mut adapter = linked_adapter(task_ref, FakeSource::default());
    let store = adapter.tasks_mut();
    store.edit(task_ref, |fields| fields.title = "Engine".to_owned());
    let mut incoming = task_fields();
    incoming.title = "Tracker title".to_owned();
    incoming.status = "done".to_owned();

    let receipt = adapter
        .apply_issue_change(change("evt-mixed", 5_000, incoming.clone()), 40)
        .expect("mixed conflict receipt");
    let replay = adapter
        .apply_issue_change(change("evt-mixed", 9_000, incoming.clone()), 41)
        .expect("mixed conflict replay");
    let push = adapter.push_task(task_ref, 50).expect("barred push");

    assert_eq!(receipt.status, LinearMirrorStatus::Conflict);
    assert_eq!(receipt.conflicts.len(), 1);
    let conflict = &receipt.conflicts[0];
    assert_eq!(conflict.field, LINEAR_FIELD_TITLE);
    assert_eq!(conflict.task_value.as_deref(), Some("Engine"));
    assert_eq!(conflict.issue_value.as_deref(), Some("Tracker title"));
    assert_eq!(replay.status, LinearMirrorStatus::Conflict);
    assert_eq!(push.status, LinearMirrorStatus::Conflict);

    let store = adapter.tasks();
    assert_eq!(store.applies, 1, "the safe field is applied exactly once");
    let snapshot = store.snapshot(task_ref);
    assert_eq!(snapshot.fields.title, "Engine");
    assert_eq!(snapshot.fields.status, "done");
    assert_eq!(snapshot.revision, 3);
    let link = store.stored_link(task_ref);
    assert_eq!(link.issue_updated_at_ms, 5_000);
    assert!(link.has_seen_event("evt-mixed"));
    assert_eq!(link.unresolved_conflicts.len(), 1);
    assert_eq!(link.unresolved_conflicts[0].field, LINEAR_FIELD_TITLE);
    let initial_hashes = task_fields().field_hashes();
    let incoming_hashes = incoming.field_hashes();
    assert_eq!(
        link.base_field_hashes.get(LINEAR_FIELD_TITLE),
        initial_hashes.get(LINEAR_FIELD_TITLE),
    );
    assert_eq!(
        link.base_field_hashes.get(LINEAR_FIELD_STATUS),
        incoming_hashes.get(LINEAR_FIELD_STATUS),
    );
    let (_, _, egress) = adapter.into_parts();
    assert_eq!(egress.updated, 0);
}

#[test]
fn disjoint_field_edits_merge_without_a_conflict() {
    let task_ref = task_id(0x18);
    let mut adapter = linked_adapter(task_ref, FakeSource::default());
    let store = adapter.tasks_mut();
    store.edit(task_ref, |fields| fields.title = "Engine".to_owned());
    let mut incoming = task_fields();
    incoming.status = "done".to_owned();

    let receipt = adapter
        .apply_issue_change(change("evt-1", 5_000, incoming), 40)
        .expect("merge");

    assert_eq!(receipt.status, LinearMirrorStatus::Applied);
    assert!(receipt.conflicts.is_empty());
    let merged = adapter.tasks().snapshot(task_ref).fields;
    assert_eq!(merged.title, "Engine");
    assert_eq!(merged.status, "done");
}

/// ONE-1959 finding 1: a merge keeps the local field, but the base must NOT
/// claim the tracker has it. The pending edit has to stay pushable.
#[test]
fn a_merged_local_edit_stays_pending_and_pushes_after_the_inbound_apply() {
    let task_ref = task_id(0x20);
    let mut adapter = linked_adapter(task_ref, FakeSource::default());
    let store = adapter.tasks_mut();
    store.edit(task_ref, |fields| fields.title = "Engine title".to_owned());
    let mut incoming = task_fields();
    incoming.status = "done".to_owned();

    let merged = adapter
        .apply_issue_change(change("evt-status", 5_000, incoming.clone()), 40)
        .expect("disjoint merge");

    assert_eq!(merged.status, LinearMirrorStatus::Applied);
    assert!(merged.conflicts.is_empty());
    let fields = adapter.tasks().snapshot(task_ref).fields;
    assert_eq!(fields.title, "Engine title");
    assert_eq!(fields.status, "done");
    // The base is the TRACKER's post-event state, so the local title reads as
    // still pending rather than as already mirrored.
    let link = adapter.tasks().stored_link(task_ref);
    assert_eq!(link.base_field_hashes, incoming.field_hashes());
    assert_ne!(
        link.base_field_hashes.get(LINEAR_FIELD_TITLE),
        fields.field_hashes().get(LINEAR_FIELD_TITLE)
    );

    let pushed = adapter.push_task(task_ref, 50).expect("push pending edit");

    assert_eq!(pushed.status, LinearMirrorStatus::Applied);
    let (_, _, egress) = adapter.into_parts();
    assert_eq!(egress.updated, 1);
    let payload = egress.payloads.last().expect("outbound payload");
    assert_eq!(payload.title, "Engine title");
    assert_eq!(payload.status, "done");
}

/// ONE-1959 finding 2: the conflict has to survive the call boundary. A push
/// carries the full local snapshot, so an unbarred push is a last-write-wins
/// overwrite of the newer tracker value by the back door.
#[test]
fn a_conflict_bars_the_next_push_from_overwriting_the_tracker() {
    let task_ref = task_id(0x21);
    let mut adapter = linked_adapter(task_ref, FakeSource::default());
    let store = adapter.tasks_mut();
    store.edit(task_ref, |fields| fields.title = "Engine".to_owned());
    let mut incoming = task_fields();
    incoming.title = "Tracker title".to_owned();

    let conflict = adapter
        .apply_issue_change(change("evt-conflict", 5_000, incoming.clone()), 40)
        .expect("conflict receipt");
    let push = adapter.push_task(task_ref, 50).expect("barred push");
    // The conflict is not swallowed as a replay: a redelivery re-surfaces it.
    let redelivered = adapter
        .apply_issue_change(change("evt-conflict", 5_000, incoming), 51)
        .expect("redelivered conflict");

    assert_eq!(conflict.status, LinearMirrorStatus::Conflict);
    assert_eq!(push.status, LinearMirrorStatus::Conflict);
    assert_eq!(push.direction, LinearSyncDirection::TaskToIssue);
    assert_eq!(push.conflicts.len(), 1);
    assert_eq!(push.conflicts[0].field, LINEAR_FIELD_TITLE);
    assert_eq!(push.conflicts[0].task_value.as_deref(), Some("Engine"));
    let barred = push.conflicts[0].issue_value.as_deref();
    assert_eq!(barred, Some("Tracker title"));
    assert_eq!(redelivered.status, LinearMirrorStatus::Conflict);
    let store = adapter.tasks();
    assert_eq!(store.applies, 0);
    assert_eq!(store.snapshot(task_ref).fields.title, "Engine");
    let link = store.stored_link(task_ref);
    assert_eq!(link.unresolved_conflicts.len(), 1);
    let (_, _, egress) = adapter.into_parts();
    assert_eq!(egress.updated, 0);
    assert_eq!(egress.payloads.len(), 1, "only the initial create was sent");
}

/// A resolved barrier is durable: neither a pre-resolution TASK snapshot nor
/// the old event under a rewritten timestamp can restore or overwrite it.
#[test]
fn a_stale_event_cannot_resurrect_a_resolved_conflict() {
    let task_ref = task_id(0x22);
    let mut adapter = linked_adapter(task_ref, FakeSource::default());
    let store = adapter.tasks_mut();
    store.edit(task_ref, |fields| fields.title = "Engine".to_owned());
    let mut stale_fields = task_fields();
    stale_fields.title = "Tracker title".to_owned();
    let conflict = adapter
        .apply_issue_change(change("evt-conflict", 5_000, stale_fields.clone()), 40)
        .expect("conflict receipt");
    assert_eq!(conflict.status, LinearMirrorStatus::Conflict);
    assert_eq!(
        adapter
            .tasks()
            .stored_link(task_ref)
            .unresolved_conflicts
            .len(),
        1,
    );
    let stale_task_snapshot = adapter.tasks().snapshot(task_ref);

    let store = adapter.tasks_mut();
    store.edit(task_ref, |fields| fields.title = "Agreed title".to_owned());
    let push = adapter.push_task(task_ref, 60).expect("resolved push");
    let resolved_link = adapter.tasks().stored_link(task_ref);
    let resolved_snapshot = adapter.tasks().snapshot(task_ref);
    let stale_push = adapter
        .push_linked_issue(&stale_task_snapshot, resolved_link.clone(), 65)
        .expect("stale pre-resolution task snapshot");
    let stale = adapter
        .apply_issue_change(change("evt-conflict", 99_000, stale_fields), 70)
        .expect("stale post-resolution event");

    assert_eq!(push.status, LinearMirrorStatus::Applied);
    assert_eq!(stale_push.status, LinearMirrorStatus::Noop);
    assert!(push.conflicts.is_empty());
    assert!(resolved_link.unresolved_conflicts.is_empty());
    assert_eq!(stale.status, LinearMirrorStatus::Noop);
    assert!(stale.conflicts.is_empty());
    assert_eq!(adapter.tasks().stored_link(task_ref), resolved_link);
    assert_eq!(adapter.tasks().snapshot(task_ref), resolved_snapshot);
    assert_eq!(resolved_snapshot.fields.title, "Agreed title");
    let (_, _, egress) = adapter.into_parts();
    assert_eq!(egress.updated, 1);
    let payload = egress.payloads.last().expect("outbound payload");
    assert_eq!(payload.title, "Agreed title");
}

/// Event identity never expires. More than the old 32-entry bound can pass,
/// then the oldest event is still a replay even under a rewritten timestamp.
#[test]
fn an_event_replay_remains_a_noop_after_more_than_thirty_two_events() {
    let task_ref = task_id(0x23);
    let mut adapter = linked_adapter(task_ref, FakeSource::default());

    for index in 0_u64..40 {
        let mut fields = task_fields();
        fields.status = format!("state-{index}");
        let receipt = adapter
            .apply_issue_change(
                change(&format!("evt-{index}"), 5_000 + index, fields),
                40 + index,
            )
            .expect("distinct inbound event");
        assert_eq!(receipt.status, LinearMirrorStatus::Applied);
    }

    let mut oldest_fields = task_fields();
    oldest_fields.status = "state-0".to_owned();
    let replay = adapter
        .apply_issue_change(change("evt-0", 99_000, oldest_fields), 100)
        .expect("oldest event replay");

    assert_eq!(replay.status, LinearMirrorStatus::Noop);
    let store = adapter.tasks();
    assert_eq!(store.applies, 40);
    assert_eq!(store.snapshot(task_ref).fields.status, "state-39");
    let link = store.stored_link(task_ref);
    assert_eq!(link.issue_updated_at_ms, 5_039);
    assert_eq!(link.seen_event_digests.len(), 41);
    assert!(link.has_seen_event("evt-0"));
}

/// ONE-1959 finding 3, the other side: distinct event ids are distinct events.
/// A shared `updated_at` is not permission to collapse them.
#[test]
fn distinct_events_that_share_a_timestamp_are_not_collapsed() {
    let task_ref = task_id(0x24);
    let mut adapter = linked_adapter(task_ref, FakeSource::default());
    let mut first_fields = task_fields();
    first_fields.status = "done".to_owned();
    let mut second_fields = first_fields.clone();
    second_fields.priority = Some(1);

    let first = adapter
        .apply_issue_change(change("evt-a", 5_000, first_fields), 40)
        .expect("first event");
    let second = adapter
        .apply_issue_change(change("evt-b", 5_000, second_fields), 41)
        .expect("second event at the same instant");

    assert_eq!(first.status, LinearMirrorStatus::Applied);
    assert_eq!(second.status, LinearMirrorStatus::Applied);
    assert_ne!(first.operation_id, second.operation_id);
    let store = adapter.tasks();
    assert_eq!(store.applies, 2);
    let fields = store.snapshot(task_ref).fields;
    assert_eq!(fields.status, "done");
    assert_eq!(fields.priority, Some(1));
}

#[test]
fn a_blank_event_id_is_rejected_before_lookup_or_mutation() {
    let task_ref = task_id(0x19);
    let mut adapter = linked_adapter(task_ref, FakeSource::default());
    let before_snapshot = adapter.tasks().snapshot(task_ref);
    let before_link = adapter.tasks().stored_link(task_ref);
    let mut incoming = task_fields();
    incoming.status = "done".to_owned();

    let error = adapter
        .apply_issue_change(change(" \t\n", 5_000, incoming), 40)
        .expect_err("blank event id");

    match error {
        LinearSyncError::Store(crate::error::Error::InvariantViolation(message)) => {
            assert_eq!(message, ERR_BLANK_EVENT_ID);
        }
        other => panic!("unexpected error: {other:?}"),
    }
    let store = adapter.tasks();
    assert_eq!(store.issue_link_lookups.get(), 0);
    assert_eq!(store.applies, 0);
    assert_eq!(store.snapshot(task_ref), before_snapshot);
    assert_eq!(store.stored_link(task_ref), before_link);
}

#[test]
fn pull_skips_unmirrored_issues_and_replays_nothing_twice() {
    let task_ref = task_id(0x1a);
    let mut mirrored = task_fields();
    mirrored.status = "done".to_owned();
    let foreign = LinearIssueChange {
        event_id: "evt-foreign".to_owned(),
        issue: issue_ref(99),
        updated_at_ms: 7_000,
        fields: task_fields(),
    };
    let page = LinearChangePage {
        changes: vec![change("evt-1", 5_000, mirrored), foreign],
        next_cursor: Some("page-2".to_owned()),
    };
    let mut adapter = linked_adapter(task_ref, FakeSource::with_page("start", page));

    let first = adapter.pull_page(None, 60).expect("first pull");
    let replay = adapter.pull_page(None, 61).expect("cursor replay");

    assert_eq!(first.applied, 1);
    assert_eq!(first.skipped_echo, 1);
    assert_eq!(first.new_cursor.as_deref(), Some("page-2"));
    assert!(first.conflicts.is_empty());
    assert_eq!(replay.applied, 0);
    assert_eq!(replay.skipped_echo, 2);
    assert_eq!(adapter.tasks().applies, 1);
}

#[test]
fn pull_reports_conflicts_without_applying_them() {
    let task_ref = task_id(0x1b);
    let mut incoming = task_fields();
    incoming.title = "Tracker title".to_owned();
    let page = LinearChangePage {
        changes: vec![change("evt-1", 5_000, incoming)],
        next_cursor: None,
    };
    let mut adapter = linked_adapter(task_ref, FakeSource::with_page("start", page));
    let store = adapter.tasks_mut();
    store.edit(task_ref, |fields| fields.title = "Engine".to_owned());

    let receipt = adapter.pull_page(None, 60).expect("pull");

    assert_eq!(receipt.applied, 0);
    assert_eq!(receipt.conflicts.len(), 1);
    assert_eq!(receipt.conflicts[0].status, LinearMirrorStatus::Conflict);
    assert_eq!(adapter.tasks().applies, 0);
}

#[test]
fn an_unlinked_issue_change_is_refused() {
    let task_ref = task_id(0x1c);
    let store = FakeStore::with_task(task_ref, task_fields());
    let mut adapter = adapter(store, FakeSource::default());

    let error = adapter
        .apply_issue_change(change("evt-1", 5_000, task_fields()), 40)
        .expect_err("no durable link");

    match error {
        LinearSyncError::Store(inner) => {
            assert_eq!(inner.kind(), crate::error::ErrorKind::InvariantViolation);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn store_level_cas_rejects_a_stale_barrier_clobber() {
    let task_ref = task_id(0x1d);
    let mut adapter = linked_adapter(task_ref, FakeSource::default());
    adapter
        .tasks_mut()
        .edit(task_ref, |fields| fields.title = "Engine".to_owned());

    // This row represents a newer operation that resolved the field. The fake
    // commits it from inside `put_link`, after the adapter's read but before
    // the store's atomic comparison.
    let mut resolved = adapter.tasks().stored_link(task_ref);
    resolved.task_revision = adapter.tasks().snapshot(task_ref).revision;
    resolved.issue_updated_at_ms = 6_000;
    resolved.base_field_hashes = adapter.tasks().snapshot(task_ref).fields.field_hashes();
    resolved.unresolved_conflicts.clear();
    resolved.last_operation_id = [0x5a; 32];
    resolved.last_direction = LinearSyncDirection::TaskToIssue;
    resolved.link_revision += 1;
    resolved.updated_at = 50;
    adapter.tasks_mut().interleaved_link_write = Some(resolved.clone());

    let mut stale_fields = task_fields();
    stale_fields.title = "Tracker title".to_owned();
    let error = adapter
        .apply_issue_change(change("evt-stale", 5_000, stale_fields), 60)
        .expect_err("stale barrier CAS");

    assert!(matches!(
        error,
        LinearSyncError::LinkConflict {
            expected: Some(0),
            found: Some(1),
        }
    ));
    let store = adapter.tasks();
    assert_eq!(store.applies, 0);
    assert_eq!(store.stored_link(task_ref), resolved);
    assert!(store.stored_link(task_ref).unresolved_conflicts.is_empty());
}

#[test]
fn operation_ids_separate_direction_revision_and_operation_kind() {
    let task_ref = task_id(0x1e);
    let create = linear_operation_id(
        LinearSyncDirection::TaskToIssue,
        task_ref,
        1,
        None,
        None,
        None,
    );
    let repeat = linear_operation_id(
        LinearSyncDirection::TaskToIssue,
        task_ref,
        1,
        None,
        None,
        None,
    );
    let update = linear_operation_id(
        LinearSyncDirection::TaskToIssue,
        task_ref,
        1,
        Some("issue-1"),
        None,
        None,
    );
    let inbound = linear_operation_id(
        LinearSyncDirection::IssueToTask,
        task_ref,
        1,
        Some("issue-1"),
        Some(5_000),
        Some("evt-1"),
    );
    let next = linear_operation_id(
        LinearSyncDirection::TaskToIssue,
        task_ref,
        2,
        None,
        None,
        None,
    );

    assert_eq!(create, repeat);
    assert_ne!(create, update);
    assert_ne!(update, inbound);
    assert_ne!(create, next);
}

/// The changed helper shape: the inbound key is `(issue_id,
/// issue_updated_at_ms, event_id)`, and the event id is the component that
/// carries it. Two events at the same instant must mint different ids, while a
/// retry of one event against an unchanged revision must mint the same id.
#[test]
fn inbound_operation_ids_bind_the_event_id_not_only_the_timestamp() {
    let task_ref = task_id(0x1e);
    let inbound = |event_id: &str, updated_at_ms: u64| {
        linear_operation_id(
            LinearSyncDirection::IssueToTask,
            task_ref,
            1,
            Some("issue-1"),
            Some(updated_at_ms),
            Some(event_id),
        )
    };

    let first = inbound("evt-a", 5_000);
    let retry = inbound("evt-a", 5_000);
    let same_instant = inbound("evt-b", 5_000);
    let redelivered = inbound("evt-a", 9_000);

    assert_eq!(first, retry);
    assert_ne!(first, same_instant);
    assert_ne!(first, redelivered);
}

#[test]
fn the_adapter_registers_field_ownership_and_needs_no_credential() {
    let task_ref = task_id(0x1f);
    let mut incoming = task_fields();
    incoming.status = "done".to_owned();
    let page = LinearChangePage {
        changes: vec![change("evt-1", 5_000, incoming)],
        next_cursor: None,
    };
    let mut adapter = linked_adapter(task_ref, FakeSource::with_page("start", page));

    // A full outbound + inbound cycle with three fakes: no token, no client,
    // no transport anywhere in the engine.
    adapter.pull_page(None, 60).expect("pull");
    adapter.push_task(task_ref, 61).expect("push");

    let registration = LINEAR_SYNC_REGISTRATION;
    assert_eq!(registration.adapter_id, LINEAR_SYNC_ADAPTER_ID);
    // v3: event identity is non-evicting and every link row carries its CAS
    // revision, so the row key namespace moves with the shape.
    assert_eq!(registration.schema_version, 3);
    assert!(LINEAR_SYNC_LINK_KEY_PREFIX.ends_with(b"v3:"));
    assert_eq!(registration.mirrored_fields.len(), 5);
    let engine_owned = registration.engine_authoritative_fields;
    assert!(engine_owned.contains(&"blocked_by"));
    let key = linear_sync_link_key(task_ref);
    assert!(key.starts_with(LINEAR_SYNC_LINK_KEY_PREFIX));
    assert_eq!(key.len(), LINEAR_SYNC_LINK_KEY_PREFIX.len() + 16);
}
