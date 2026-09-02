//! Mirror-adapter tests (ONE-1905). Everything here runs on injected fakes:
//! no vault, no network, and no Linear credential exists anywhere in the
//! crate for these tests to need.

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
        let found = self
            .links
            .values()
            .find(|link| link.issue.issue_id == issue.issue_id);
        Ok(found.cloned())
    }

    fn put_link(&mut self, link: &TaskIssueLink) -> LinearSyncResult<()> {
        self.links.insert(link.task_ref, link.clone());
        Ok(())
    }
}

/// Records every operation id it is handed; holds no credential, no client,
/// and no transport — exactly the shape the host implements behind the
/// outbound door.
#[derive(Debug, Default)]
struct FakeEgress {
    clock_ms: u64,
    created: usize,
    updated: usize,
    operations: Vec<[u8; 32]>,
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
    assert_eq!(store.stored_link(task_ref).issue_updated_at_ms, 6_000);
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
fn same_field_concurrent_edit_yields_a_conflict_and_mutates_neither_side() {
    let task_ref = task_id(0x17);
    let mut adapter = linked_adapter(task_ref, FakeSource::default());
    let store = adapter.tasks_mut();
    store.edit(task_ref, |fields| fields.title = "Engine".to_owned());
    let mut incoming = task_fields();
    incoming.title = "Tracker title".to_owned();

    let receipt = adapter
        .apply_issue_change(change("evt-1", 5_000, incoming), 40)
        .expect("conflict receipt");

    assert_eq!(receipt.status, LinearMirrorStatus::Conflict);
    assert_eq!(receipt.conflicts.len(), 1);
    let conflict = &receipt.conflicts[0];
    assert_eq!(conflict.field, LINEAR_FIELD_TITLE);
    assert_eq!(conflict.task_value.as_deref(), Some("Engine"));
    assert_eq!(conflict.issue_value.as_deref(), Some("Tracker title"));
    let store = adapter.tasks();
    assert_eq!(store.applies, 0);
    assert_eq!(store.snapshot(task_ref).fields.title, "Engine");
    assert_eq!(store.stored_link(task_ref).issue_updated_at_ms, 1_000);
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

#[test]
fn replaying_one_inbound_event_applies_it_once() {
    let task_ref = task_id(0x19);
    let mut adapter = linked_adapter(task_ref, FakeSource::default());
    let mut incoming = task_fields();
    incoming.status = "done".to_owned();

    let first = adapter
        .apply_issue_change(change("evt-1", 5_000, incoming.clone()), 40)
        .expect("first apply");
    let replay = adapter
        .apply_issue_change(change("evt-1", 5_000, incoming), 41)
        .expect("replay");

    assert_eq!(first.status, LinearMirrorStatus::Applied);
    assert_eq!(replay.status, LinearMirrorStatus::Noop);
    assert_eq!(adapter.tasks().applies, 1);
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
fn a_store_side_pull_watermark_also_suppresses_replays() {
    let task_ref = task_id(0x1d);
    let adapter = linked_adapter(task_ref, FakeSource::default());
    let link = adapter.tasks().stored_link(task_ref);
    let mut snapshot = adapter.tasks().snapshot(task_ref);
    snapshot.last_pulled_updated_at_ms = Some(9_000);
    let replay = change("evt-1", 5_000, task_fields());

    assert!(inbound_already_seen(&link, &snapshot, &replay, [0_u8; 32]));
}

#[test]
fn operation_ids_separate_direction_revision_and_operation_kind() {
    let task_ref = task_id(0x1e);
    let create = linear_operation_id(LinearSyncDirection::TaskToIssue, task_ref, 1, None, None);
    let repeat = linear_operation_id(LinearSyncDirection::TaskToIssue, task_ref, 1, None, None);
    let update = linear_operation_id(
        LinearSyncDirection::TaskToIssue,
        task_ref,
        1,
        Some("issue-1"),
        None,
    );
    let inbound = linear_operation_id(
        LinearSyncDirection::IssueToTask,
        task_ref,
        1,
        Some("issue-1"),
        Some(5_000),
    );
    let next = linear_operation_id(LinearSyncDirection::TaskToIssue, task_ref, 2, None, None);

    assert_eq!(create, repeat);
    assert_ne!(create, update);
    assert_ne!(update, inbound);
    assert_ne!(create, next);
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
    assert_eq!(registration.schema_version, 1);
    assert_eq!(registration.mirrored_fields.len(), 5);
    let engine_owned = registration.engine_authoritative_fields;
    assert!(engine_owned.contains(&"blocked_by"));
    let key = linear_sync_link_key(task_ref);
    assert!(key.starts_with(LINEAR_SYNC_LINK_KEY_PREFIX));
    assert_eq!(key.len(), LINEAR_SYNC_LINK_KEY_PREFIX.len() + 16);
}
