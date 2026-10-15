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

    fn update_issue_conditional(
        &mut self,
        operation_id: [u8; 32],
        issue: &LinearIssueRef,
        _expected_base: &BTreeMap<String, [u8; 32]>,
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

    // A stale payload must not overwrite the TASK behind the link watermark.
    let mut incoming = task_fields();
    incoming.status = "done".to_owned();
    let behind_link = adapter
        .apply_issue_change(change("evt-behind-link", 5_000, incoming.clone()), 42)
        .expect("behind link watermark");
    assert_eq!(behind_link.status, LinearMirrorStatus::Noop);
    assert_eq!(adapter.tasks().applies, 0);
    assert_eq!(adapter.tasks().snapshot(task_ref).revision, 1);
    assert_eq!(adapter.tasks().snapshot(task_ref).fields.status, "todo");

    // Preserve the independent store-watermark guard as well as the link
    // watermark exercised above.
    let mut snapshot = adapter.tasks().snapshot(task_ref);
    snapshot.last_pulled_updated_at_ms = Some(9_000);
    adapter.tasks_mut().snapshots.insert(task_ref, snapshot);
    let replay = change("evt-behind-store", 8_000, incoming);
    let receipt = adapter
        .apply_issue_change(replay, 43)
        .expect("behind store watermark");
    assert_eq!(receipt.status, LinearMirrorStatus::Noop);
    let store = adapter.tasks();
    assert_eq!(store.applies, 0);
    assert_eq!(store.snapshot(task_ref).revision, 1);
    for field in LINEAR_MIRRORED_FIELDS {
        assert_eq!(
            store.snapshot(task_ref).fields.field_value(field),
            task_fields().field_value(field),
        );
    }
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
        .apply_issue_change(change(" \t\n", 5_000, incoming.clone()), 40)
        .expect_err("blank event id");

    assert!(matches!(
        error,
        LinearSyncError::Store(crate::error::Error::InvariantViolation(_))
    ));
    let store = adapter.tasks();
    assert_eq!(store.issue_link_lookups.get(), 0);
    assert_eq!(store.applies, 0);
    let after_snapshot = store.snapshot(task_ref);
    assert_eq!(after_snapshot.task_ref, before_snapshot.task_ref);
    assert_eq!(after_snapshot.revision, before_snapshot.revision);
    assert_eq!(
        after_snapshot.issue.as_ref().map(|issue| &issue.issue_id),
        before_snapshot.issue.as_ref().map(|issue| &issue.issue_id),
    );
    for field in LINEAR_MIRRORED_FIELDS {
        assert_eq!(
            after_snapshot.fields.field_value(field),
            before_snapshot.fields.field_value(field),
        );
    }
    let after_link = store.stored_link(task_ref);
    for event_id in ["evt-create-1", " \t\n"] {
        assert_eq!(
            after_link.has_seen_event(event_id),
            before_link.has_seen_event(event_id),
        );
    }

    // The rejected event must leave neither a push barrier nor a watermark
    // that suppresses a subsequent valid change.
    let push = adapter.push_task(task_ref, 41).expect("unchanged push");
    assert_eq!(push.status, LinearMirrorStatus::Noop);
    let valid = adapter
        .apply_issue_change(change("evt-valid", 4_000, incoming), 42)
        .expect("valid change after rejection");
    assert_eq!(valid.status, LinearMirrorStatus::Applied);
    assert_eq!(adapter.tasks().snapshot(task_ref).fields.status, "done");
    assert_eq!(adapter.tasks().applies, 1);
    let (_, _, egress) = adapter.into_parts();
    assert_eq!(egress.created, 1);
    assert_eq!(egress.updated, 0);
}

/// The changed helper shape: the inbound key is `(issue_id,
/// issue_updated_at_ms, event_id)`, and the event id is the component that
/// carries it. Two events at the same instant must mint different ids, while a
/// retry of one event against an unchanged revision must mint the same id.
#[test]
fn inbound_operation_ids_bind_the_event_id_not_only_the_timestamp() {
    let task_ref = task_id(0x1e);
    let inbound = |event_id: &str, updated_at_ms: u64| {
        let mut adapter = linked_adapter(task_ref, FakeSource::default());
        let mut incoming = task_fields();
        incoming.status = "done".to_owned();
        let receipt = adapter
            .apply_issue_change(change(event_id, updated_at_ms, incoming), 40)
            .expect("inbound change");
        assert_eq!(receipt.status, LinearMirrorStatus::Applied);
        assert_eq!(adapter.tasks().applies, 1);
        assert_eq!(adapter.tasks().snapshot(task_ref).fields.status, "done");
        receipt.operation_id
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
    // v4: event identity and link CAS remain, with a separate remote snapshot
    // hashes, so the row key namespace moves with the shape.
    assert_eq!(registration.schema_version, 4);
    assert!(LINEAR_LINKS.decl().prefix.ends_with(b"v4:"));
    assert_eq!(registration.mirrored_fields.len(), 5);
    let engine_owned = registration.engine_authoritative_fields;
    assert!(engine_owned.contains(&"blocked_by"));
    let key = LINEAR_LINKS.key_bytes(&task_ref);
    assert!(key.starts_with(LINEAR_LINKS.decl().prefix));
    assert_eq!(key.len(), LINEAR_LINKS.decl().prefix.len() + 16);
}

/// Unlike the older counter-only fake, this egress enforces the production
/// bridge contract against its actual current remote fields on every update.
#[derive(Clone)]
struct CasEgress {
    remote: std::rc::Rc<std::cell::RefCell<MirroredTaskFields>>,
    updates: std::rc::Rc<std::cell::Cell<usize>>,
}

impl LinearEgress for CasEgress {
    fn create_issue(
        &mut self,
        _operation_id: [u8; 32],
        _task_ref: EntityId,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        *self.remote.borrow_mut() = fields.clone();
        Ok(change("cas-created", 1_000, fields.clone()))
    }

    fn update_issue_conditional(
        &mut self,
        _operation_id: [u8; 32],
        issue: &LinearIssueRef,
        expected_remote: &BTreeMap<String, [u8; 32]>,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        if &self.remote.borrow().field_hashes() != expected_remote {
            return Err(LinearSyncError::RemoteChanged);
        }
        *self.remote.borrow_mut() = fields.clone();
        self.updates.set(self.updates.get() + 1);
        Ok(LinearIssueChange {
            event_id: format!("cas-update-{}", self.updates.get()),
            issue: issue.clone(),
            updated_at_ms: 10_000 + self.updates.get() as u64,
            fields: fields.clone(),
        })
    }
}

#[test]
fn resolved_conflict_uses_remote_snapshot_not_old_merge_base_for_cas() {
    for (seed, resolution, unrelated_event) in [
        (0xa1, "Tracker", false),
        (0xa2, "Agreed", true),
        (0xa3, "Ship the wave", false),
        (0xa4, "Ship the wave", true),
    ] {
        let task = task_id(seed);
        let initial = task_fields();
        let remote = std::rc::Rc::new(std::cell::RefCell::new(initial.clone()));
        let updates = std::rc::Rc::new(std::cell::Cell::new(0));
        let egress = CasEgress {
            remote: remote.clone(),
            updates: updates.clone(),
        };
        let mut adapter = LinearSyncAdapter::new(
            FakeStore::with_task(task, initial.clone()),
            FakeSource::default(),
            egress,
        );
        adapter.push_task(task, 10).expect("initial link");
        adapter
            .tasks_mut()
            .edit(task, |fields| fields.title = "Engine".into());
        let mut incoming = initial.clone();
        incoming.title = "Tracker".into();
        *remote.borrow_mut() = incoming.clone();
        let conflict = adapter
            .apply_issue_change(change("title-conflict", 5_000, incoming.clone()), 20)
            .expect("record conflict");
        assert_eq!(conflict.status, LinearMirrorStatus::Conflict);
        let pinned = adapter.tasks().stored_link(task);
        assert_eq!(
            pinned.base_field_hashes[LINEAR_FIELD_TITLE],
            initial.field_hashes()[LINEAR_FIELD_TITLE]
        );
        assert_eq!(pinned.remote_field_hashes, incoming.field_hashes());

        adapter
            .tasks_mut()
            .edit(task, |fields| fields.title = resolution.into());
        if unrelated_event {
            // An unrelated tracker event must neither re-pin a third-value
            // resolution nor overwrite a return to the original common base.
            incoming.status = "in_review".into();
            *remote.borrow_mut() = incoming.clone();
            adapter
                .apply_issue_change(
                    change("status-after-resolution", 6_000, incoming.clone()),
                    21,
                )
                .expect("merge unrelated event");
            let pending = adapter.tasks().stored_link(task);
            assert_eq!(
                pending.unresolved_conflicts.len(),
                1,
                "pending resolution keeps its witness"
            );
            assert_eq!(
                pending.base_field_hashes[LINEAR_FIELD_TITLE],
                initial.field_hashes()[LINEAR_FIELD_TITLE]
            );
            assert_eq!(pending.remote_field_hashes, incoming.field_hashes());
            assert_eq!(
                adapter.tasks().snapshot(task).fields.title,
                resolution,
                "unrelated inbound event must preserve local resolution"
            );
            assert_eq!(adapter.tasks().snapshot(task).fields.status, "in_review");
        }
        let receipt = adapter
            .push_task(task, 30)
            .expect("conditional resolution push");
        assert_eq!(receipt.status, LinearMirrorStatus::Applied);
        assert_eq!(updates.get(), 1);
        assert_eq!(remote.borrow().title, resolution);
        let settled = adapter.tasks().stored_link(task);
        assert!(settled.unresolved_conflicts.is_empty());
        assert_eq!(settled.base_field_hashes, remote.borrow().field_hashes());
        assert_eq!(settled.remote_field_hashes, remote.borrow().field_hashes());
        let replay = adapter
            .apply_issue_change(change("title-conflict", 5_000, incoming), 31)
            .expect("stale event replay");
        assert_eq!(replay.status, LinearMirrorStatus::Noop);
        assert_eq!(
            adapter.tasks().stored_link(task).remote_field_hashes,
            remote.borrow().field_hashes()
        );
    }
}
