use super::*;
use crate::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::linear_sync::*;
use crate::wave_orchestration::*;
use crate::{EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

#[test]
fn wave_plan_attempt_lands_idempotent_tasks_and_dispatch_reads_live_blockers() -> WaveResult<()> {
    let dir = tempfile::tempdir().map_err(crate::Error::from)?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let facade = vault.memory(owner, EdgeActorClass::Human);
    let epic = facade
        .tasks_create(
            &TaskCreateSpec::new(Value::from("epic"), None, None, Some(100))
                .with_assignee(TaskAssignee::Peer { actor_ref: owner }),
        )
        .expect("epic")
        .task_ref
        .unwrap();
    vault.enqueue_wave_plan(epic, "cut the goal", serde_json::Value::Null, 100)?;
    let queue = AttemptQueue::new(&vault);
    let ClaimOutcome::Claimed(attempt) = queue.claim_kind(
        WAVE_PLAN_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: "planner".into(),
            now: 100,
        },
    )?
    else {
        panic!("planning attempt");
    };
    let plan = WavePlan {
        schema_version: 1,
        plan_ref: "test-plan".into(),
        epic_task_ref: epic,
        tasks: vec![
            PlannedTask {
                local_key: "a".into(),
                label: "first".into(),
                spec: serde_json::json!({"work": 1}),
                assignee_ref: None,
                blocked_by: vec![],
            },
            PlannedTask {
                local_key: "b".into(),
                label: "second".into(),
                spec: serde_json::json!({"work": 2}),
                assignee_ref: None,
                blocked_by: vec!["a".into()],
            },
        ],
    };
    let receipt =
        vault.apply_wave_plan_attempt(owner, EdgeActorClass::Human, &attempt, plan.clone(), 100)?;
    let replay =
        vault.apply_wave_plan_attempt(owner, EdgeActorClass::Human, &attempt, plan.clone(), 101)?;
    assert_eq!(receipt.task_refs, replay.task_refs);
    assert_eq!(receipt.blocked_by_edges, 1);
    let a = receipt.task_refs["a"];
    let b = receipt.task_refs["b"];
    assert_eq!(vault.targets(&b, EdgeKind::BlockedBy, None)?, vec![a]);
    let orchestration =
        WaveOrchestrator::new(VaultWaveTaskPort::new(&vault, owner, EdgeActorClass::Human));
    assert_eq!(orchestration.ready_set(&[a, b])?, vec![a]);
    let claim = || {
        queue.claim_kind(
            super::consts::TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "executor".into(),
                now: 101,
            },
        )
    };
    let ClaimOutcome::Claimed(first) = claim()? else {
        panic!("ready first task");
    };
    assert_eq!(first.task_ref.as_deref(), Some(a.to_hex().as_str()));
    assert!(matches!(claim()?, ClaimOutcome::Empty));
    facade
        .land_task_result(
            a,
            &TaskResultInput {
                result_ref: owner,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: 102,
            },
        )
        .expect("land");
    assert_eq!(orchestration.ready_set(&[b])?, vec![b]);
    let ClaimOutcome::Claimed(second) = claim()? else {
        panic!("unblocked second task");
    };
    assert_eq!(second.task_ref.as_deref(), Some(b.to_hex().as_str()));
    assert!(
        blocked_by_edge_write(
            a,
            crate::registry::ENTITY_TYPE_PERSON,
            b,
            crate::registry::ENTITY_TYPE_TASK
        )
        .is_err()
    );
    let mut changed = plan;
    changed.tasks[0].label = "changed".into();
    assert!(
        vault
            .apply_wave_plan_attempt(owner, EdgeActorClass::Human, &attempt, changed, 103)
            .is_err()
    );
    Ok(())
}

#[test]
fn wave_task_counts_follow_injected_window_and_rollover() -> WaveResult<()> {
    let clock = crate::ports::ManualClock::new(100);
    let config = VaultConfig {
        store_clock: clock.bundle(),
        ..VaultConfig::default()
    };
    let dir = tempfile::tempdir().map_err(crate::Error::from)?;
    let vault = Vault::open(dir.path(), config)?;
    let owner = EntityId::from_bytes([0x42; 16])?;
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let facade = vault.memory(owner, EdgeActorClass::Human);
    let epic = facade
        .tasks_create(
            &TaskCreateSpec::new(Value::from("epic"), None, None, Some(100))
                .with_assignee(TaskAssignee::Peer { actor_ref: owner }),
        )
        .expect("epic")
        .task_ref
        .expect("task");
    assert_eq!(vault.task_create_count(owner, 60)?, 1);
    vault.enqueue_wave_plan(epic, "cut", serde_json::Value::Null, 100)?;
    let ClaimOutcome::Claimed(attempt) = AttemptQueue::new(&vault).claim_kind(
        WAVE_PLAN_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: "planner".into(),
            now: 100,
        },
    )?
    else {
        panic!("planning attempt")
    };
    let plan = WavePlan {
        schema_version: 1,
        plan_ref: "injected-window".into(),
        epic_task_ref: epic,
        tasks: vec![PlannedTask {
            local_key: "first".into(),
            label: "work".into(),
            spec: serde_json::json!({"work": 1}),
            assignee_ref: None,
            blocked_by: vec![],
        }],
    };
    vault.apply_wave_plan_attempt(owner, EdgeActorClass::Human, &attempt, plan, 100)?;
    assert_eq!(vault.task_create_count(owner, 60)?, 2);
    clock.set(160);
    assert_eq!(vault.task_create_count(owner, 60)?, 0);
    facade
        .tasks_create(
            &TaskCreateSpec::new(Value::from("next"), None, None, Some(160))
                .with_assignee(TaskAssignee::Peer { actor_ref: owner }),
        )
        .expect("next task");
    assert_eq!(vault.task_create_count(owner, 60)?, 1);
    Ok(())
}

#[derive(Clone)]
struct Tracker {
    changes: Rc<RefCell<Vec<LinearIssueChange>>>,
    cursors: Rc<RefCell<Vec<Option<String>>>>,
    current: Rc<RefCell<BTreeMap<String, LinearIssueChange>>>,
    updates: Rc<RefCell<usize>>,
    more: Rc<std::cell::Cell<bool>>,
}
impl LinearChangeSource for Tracker {
    fn current_issue(&mut self, issue: &LinearIssueRef) -> LinearSyncResult<LinearIssueChange> {
        self.current
            .borrow()
            .get(&issue.issue_id)
            .cloned()
            .ok_or_else(|| LinearSyncError::Transport("missing current tracker issue".into()))
    }

    fn changes_since(&mut self, cursor: Option<&str>) -> LinearSyncResult<LinearChangePage> {
        self.cursors.borrow_mut().push(cursor.map(str::to_owned));
        let changes = std::mem::take(&mut *self.changes.borrow_mut());
        for change in &changes {
            self.current
                .borrow_mut()
                .insert(change.issue.issue_id.clone(), change.clone());
        }
        Ok(LinearChangePage {
            next_cursor: (!changes.is_empty()).then(|| "next".into()),
            changes,
            has_more: self.more.replace(false),
        })
    }
}
impl LinearEgress for Tracker {
    fn create_issue(
        &mut self,
        _: [u8; 32],
        task: EntityId,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        let change = LinearIssueChange {
            unmapped_assignee: false,
            event_id: format!("create-{}", task.to_hex()),
            issue: LinearIssueRef {
                issue_id: task.to_hex(),
                team_id: "team".into(),
                identifier: "ISSUE-1".into(),
            },
            updated_at_ms: 1000,
            fields: fields.clone(),
        };
        self.current
            .borrow_mut()
            .insert(change.issue.issue_id.clone(), change.clone());
        Ok(change)
    }
    fn update_issue(
        &mut self,
        _: [u8; 32],
        issue: &LinearIssueRef,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        *self.updates.borrow_mut() += 1;
        let change = LinearIssueChange {
            unmapped_assignee: false,
            event_id: format!("update-{}", issue.issue_id),
            issue: issue.clone(),
            updated_at_ms: 2000,
            fields: fields.clone(),
        };
        self.current
            .borrow_mut()
            .insert(issue.issue_id.clone(), change.clone());
        Ok(change)
    }
}

#[test]
fn scheduled_mirror_preflights_linked_issue_before_full_snapshot_push() -> LinearSyncResult<()> {
    let dir = tempfile::tempdir().map_err(crate::Error::from)?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let task = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(
            &TaskCreateSpec::new(Value::from("work"), Some("base".into()), None, Some(100))
                .with_assignee(TaskAssignee::Peer { actor_ref: owner }),
        )
        .expect("task")
        .task_ref
        .unwrap();
    let tracker = Tracker {
        changes: Rc::new(RefCell::new(Vec::new())),
        cursors: Rc::new(RefCell::new(Vec::new())),
        current: Rc::new(RefCell::new(BTreeMap::new())),
        updates: Rc::new(RefCell::new(0)),
        more: Rc::new(std::cell::Cell::new(false)),
    };
    let mut adapter = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        tracker.clone(),
        tracker.clone(),
    );
    assert_eq!(
        adapter.synchronize(100)?.0[0].status,
        LinearMirrorStatus::Linked
    );
    let initial = adapter.tasks().task_snapshot(task)?;
    let issue = adapter.tasks().link(task)?.expect("link").issue;
    let mut local = initial.fields.clone();
    local.title = "local".into();
    adapter
        .tasks_mut()
        .apply_issue_fields(task, initial.revision, &local, 101)?;
    let mut remote = initial.fields;
    remote.title = "remote".into();
    remote.status = "remote-status".into();
    tracker.current.borrow_mut().insert(
        issue.issue_id.clone(),
        LinearIssueChange {
            unmapped_assignee: false,
            event_id: "remote-before-scheduled-push".into(),
            issue: issue.clone(),
            updated_at_ms: 2000,
            fields: remote.clone(),
        },
    );
    // The remote event is NOT in a cursor page; only the exact-issue preflight
    // can prevent the scheduled full snapshot from overwriting it.
    let (pushed, _) = adapter.synchronize(102)?;
    assert_eq!(pushed[0].status, LinearMirrorStatus::Conflict);
    assert_eq!(*tracker.updates.borrow(), 0);
    assert_eq!(tracker.current.borrow()[&issue.issue_id].fields, remote);
    let stored = adapter.tasks().task_snapshot(task)?;
    assert_eq!(stored.fields.title, "local");
    assert_eq!(stored.fields.status, "remote-status");
    assert!(!adapter.tasks().dirty_tasks()?.is_empty());
    Ok(())
}

#[test]
fn linear_vault_occ_cas_reverse_lookup_and_production_push_poll() -> LinearSyncResult<()> {
    let dir = tempfile::tempdir().map_err(crate::Error::from)?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let task = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(
            &TaskCreateSpec::new(Value::from("work"), Some("title".into()), None, Some(100))
                .with_assignee(TaskAssignee::Peer { actor_ref: owner }),
        )
        .expect("create")
        .task_ref
        .unwrap();
    let tracker = Tracker {
        changes: Rc::new(RefCell::new(Vec::new())),
        cursors: Rc::new(RefCell::new(Vec::new())),
        current: Rc::new(RefCell::new(BTreeMap::new())),
        updates: Rc::new(RefCell::new(0)),
        more: Rc::new(std::cell::Cell::new(false)),
    };
    let mut adapter = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        tracker.clone(),
        tracker.clone(),
    );
    let (pushed, _) = adapter.synchronize(100)?;
    assert_eq!(pushed.len(), 1);
    assert_eq!(pushed[0].status, LinearMirrorStatus::Linked);
    assert!(adapter.tasks().dirty_tasks()?.is_empty());
    assert_eq!(*tracker.cursors.borrow(), vec![None]);
    let original = adapter.tasks().task_snapshot(task)?;
    let link = adapter.tasks().link(task)?.unwrap();
    assert_eq!(
        adapter.tasks().link_for_issue(&link.issue)?,
        Some(link.clone())
    );
    let mut new_fields = original.fields.clone();
    new_fields.description = Some("tracker description".into());
    let inbound = LinearIssueChange {
        unmapped_assignee: false,
        event_id: "inbound-edit".into(),
        issue: link.issue.clone(),
        updated_at_ms: 3000,
        fields: new_fields.clone(),
    };
    tracker
        .current
        .borrow_mut()
        .insert(link.issue.issue_id.clone(), inbound.clone());
    tracker.changes.borrow_mut().push(inbound);
    let (_, pulled) = adapter.synchronize(101)?;
    assert_eq!(pulled.applied, 1);
    assert_eq!(adapter.tasks().task_snapshot(task)?.fields, new_fields);
    assert!(matches!(
        adapter
            .tasks_mut()
            .apply_issue_fields(task, original.revision, &new_fields, 102),
        Err(LinearSyncError::Conflict { .. })
    ));
    let stale = TaskIssueLink {
        link_revision: link.link_revision + 1,
        ..link.clone()
    };
    assert!(matches!(
        adapter
            .tasks_mut()
            .put_link(Some(link.link_revision), &stale),
        Err(LinearSyncError::LinkConflict { .. })
    ));
    let old_revision = adapter.tasks().task_snapshot(task)?.revision;
    vault
        .memory(owner, EdgeActorClass::Human)
        .mark_task_started(task, 103)
        .expect("started");
    assert!(adapter.tasks().task_snapshot(task)?.revision > old_revision);
    assert!(!adapter.tasks().acknowledge_push(task, old_revision)?);
    vault
        .memory(owner, EdgeActorClass::Human)
        .land_task_result(
            task,
            &TaskResultInput {
                result_ref: owner,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: 104,
            },
        )
        .expect("completed before restart");
    let before_close = adapter.tasks().link(task)?;
    drop(adapter);
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    assert_eq!(VaultLinearTaskStore::new(&vault).link(task)?, before_close);
    let mut reopened = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        tracker.clone(),
        tracker.clone(),
    );
    let (pushed, _) = reopened.synchronize(104)?;
    assert_eq!(pushed.len(), 1);
    assert_eq!(pushed[0].status, LinearMirrorStatus::Applied);
    assert!(reopened.tasks().dirty_tasks()?.is_empty());
    assert_eq!(
        *tracker.cursors.borrow(),
        vec![None, None, Some("next".into())]
    );
    assert!(reopened.synchronize(105)?.0.is_empty());
    Ok(())
}

#[test]
fn scheduled_linear_pull_blocks_same_field_overwrite_before_egress() -> LinearSyncResult<()> {
    let dir = tempfile::tempdir().map_err(crate::Error::from)?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let task = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            Value::from("work"),
            Some("original".into()),
            None,
            Some(100),
        ))
        .expect("task")
        .task_ref
        .unwrap();
    let tracker = Tracker {
        changes: Rc::new(RefCell::new(Vec::new())),
        cursors: Rc::new(RefCell::new(Vec::new())),
        current: Rc::new(RefCell::new(BTreeMap::new())),
        updates: Rc::new(RefCell::new(0)),
        more: Rc::new(std::cell::Cell::new(false)),
    };
    let mut adapter = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        tracker.clone(),
        tracker.clone(),
    );
    let (created, _) = adapter.synchronize(100)?;
    assert_eq!(created[0].status, LinearMirrorStatus::Linked);
    let link = adapter.tasks().link(task)?.unwrap();
    let old = adapter.tasks().task_snapshot(task)?;
    let mut local = old.fields.clone();
    local.description = Some("local edit".into());
    adapter
        .tasks_mut()
        .apply_issue_fields(task, old.revision, &local, 101)?;
    let mut remote = old.fields;
    remote.description = Some("remote edit".into());
    tracker.changes.borrow_mut().push(LinearIssueChange {
        unmapped_assignee: false,
        event_id: "remote-change".into(),
        issue: link.issue,
        updated_at_ms: 3000,
        fields: remote,
    });
    let (pushed, pulled) = adapter.synchronize(102)?;
    assert_eq!(pulled.conflicts.len(), 1);
    assert_eq!(pushed[0].status, LinearMirrorStatus::Conflict);
    assert_eq!(
        *tracker.updates.borrow(),
        0,
        "remote edit must not be overwritten"
    );
    assert_eq!(adapter.tasks().dirty_tasks()?.len(), 1);
    Ok(())
}

#[test]
fn scheduled_linear_final_pages_push_and_restart_from_the_saved_checkpoint() -> LinearSyncResult<()>
{
    let dir = tempfile::tempdir().map_err(crate::Error::from)?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let create_task = |vault: &Vault, label: &str| {
        vault
            .memory(owner, EdgeActorClass::Human)
            .tasks_create(&TaskCreateSpec::new(
                Value::from("work"),
                Some(label.into()),
                None,
                Some(100),
            ))
            .expect("create TASK")
            .task_ref
            .unwrap()
    };
    let anchor = create_task(&vault, "anchor");
    let tracker = Tracker {
        changes: Rc::new(RefCell::new(Vec::new())),
        cursors: Rc::new(RefCell::new(Vec::new())),
        current: Rc::new(RefCell::new(BTreeMap::new())),
        updates: Rc::new(RefCell::new(0)),
        more: Rc::new(std::cell::Cell::new(false)),
    };
    let mut adapter = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        tracker.clone(),
        tracker.clone(),
    );
    assert_eq!(adapter.synchronize(100)?.0.len(), 1);
    let link = adapter.tasks().link(anchor)?.unwrap();
    for n in 0..2 {
        let pending = create_task(&vault, &format!("pending-{n}"));
        let mut remote = adapter.tasks().task_snapshot(anchor)?.fields;
        remote.description = Some(format!("tracker edit {n}"));
        tracker.changes.borrow_mut().push(LinearIssueChange {
            unmapped_assignee: false,
            event_id: format!("remote-{n}"),
            issue: link.issue.clone(),
            updated_at_ms: 2000 + n,
            fields: remote,
        });
        let (pushed, pulled) = adapter.synchronize(101 + n)?;
        assert_eq!(pulled.applied, 1);
        assert_eq!(pulled.new_cursor.as_deref(), Some("next"));
        assert!(
            !pulled.has_more,
            "final nonempty page cannot starve outbound"
        );
        assert!(pushed.iter().any(|receipt| receipt.task_ref == pending));
        assert!(adapter.tasks().dirty_tasks()?.is_empty());
    }
    let before_close = adapter.tasks().link(anchor)?;
    drop(adapter);
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    assert_eq!(
        VaultLinearTaskStore::new(&vault).link(anchor)?,
        before_close
    );
    let pending = create_task(&vault, "after-restart");
    let mut reopened = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        tracker.clone(),
        tracker.clone(),
    );
    let mut remote = reopened.tasks().task_snapshot(anchor)?.fields;
    remote.description = Some("after restart".into());
    tracker.changes.borrow_mut().push(LinearIssueChange {
        unmapped_assignee: false,
        event_id: "remote-after-restart".into(),
        issue: link.issue.clone(),
        updated_at_ms: 3000,
        fields: remote,
    });
    let (pushed, pulled) = reopened.synchronize(110)?;
    assert_eq!(
        tracker.cursors.borrow().last().cloned(),
        Some(Some("next".into()))
    );
    assert_eq!(pulled.applied, 1);
    assert!(pushed.iter().any(|receipt| receipt.task_ref == pending));
    assert!(reopened.tasks().dirty_tasks()?.is_empty());

    // A true multi-page continuation defers writes but persists its cursor.
    let pending = create_task(&vault, "pending-page");
    tracker.more.set(true);
    let mut next = reopened.tasks().task_snapshot(anchor)?.fields;
    next.description = Some("page one".into());
    tracker.changes.borrow_mut().push(LinearIssueChange {
        unmapped_assignee: false,
        event_id: "remote-page-one".into(),
        issue: link.issue,
        updated_at_ms: 4000,
        fields: next,
    });
    let (pushed, first) = reopened.synchronize(111)?;
    assert!(first.has_more);
    assert!(pushed.is_empty());
    assert!(
        reopened
            .tasks()
            .dirty_tasks()?
            .iter()
            .any(|(task, _)| *task == pending)
    );
    let (pushed, final_page) = reopened.synchronize(112)?;
    assert!(!final_page.has_more);
    assert!(pushed.iter().any(|receipt| receipt.task_ref == pending));
    assert!(reopened.tasks().dirty_tasks()?.is_empty());
    Ok(())
}

#[test]
fn raw_task_write_has_no_mirror_actor_and_cannot_hold_later_tasks() -> LinearSyncResult<()> {
    let dir = tempfile::tempdir().map_err(crate::Error::from)?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let create = |label: &str| {
        vault
            .memory(owner, EdgeActorClass::Human)
            .tasks_create(&TaskCreateSpec::new(
                Value::from("work"),
                Some(label.into()),
                None,
                Some(100),
            ))
            .unwrap()
            .task_ref
            .unwrap()
    };
    let raw = create("raw task");
    let trusted = create("trusted task");
    let mut body = super::wire_decode::task_verb_body(&vault, raw)?.unwrap();
    body.label = Some("unattributed update".into());
    vault.put_entity(
        &raw,
        crate::registry::ENTITY_TYPE_TASK,
        TimeRange {
            start: 101,
            end: 101,
        },
        101,
        &super::wire_encode::encode_task_verb_body(body),
    )?;
    let store = VaultLinearTaskStore::new(&vault);
    assert!(store.dirty_writer(raw)?.is_none());
    assert_eq!(store.dirty_writer(trusted)?.unwrap().actor_ref, owner);
    let tracker = Tracker {
        changes: Rc::new(RefCell::new(Vec::new())),
        cursors: Rc::new(RefCell::new(Vec::new())),
        current: Rc::new(RefCell::new(BTreeMap::new())),
        updates: Rc::new(RefCell::new(0)),
        more: Rc::new(std::cell::Cell::new(false)),
    };
    let mut adapter = LinearSyncAdapter::new(store, tracker.clone(), tracker);
    let (pushed, pulled) = adapter.synchronize(102)?;
    assert_eq!(pulled.refused_outbound, vec![raw]);
    assert!(pushed.iter().any(|receipt| receipt.task_ref == trusted));
    assert_eq!(adapter.tasks().dirty_tasks()?, vec![(raw, 2)]);
    Ok(())
}

#[test]
fn inbound_merge_preserves_verified_writer_for_unsent_local_terminal() -> LinearSyncResult<()> {
    let dir = tempfile::tempdir().map_err(crate::Error::from)?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let facade = vault.memory(owner, EdgeActorClass::Human);
    let task = facade
        .tasks_create(&TaskCreateSpec::new(
            Value::from("work"),
            Some("title".into()),
            None,
            Some(100),
        ))
        .unwrap()
        .task_ref
        .unwrap();
    let tracker = Tracker {
        changes: Rc::new(RefCell::new(Vec::new())),
        cursors: Rc::new(RefCell::new(Vec::new())),
        current: Rc::new(RefCell::new(BTreeMap::new())),
        updates: Rc::new(RefCell::new(0)),
        more: Rc::new(std::cell::Cell::new(false)),
    };
    let mut adapter = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        tracker.clone(),
        tracker.clone(),
    );
    assert_eq!(adapter.synchronize(100)?.0.len(), 1);
    let link = adapter.tasks().link(task)?.unwrap();
    facade
        .land_task_result(
            task,
            &TaskResultInput {
                result_ref: owner,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: 101,
            },
        )
        .unwrap();
    assert_eq!(
        adapter.tasks().dirty_writer(task)?.unwrap().actor_ref,
        owner
    );
    let mut remote = adapter.tasks().task_snapshot(task)?.fields;
    remote.status = "queued".into();
    remote.description = Some("tracker note".into());
    tracker.changes.borrow_mut().push(LinearIssueChange {
        unmapped_assignee: false,
        event_id: "remote-disjoint".into(),
        issue: link.issue,
        updated_at_ms: 3000,
        fields: remote,
    });
    let (pushed, pulled) = adapter.synchronize(102)?;
    assert_eq!(pulled.applied, 1);
    assert!(pulled.refused_outbound.is_empty());
    assert!(pushed.iter().any(|receipt| receipt.task_ref == task));
    assert_eq!(*tracker.updates.borrow(), 1);
    assert!(adapter.tasks().dirty_tasks()?.is_empty());
    Ok(())
}

#[test]
fn scheduled_linear_exports_working_without_a_terminal_result() -> LinearSyncResult<()> {
    let dir = tempfile::tempdir().map_err(crate::Error::from)?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let facade = vault.memory(owner, EdgeActorClass::Human);
    let task = facade
        .tasks_create(&TaskCreateSpec::new(
            Value::from("work"),
            Some("title".into()),
            None,
            Some(100),
        ))
        .unwrap()
        .task_ref
        .unwrap();
    let tracker = Tracker {
        changes: Rc::new(RefCell::new(Vec::new())),
        cursors: Rc::new(RefCell::new(Vec::new())),
        current: Rc::new(RefCell::new(BTreeMap::new())),
        updates: Rc::new(RefCell::new(0)),
        more: Rc::new(std::cell::Cell::new(false)),
    };
    let mut adapter = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        tracker.clone(),
        tracker.clone(),
    );
    assert_eq!(adapter.synchronize(100)?.0.len(), 1);
    facade.mark_task_started(task, 101).unwrap();
    assert_eq!(
        adapter.tasks().task_snapshot(task)?.fields.status,
        "working"
    );
    let (pushed, _) = adapter.synchronize(102)?;
    assert_eq!(pushed.len(), 1);
    assert_eq!(pushed[0].status, LinearMirrorStatus::Applied);
    assert_eq!(*tracker.updates.borrow(), 1);
    assert_eq!(
        adapter.tasks().task_snapshot(task)?.fields.status,
        "working"
    );
    assert_eq!(adapter.tasks().dirty_tasks()?.len(), 0);
    Ok(())
}

#[test]
fn interrupted_live_task_projects_tracker_status_without_forging_terminal() -> LinearSyncResult<()>
{
    let dir = tempfile::tempdir().map_err(crate::Error::from)?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let task = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            Value::from("work"),
            Some("title".into()),
            None,
            Some(100),
        ))
        .unwrap()
        .task_ref
        .unwrap();
    let tracker = Tracker {
        changes: Rc::new(RefCell::new(Vec::new())),
        cursors: Rc::new(RefCell::new(Vec::new())),
        current: Rc::new(RefCell::new(BTreeMap::new())),
        updates: Rc::new(RefCell::new(0)),
        more: Rc::new(std::cell::Cell::new(false)),
    };
    let mut adapter =
        LinearSyncAdapter::new(VaultLinearTaskStore::new(&vault), tracker.clone(), tracker);
    assert_eq!(adapter.synchronize(100)?.0.len(), 1);
    // An interrupted standard-task row can also be produced by the ladder.
    // Seed through the normal TASK batch door, then assert the production
    // snapshot keeps the live state separate from a terminal result.
    let mut body = super::wire_decode::task_verb_body(&vault, task)?.unwrap();
    body.state = Some(TaskExecutionState::Interrupted { ladder: None });
    vault.put_entity(
        &task,
        crate::registry::ENTITY_TYPE_TASK,
        TimeRange {
            start: 101,
            end: 101,
        },
        101,
        &super::wire_encode::encode_task_verb_body(body),
    )?;
    assert_eq!(
        adapter.tasks().task_snapshot(task)?.fields.status,
        "interrupted"
    );
    let row = super::wire_decode::task_verb_body(&vault, task)?.unwrap();
    assert!(row.terminal().is_none());
    Ok(())
}

#[test]
fn unrelated_unmapped_inbound_issue_does_not_hold_outbound_task() -> LinearSyncResult<()> {
    let dir = tempfile::tempdir().map_err(crate::Error::from)?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let task = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            Value::from("work"),
            Some("authorized".into()),
            None,
            Some(100),
        ))
        .unwrap()
        .task_ref
        .unwrap();
    let tracker = Tracker {
        changes: Rc::new(RefCell::new(vec![LinearIssueChange {
            unmapped_assignee: true,
            event_id: "outside".into(),
            issue: LinearIssueRef {
                issue_id: "unlinked".into(),
                team_id: "team".into(),
                identifier: "TEAM-9".into(),
            },
            updated_at_ms: 2000,
            fields: MirroredTaskFields {
                title: "outside".into(),
                description: None,
                priority: None,
                assignee_ref: Some("unknown-provider-user".into()),
                status: "queued".into(),
            },
        }])),
        cursors: Rc::new(RefCell::new(Vec::new())),
        current: Rc::new(RefCell::new(BTreeMap::new())),
        updates: Rc::new(RefCell::new(0)),
        more: Rc::new(std::cell::Cell::new(false)),
    };
    let mut adapter =
        LinearSyncAdapter::new(VaultLinearTaskStore::new(&vault), tracker.clone(), tracker);
    let (pushed, pulled) = adapter.synchronize(101)?;
    assert_eq!(pulled.skipped_echo, 1);
    assert!(pulled.refused_inbound.is_empty());
    assert_eq!(pushed.len(), 1);
    assert_eq!(pushed[0].task_ref, task);
    assert!(adapter.tasks().dirty_tasks()?.is_empty());
    Ok(())
}

#[test]
fn linked_unmapped_inbound_issue_is_replayed_without_blocking_outbound() -> LinearSyncResult<()> {
    let dir = tempfile::tempdir().map_err(crate::Error::from)?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let create = |label: &str| {
        vault
            .memory(owner, EdgeActorClass::Human)
            .tasks_create(&TaskCreateSpec::new(
                Value::from("work"),
                Some(label.into()),
                None,
                Some(100),
            ))
            .unwrap()
            .task_ref
            .unwrap()
    };
    let linked = create("linked");
    let tracker = Tracker {
        changes: Rc::new(RefCell::new(Vec::new())),
        cursors: Rc::new(RefCell::new(Vec::new())),
        current: Rc::new(RefCell::new(BTreeMap::new())),
        updates: Rc::new(RefCell::new(0)),
        more: Rc::new(std::cell::Cell::new(false)),
    };
    let mut adapter = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        tracker.clone(),
        tracker.clone(),
    );
    adapter.synchronize(100)?;
    let link_before = adapter.tasks().link(linked)?.unwrap();
    let issue = link_before.issue.clone();
    let pending = create("later");
    let before = adapter.tasks().task_snapshot(linked)?;
    tracker.changes.borrow_mut().push(LinearIssueChange {
        unmapped_assignee: true,
        event_id: "unknown".into(),
        issue: issue.clone(),
        updated_at_ms: 3000,
        fields: MirroredTaskFields {
            assignee_ref: Some("unknown-provider-user".into()),
            ..before.fields.clone()
        },
    });
    let (pushed, pulled) = adapter.synchronize(101)?;
    assert_eq!(pulled.refused_inbound, vec![issue]);
    assert_eq!(
        adapter.tasks().inbound_refusals()?,
        vec![link_before.issue.clone()]
    );
    assert_eq!(
        pulled.new_cursor, None,
        "the rejected page must replay after mapping"
    );
    assert!(pushed.iter().any(|receipt| receipt.task_ref == pending));
    assert_eq!(adapter.tasks().task_snapshot(linked)?.fields, before.fields);
    assert_eq!(adapter.tasks().link(linked)?, Some(link_before));
    Ok(())
}
