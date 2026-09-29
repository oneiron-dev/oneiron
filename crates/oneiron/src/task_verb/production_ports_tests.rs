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
    // The TASKs and the planning attempt settle in the same commit. A caller
    // that stops after apply cannot leave a reclaimable planning lease.
    assert_eq!(
        queue.get(attempt.id)?.expect("planning row").state,
        crate::attempt_queue::AttemptState::Completed
    );
    assert!(
        vault
            .apply_wave_plan_attempt(owner, EdgeActorClass::Human, &attempt, plan.clone(), 101)
            .is_err()
    );
    assert_eq!(receipt.blocked_by_edges, 1);
    let a = receipt.task_refs["a"];
    let b = receipt.task_refs["b"];
    assert_eq!(vault.targets(&b, EdgeKind::BlockedBy, None)?, vec![a]);
    let orchestration =
        WaveOrchestrator::new(VaultWaveTaskPort::new(&vault, owner, EdgeActorClass::Human));
    assert_eq!(orchestration.ready_set(&[a, b])?, vec![a]);
    // The first raw TASK page is the non-wave epic. Even an empty filtered
    // page advances its cursor so the durable scan finds later wave TASKs.
    let first_page = vault.wave_dispatch_page(None, 1)?;
    assert!(first_page.task_refs.is_empty());
    assert!(!first_page.exhausted);
    let mut cursor = first_page.next_after;
    let mut recovered = Vec::new();
    for _ in 0..8 {
        let page = vault.wave_dispatch_page(cursor, 1)?;
        recovered.extend(page.task_refs);
        cursor = page.next_after;
        if page.exhausted {
            break;
        }
    }
    recovered.sort();
    let mut expected = vec![a, b];
    expected.sort();
    assert_eq!(recovered, expected);
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
    let mut cursor = None;
    let mut still_live = Vec::new();
    for _ in 0..8 {
        let page = vault.wave_dispatch_page(cursor, 1)?;
        still_live.extend(page.task_refs);
        cursor = page.next_after;
        if page.exhausted {
            break;
        }
    }
    assert_eq!(
        still_live,
        vec![b],
        "settled blocker is no longer a dispatch candidate"
    );
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
        Ok(LinearChangePage {
            changes: std::mem::take(&mut *self.changes.borrow_mut()),
            next_cursor: cursor.is_none().then(|| "next".to_owned()),
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
    fn update_issue_conditional(
        &mut self,
        _: [u8; 32],
        issue: &LinearIssueRef,
        expected_remote: &std::collections::BTreeMap<String, [u8; 32]>,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        if self
            .current
            .borrow()
            .get(&issue.issue_id)
            .map(|change| change.fields.field_hashes())
            .as_ref()
            != Some(expected_remote)
        {
            return Err(LinearSyncError::RemoteChanged);
        }
        *self.updates.borrow_mut() += 1;
        let change = LinearIssueChange {
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
fn scheduled_mirror_refuses_unpulled_remote_edit_at_conditional_push() -> LinearSyncResult<()> {
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
    };
    let mut adapter = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        tracker.clone(),
        tracker.clone(),
    );
    assert_eq!(
        adapter.synchronize(100, 64)?.0[0].status,
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
            event_id: "remote-before-scheduled-push".into(),
            issue: issue.clone(),
            updated_at_ms: 2000,
            fields: remote.clone(),
        },
    );
    // This edit has NOT reached the cursor page. The atomic remote-hash CAS
    // refuses the stale local full snapshot without a read-then-write window.
    assert!(matches!(
        adapter.synchronize(102, 64),
        Err(LinearSyncError::RemoteChanged)
    ));
    assert_eq!(*tracker.updates.borrow(), 0);
    assert_eq!(tracker.current.borrow()[&issue.issue_id].fields, remote);
    assert_eq!(adapter.tasks().task_snapshot(task)?.fields.title, "local");
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
    };
    let mut adapter = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        tracker.clone(),
        tracker.clone(),
    );
    let (pushed, _) = adapter.synchronize(100, 64)?;
    assert_eq!(pushed.len(), 1);
    assert_eq!(pushed[0].status, LinearMirrorStatus::Linked);
    assert!(adapter.tasks().dirty_tasks()?.is_empty());
    assert_eq!(*tracker.cursors.borrow(), vec![None, Some("next".into())]);
    let original = adapter.tasks().task_snapshot(task)?;
    let link = adapter.tasks().link(task)?.unwrap();
    assert_eq!(
        adapter.tasks().link_for_issue(&link.issue)?,
        Some(link.clone())
    );
    let mut new_fields = original.fields.clone();
    new_fields.description = Some("tracker description".into());
    let inbound = LinearIssueChange {
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
    let (_, pulled) = adapter.synchronize(101, 64)?;
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
    let (pushed, _) = reopened.synchronize(104, 64)?;
    assert_eq!(pushed.len(), 1);
    assert_eq!(pushed[0].status, LinearMirrorStatus::Applied);
    assert!(reopened.tasks().dirty_tasks()?.is_empty());
    assert_eq!(
        *tracker.cursors.borrow(),
        vec![
            None,
            Some("next".into()),
            Some("next".into()),
            Some("next".into())
        ]
    );
    assert!(reopened.synchronize(105, 64)?.0.is_empty());
    Ok(())
}

#[derive(Clone, Default)]
struct ControlledTracker {
    state: Rc<RefCell<ControlledState>>,
}

#[derive(Default)]
struct ControlledState {
    pages: std::collections::BTreeMap<String, LinearChangePage>,
    remote: std::collections::BTreeMap<String, MirroredTaskFields>,
    refused: Option<String>,
    race_change: Option<(String, MirroredTaskFields)>,
    operations: Vec<String>,
    updates: Vec<(String, MirroredTaskFields)>,
}

impl LinearChangeSource for ControlledTracker {
    fn changes_since(&mut self, cursor: Option<&str>) -> LinearSyncResult<LinearChangePage> {
        let mut state = self.state.borrow_mut();
        state
            .operations
            .push(format!("pull:{}", cursor.unwrap_or("start")));
        let page = state
            .pages
            .get(cursor.unwrap_or("start"))
            .cloned()
            .unwrap_or(LinearChangePage {
                changes: Vec::new(),
                next_cursor: None,
            });
        for change in &page.changes {
            state
                .remote
                .insert(change.issue.issue_id.clone(), change.fields.clone());
        }
        Ok(page)
    }
}

impl LinearEgress for ControlledTracker {
    fn create_issue(
        &mut self,
        _operation_id: [u8; 32],
        task: EntityId,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        let issue = LinearIssueRef {
            issue_id: task.to_hex(),
            team_id: "team".into(),
            identifier: task.to_hex(),
        };
        self.state
            .borrow_mut()
            .remote
            .insert(issue.issue_id.clone(), fields.clone());
        Ok(LinearIssueChange {
            event_id: format!("create-{}", task.to_hex()),
            issue,
            updated_at_ms: 1000,
            fields: fields.clone(),
        })
    }

    fn update_issue_conditional(
        &mut self,
        _operation_id: [u8; 32],
        issue: &LinearIssueRef,
        expected_base: &std::collections::BTreeMap<String, [u8; 32]>,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        let mut state = self.state.borrow_mut();
        state.operations.push(format!("push:{}", issue.issue_id));
        if let Some((id, changed)) = state.race_change.take() {
            state.remote.insert(id, changed);
        }
        if state.refused.as_deref() == Some(issue.issue_id.as_str()) {
            return Err(LinearSyncError::Transport(
                "permanently rejected issue".into(),
            ));
        }
        if state
            .remote
            .get(&issue.issue_id)
            .map(MirroredTaskFields::field_hashes)
            .as_ref()
            != Some(expected_base)
        {
            return Err(LinearSyncError::RemoteChanged);
        }
        state.remote.insert(issue.issue_id.clone(), fields.clone());
        state.updates.push((issue.issue_id.clone(), fields.clone()));
        Ok(LinearIssueChange {
            event_id: format!("update-{}", state.updates.len()),
            issue: issue.clone(),
            updated_at_ms: 2000 + state.updates.len() as u64,
            fields: fields.clone(),
        })
    }
}

fn mirror_fixture() -> LinearSyncResult<(tempfile::TempDir, Vault, EntityId)> {
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
    Ok((dir, vault, owner))
}

fn mirror_task(vault: &Vault, owner: EntityId, label: &str) -> EntityId {
    vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(
            &TaskCreateSpec::new(Value::from("work"), Some(label.to_owned()), None, Some(100))
                .with_assignee(TaskAssignee::Peer { actor_ref: owner }),
        )
        .expect("mirror TASK")
        .task_ref
        .expect("task ref")
}

fn terminal_task(vault: &Vault, owner: EntityId, task: EntityId, now: u64) {
    vault
        .memory(owner, EdgeActorClass::Human)
        .land_task_result(
            task,
            &TaskResultInput {
                result_ref: owner,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: now,
            },
        )
        .expect("complete mirrored TASK");
}

#[test]
fn scheduled_mirror_pulls_all_pages_before_dirty_full_snapshot_push() -> LinearSyncResult<()> {
    let (_dir, vault, owner) = mirror_fixture()?;
    let task = mirror_task(&vault, owner, "first");
    let tracker = ControlledTracker::default();
    let mut adapter = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        tracker.clone(),
        tracker.clone(),
    );
    adapter.synchronize(100, 64)?; // durable link at 1000
    let link = adapter.tasks().link(task)?.expect("linked");
    terminal_task(&vault, owner, task, 101);
    let mut remote = adapter.tasks().task_snapshot(task)?.fields;
    remote.status = "queued".into();
    remote.description = Some("remote edit at 1500".into());
    let mut state = tracker.state.borrow_mut();
    state.pages.insert(
        "start".into(),
        LinearChangePage {
            changes: vec![],
            next_cursor: Some("second".into()),
        },
    );
    state.pages.insert(
        "second".into(),
        LinearChangePage {
            changes: vec![LinearIssueChange {
                event_id: "human-edit".into(),
                issue: link.issue,
                updated_at_ms: 1500,
                fields: remote.clone(),
            }],
            next_cursor: None,
        },
    );
    state.operations.clear();
    drop(state);
    let (pushed, pulled) = adapter.synchronize(102, 64)?;
    assert_eq!(pulled.applied, 1);
    assert_eq!(pushed.len(), 1);
    assert_eq!(
        adapter.tasks().task_snapshot(task)?.fields.description,
        remote.description
    );
    let state = tracker.state.borrow();
    assert_eq!(state.operations[..2], ["pull:start", "pull:second"]);
    assert!(state.operations[2].starts_with("push:"));
    assert_eq!(
        state
            .updates
            .last()
            .expect("conditional update")
            .1
            .description,
        remote.description
    );
    Ok(())
}

#[test]
fn scheduled_mirror_rejection_keeps_first_dirty_but_moves_second_and_inbound()
-> LinearSyncResult<()> {
    let (_dir, vault, owner) = mirror_fixture()?;
    let a = mirror_task(&vault, owner, "a");
    let b = mirror_task(&vault, owner, "b");
    let c = mirror_task(&vault, owner, "c");
    let tracker = ControlledTracker::default();
    let mut adapter = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        tracker.clone(),
        tracker.clone(),
    );
    adapter.synchronize(100, 64)?;
    terminal_task(&vault, owner, a, 101);
    terminal_task(&vault, owner, b, 101);
    let (bad, good) = if a < b { (a, b) } else { (b, a) };
    let mut incoming = adapter.tasks().task_snapshot(c)?.fields;
    incoming.description = Some("unrelated inbound".into());
    let issue = adapter.tasks().link(c)?.expect("third link").issue;
    {
        let mut state = tracker.state.borrow_mut();
        state.refused = Some(bad.to_hex());
        state.pages.insert(
            "start".into(),
            LinearChangePage {
                changes: vec![LinearIssueChange {
                    event_id: "third-edit".into(),
                    issue,
                    updated_at_ms: 1500,
                    fields: incoming.clone(),
                }],
                next_cursor: None,
            },
        );
        state.operations.clear();
    }
    assert!(
        adapter.synchronize(102, 64).is_err(),
        "failed first item remains reported"
    );
    let dirty = adapter.tasks().dirty_tasks()?;
    assert!(dirty.iter().any(|(task, _)| *task == bad));
    assert!(!dirty.iter().any(|(task, _)| *task == good));
    assert_eq!(
        adapter.tasks().task_snapshot(c)?.fields.description,
        incoming.description
    );
    assert!(
        tracker
            .state
            .borrow()
            .updates
            .iter()
            .any(|(id, _)| id == &good.to_hex())
    );
    Ok(())
}

#[test]
fn conditional_push_refuses_remote_edit_racing_after_terminal_pull() -> LinearSyncResult<()> {
    let (_dir, vault, owner) = mirror_fixture()?;
    let task = mirror_task(&vault, owner, "race");
    let tracker = ControlledTracker::default();
    let mut adapter = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        tracker.clone(),
        tracker.clone(),
    );
    adapter.synchronize(100, 64)?;
    terminal_task(&vault, owner, task, 101);
    let mut raced = adapter.tasks().task_snapshot(task)?.fields;
    raced.status = "queued".into();
    raced.description = Some("human race".into());
    tracker.state.borrow_mut().race_change = Some((task.to_hex(), raced.clone()));
    assert!(matches!(
        adapter.synchronize(102, 64),
        Err(LinearSyncError::RemoteChanged)
    ));
    assert!(
        adapter
            .tasks()
            .dirty_tasks()?
            .iter()
            .any(|(id, _)| *id == task)
    );
    assert!(
        tracker.state.borrow().updates.is_empty(),
        "no remote overwrite"
    );
    let issue = adapter.tasks().link(task)?.expect("link").issue;
    tracker.state.borrow_mut().pages.insert(
        "start".into(),
        LinearChangePage {
            changes: vec![LinearIssueChange {
                event_id: "raced-human-edit".into(),
                issue,
                updated_at_ms: 1500,
                fields: raced.clone(),
            }],
            next_cursor: None,
        },
    );
    adapter.synchronize(103, 64)?;
    assert_eq!(
        adapter.tasks().task_snapshot(task)?.fields.description,
        raced.description
    );
    assert_eq!(
        tracker
            .state
            .borrow()
            .updates
            .last()
            .expect("merged push")
            .1
            .description,
        raced.description
    );
    Ok(())
}

#[test]
fn working_task_pushes_authoritative_status_before_terminal_settlement() -> LinearSyncResult<()> {
    let (_dir, vault, owner) = mirror_fixture()?;
    let task = mirror_task(&vault, owner, "working status");
    let tracker = ControlledTracker::default();
    let mut adapter = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        tracker.clone(),
        tracker.clone(),
    );
    let (created, _) = adapter.synchronize(100, 64)?;
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].status, LinearMirrorStatus::Linked);
    assert_eq!(
        tracker.state.borrow().remote[&task.to_hex()].status,
        "queued"
    );

    vault
        .memory(owner, EdgeActorClass::Human)
        .mark_task_started(task, 101)
        .expect("start work");
    let working = adapter.tasks().task_snapshot(task)?;
    assert_eq!(working.fields.status, "working");
    let (pushed, _) = adapter.synchronize(102, 64)?;
    assert_eq!(pushed.len(), 1);
    assert_eq!(pushed[0].status, LinearMirrorStatus::Applied);
    assert_eq!(
        tracker.state.borrow().remote[&task.to_hex()].status,
        "working"
    );
    assert!(adapter.tasks().dirty_tasks()?.is_empty());
    Ok(())
}

#[test]
fn raw_task_write_has_no_verified_mirror_writer() -> LinearSyncResult<()> {
    let (_dir, vault, owner) = mirror_fixture()?;
    let raw = mirror_task(&vault, owner, "raw task");
    let trusted = mirror_task(&vault, owner, "trusted task");
    let mut body = super::wire_decode::task_verb_body(&vault, raw)?.expect("raw body");
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
    // The generic batch door cleared the facade's stamp: the Linear effect
    // door has no writer to authorize this revision for.
    assert!(store.dirty_writer(raw)?.is_none());
    assert_eq!(
        store.dirty_writer(trusted)?.map(|w| w.actor_ref),
        Some(owner)
    );
    Ok(())
}

#[test]
fn inbound_merge_preserves_verified_writer_for_unsent_local_terminal() -> LinearSyncResult<()> {
    let (_dir, vault, owner) = mirror_fixture()?;
    let task = mirror_task(&vault, owner, "title");
    let tracker = Tracker {
        changes: Rc::new(RefCell::new(Vec::new())),
        cursors: Rc::new(RefCell::new(Vec::new())),
        current: Rc::new(RefCell::new(BTreeMap::new())),
        updates: Rc::new(RefCell::new(0)),
    };
    let mut adapter = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        tracker.clone(),
        tracker.clone(),
    );
    assert_eq!(adapter.synchronize(100, 64)?.0.len(), 1);
    let link = adapter.tasks().link(task)?.expect("linked");
    terminal_task(&vault, owner, task, 101);
    assert_eq!(
        adapter.tasks().dirty_writer(task)?.map(|w| w.actor_ref),
        Some(owner)
    );
    let mut remote = link_fields(&tracker, &link.issue);
    remote.description = Some("tracker note".into());
    tracker.changes.borrow_mut().push(LinearIssueChange {
        event_id: "remote-disjoint".into(),
        issue: link.issue.clone(),
        updated_at_ms: 3000,
        fields: remote.clone(),
    });
    tracker
        .current
        .borrow_mut()
        .get_mut(&link.issue.issue_id)
        .expect("remote issue")
        .fields = remote;
    // The inbound disjoint merge writes a new TASK revision through the
    // generic door; the unsent local terminal keeps its verified writer.
    assert_eq!(adapter.pull_page(Some("next"), 102)?.applied, 1);
    assert_eq!(
        adapter.tasks().dirty_writer(task)?.map(|w| w.actor_ref),
        Some(owner)
    );
    let (pushed, _) = adapter.synchronize(103, 64)?;
    assert!(pushed.iter().any(|receipt| receipt.task_ref == task));
    assert_eq!(*tracker.updates.borrow(), 1);
    assert!(adapter.tasks().dirty_tasks()?.is_empty());
    Ok(())
}

fn link_fields(tracker: &Tracker, issue: &LinearIssueRef) -> MirroredTaskFields {
    tracker.current.borrow()[&issue.issue_id].fields.clone()
}
