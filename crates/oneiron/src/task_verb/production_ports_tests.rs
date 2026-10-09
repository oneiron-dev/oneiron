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
