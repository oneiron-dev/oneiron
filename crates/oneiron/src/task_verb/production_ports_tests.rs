use super::*;
use crate::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::linear_sync::*;
use crate::wave_orchestration::*;
use crate::{EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value;
use std::{cell::RefCell, rc::Rc};

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

#[derive(Clone)]
struct Tracker(Rc<RefCell<Vec<LinearIssueChange>>>);
impl LinearChangeSource for Tracker {
    fn changes_since(&mut self, _: Option<&str>) -> LinearSyncResult<LinearChangePage> {
        Ok(LinearChangePage {
            changes: std::mem::take(&mut *self.0.borrow_mut()),
            next_cursor: Some("next".into()),
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
        Ok(LinearIssueChange {
            event_id: format!("create-{}", task.to_hex()),
            issue: LinearIssueRef {
                issue_id: task.to_hex(),
                team_id: "team".into(),
                identifier: "ISSUE-1".into(),
            },
            updated_at_ms: 1000,
            fields: fields.clone(),
        })
    }
    fn update_issue(
        &mut self,
        _: [u8; 32],
        issue: &LinearIssueRef,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange> {
        Ok(LinearIssueChange {
            event_id: format!("update-{}", issue.issue_id),
            issue: issue.clone(),
            updated_at_ms: 2000,
            fields: fields.clone(),
        })
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
    let tracker = Tracker(Rc::new(RefCell::new(Vec::new())));
    let mut adapter = LinearSyncAdapter::new(
        VaultLinearTaskStore::new(&vault),
        tracker.clone(),
        tracker.clone(),
    );
    let (pushed, _) = adapter.synchronize(100)?;
    assert_eq!(pushed.len(), 1);
    assert_eq!(pushed[0].status, LinearMirrorStatus::Linked);
    let original = adapter.tasks().task_snapshot(task)?;
    let link = adapter.tasks().link(task)?.unwrap();
    assert_eq!(
        adapter.tasks().link_for_issue(&link.issue)?,
        Some(link.clone())
    );
    let mut new_fields = original.fields.clone();
    new_fields.description = Some("tracker description".into());
    tracker.0.borrow_mut().push(LinearIssueChange {
        event_id: "inbound-edit".into(),
        issue: link.issue.clone(),
        updated_at_ms: 3000,
        fields: new_fields.clone(),
    });
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
    let before_close = adapter.tasks().link(task)?;
    drop(adapter);
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    assert_eq!(VaultLinearTaskStore::new(&vault).link(task)?, before_close);
    Ok(())
}
