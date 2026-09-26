use std::cell::RefCell;

use super::*;
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec, TaskResultInput, TaskTerminalDisposition};
use oneiron::wave_orchestration::{PlannedTask, WAVE_PLAN_SCHEMA_VERSION, WavePlan};
use oneiron::{TimeRange, VaultConfig};
use rmpv::Value;

struct AgentPlanner {
    seen: RefCell<Vec<WavePlanRequest>>,
    bad: bool,
}

impl WavePlanner for AgentPlanner {
    fn cut_plan(&self, request: WavePlanRequest) -> WaveResult<WavePlan> {
        self.seen.borrow_mut().push(request.clone());
        Ok(WavePlan {
            schema_version: WAVE_PLAN_SCHEMA_VERSION,
            plan_ref: "driver-plan".to_owned(),
            epic_task_ref: request.epic_task_ref,
            tasks: vec![
                PlannedTask {
                    local_key: "first".to_owned(),
                    label: "First".to_owned(),
                    spec: serde_json::json!({"action":"first"}),
                    assignee_ref: None,
                    blocked_by: vec![],
                },
                PlannedTask {
                    local_key: "second".to_owned(),
                    label: "Second".to_owned(),
                    spec: serde_json::json!({"action":"second"}),
                    assignee_ref: None,
                    blocked_by: vec![if self.bad { "missing" } else { "first" }.to_owned()],
                },
            ],
        })
    }
}

fn fixture(vault: &Vault, owner: EntityId) -> oneiron::Result<EntityId> {
    vault.put_entity(
        &owner,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    Ok(vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(
            &TaskCreateSpec::new(Value::from("epic"), None, None, Some(100))
                .with_assignee(TaskAssignee::Peer { actor_ref: owner }),
        )
        .expect("epic")
        .task_ref
        .expect("task ref"))
}

#[test]
fn planning_attempt_applies_cut_and_dispatch_reads_live_completion() -> WaveResult<()> {
    let dir = tempfile::tempdir().map_err(oneiron::Error::from)?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    let epic = fixture(&vault, owner)?;
    vault.enqueue_wave_plan(epic, "do work", serde_json::json!({"budget":2}), 100)?;
    let planner = AgentPlanner {
        seen: RefCell::new(Vec::new()),
        bad: false,
    };
    let host = WaveHost::new(&vault, planner, owner, EdgeActorClass::Human);
    let landed = host.run_plan_once("planner-1", 100)?.expect("claimed");
    let first = landed.task_refs["first"];
    let second = landed.task_refs["second"];
    assert_eq!(landed.blocked_by_edges, 1);
    assert_eq!(host.planner.seen.borrow()[0].epic_task_ref, epic);
    assert_eq!(host.planner.seen.borrow()[0].objective, "do work");
    assert_eq!(host.ready_to_dispatch(&[first, second])?, vec![first]);
    assert!(host.run_plan_once("planner-1", 101)?.is_none());
    vault
        .memory(owner, EdgeActorClass::Human)
        .land_task_result(
            first,
            &TaskResultInput {
                result_ref: owner,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: 102,
            },
        )
        .expect("complete first");
    assert_eq!(host.ready_to_dispatch(&[second])?, vec![second]);
    Ok(())
}

#[test]
fn invalid_agent_cut_does_not_complete_attempt_or_land_tasks() -> WaveResult<()> {
    let dir = tempfile::tempdir().map_err(oneiron::Error::from)?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = EntityId::now();
    let epic = fixture(&vault, owner)?;
    vault.enqueue_wave_plan(epic, "do work", serde_json::Value::Null, 100)?;
    let host = WaveHost::new(
        &vault,
        AgentPlanner {
            seen: RefCell::new(Vec::new()),
            bad: true,
        },
        owner,
        EdgeActorClass::Human,
    );
    assert!(host.run_plan_once("planner-1", 100).is_err());
    let request = host.planner.seen.borrow();
    let attempt = AttemptQueue::new(&vault)
        .get(request[0].planner_attempt_ref)?
        .expect("attempt");
    assert_eq!(attempt.state, oneiron::attempt_queue::AttemptState::Leased);
    assert!(host.ready_to_dispatch(&[])?.is_empty());
    Ok(())
}
