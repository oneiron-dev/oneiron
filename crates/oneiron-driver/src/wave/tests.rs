use std::cell::RefCell;

use super::*;
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec};
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

/// The host a planning pass runs under here: it builds no Dreamer executor
/// and staffs no fan-out decision ladder, so the factory's default lends no
/// decisions to a cut (FIX 8599).
struct NoLadderHost;

impl PassExecutorFactory for NoLadderHost {
    type Exec<'p> = NoExecutor;

    fn executor<'p>(&'p mut self, _guard: &'p oneiron::BudgetGuard) -> oneiron::Result<NoExecutor> {
        Err(oneiron::Error::InvalidConfig(
            "the wave host tests run no Dreamer pass".into(),
        ))
    }
}

struct NoExecutor;

impl oneiron::DreamerAttemptExecutor for NoExecutor {
    async fn execute(
        &mut self,
        _attempt: &oneiron::DreamerAdmittedAttempt,
        _ctx: &mut oneiron::WakeAttemptContext<'_>,
    ) -> oneiron::Result<oneiron::DreamerAttemptExecution> {
        unreachable!("the wave host tests run no Dreamer pass")
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

struct DifferentCut(std::cell::Cell<usize>);
impl WavePlanner for DifferentCut {
    fn cut_plan(&self, request: WavePlanRequest) -> WaveResult<WavePlan> {
        self.0.set(self.0.get() + 1);
        Ok(WavePlan {
            schema_version: WAVE_PLAN_SCHEMA_VERSION,
            plan_ref: "different-cut".into(),
            epic_task_ref: request.epic_task_ref,
            tasks: vec![PlannedTask {
                local_key: "duplicate".into(),
                label: "Must not land".into(),
                spec: serde_json::Value::Null,
                assignee_ref: None,
                blocked_by: vec![],
            }],
        })
    }
}

/// The old host could stop after TASK commit and before a separate queue
/// completion. Reclaim then ran a DIFFERENT planner cut and minted duplicates.
#[test]
fn completed_cut_survives_restart_and_reclaim_without_a_second_plan() -> WaveResult<()> {
    use oneiron::attempt_queue::{AttemptState, ClaimAttempt, ClaimOutcome, CleanupAttemptLeases};
    let dir = tempfile::tempdir().map_err(oneiron::Error::from)?;
    let owner = EntityId::now();
    let (attempt_id, first, second) = {
        let vault = Vault::open(dir.path(), VaultConfig::default())?;
        let epic = fixture(&vault, owner)?;
        vault.enqueue_wave_plan(epic, "stable objective", serde_json::Value::Null, 100)?;
        let queue = AttemptQueue::new(&vault);
        let ClaimOutcome::Claimed(attempt) = queue.claim_kind(
            WAVE_PLAN_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "crashed-host".into(),
                now: 100,
            },
        )?
        else {
            panic!("plan claim");
        };
        let first_cut = AgentPlanner {
            seen: RefCell::new(Vec::new()),
            bad: false,
        }
        .cut_plan(WavePlanRequest {
            epic_task_ref: epic,
            planner_attempt_ref: attempt.id,
            objective: "stable objective".into(),
            constraints: serde_json::Value::Null,
            now: 100,
        })?;
        // Simulates the crash exactly after the old core apply returned,
        // BEFORE the old driver could call queue.complete separately.
        let receipt = vault.apply_wave_plan_attempt(
            owner,
            EdgeActorClass::Human,
            &attempt,
            first_cut,
            100,
        )?;
        assert_eq!(
            queue.get(attempt.id)?.expect("attempt").state,
            AttemptState::Completed
        );
        (
            attempt.id,
            receipt.task_refs["first"],
            receipt.task_refs["second"],
        )
    };
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let queue = AttemptQueue::new(&vault);
    let cleanup = queue.cleanup_leases(CleanupAttemptLeases {
        now: u64::MAX,
        lease_timeout_secs: 1,
    })?;
    assert_eq!(
        cleanup.stale_requeued, 0,
        "a committed cut cannot be reclaimed"
    );
    assert_eq!(
        queue.get(attempt_id)?.expect("attempt after restart").state,
        AttemptState::Completed
    );
    let host = WaveHost::new(
        &vault,
        DifferentCut(std::cell::Cell::new(0)),
        owner,
        EdgeActorClass::Human,
    );
    assert!(
        host.run_plan_once(&NoLadderHost, "restarted-host", 100_001)?
            .is_none()
    );
    assert_eq!(
        host.planner.0.get(),
        0,
        "no second planner cut after reclaim"
    );
    assert_eq!(host.ready_to_dispatch(&[first, second])?, vec![first]);
    Ok(())
}
