//! Wave-orchestration tests (ONE-1905). Pure fakes: no vault, no dispatch,
//! no attempt queue — the organ is defined by what it refuses to write.

use super::*;

const TASK_TYPE: u8 = ENTITY_TYPE_TASK;
const LIST_TYPE: u8 = crate::registry::ENTITY_TYPE_TASK_LIST;

fn entity(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("test entity id")
}

fn planned(local_key: &str, blocked_by: &[&str]) -> PlannedTask {
    PlannedTask {
        local_key: local_key.to_owned(),
        label: format!("task {local_key}"),
        spec: Value::Null,
        assignee_ref: None,
        blocked_by: blocked_by.iter().map(|key| (*key).to_owned()).collect(),
    }
}

fn plan(tasks: Vec<PlannedTask>) -> WavePlan {
    WavePlan {
        schema_version: WAVE_PLAN_SCHEMA_VERSION,
        plan_ref: "plan-1".to_owned(),
        epic_task_ref: entity(0x01),
        tasks,
    }
}

fn validate(cut: WavePlan) -> WaveResult<ValidatedWavePlan> {
    WaveOrchestrator::<FakePort>::validate(cut)
}

/// A durable side that mints TASK rows and gates every edge through
/// [`blocked_by_edge_write`], exactly like a vault-backed port must.
#[derive(Debug, Default)]
struct FakePort {
    minted: BTreeMap<String, EntityId>,
    mint_types: BTreeMap<String, u8>,
    entity_types: BTreeMap<EntityId, u8>,
    edges: BTreeSet<(EntityId, EntityId)>,
    succeeded: BTreeSet<EntityId>,
    next_seed: u8,
}

impl FakePort {
    fn task_ref(&self, local_key: &str) -> EntityId {
        *self.minted.get(local_key).expect("minted task ref")
    }

    fn entity_type(&self, task_ref: EntityId) -> u8 {
        let known = self.entity_types.get(&task_ref).copied();
        known.unwrap_or_default()
    }

    fn mint(&mut self, local_key: &str) -> EntityId {
        if let Some(existing) = self.minted.get(local_key) {
            return *existing;
        }
        self.next_seed += 1;
        let task_ref = entity(0x40 + self.next_seed);
        let configured = self.mint_types.get(local_key).copied();
        let type_byte = configured.unwrap_or(ENTITY_TYPE_TASK);
        self.minted.insert(local_key.to_owned(), task_ref);
        self.entity_types.insert(task_ref, type_byte);
        task_ref
    }
}

impl WaveTaskPort for FakePort {
    fn apply_validated_plan(
        &mut self,
        plan: &ValidatedWavePlan,
        _now: u64,
    ) -> WaveResult<Vec<WaveTaskWrite>> {
        for local_key in &plan.topological_order {
            self.mint(local_key);
        }
        let mut writes = Vec::with_capacity(plan.topological_order.len());
        for local_key in &plan.topological_order {
            let task = plan.tasks.get(local_key).expect("planned task");
            let task_ref = self.task_ref(local_key);
            let mut blocker_refs = Vec::with_capacity(task.blocked_by.len());
            for blocker_key in &task.blocked_by {
                let blocker_ref = self.task_ref(blocker_key);
                let edge = blocked_by_edge_write(
                    task_ref,
                    self.entity_type(task_ref),
                    blocker_ref,
                    self.entity_type(blocker_ref),
                )?;
                self.edges.insert((edge.dependent, edge.blocker));
                blocker_refs.push(blocker_ref);
            }
            writes.push(WaveTaskWrite {
                local_key: local_key.clone(),
                task_ref,
                label: task.label.clone(),
                assignee_ref: task.assignee_ref,
                blocker_refs,
            });
        }
        Ok(writes)
    }

    fn task_terminal_success(&self, task_ref: EntityId) -> WaveResult<bool> {
        Ok(self.succeeded.contains(&task_ref))
    }

    fn blockers(&self, task_ref: EntityId) -> WaveResult<Vec<EntityId>> {
        let mut blockers = Vec::new();
        for (dependent, blocker) in &self.edges {
            if *dependent == task_ref {
                blockers.push(*blocker);
            }
        }
        Ok(blockers)
    }
}

#[test]
fn validate_rejects_a_cycle() {
    let cut = plan(vec![planned("a", &["b"]), planned("b", &["a"])]);

    let error = validate(cut).expect_err("cycle");

    let LinearSyncError::Store(inner) = error else {
        panic!("unexpected error: {error:?}");
    };
    assert_eq!(inner.kind(), crate::error::ErrorKind::InvariantViolation);
}

#[test]
fn validate_rejects_an_unknown_blocker() {
    let cut = plan(vec![planned("a", &["ghost"])]);

    let error = validate(cut).expect_err("unknown blocker");

    let LinearSyncError::Store(inner) = error else {
        panic!("unexpected error: {error:?}");
    };
    assert_eq!(inner.kind(), crate::error::ErrorKind::InvariantViolation);
}

#[test]
fn validate_rejects_a_self_edge() {
    let cut = plan(vec![planned("a", &["a"])]);

    let error = validate(cut).expect_err("self edge");

    let LinearSyncError::Store(inner) = error else {
        panic!("unexpected error: {error:?}");
    };
    assert_eq!(inner.kind(), crate::error::ErrorKind::InvariantViolation);
}

#[test]
fn validate_rejects_duplicate_local_keys() {
    let cut = plan(vec![planned("a", &[]), planned("a", &[])]);

    let error = validate(cut).expect_err("duplicate local key");

    let LinearSyncError::Store(inner) = error else {
        panic!("unexpected error: {error:?}");
    };
    assert_eq!(inner.kind(), crate::error::ErrorKind::InvariantViolation);
}

#[test]
fn validate_rejects_an_unsupported_schema_version() {
    let mut cut = plan(vec![planned("a", &[])]);
    cut.schema_version = WAVE_PLAN_SCHEMA_VERSION + 1;

    let error = validate(cut).expect_err("schema version");

    let LinearSyncError::Store(inner) = error else {
        panic!("unexpected error: {error:?}");
    };
    assert_eq!(inner.kind(), crate::error::ErrorKind::InvariantViolation);
}

#[test]
fn blocked_by_edge_write_gates_on_the_task_type_byte() {
    let dependent = entity(0x51);
    let blocker = entity(0x52);

    let allowed = blocked_by_edge_write(dependent, TASK_TYPE, blocker, TASK_TYPE);
    let refused = blocked_by_edge_write(dependent, TASK_TYPE, blocker, LIST_TYPE);
    let self_edge = blocked_by_edge_write(dependent, TASK_TYPE, dependent, TASK_TYPE);

    let edge = allowed.expect("two task endpoints");
    assert_eq!(edge.dependent, dependent);
    assert_eq!(edge.blocker, blocker);
    assert_eq!(edge.kind(), EdgeKind::BlockedBy);

    let error = refused.expect_err("non-task blocker");
    let LinearSyncError::Store(inner) = error else {
        panic!("unexpected error: {error:?}");
    };
    assert_eq!(inner.kind(), crate::error::ErrorKind::InvariantViolation);

    let error = self_edge.expect_err("self edge");
    let LinearSyncError::Store(inner) = error else {
        panic!("unexpected error: {error:?}");
    };
    assert_eq!(inner.kind(), crate::error::ErrorKind::InvariantViolation);
}
