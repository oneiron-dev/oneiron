//! Engine/fixture boundary for the S5 protocol. No simulated browser semantics.
use serde_json::{Value,json};
use super::{config::Config, drift_plan::Assignment, fixture, taskgen::Plan, programs::Program, Result};

/// All values here are original public engine/checker answers, not predicted outcomes.
#[derive(Clone)]
pub(super) struct Execution {
    pub(crate) reset:Value, pub(crate) library:Value, pub(crate) checker:Value,
    pub(crate) measures:Value, pub(crate) evidence:std::path::PathBuf, pub(crate) lifecycle:Value,
}
#[derive(Clone)]
pub(super) struct Recovery {
    pub(crate) execution:Execution,
    pub(crate) proposal:Value,
    pub(crate) author_trace:Value,
    pub(crate) finishing_role:Value,
}
/// A driver must stop/drain its owned candidate before returning an execution,
/// bind every checker input to its reset, and keep the proposing guest alive
/// across the recovery/checkpoint/proposal sequence. It must not reset inside
/// proposal admission. The independent confirmation calls each get a new guest.
pub(super) trait Engine {
    async fn strict(&mut self, assignment:&Assignment, program:&Program, workflow:&str) -> Result<Execution>;
    async fn recover(&mut self, assignment:&Assignment, program:&Program, failure:&Value) -> Result<Recovery>;
    async fn propose(&mut self, assignment:&Assignment, program:&Program, recovery:&Recovery, spec:Value) -> Result<Value>;
}

/// S5 cannot refile an original workflow into a new scratch vault under a
/// replacement ID. Keep that continuity gap distinct from transport readiness.
pub(super) struct FixtureTransport<'a> { pub(crate) config:&'a Config, pub(crate) plan:&'a Plan }
impl Engine for FixtureTransport<'_> {
    async fn strict(&mut self, _assignment:&Assignment, _program:&Program, _workflow:&str) -> Result<Execution> {
        fixture::forward_target(self.plan, &self.config.browser)?;
        Err("s5_original_workflow_vault_unavailable".into())
    }
    async fn recover(&mut self, _assignment:&Assignment, _program:&Program, _failure:&Value) -> Result<Recovery> {
        fixture::forward_target(self.plan, &self.config.browser)?;
        Err("s5_original_workflow_vault_unavailable".into())
    }
    async fn propose(&mut self, _assignment:&Assignment, _program:&Program, _recovery:&Recovery, _spec:Value) -> Result<Value> {
        fixture::forward_target(self.plan, &self.config.browser)?;
        Err("s5_original_workflow_vault_unavailable".into())
    }
}

pub(super) fn lifecycle(snapshot:&Value, workflow:&str) -> Result<Vec<Value>> {
    let retired = snapshot["retired"].as_array().ok_or("public_retired_evidence_missing")?;
    let mut events = Vec::new();
    for item in retired.iter().filter(|r| r["card"]["workflow"] == workflow) {
        let reason = item["reason"].as_str().ok_or("retirement_reason_missing")?;
        if reason == "drift" || reason.starts_with("superseded:") {
            events.push(json!({"kind":"engine_retirement","workflow":workflow,"reason":reason,
                "retired_at":item["retired_at"],"strict_misses":item["card"]["strict_misses"],
                "source":"self.browser.library.retired","receipt":item}));
        }
    }
    Ok(events)
}
