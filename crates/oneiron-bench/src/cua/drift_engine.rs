//! Engine/fixture boundary for the S5 protocol. No simulated browser semantics.
use super::{Result, config::Config, drift_plan::Assignment, fixture, programs::Program};
use serde_json::{Value, json};

/// All values here are original public engine/checker answers, not predicted outcomes.
#[derive(Clone)]
pub(super) struct Execution {
    pub(crate) reset: Value,
    pub(crate) library: Value,
    pub(crate) checker: Value,
    pub(crate) measures: Value,
    pub(crate) evidence: std::path::PathBuf,
    pub(crate) lifecycle: Value,
}
#[derive(Clone)]
pub(super) struct Recovery {
    pub(crate) execution: Execution,
    pub(crate) proposal: Value,
    pub(crate) author_trace: Value,
    pub(crate) finishing_role: Value,
}
/// A driver must stop/drain its owned candidate before returning an execution,
/// bind every checker input to its reset, and keep the proposing guest alive
/// across the recovery/checkpoint/proposal sequence. It must not reset inside
/// proposal admission. The independent confirmation calls each get a new guest.
pub(super) trait Engine {
    async fn strict(
        &mut self,
        assignment: &Assignment,
        program: &Program,
        workflow: &str,
    ) -> Result<Execution>;
    async fn recover(
        &mut self,
        assignment: &Assignment,
        program: &Program,
        failure: &Value,
    ) -> Result<Recovery>;
    async fn propose(
        &mut self,
        assignment: &Assignment,
        program: &Program,
        recovery: &Recovery,
        spec: Value,
    ) -> Result<Value>;
}

/// The single FIX 8061 integration seam. Deliberately no boolean readiness
/// override: this head cannot prepare even one dynamic-fixture engine guest.
/// When the engine lane supplies it, this adapter must use PR1's fixture,
/// served lifecycle, checker and provider gate for the above operations.
/// Keeping the protocol separate lets the serial scheduler retain all assigned
/// cells today without substituting fresh solves for strict library calls.
pub(super) struct FixtureTransport<'a> {
    pub(crate) config: &'a Config,
}
impl Engine for FixtureTransport<'_> {
    async fn strict(
        &mut self,
        _assignment: &Assignment,
        _program: &Program,
        _workflow: &str,
    ) -> Result<Execution> {
        fixture::transport_ready(self.config)?;
        Err("fixture_transport_unavailable".into())
    }
    async fn recover(
        &mut self,
        _assignment: &Assignment,
        _program: &Program,
        _failure: &Value,
    ) -> Result<Recovery> {
        fixture::transport_ready(self.config)?;
        Err("fixture_transport_unavailable".into())
    }
    async fn propose(
        &mut self,
        _assignment: &Assignment,
        _program: &Program,
        _recovery: &Recovery,
        _spec: Value,
    ) -> Result<Value> {
        fixture::transport_ready(self.config)?;
        Err("fixture_transport_unavailable".into())
    }
}

pub(super) fn lifecycle(snapshot: &Value, workflow: &str) -> Result<Vec<Value>> {
    let retired = snapshot["retired"]
        .as_array()
        .ok_or("public_retired_evidence_missing")?;
    let mut events = Vec::new();
    for item in retired.iter().filter(|r| r["card"]["workflow"] == workflow) {
        let reason = item["reason"].as_str().ok_or("retirement_reason_missing")?;
        if reason == "drift" || reason.starts_with("superseded:") {
            events.push(
                json!({"kind":"engine_retirement","workflow":workflow,"reason":reason,
                "retired_at":item["retired_at"],"strict_misses":item["card"]["strict_misses"],
                "source":"self.browser.library.retired","receipt":item}),
            );
        }
    }
    Ok(events)
}
