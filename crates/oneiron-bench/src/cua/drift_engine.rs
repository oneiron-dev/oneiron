//! Engine/fixture boundary for the S5 protocol. No simulated browser semantics.
use super::{
    Result, config::Config, drift_plan::Assignment, fixture, programs::Program, served::Served,
    taskgen::Plan, write_json,
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

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

/// S5 cannot refile an original workflow into a new scratch vault under a
/// replacement ID. Keep that continuity gap distinct from transport readiness.
pub(super) struct FixtureTransport<'a> {
    config: &'a Config,
    plan: &'a Plan,
    binary: &'a Path,
    evidence: PathBuf,
    setup: Option<Result<()>>,
}
impl<'a> FixtureTransport<'a> {
    pub(crate) fn new(
        config: &'a Config,
        plan: &'a Plan,
        binary: &'a Path,
        evidence: PathBuf,
    ) -> Self {
        Self {
            config,
            plan,
            binary,
            evidence,
            setup: None,
        }
    }
    pub(crate) fn setup_failure(&self) -> Option<&str> {
        self.setup
            .as_ref()
            .and_then(|result| result.as_ref().err().map(String::as_str))
    }
    async fn ready(&mut self) -> Result<()> {
        fixture::forward_target(self.plan, &self.config.browser)?;
        if self.setup.is_none() {
            self.setup = Some(self.preflight().await);
        }
        self.setup
            .as_ref()
            .ok_or("s5_browser_setup_missing")?
            .clone()
    }
    /// This vault proves setup only. It cannot hold the original workflow;
    /// never put a replacement program here or claim a strict execution.
    async fn preflight(&self) -> Result<()> {
        fs::create_dir(&self.evidence).map_err(|e| {
            format!("browser_pack_unavailable:s5_preflight_new_directory_required_no_retry:{e}")
        })?;
        let result: Result<()> = async {
            let arm = self.config.arms.get("C").ok_or("arm_unavailable")?;
            let mut served = Served::fresh(
                self.binary,
                &self.evidence,
                arm,
                &self.config.browser,
                self.plan,
                Duration::from_secs(self.config.startup_seconds),
                Duration::from_millis(self.config.continuation_poll_ms),
            )
            .await?;
            served.stop().await
        }
        .await;
        write_json(
            &self.evidence.join("s5-preflight.json"),
            &json!({
                "status":if result.is_ok() {"ready"} else {"failed"}, "stop_cause":result.as_ref().err(),
                "browser_setup_evidence":"browser-setup.json", "original_workflow_vault":false
            }),
        )?;
        result
    }
}
impl Engine for FixtureTransport<'_> {
    async fn strict(
        &mut self,
        _assignment: &Assignment,
        _program: &Program,
        _workflow: &str,
    ) -> Result<Execution> {
        self.ready().await?;
        Err("s5_original_workflow_vault_unavailable".into())
    }
    async fn recover(
        &mut self,
        _assignment: &Assignment,
        _program: &Program,
        _failure: &Value,
    ) -> Result<Recovery> {
        self.ready().await?;
        Err("s5_original_workflow_vault_unavailable".into())
    }
    async fn propose(
        &mut self,
        _assignment: &Assignment,
        _program: &Program,
        _recovery: &Recovery,
        _spec: Value,
    ) -> Result<Value> {
        self.ready().await?;
        Err("s5_original_workflow_vault_unavailable".into())
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
