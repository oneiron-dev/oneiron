//! One deterministic host-private checker. No candidate process loads this bundle.
use std::path::Path;
use serde_json::{Value, json};
use tokio::time::Instant;
use super::{Result, served::{Process, isolated}, taskgen::Plan, write_json};

pub(super) async fn evaluate(plan: &Plan, dir: &Path, reset: &Value, state: &Value,
    events: &[Value], artifacts: Value, deadline: Instant) -> Result<Value> {
    let identity = json!({"fixture":reset["fixture"],"version":reset["version"],"seed":reset["seed"],
        "run_id":reset["run_id"],"data_sha256":reset["data_sha256"]});
    let bundle = json!({"checker_version":plan.checker_version,"reset":reset,"state":state,"events":events,
        "cutoff_sequence":events.last().map(|e| &e["sequence"]),
        "engine":{"identity":identity,"field_provenance":null,"refusals":null},
        "artifacts":{"identity":identity,"files":artifacts}});
    let path = dir.join("checker-input.json");
    write_json(&path,&bundle)?;
    let stdout = dir.join("checker.json");
    let mut command = isolated(Path::new("python3"));
    command.arg("-I").arg(plan.fixture_root.join("checkers")).arg("--bundle").arg(&path)
        .stdout(std::fs::File::create(&stdout).map_err(|e| e.to_string())?)
        .stderr(std::fs::File::create(dir.join("checker.stderr")).map_err(|e| e.to_string())?);
    let mut child = Process::spawn(command)?;
    let status = tokio::time::timeout_at(deadline,child.child().wait()).await.map_err(|_| "checker_timeout")?
        .map_err(|e| e.to_string())?;
    let result: Value = super::read(&stdout)?;
    if !status.success() && result.get("evidence_failure").is_none() { return Err("checker_process_failed".into()) }
    Ok(result)
}
