//! Five edit-task shapes with an independent tests-plus-contract oracle.
//! Candidate-controlled test files and Cargo manifests never enter the oracle.

use super::{BeamError, BeamResult};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

const PACK: &str = include_str!("../../fixtures/edit_path/tasks.json");
const ORACLE_MANIFEST: &str = r#"[package]
name = "subject"
version = "0.1.0"
edition = "2024"
[workspace]
"#;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EditTaskPack {
    version: u32,
    repo: String,
    tasks: Vec<EditTask>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EditTask {
    id: String,
    shape: String,
    instruction: String,
    files: BTreeMap<String, String>,
    tests: String,
    contracts: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EditAttempt {
    arm: String,
    task: String,
    candidate: PathBuf,
}

#[derive(Debug, Default, Serialize)]
pub(super) struct EditArmScore {
    successes: usize,
    regressions: usize,
    failures: usize,
}
#[derive(Debug, Serialize)]
pub(super) struct EditOracleResult {
    arm: String,
    task: String,
    tests_pass: bool,
    contracts_pass: bool,
    success: bool,
    regression: bool,
}
#[derive(Debug, Serialize)]
pub(super) struct EditPathReport {
    oracle: &'static str,
    results: Vec<EditOracleResult>,
    arms: BTreeMap<String, EditArmScore>,
}

fn pack() -> BeamResult<EditTaskPack> {
    let pack: EditTaskPack = serde_json::from_str(PACK)?;
    if pack.version != 1 || pack.tasks.len() != 5 {
        return Err(BeamError::InvalidFixture {
            fixture_id: pack.repo,
            reason: "invalid edit task pack".into(),
        });
    }
    Ok(pack)
}

/// Materializes tasks, but not the sealed oracle or solution patches.
pub(super) fn write_pack(root: &Path) -> BeamResult<serde_json::Value> {
    let pack = pack()?;
    let mut tasks = Vec::new();
    for task in &pack.tasks {
        let sandbox = root.join(&task.id);
        std::fs::create_dir_all(sandbox.join("src"))?;
        for (name, text) in &task.files {
            std::fs::write(sandbox.join(name), text)?;
        }
        std::fs::write(sandbox.join("Cargo.toml"), ORACLE_MANIFEST)?;
        tasks.push(serde_json::json!({"task": task.id, "shape":task.shape,"instruction":task.instruction,"candidate":sandbox}));
    }
    Ok(serde_json::json!({"version":pack.version,"tasks":tasks}))
}

/// Scores attempts independently for each arm. A caught regression can never
/// increment success, even when the candidate passes its functional tests.
pub(super) fn run_manifest(path: &Path) -> BeamResult<EditPathReport> {
    let attempts: Vec<EditAttempt> = serde_json::from_slice(&std::fs::read(path)?)?;
    let pack = pack()?;
    let mut report = EditPathReport {
        oracle: "tests-plus-contract/v1",
        results: Vec::new(),
        arms: BTreeMap::new(),
    };
    for mut attempt in attempts {
        if attempt.candidate.is_relative() {
            attempt.candidate = path
                .parent()
                .unwrap_or(Path::new("."))
                .join(&attempt.candidate);
        }
        let task = pack
            .tasks
            .iter()
            .find(|task| task.id == attempt.task)
            .ok_or_else(|| BeamError::InvalidFixture {
                fixture_id: attempt.task.clone(),
                reason: "unknown edit task".into(),
            })?;
        let result = evaluate(task, &attempt)?;
        let score = report.arms.entry(attempt.arm).or_default();
        score.successes += usize::from(result.success);
        score.regressions += usize::from(result.regression);
        score.failures += usize::from(!result.tests_pass);
        report.results.push(result);
    }
    Ok(report)
}

fn evaluate(task: &EditTask, attempt: &EditAttempt) -> BeamResult<EditOracleResult> {
    let oracle = tempfile::tempdir()?;
    std::fs::create_dir(oracle.path().join("src"))?;
    std::fs::create_dir(oracle.path().join("tests"))?;
    // This fixture has two source units. Only those units can affect the build;
    // candidate tests/build.rs/manifests cannot replace the independent oracle.
    for name in task.files.keys() {
        let path = attempt.candidate.join(name);
        let meta = std::fs::symlink_metadata(&path)?;
        if !meta.file_type().is_file() || meta.len() > 1024 * 1024 {
            return Err(BeamError::InvalidFixture {
                fixture_id: task.id.clone(),
                reason: "candidate source must be a bounded regular file".into(),
            });
        }
        std::fs::write(oracle.path().join(name), std::fs::read(path)?)?;
    }
    std::fs::write(oracle.path().join("Cargo.toml"), ORACLE_MANIFEST)?;
    std::fs::write(oracle.path().join("tests/task.rs"), &task.tests)?;
    std::fs::write(oracle.path().join("tests/contract.rs"), &task.contracts)?;
    let tests_pass = test_suite(oracle.path(), "task")?;
    let contracts_pass = test_suite(oracle.path(), "contract")?;
    Ok(EditOracleResult {
        arm: attempt.arm.clone(),
        task: task.id.clone(),
        tests_pass,
        contracts_pass,
        success: tests_pass && contracts_pass,
        regression: !contracts_pass,
    })
}

fn test_suite(root: &Path, test: &str) -> BeamResult<bool> {
    let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .args(["test", "--quiet", "--offline", "--test", test])
        .current_dir(root)
        .env("CARGO_TARGET_DIR", root.join("target"))
        .env("CARGO_BUILD_JOBS", "1")
        .env("RUST_TEST_THREADS", "1")
        .output()?;
    Ok(output.status.success())
}

#[cfg(test)]
mod tests;
