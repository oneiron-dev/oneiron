use super::*;

#[test]
fn edit_path_oracle_separates_success_and_caught_regressions_per_arm() -> BeamResult<()> {
    let root = tempfile::tempdir()?;
    let manifest = write_pack(root.path())?;
    assert_eq!(manifest["tasks"].as_array().unwrap().len(), 5);
    let solutions: BTreeMap<String, BTreeMap<String, String>> =
        serde_json::from_str(include_str!("../../../fixtures/edit_path/solutions.json"))?;
    let mut attempts = Vec::new();
    for (task, files) in &solutions {
        let candidate = root.path().join(task);
        for (name, content) in files {
            std::fs::write(candidate.join(name), content)?;
        }
        attempts.push(serde_json::json!({"arm":"sdk","task":task,"candidate":candidate}));
    }
    let broken = root.path().join("broken");
    std::fs::create_dir_all(broken.join("src"))?;
    // A refactor updates the declaration but leaves its other-file caller stale.
    std::fs::write(
        broken.join("src/lib.rs"),
        include_str!("../../../fixtures/edit_path/repo/src/lib.rs"),
    )?;
    std::fs::write(
        broken.join("src/math.rs"),
        &solutions["cross_file_refactor"]["src/math.rs"],
    )?;
    attempts
        .push(serde_json::json!({"arm":"files","task":"cross_file_refactor","candidate":broken}));
    let regressing = root.path().join("regressing");
    std::fs::create_dir_all(regressing.join("src"))?;
    std::fs::write(
        regressing.join("src/lib.rs"),
        &solutions["contract_cleanup"]["src/lib.rs"],
    )?;
    std::fs::write(
        regressing.join("src/math.rs"),
        solutions["contract_cleanup"]["src/math.rs"].replace("u64::from(quantity != 0) * 5", "5"),
    )?;
    attempts
        .push(serde_json::json!({"arm":"files","task":"contract_cleanup","candidate":regressing}));
    let path = root.path().join("attempts.json");
    std::fs::write(&path, serde_json::to_vec(&attempts)?)?;
    let report = run_manifest(&path)?;
    assert_eq!(report.arms["sdk"].successes, 5);
    assert_eq!(report.arms["sdk"].regressions, 0);
    assert_eq!(report.arms["files"].successes, 0);
    assert_eq!(report.arms["files"].regressions, 2);
    let cleanup = report.results.last().unwrap();
    assert!(cleanup.tests_pass);
    assert!(!cleanup.contracts_pass);
    assert!(!cleanup.success);
    assert!(cleanup.regression);
    Ok(())
}

#[test]
fn edit_oracle_rejects_successful_exit_without_completed_tests() -> BeamResult<()> {
    let root = tempfile::tempdir()?;
    write_pack(root.path())?;
    let candidate = root.path().join("small_edit");
    std::fs::write(
        candidate.join("src/lib.rs"),
        r#"pub mod math; pub fn quote(_: u64, _: u64) -> Option<u64> { std::process::exit(0) } pub fn currency() -> &'static str { "EUR" }"#,
    )?;
    let task = pack()?.tasks.remove(0);
    let result = evaluate(
        &task,
        &EditAttempt {
            arm: "fixture".into(),
            task: task.id.clone(),
            candidate,
        },
    )?;
    assert!(!result.tests_pass);
    assert!(!result.contracts_pass);
    assert!(!result.success);
    Ok(())
}
