use super::*;

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
