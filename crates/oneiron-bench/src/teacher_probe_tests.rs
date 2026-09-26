use super::*;
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/teacher_probe");
const MODEL: &str = "McGill-NLP/LLM2Vec-Qwen3-8B-mntp@fixture-v1";
fn candidate(path: &Path) {
    std::fs::copy(PathBuf::from(FIXTURES).join("candidate.fixture.json"), path).unwrap();
}
fn input() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("candidate.json");
    let output = dir.path().join("approved.json");
    candidate(&manifest);
    (
        dir,
        manifest,
        output,
        PathBuf::from(FIXTURES).join("checkpoint"),
    )
}
fn fixture_runner() -> PathBuf {
    PathBuf::from(FIXTURES).join("fixture_runner.py")
}
fn cli(checkpoint: &Path, manifest: &Path, output: &Path) -> Vec<String> {
    [
        "--checkpoint".into(),
        checkpoint.display().to_string(),
        "--runner".into(),
        fixture_runner().display().to_string(),
        "--manifest".into(),
        manifest.display().to_string(),
        "--out".into(),
        output.display().to_string(),
    ]
    .to_vec()
}
#[test]
fn fixture_checkpoint_runs_probe_and_releases_only_a_passing_manifest() {
    let (_dir, manifest, output, checkpoint) = input();
    assert_eq!(
        run(&cli(&checkpoint, &manifest, &output)),
        ExitCode::SUCCESS
    );
    assert_eq!(
        std::fs::read(output).unwrap(),
        std::fs::read(manifest).unwrap()
    );
}
#[test]
fn below_bar_checkpoint_blocks_teacher_pin() {
    let (dir, manifest, output, checkpoint) = input();
    let bad = dir.path().join("bad-checkpoint");
    std::fs::create_dir(&bad).unwrap();
    std::fs::write(bad.join("model_id"), format!("{MODEL}\n")).unwrap();
    let mut result: serde_json::Value =
        serde_json::from_slice(&std::fs::read(checkpoint.join("output.json")).unwrap()).unwrap();
    for tags in result["predictions"].as_array_mut().unwrap().iter_mut() {
        *tags = serde_json::Value::Array(vec!["O".into(); tags.as_array().unwrap().len()]);
    }
    std::fs::write(
        bad.join("output.json"),
        serde_json::to_vec(&result).unwrap(),
    )
    .unwrap();
    assert!(
        gate(&bad, &fixture_runner(), &manifest, &output)
            .unwrap_err()
            .contains("FAIL")
    );
    assert_eq!(run(&cli(&bad, &manifest, &output)), ExitCode::FAILURE);
    assert!(!output.exists());
}
#[test]
fn wrong_model_or_malformed_bio_fails_closed() {
    let (dir, manifest, output, checkpoint) = input();
    let bad = dir.path().join("wrong-checkpoint");
    std::fs::create_dir(&bad).unwrap();
    std::fs::write(bad.join("model_id"), format!("{MODEL}\n")).unwrap();
    let mut result: serde_json::Value =
        serde_json::from_slice(&std::fs::read(checkpoint.join("output.json")).unwrap()).unwrap();
    result["model_id"] = "other/model@v1".into();
    std::fs::write(
        bad.join("output.json"),
        serde_json::to_vec(&result).unwrap(),
    )
    .unwrap();
    assert!(gate(&bad, &fixture_runner(), &manifest, &output).is_err());
    assert!(!output.exists());
    result["model_id"] = MODEL.into();
    result["predictions"][0][0] = "I-ORG".into();
    std::fs::write(
        bad.join("output.json"),
        serde_json::to_vec(&result).unwrap(),
    )
    .unwrap();
    assert!(gate(&bad, &fixture_runner(), &manifest, &output).is_err());
    assert!(!output.exists());
}
#[test]
fn exact_entity_boundaries_and_types_not_token_accuracy() {
    let gold: Probe = serde_json::from_str(GOLD).unwrap();
    let mut predictions = gold
        .sentences
        .iter()
        .map(|s| s.tags.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        evaluate(
            &gold,
            &RunnerOutput {
                model_id: MODEL.into(),
                predictions: predictions.clone()
            }
        )
        .unwrap()
        .0,
        1_000_000
    );
    predictions[0][0] = "B-PER".into();
    assert!(
        evaluate(
            &gold,
            &RunnerOutput {
                model_id: MODEL.into(),
                predictions
            }
        )
        .unwrap()
        .0 < 1_000_000
    );
}
