use super::*;
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/teacher_probe");
const MODEL: &str = "McGill-NLP/LLM2Vec-Qwen3-8B-mntp@fixture-v1";
fn candidate(path: &Path) {
    std::fs::copy(PathBuf::from(FIXTURES).join("candidate.fixture.json"), path).unwrap();
}
fn input() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("candidate.json");
    let output = dir.path().join("approved.json");
    candidate(&manifest);
    let policy_path = dir.path().join("policy.json");
    let vault = oneiron::Vault::open(
        dir.path().join("policy-vault"),
        oneiron::VaultConfig::device(),
    )
    .unwrap();
    std::fs::write(
        &policy_path,
        serde_json::to_vec(&vault.teacher_probe_policy(None).unwrap()).unwrap(),
    )
    .unwrap();
    (
        dir,
        manifest,
        output,
        PathBuf::from(FIXTURES).join("checkpoint"),
        policy_path,
    )
}
fn fixture_runner() -> PathBuf {
    PathBuf::from(FIXTURES).join("fixture_runner.py")
}
fn cli(checkpoint: &Path, manifest: &Path, policy: &Path, output: &Path) -> Vec<String> {
    [
        "--checkpoint".into(),
        checkpoint.display().to_string(),
        "--runner".into(),
        fixture_runner().display().to_string(),
        "--manifest".into(),
        manifest.display().to_string(),
        "--policy".into(),
        policy.display().to_string(),
        "--out".into(),
        output.display().to_string(),
    ]
    .to_vec()
}
#[test]
fn fixture_checkpoint_runs_probe_and_releases_only_a_passing_manifest() {
    let (_dir, manifest, output, checkpoint, policy) = input();
    assert_eq!(
        run(&cli(&checkpoint, &manifest, &policy, &output)),
        ExitCode::SUCCESS
    );
    assert_eq!(
        std::fs::read(&output).unwrap(),
        std::fs::read(&manifest).unwrap()
    );
    let selected = ModelManifest::load(&output).unwrap();
    let approval = TeacherProbeApproval::load(&approval_path(&output)).unwrap();
    let vault =
        oneiron::Vault::open(_dir.path().join("vault"), oneiron::VaultConfig::device()).unwrap();
    assert!(vault.set_model_manifest(&selected).is_err());
    vault
        .set_model_manifest_with_teacher_approval(&selected, &approval)
        .unwrap();
    assert_eq!(vault.model_manifest().unwrap(), Some(selected));
}
#[test]
fn below_bar_checkpoint_blocks_teacher_pin() {
    let (dir, manifest, output, checkpoint, policy) = input();
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
        gate(&bad, &fixture_runner(), &manifest, &policy, &output)
            .unwrap_err()
            .contains("FAIL")
    );
    assert_eq!(
        run(&cli(&bad, &manifest, &policy, &output)),
        ExitCode::FAILURE
    );
    assert!(!output.exists());
    assert!(!approval_path(&output).exists());
    let candidate = ModelManifest::load(&manifest).unwrap();
    let vault =
        oneiron::Vault::open(dir.path().join("vault"), oneiron::VaultConfig::device()).unwrap();
    assert!(vault.set_model_manifest(&candidate).is_err());
    assert!(vault.model_manifest().unwrap().is_none());
}
#[test]
fn passing_base_with_unprobed_teacher_route_cannot_publish() {
    let (_dir, manifest, output, checkpoint, policy) = input();
    let mut raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    for (role, binding) in raw["roles"].as_object_mut().unwrap() {
        binding["route_models"] = serde_json::json!({
            "on_device": format!("local/unprobed-{role}@r1")
        });
    }
    std::fs::write(&manifest, serde_json::to_vec(&raw).unwrap()).unwrap();
    assert!(ModelManifest::load(&manifest).is_ok());
    assert_eq!(
        run(&cli(&checkpoint, &manifest, &policy, &output)),
        ExitCode::FAILURE
    );
    assert!(!output.exists());
    assert!(!approval_path(&output).exists());
}
#[test]
fn bench_uses_exported_vault_policy_not_a_compiled_eighty_percent_bar() {
    let (dir, manifest, output, checkpoint, policy) = input();
    let mut strict: TeacherProbePolicy = TeacherProbePolicy::load(&policy).unwrap();
    strict.vault_min_f1_millionths = 900_000;
    strict.min_f1_millionths = 900_000;
    std::fs::write(&policy, serde_json::to_vec(&strict).unwrap()).unwrap();
    let candidate = dir.path().join("eighty-five-checkpoint");
    std::fs::create_dir(&candidate).unwrap();
    std::fs::write(candidate.join("model_id"), format!("{MODEL}\n")).unwrap();
    let mut result: serde_json::Value =
        serde_json::from_slice(&std::fs::read(checkpoint.join("output.json")).unwrap()).unwrap();
    // Four of 24 spans are dropped: exact span micro-F1 = 40/44 = 0.909;
    // six dropped: 36/42 = 0.857, which is above 0.8 but below 0.9.
    for sentence in result["predictions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .take(3)
    {
        let tags = sentence.as_array_mut().unwrap();
        for tag in tags.iter_mut() {
            *tag = "O".into();
        }
    }
    std::fs::write(
        candidate.join("output.json"),
        serde_json::to_vec(&result).unwrap(),
    )
    .unwrap();
    assert_eq!(
        run(&cli(&candidate, &manifest, &policy, &output)),
        ExitCode::FAILURE
    );
    assert!(!output.exists());
    assert!(!approval_path(&output).exists());
}

#[test]
fn wrong_model_or_malformed_bio_fails_closed() {
    let (dir, manifest, output, checkpoint, policy) = input();
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
    assert!(gate(&bad, &fixture_runner(), &manifest, &policy, &output).is_err());
    assert!(!output.exists());
    result["model_id"] = MODEL.into();
    result["predictions"][0][0] = "I-ORG".into();
    std::fs::write(
        bad.join("output.json"),
        serde_json::to_vec(&result).unwrap(),
    )
    .unwrap();
    assert!(gate(&bad, &fixture_runner(), &manifest, &policy, &output).is_err());
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
