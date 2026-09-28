//! Run the shipped binary, not only its Rust scoring function, against CI fixtures.
use oneiron::llm::manifest::{ModelManifest, TeacherProbeApproval};
use oneiron::{Vault, VaultConfig};
use std::path::{Path, PathBuf};
use std::process::Command;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/teacher_probe");
fn invoke(
    checkpoint: &Path,
    manifest: &Path,
    policy: &Path,
    approved: &Path,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_oneiron-bench"))
        .args(["teacher-probe", "--checkpoint"])
        .arg(checkpoint)
        .args([
            "--runner",
            &format!("{FIXTURES}/fixture_runner.py"),
            "--manifest",
        ])
        .arg(manifest)
        .arg("--policy")
        .arg(policy)
        .arg("--out")
        .arg(approved)
        .output()
        .expect("teacher probe CLI fixture")
}
#[test]
fn checkpoint_gate_cli_releases_only_the_passing_candidate() {
    let fixtures = PathBuf::from(FIXTURES);
    let temp = tempfile::tempdir().expect("teacher probe CLI fixture");
    let manifest = fixtures.join("candidate.fixture.json");
    let vault = Vault::open(temp.path().join("accepted-vault"), VaultConfig::device())
        .expect("accepted vault opens");
    let policy = temp.path().join("resolved-policy.json");
    std::fs::write(
        &policy,
        serde_json::to_vec(&vault.teacher_probe_policy(None).expect("vault policy"))
            .expect("policy serialization"),
    )
    .expect("policy export");
    let good = temp.path().join("good-approved.json");
    let result = invoke(&fixtures.join("checkpoint"), &manifest, &policy, &good);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        std::fs::read(&good).expect("teacher probe CLI fixture"),
        std::fs::read(&manifest).expect("teacher probe CLI fixture")
    );
    let approval_path = PathBuf::from(format!("{}.approval.json", good.display()));
    let selected = ModelManifest::load(&good).expect("approved manifest");
    let approval = TeacherProbeApproval::load(&approval_path).expect("probe approval");
    assert!(vault.set_model_manifest(&selected).is_err());
    vault
        .set_model_manifest_with_teacher_approval(&selected, &approval)
        .expect("passing checkpoint pins");
    assert_eq!(
        vault.model_manifest().expect("manifest read"),
        Some(selected)
    );
    let bad = temp.path().join("bad-approved.json");
    let result = invoke(
        &fixtures.join("below_bar_checkpoint"),
        &manifest,
        &policy,
        &bad,
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("FAIL"));
    assert!(!bad.exists());
    assert!(!PathBuf::from(format!("{}.approval.json", bad.display())).exists());
    let rejected = Vault::open(temp.path().join("rejected-vault"), VaultConfig::device())
        .expect("rejected vault opens");
    let candidate = ModelManifest::load(&manifest).expect("candidate parses");
    assert!(rejected.set_model_manifest(&candidate).is_err());
    assert!(rejected.model_manifest().expect("manifest read").is_none());
}
