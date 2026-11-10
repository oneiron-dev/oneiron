//! Runs the shipped bench flow to produce and check the approved E2E manifest fixture.
//! Regenerate with ONEIRON_WRITE_E2E_FIXTURE=1 cargo test -p oneiron-bench --test e2e_approved_manifest_fixture -- --nocapture.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]
use oneiron::llm::manifest::{ModelManifest, TeacherProbeApproval};
use oneiron::{Vault, VaultConfig};
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;
use std::process::Command;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/teacher_probe");
const E2E_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/e2e/fixtures/model-manifests"
);

#[test]
fn e2e_approved_manifest_fixture_matches_the_bench_flow() {
    let fixtures = PathBuf::from(FIXTURES);
    let temp = tempfile::tempdir().expect("E2E manifest fixture");
    let vault = Vault::open(temp.path().join("policy-vault"), VaultConfig::device())
        .expect("policy vault opens");
    let policy = temp.path().join("resolved-policy.json");
    std::fs::write(
        &policy,
        serde_json::to_vec(&vault.teacher_probe_policy(None).expect("vault policy"))
            .expect("policy serialization"),
    )
    .expect("policy export");
    let candidate = ModelManifest::load(&fixtures.join("candidate.fixture.json"))
        .expect("candidate manifest");
    let manifest = temp.path().join("candidate.json");
    std::fs::write(
        &manifest,
        serde_json::to_vec_pretty(&candidate).expect("candidate serialization"),
    )
    .expect("candidate export");
    let output = temp.path().join("approved.json");
    let result = Command::new(env!("CARGO_BIN_EXE_oneiron-bench"))
        .args(["teacher-probe", "--checkpoint"])
        .arg(fixtures.join("checkpoint"))
        .args([
            "--runner",
            &format!("{FIXTURES}/fixture_runner.py"),
            "--manifest",
        ])
        .arg(&manifest)
        .arg("--policy")
        .arg(&policy)
        .arg("--out")
        .arg(&output)
        .output()
        .expect("teacher probe CLI fixture");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let approved = ModelManifest::load(&output).expect("approved manifest");
    let approval = TeacherProbeApproval::load(&temp.path().join("approved.json.approval.json"))
        .expect("probe approval");
    let vault = Vault::open(temp.path().join("install-vault"), VaultConfig::device())
        .expect("install vault opens");
    assert!(vault.set_model_manifest(&approved).is_err());
    vault
        .set_model_manifest_with_teacher_approval(&approved, &approval)
        .expect("passing checkpoint pins");
    let read = vault
        .model_manifest()
        .expect("manifest read")
        .expect("installed manifest");
    assert_eq!(read, approved);
    let value = serde_json::json!({
        "manifest": serde_json::to_value(&read).expect("manifest value"),
        "teacher_approval": serde_json::to_value(&approval).expect("approval value"),
    });
    let mut bytes = serde_json::to_vec_pretty(&value).expect("fixture serialization");
    bytes.push(b'\n');
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let e2e_dir = PathBuf::from(E2E_DIR);
    let fixture_file = e2e_dir.join("muse-loop-04-approved-model-manifest.json");
    let manifest_file = e2e_dir.join("manifest.json");
    if std::env::var("ONEIRON_WRITE_E2E_FIXTURE").as_deref() == Ok("1") {
        std::fs::create_dir_all(&e2e_dir).expect("fixture directory");
        std::fs::write(&fixture_file, &bytes).expect("fixture export");
        println!(
            "E2E-FIXTURE sha256={digest} bytes={} f1_millionths={}",
            bytes.len(),
            approval.f1_millionths
        );
        println!(
            "E2E-FIXTURE-JSON {}",
            serde_json::to_string(&value).expect("fixture one-line serialization")
        );
        return;
    }
    assert_eq!(
        std::fs::read_to_string(&fixture_file).expect("committed fixture"),
        String::from_utf8(bytes).expect("fixture UTF-8"),
        "regenerate: ONEIRON_WRITE_E2E_FIXTURE=1 cargo test -p oneiron-bench --test e2e_approved_manifest_fixture -- --nocapture, then update sha256 in manifest.json"
    );
    let catalog: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_file).expect("fixture catalog"))
            .expect("fixture catalog JSON");
    let asset = catalog["assets"]
        .as_array()
        .expect("fixture assets")
        .iter()
        .find(|asset| asset["id"] == "muse-loop-04-approved-model-manifest")
        .expect("approved manifest asset");
    assert_eq!(asset["path"], "muse-loop-04-approved-model-manifest.json");
    assert_eq!(asset["sha256"].as_str(), Some(digest.as_str()));
}
