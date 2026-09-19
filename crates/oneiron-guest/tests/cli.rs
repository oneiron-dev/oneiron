//! Native CLI artifact generation and pinning, not microVM boot evidence.

use std::{fs, process::Command};

#[test]
fn conformance_cli_creates_once_and_reports_the_artifact_digest() {
    let directory = tempfile::tempdir().expect("temporary artifact directory");
    let artifact = directory.path().join("conformance.wasm");
    let executable = env!("CARGO_BIN_EXE_oneiron-guest");
    let generated = Command::new(executable)
        .arg("--write-conformance")
        .arg(&artifact)
        .output()
        .expect("run artifact generator");
    assert!(generated.status.success());
    let bytes = fs::read(&artifact).expect("generated artifact");
    assert_eq!(bytes, oneiron_guest::conformance::component().unwrap());

    let digest = Command::new(executable)
        .arg("--artifact-digest")
        .arg(&artifact)
        .output()
        .expect("run artifact digest");
    assert!(digest.status.success());
    assert_eq!(
        String::from_utf8(digest.stdout).unwrap().trim(),
        blake3::hash(&bytes).to_hex().as_str()
    );

    let overwrite = Command::new(executable)
        .arg("--write-conformance")
        .arg(&artifact)
        .output()
        .expect("attempt duplicate artifact");
    assert!(!overwrite.status.success());
    assert_eq!(fs::read(&artifact).unwrap(), bytes);
}

#[test]
fn production_cli_refuses_an_ordinary_host_process() {
    let result = Command::new(env!("CARGO_BIN_EXE_oneiron-guest"))
        .output()
        .expect("run guarded entry point");
    // A child test process is never Linux PID 1, even under a privileged runner.
    assert!(!result.status.success());
}
