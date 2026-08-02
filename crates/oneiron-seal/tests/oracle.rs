//! CI differential oracle (§9, amendment A6). Runs ONLY on the designated
//! `seal-oracle` CI leg with the pinned oracle image available. Locally, or
//! anywhere pyHanko is absent, every case skips with a message.
//!
//! Raw sealed bytes are never compared byte-for-byte across implementations;
//! the oracle compares normalized semantics and cross-validation results.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::process::Command;
use std::sync::Arc;

use oneiron_seal::{
    FetchPolicy, NativeSealEngine, OfflineFetcher, PadesProfile, PdfSealEngine, SealConfig,
    SealRequest, SealResourceLimits,
};

use support::{FixedClock, FixtureBackend, TEST_TIME_MS, p256_identity};

fn oracle_available() -> bool {
    Command::new("python3")
        .arg("-c")
        .arg("import pyhanko")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn seal_sample() -> Vec<u8> {
    let id = p256_identity(false);
    let anchor = id.cert_der.clone();
    let engine = NativeSealEngine::new(
        SealConfig {
            trust_anchors_der: vec![anchor],
            timestamp_authorities: Vec::new(),
            fetch_policy: FetchPolicy::default(),
            resource_limits: SealResourceLimits::default(),
        },
        Arc::new(FixtureBackend::new(id)),
        Arc::new(OfflineFetcher),
        Arc::new(FixedClock(TEST_TIME_MS)),
    )
    .unwrap();
    let input = std::fs::read(format!(
        "{}/tests/fixtures/pdf-input/classic_1page.pdf",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(engine.seal_pdf(
            &input,
            &SealRequest {
                operation_id: "oracle-row".to_string(),
                target_profile: PadesProfile::BaselineB,
            },
        ))
        .unwrap()
        .bytes
}

/// Oracle matrix row 2: native seal -> pyHanko validate.
#[test]
fn native_seal_pyhanko_validate() {
    if !oracle_available() {
        eprintln!("seal-oracle: pyHanko not installed; skipping (CI-only leg)");
        return;
    }
    let sealed = seal_sample();
    let dir = tempfile::tempdir().unwrap();
    let pdf_path = dir.path().join("sealed.pdf");
    std::fs::write(&pdf_path, &sealed).unwrap();
    let runner = format!("{}/oracle/run.py", env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("python3")
        .arg(&runner)
        .arg("validate")
        .arg(&pdf_path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "oracle validate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["valid"], serde_json::json!(true));
}

/// Oracle matrix row 4: native seal -> `pdfsig` validation (present in the
/// pinned CI image). Skips cleanly where pdfsig is absent.
#[test]
fn native_seal_pdfsig_validate() {
    let available = Command::new("pdfsig")
        .arg("-v")
        .output()
        .is_ok_and(|o| o.status.success());
    if !available {
        eprintln!("seal-oracle: pdfsig not installed; skipping (CI-only leg)");
        return;
    }
    let sealed = seal_sample();
    let dir = tempfile::tempdir().unwrap();
    let pdf_path = dir.path().join("sealed.pdf");
    std::fs::write(&pdf_path, &sealed).unwrap();
    let out = Command::new("pdfsig").arg(&pdf_path).output().unwrap();
    assert!(
        out.status.success(),
        "pdfsig rejected the native seal: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Signature is Valid"),
        "unexpected pdfsig verdict: {stdout}"
    );
}
