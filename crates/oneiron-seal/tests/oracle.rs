//! CI differential oracle (§9, amendment A6). The pyHanko check runs when
//! pyHanko is available; optional reader wrappers and extra `pdfsig` binaries
//! run only when configured. Missing optional tools skip explicitly.
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

fn fixture_input() -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/pdf-input/interop_1page.pdf",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn seal_sample() -> Vec<u8> {
    seal_sample_from_input(&fixture_input())
}

fn seal_sample_from_input(input: &[u8]) -> Vec<u8> {
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
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(engine.seal_pdf(
            input,
            &SealRequest {
                operation_id: "oracle-row".to_string(),
                target_profile: PadesProfile::BaselineB,
            },
        ))
        .unwrap()
        .bytes
}

/// Run one configured reader wrapper against a fresh native seal. The wrapper
/// contract is one PDF argument, exit 0 for a successful check, exit 1 for a
/// failed check, and exit 77 when its optional tool is not installed. Its JSON
/// report carries the reader and version for the interop record.
fn optional_reader_validate(env_var: &str, reader: &str, expected_mode: &str) {
    let Some(binary) = std::env::var_os(env_var).filter(|value| !value.is_empty()) else {
        eprintln!("seal-oracle: {reader} wrapper not configured; skipping (optional leg)");
        return;
    };
    let sealed = seal_sample();
    let dir = tempfile::tempdir().unwrap();
    let pdf_path = dir.path().join("sealed.pdf");
    std::fs::write(&pdf_path, &sealed).unwrap();
    let out = Command::new(&binary)
        .arg(&pdf_path)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {reader} wrapper {binary:?}: {error}"));
    if out.status.code() == Some(77) {
        eprintln!("seal-oracle: {reader} is not installed; skipping (optional leg)");
        return;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "{reader} rejected or could not parse the native seal (status {:?}): stdout={stdout:?}; stderr={stderr:?}",
        out.status.code()
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|error| {
        panic!("{reader} wrapper must emit JSON: {error}; stdout={stdout:?}")
    });
    assert_eq!(
        report["reader"], reader,
        "unexpected reader report: {stdout:?}"
    );
    assert!(
        report["version"]
            .as_str()
            .is_some_and(|version| !version.is_empty()),
        "reader version is required in the JSON report: {stdout:?}"
    );
    assert_eq!(
        report["mode"], expected_mode,
        "unexpected check mode: {stdout:?}"
    );
    assert_eq!(
        report["status"], "pass",
        "reader did not report pass: {stdout:?}"
    );
    if reader == "dss" {
        assert!(
            report["dss_ades_indication"]
                .as_str()
                .is_some_and(|indication| !indication.is_empty()),
            "DSS indication is required: {stdout:?}"
        );
        assert!(
            report["dss_ades_subindication"].is_string(),
            "DSS sub-indication field is required (empty is allowed): {stdout:?}"
        );
    }
    println!("{}", stdout.trim());
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

/// Optional DSS wrapper. Unlike parse-only readers, DSS must verify CMS integrity.
#[test]
fn native_seal_dss_validate() {
    optional_reader_validate("SEAL_DSS_BIN", "dss", "verify");
}

/// Optional PDFBox wrapper. It verifies CMS integrity and the signed byte range.
#[test]
fn native_seal_pdfbox_validate() {
    optional_reader_validate("SEAL_PDFBOX_BIN", "pdfbox", "verify");
}

/// Optional PDFium reader check. PDFium parses/opens the PDF; it does not
/// validate the detached CMS signature.
#[test]
fn native_seal_pdfium_parse() {
    optional_reader_validate("SEAL_PDFIUM_BIN", "pdfium", "parse");
}

/// Optional pdf.js reader check. pdf.js parses/opens the PDF; it does not
/// validate the detached CMS signature.
#[test]
fn native_seal_pdfjs_parse() {
    optional_reader_validate("SEAL_PDFJS_BIN", "pdfjs", "parse");
}

/// Optional qpdf structural check.
#[test]
fn native_seal_qpdf_check() {
    optional_reader_validate("SEAL_QPDF_BIN", "qpdf", "check");
}

/// Additional Poppler builds can be listed with the host path-list syntax.
/// Each entry is the path to a pdfsig-compatible executable.
#[test]
fn native_seal_pdfsig_extra_binaries_validate() {
    let binaries: Vec<_> = std::env::var_os("PDFSIG_EXTRA_BINARIES")
        .map(|paths| {
            std::env::split_paths(&paths)
                .filter(|path| !path.as_os_str().is_empty())
                .collect()
        })
        .unwrap_or_default();
    if binaries.is_empty() {
        eprintln!("seal-oracle: PDFSIG_EXTRA_BINARIES not set; skipping (optional leg)");
        return;
    }

    let sealed = seal_sample();
    let dir = tempfile::tempdir().unwrap();
    let pdf_path = dir.path().join("sealed.pdf");
    std::fs::write(&pdf_path, &sealed).unwrap();
    for binary in binaries {
        let version = Command::new(&binary)
            .arg("-v")
            .output()
            .unwrap_or_else(|error| panic!("cannot query extra pdfsig {binary:?}: {error}"));
        assert!(
            version.status.success(),
            "extra pdfsig {binary:?} did not report its version: {}",
            String::from_utf8_lossy(&version.stderr)
        );
        let version_text = format!(
            "{}{}",
            String::from_utf8_lossy(&version.stdout),
            String::from_utf8_lossy(&version.stderr)
        );
        println!(
            "seal-oracle: {}",
            version_text
                .lines()
                .find(|line| line.contains("pdfsig version"))
                .unwrap_or("pdfsig version unknown")
        );
        let out = Command::new(&binary)
            .arg(&pdf_path)
            .output()
            .unwrap_or_else(|error| panic!("cannot run extra pdfsig {binary:?}: {error}"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "extra pdfsig {binary:?} rejected the native seal (status {:?}): stdout={stdout:?}; stderr={stderr:?}",
            out.status.code()
        );
        assert!(
            stdout.contains("Signature is Valid"),
            "extra pdfsig {binary:?} did not report a valid signature: {stdout:?}"
        );
    }
}

/// Manually export the synthetic signed fixture for standalone interop checks.
/// The key is test-only and its private material is not written to the PDF.
/// `SEAL_SAMPLE_INPUT` optionally supplies a prepared PDF; otherwise the
/// structurally clean `interop_1page.pdf` fixture is used.
/// Run with `SEAL_SAMPLE_OUTPUT=/path/out.pdf cargo test -p oneiron-seal --features seal-oracle --test oracle export_signed_sample -- --ignored --exact`.
#[test]
#[ignore = "manual signed-sample export; set SEAL_SAMPLE_OUTPUT"]
fn export_signed_sample() {
    let output = std::env::var_os("SEAL_SAMPLE_OUTPUT")
        .expect("set SEAL_SAMPLE_OUTPUT to the destination PDF path");
    let input = std::env::var_os("SEAL_SAMPLE_INPUT").map_or_else(fixture_input, |path| {
        std::fs::read(&path)
            .unwrap_or_else(|error| panic!("cannot read sample input {path:?}: {error}"))
    });
    let bytes = seal_sample_from_input(&input);
    std::fs::write(&output, &bytes)
        .unwrap_or_else(|error| panic!("cannot write signed sample to {output:?}: {error}"));
    eprintln!(
        "seal-oracle: wrote {} signed test bytes to {}",
        bytes.len(),
        std::path::Path::new(&output).display()
    );
}
