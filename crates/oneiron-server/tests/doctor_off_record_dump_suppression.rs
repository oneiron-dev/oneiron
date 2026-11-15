//! Census row L6-18: `oneiron doctor` reports the operator's core-dump switch
//! for a process that holds an off-record room, as a serve started with the
//! same settings applies it. Suppression is on by default;
//! `off_record_dump_suppression = false` in the config file, or
//! `ONEIRON_OFF_RECORD_DUMP_SUPPRESSION=false`, turns it off, and the
//! environment stands over the file. Public paths only: the shipped
//! `oneiron` binary.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::Command;

use serde_json::Value;

const SECRET: &str = "dump-switch-issuer-key-not-a-bearer";
const ENV_SWITCH: &str = "ONEIRON_OFF_RECORD_DUMP_SUPPRESSION";

#[test]
fn doctor_reports_the_off_record_dump_suppression_switch() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let config = dir.path().join("oneiron.toml");
    let init = oneiron(
        &["init", vault.to_str().unwrap(), "--embedder", "none"],
        &config,
    )
    .output()
    .expect("run oneiron init");
    assert!(
        init.status.success(),
        "oneiron init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    // A top-level key goes before the file's first table, or TOML reads it
    // as that table's.
    let written = std::fs::read_to_string(&config).unwrap();
    let switched_off = dir.path().join("switched-off.toml");
    std::fs::write(
        &switched_off,
        format!("off_record_dump_suppression = false\n{written}"),
    )
    .unwrap();

    let cases = [
        ("the default", &config, None, true),
        ("the config file's false", &switched_off, None, false),
        ("the environment's false", &config, Some("false"), false),
        (
            "the environment's true over the file's false",
            &switched_off,
            Some("true"),
            true,
        ),
    ];
    for (case, config, environment, expected) in cases {
        let mut doctor = oneiron(&["doctor", vault.to_str().unwrap()], config);
        if let Some(value) = environment {
            doctor.env(ENV_SWITCH, value);
        }
        let output = doctor.output().expect("run oneiron doctor");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "doctor failed under {case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
            panic!("doctor printed no JSON under {case} ({error}): {stdout}")
        });
        assert_eq!(
            report["config_errors"],
            Value::Null,
            "the settings resolve under {case}: {stdout}"
        );
        let switch = &report["off_record_dump_suppression"];
        assert_eq!(
            switch["enabled"],
            Value::Bool(expected),
            "doctor reports suppression {} under {case}: {stdout}",
            if expected { "on" } else { "off" }
        );
        let mechanisms = switch["mechanisms"].as_array().cloned().unwrap_or_default();
        assert!(
            mechanisms.contains(&Value::from("RLIMIT_CORE 0")),
            "doctor names what suppression changes on this platform under {case}: {stdout}"
        );
    }
}

fn oneiron(args: &[&str], config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
    // Do not inherit vault, model or switch settings from the build host.
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("ONEIRON_") {
            command.env_remove(name);
        }
    }
    command
        .args(args)
        .arg("--config")
        .arg(config)
        .env("ONEIRON_AUTH_SECRET", SECRET);
    command
}
