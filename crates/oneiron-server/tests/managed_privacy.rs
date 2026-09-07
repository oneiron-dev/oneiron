//! Privacy inputs must not be accepted and dropped by managed contract v1.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use clap::Parser;
use oneiron_server::config::ServeArgs;
use oneiron_server::managed::{ManagedArgs, ManagedError};
use oneiron_vault_contract::{CONTRACT_VERSION, DEK_LEN, TOKEN_LEN, write_credentials};

#[derive(Parser)]
struct ArgvProbe {
    #[command(flatten)]
    serve: ServeArgs,
}

fn managed_argv(root: &Path) -> Vec<String> {
    let path = |name: &str| root.join(name).display().to_string();
    vec![
        "--managed-by-hypnos".to_owned(),
        "--contract-version".to_owned(),
        CONTRACT_VERSION.to_string(),
        "--vault-name".to_owned(),
        "privacy-canary".to_owned(),
        "--data-dir".to_owned(),
        path("data"),
        "--http-socket".to_owned(),
        path("http.sock"),
        "--ctl-socket".to_owned(),
        path("ctl.sock"),
        "--hypnos-socket".to_owned(),
        path("sup.sock"),
        "--ready-fd".to_owned(),
        "1".to_owned(),
        "--credentials-fd".to_owned(),
        "0".to_owned(),
    ]
}

// Environment changes stay inside a child. Parallel test threads never mutate
// the process environment. The descriptor offsets pin rejection before any IO.
fn boot_refused(
    run: &Path,
    extra_args: &[String],
    extra_env: &[(&str, OsString)],
) -> anyhow::Result<Output> {
    let mut frame = Vec::new();
    write_credentials(&mut frame, &[0x11; DEK_LEN], &[0x22; TOKEN_LEN])?;
    let frame_path = run.join("creds");
    std::fs::write(&frame_path, frame)?;
    let frame_file = std::fs::File::open(frame_path)?;
    let mut frame_probe = frame_file.try_clone()?;
    let ready_path = run.join("ready");
    let ready = std::fs::File::create(&ready_path)?;
    let output = Command::new(env!("CARGO_BIN_EXE_oneiron-server"))
        .arg("serve")
        .args(managed_argv(run))
        .args(extra_args)
        .env_clear()
        .envs(extra_env.iter().map(|(key, value)| (*key, value)))
        .stdin(Stdio::from(frame_file))
        .stdout(Stdio::from(ready))
        .stderr(Stdio::piped())
        .output()?;
    assert!(!output.status.success());
    assert_eq!(std::io::Seek::stream_position(&mut frame_probe)?, 0);
    assert!(std::fs::read(ready_path)?.is_empty());
    for path in ["data", "http.sock", "ctl.sock", "sup.sock"] {
        assert!(!run.join(path).exists(), "refused boot created {path}");
    }
    Ok(output)
}

#[test]
fn managed_privacy_flags_are_refused_in_both_cli_forms() {
    for (flag, value) in [
        ("privacy-posture", "hosted"),
        ("privacy-posture", "self_host_local"),
        ("hosted-kms-key-ref", "kms://example/cli-secret-ref"),
        ("hosted-kms-key-ref", ""),
    ] {
        for joined in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let extra = if joined {
                vec![format!("--{flag}={value}")]
            } else {
                vec![format!("--{flag}"), value.to_owned()]
            };
            let mut argv = vec!["oneiron-server".to_owned()];
            argv.extend(managed_argv(dir.path()));
            argv.extend(extra.iter().cloned());
            let args = ArgvProbe::try_parse_from(argv).unwrap().serve;
            let error = ManagedArgs::from_serve_args(&args).unwrap_err();
            assert!(
                matches!(
                    &error,
                    ManagedError::ConflictingFlag { flag: found, .. } if *found == flag
                ),
                "{error}"
            );
            assert!(!format!("{error:?}").contains("kms://example/cli-secret-ref"));

            let output = boot_refused(dir.path(), &extra, &[]).unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains(&format!("conflicts with --{flag}")),
                "{stderr}"
            );
            assert!(!stderr.contains("kms://example/cli-secret-ref"));
        }
    }
}

#[test]
fn managed_privacy_environment_is_refused_without_parsing_or_echoing_values() {
    for (env, values) in [
        (
            "ONEIRON_PRIVACY_POSTURE",
            ["hosted", "self_host_local", "not-a-posture", ""],
        ),
        (
            "ONEIRON_HOSTED_KMS_KEY_REF",
            ["kms://example/env-secret-ref", " ", "invalid-ref", ""],
        ),
        (
            "ONEIRON_CONFIG",
            ["/nonexistent/oneiron.toml", " ", "not-a-path", ""],
        ),
    ] {
        for value in values
            .map(OsString::from)
            .into_iter()
            .chain([OsString::from_vec(vec![0xff])])
        {
            let dir = tempfile::tempdir().unwrap();
            let output = boot_refused(dir.path(), &[], &[(env, value)]).unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains(&format!("conflicts with {env}")),
                "{stderr}"
            );
            assert!(!stderr.contains("kms://example/env-secret-ref"));
            assert!(!stderr.contains("not-a-posture"));
            assert!(!stderr.contains("invalid-ref"));
        }
    }
}

#[test]
fn managed_privacy_files_are_refused_at_each_explicit_config_door() {
    for contents in [
        "privacy_posture = \"hosted\"\n",
        "hosted_kms_key_ref = \"kms://example/file-secret-ref\"\n",
        "privacy_posture = \"hosted\"\nhosted_kms_key_ref = \"kms://example/file-secret-ref\"\n",
        "this is not valid TOML",
    ] {
        for source in ["--config", "--config=", "ONEIRON_CONFIG"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("oneiron.toml");
            std::fs::write(&path, contents).unwrap();
            let extra_args = match source {
                "--config" => vec![source.to_owned(), path.display().to_string()],
                "--config=" => vec![format!("{source}{}", path.display())],
                _ => Vec::new(),
            };
            let extra_env = if source == "ONEIRON_CONFIG" {
                vec![(source, path.into_os_string())]
            } else {
                Vec::new()
            };
            let output = boot_refused(dir.path(), &extra_args, &extra_env).unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            let named = source.trim_end_matches('=');
            assert!(
                stderr.contains(&format!("conflicts with {named}")),
                "{stderr}"
            );
            assert!(!stderr.contains("kms://example/file-secret-ref"));
            assert!(!stderr.contains("parse config file"));
        }
    }
}
