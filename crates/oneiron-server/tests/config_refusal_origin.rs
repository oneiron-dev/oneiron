//! FIX [CONFIG-REFUSED-VALUE-NAMES-NO-FILE-LINE]: a value serve refuses after
//! the parse names where it was set. One set in the config file or the
//! owner's settings file names that file and the line of its key; one set in
//! the environment or on the command line names that layer. The refusal
//! itself is unchanged under it, and no value is repeated. Public paths
//! only: the shipped `oneiron` binary.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// A refused command stops at once; one that runs this long was not refused.
const STOPS_WITHIN: Duration = Duration::from_secs(120);
/// A blank key reference, which the custody check refuses whichever layer
/// sets it.
const BLANK_KEY_REF: &str = "   ";
/// What that refusal says.
const BLANK_KEY_REF_REFUSED: &str = "KMS key custody requires a non-empty key reference";

/// A value refused as its layer is applied (`house_role`) names the file and
/// the line of its key.
#[test]
fn a_role_refused_from_the_config_file_names_the_file_and_the_line() {
    let dir = tempfile::tempdir().unwrap();
    let config = file(
        dir.path(),
        "role.toml",
        "# the house role\n\nhouse_role = \"no-such-role\"\n",
    );
    let error = serve_refused(dir.path(), &["--config", config.to_str().unwrap()], &[]);
    assert!(
        error.contains(&format!(
            "house_role is set in config file {} at line 3",
            config.display()
        )),
        "{error}"
    );
    assert!(error.contains("house_role must be"), "{error}");
    assert!(!error.contains("no-such-role"), "{error}");
}

/// A value refused when the merged config is checked (`[limits]`) names the
/// file and the line of its key.
#[test]
fn a_limit_refused_from_the_config_file_names_the_file_and_the_line() {
    let dir = tempfile::tempdir().unwrap();
    let config = file(
        dir.path(),
        "limits.toml",
        "host = \"127.0.0.1\"\n\n[limits]\nmax_connections = 0\n",
    );
    let error = serve_refused(dir.path(), &["--config", config.to_str().unwrap()], &[]);
    assert!(
        error.contains(&format!(
            "limits.max_connections is set in config file {} at line 4",
            config.display()
        )),
        "{error}"
    );
    assert!(
        error.contains("limits.max_connections must be at least 1"),
        "{error}"
    );
}

/// The owner's settings file is a layer of its own, over the config file.
#[test]
fn a_role_refused_from_the_settings_file_names_that_file_and_the_line() {
    let dir = tempfile::tempdir().unwrap();
    let config = file(dir.path(), "base.toml", "house_role = \"member\"\n");
    let settings = file(
        dir.path(),
        "settings.toml",
        "house_role = \"no-such-role\"\n",
    );
    let error = serve_refused(
        dir.path(),
        &[
            "--config",
            config.to_str().unwrap(),
            "--settings-file",
            settings.to_str().unwrap(),
        ],
        &[],
    );
    assert!(
        error.contains(&format!(
            "house_role is set in settings file {} at line 1",
            settings.display()
        )),
        "{error}"
    );
    assert!(!error.contains("is set in config file"), "{error}");
}

/// A value refused from the environment names the environment; the same
/// value from the command line names the command line. The config file
/// under them sets the same key well and is not named, and no reference is
/// repeated.
#[test]
fn a_key_reference_refused_from_the_environment_or_a_flag_names_that_layer() {
    let dir = tempfile::tempdir().unwrap();
    let config = file(
        dir.path(),
        "custody.toml",
        "hosted_kms_key_ref = \"kms://example/file-ref\"\n",
    );
    let error = serve_refused(
        dir.path(),
        &["--config", config.to_str().unwrap()],
        &[("ONEIRON_HOSTED_KMS_KEY_REF", BLANK_KEY_REF)],
    );
    assert!(error.contains("from the environment"), "{error}");
    assert!(error.contains(BLANK_KEY_REF_REFUSED), "{error}");
    assert!(!error.contains("is set in config file"), "{error}");
    assert!(!error.contains("kms://example/file-ref"), "{error}");

    let error = serve_refused(
        dir.path(),
        &[
            "--config",
            config.to_str().unwrap(),
            "--hosted-kms-key-ref",
            BLANK_KEY_REF,
        ],
        &[],
    );
    assert!(error.contains("from the command line"), "{error}");
    assert!(error.contains(BLANK_KEY_REF_REFUSED), "{error}");
    assert!(!error.contains("is set in config file"), "{error}");
}

/// A new file `name` in `dir` that holds `text`, mode 0600.
fn file(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

/// The standard error of `oneiron serve <args>` with `env` set, which must
/// stop by itself with a failure.
fn serve_refused(home: &Path, args: &[&str], env: &[(&str, &str)]) -> String {
    let mut all = vec!["serve"];
    all.extend_from_slice(args);
    let (status, _, error) = ran(home, &all, env);
    assert!(!status.success(), "oneiron {all:?} must fail: {error}");
    error
}

/// How `oneiron <args>` ended with `env` set, then its standard output and
/// its standard error. Both are written to files, so no full pipe holds the
/// command. A command that was not refused would serve until it is stopped,
/// so one that outlasts [`STOPS_WITHIN`] is stopped and fails the test.
fn ran(home: &Path, args: &[&str], env: &[(&str, &str)]) -> (ExitStatus, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
    // Do not inherit vault, model or switch settings from the build host.
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("ONEIRON_") {
            command.env_remove(name);
        }
    }
    command.envs(env.iter().copied());
    let printed = tempfile::tempdir().unwrap();
    let output = printed.path().join("output");
    let error = printed.path().join("error");
    let mut child = command
        .args(args)
        .env("HOME", home)
        .stdin(Stdio::null())
        .stdout(File::create(&output).unwrap())
        .stderr(File::create(&error).unwrap())
        .spawn()
        .expect("run oneiron");
    let deadline = Instant::now() + STOPS_WITHIN;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("oneiron {args:?} did not stop within {STOPS_WITHIN:?}: it was not refused");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let text = |path: &Path| String::from_utf8_lossy(&std::fs::read(path).unwrap()).into_owned();
    (status, text(&output), text(&error))
}
