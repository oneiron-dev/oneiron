//! FIX [CONFIG-VALIDATION-PORT]: a config file is read only once it is
//! admitted by who else can reach it. A file any user can write is refused,
//! because it decides what the server serves and whom it trusts. A file that
//! sets `auth_secret` holds the issuer key, so it must be its owner's alone,
//! and the refusal names the line that sets the key and never the key. The
//! same rule holds for `--settings-file` and for the config `model-workers`
//! reads, whose parse failure names a place and prints no line of the file.
//! Public paths only: the shipped `oneiron` binary.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// An issuer key no output may repeat.
const SECRET: &str = "config-admission-issuer-key-not-a-bearer";
/// A setting serve refuses once it has read and parsed the file that holds
/// it, so a config that was admitted stops serve all the same.
const REFUSED_SETTING: &str = "house_role = \"no-such-role\"\n";
/// What that refusal says: the mark of a file that was read.
const READ_AND_PARSED: &str = "house_role must be";
/// A refused command stops at once; one that runs this long was not refused.
const STOPS_WITHIN: Duration = Duration::from_secs(120);

#[test]
fn a_config_any_user_can_write_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    for mode in [0o666, 0o646, 0o602] {
        let name = format!("writable-{mode:o}.toml");
        let config = config_file(dir.path(), &name, REFUSED_SETTING, mode);
        let error = serve_refused(dir.path(), &config, None);
        assert!(error.contains("chmod o-w"), "mode {mode:o}: {error}");
        assert!(error.contains(&name), "mode {mode:o}: {error}");
        assert!(
            error.contains(&format!("mode {mode:o}")),
            "mode {mode:o}: {error}"
        );
        assert!(
            !error.contains(READ_AND_PARSED),
            "mode {mode:o} was read: {error}"
        );
    }
}

/// The control of the refusals: a file no other user can write is read. Mode
/// 0664 is what a hand-written file gets under umask 002, where the group is
/// the user's own.
#[test]
fn a_config_no_other_user_can_write_is_read() {
    let dir = tempfile::tempdir().unwrap();
    for mode in [0o600, 0o644, 0o664] {
        let name = format!("closed-{mode:o}.toml");
        let config = config_file(dir.path(), &name, REFUSED_SETTING, mode);
        let error = serve_refused(dir.path(), &config, None);
        assert!(error.contains(READ_AND_PARSED), "mode {mode:o}: {error}");
        assert!(!error.contains("chmod"), "mode {mode:o}: {error}");
    }
}

#[test]
fn a_config_that_sets_the_issuer_key_is_its_owners_alone() {
    let dir = tempfile::tempdir().unwrap();
    let text = format!(
        "host = \"127.0.0.1\"\n# the issuer key\nauth_secret = \"{SECRET}\"\n{REFUSED_SETTING}"
    );
    for mode in [0o644, 0o640, 0o604] {
        let name = format!("keyed-{mode:o}.toml");
        let config = config_file(dir.path(), &name, &text, mode);
        let error = serve_refused(dir.path(), &config, None);
        assert!(
            error.contains("auth_secret at line 3"),
            "mode {mode:o}: {error}"
        );
        assert!(error.contains("chmod 600"), "mode {mode:o}: {error}");
        assert!(error.contains(&name), "mode {mode:o}: {error}");
        assert!(!error.contains(SECRET), "mode {mode:o}: {error}");
        assert!(
            !error.contains(READ_AND_PARSED),
            "mode {mode:o} was read: {error}"
        );
    }
    // The owner's alone: read, and the refusal it then meets says nothing of
    // the key.
    let config = config_file(dir.path(), "keyed-600.toml", &text, 0o600);
    let error = serve_refused(dir.path(), &config, None);
    assert!(error.contains(READ_AND_PARSED), "{error}");
    assert!(!error.contains(SECRET), "{error}");
}

/// A link is followed, and the file it names is the one checked and read.
#[test]
fn a_linked_config_is_admitted_as_the_file_it_names() {
    let dir = tempfile::tempdir().unwrap();
    let open = config_file(dir.path(), "target-open.toml", REFUSED_SETTING, 0o666);
    let to_open = dir.path().join("link-open.toml");
    std::os::unix::fs::symlink(&open, &to_open).unwrap();
    let error = serve_refused(dir.path(), &to_open, None);
    assert!(error.contains("chmod o-w"), "{error}");
    assert!(!error.contains(READ_AND_PARSED), "{error}");

    let closed = config_file(dir.path(), "target-closed.toml", REFUSED_SETTING, 0o644);
    let to_closed = dir.path().join("link-closed.toml");
    std::os::unix::fs::symlink(&closed, &to_closed).unwrap();
    let error = serve_refused(dir.path(), &to_closed, None);
    assert!(error.contains(READ_AND_PARSED), "{error}");
}

#[test]
fn a_settings_file_is_admitted_as_the_config_is() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_file(dir.path(), "oneiron.toml", "host = \"127.0.0.1\"\n", 0o644);
    let settings = config_file(dir.path(), "settings.toml", REFUSED_SETTING, 0o666);
    let error = serve_refused(dir.path(), &config, Some(&settings));
    assert!(error.contains("chmod o-w"), "{error}");
    assert!(error.contains("settings.toml"), "{error}");
    assert!(!error.contains(READ_AND_PARSED), "{error}");
}

#[test]
fn model_workers_refuses_a_config_any_user_can_write() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_file(dir.path(), "workers-open.toml", REFUSED_SETTING, 0o666);
    let error = refused(
        dir.path(),
        &["model-workers", "--config", config.to_str().unwrap()],
    );
    assert!(error.contains("chmod o-w"), "{error}");
    assert!(error.contains("workers-open.toml"), "{error}");
}

/// The parser's own message quotes the line it failed on, and that line can
/// hold the issuer key: the failure names the file and the place alone.
#[test]
fn model_workers_names_only_the_place_of_a_line_it_cannot_read() {
    let dir = tempfile::tempdir().unwrap();
    let text = format!("auth_secret = \"{SECRET}\" trailing\n");
    let config = config_file(dir.path(), "workers-broken.toml", &text, 0o600);
    let error = refused(
        dir.path(),
        &["model-workers", "--config", config.to_str().unwrap()],
    );
    assert!(error.contains("workers-broken.toml"), "{error}");
    assert!(error.contains("line 1"), "{error}");
    assert!(!error.contains(SECRET), "{error}");
}

/// A new file `name` in `dir` that holds `text`, its mode exactly `mode`
/// whatever the umask of the test process.
fn config_file(dir: &Path, name: &str, text: &str, mode: u32) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

/// What `oneiron serve` says when it stops on `config`, and on `settings`
/// as its `--settings-file` when one is given.
fn serve_refused(home: &Path, config: &Path, settings: Option<&Path>) -> String {
    let mut args = vec!["serve", "--config", config.to_str().unwrap()];
    if let Some(settings) = settings {
        args.extend(["--settings-file", settings.to_str().unwrap()]);
    }
    refused(home, &args)
}

/// The standard error of `oneiron <args>`, which must stop by itself with a
/// failure. A command that was not refused would serve until it is stopped,
/// so one that outlasts [`STOPS_WITHIN`] is stopped and fails the test.
fn refused(home: &Path, args: &[&str]) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
    // Do not inherit vault, model or switch settings from the build host.
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("ONEIRON_") {
            command.env_remove(name);
        }
    }
    let mut child = command
        .args(args)
        .env("HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
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
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    let stderr = String::from_utf8_lossy(&stderr).into_owned();
    assert!(!status.success(), "oneiron {args:?} must fail: {stderr}");
    stderr
}
