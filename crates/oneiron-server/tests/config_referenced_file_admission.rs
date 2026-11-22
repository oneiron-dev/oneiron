//! FIX [CONFIG-SIDE-FILES-MODE-UNCHECKED] and
//! [CONFIG-SIDE-FILE-PARSE-ERRORS-PRINT-PARSER-MESSAGE]: a file a config
//! refers to decides what a model is told, what runs or whom the server
//! trusts, so one that any user can write is refused as the config file
//! itself is. One that does not parse names the file and the place, and
//! never prints the parser's message, which names a key or quotes a line or
//! a value. Public paths only: the shipped `oneiron` binary.
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

/// A setting serve refuses once it has read every file its `[models]`
/// refers to, so a config whose files were all admitted stops serve all the
/// same.
const REFUSED_SETTING: &str = "house_role = \"no-such-role\"\n";
/// What that refusal says: the mark of a config whose files were all read.
const READ_AND_PARSED: &str = "house_role must be";
/// Text no refusal may repeat: it stands for a line or a value of a file.
const MARKER: &str = "referenced-file-text-not-for-output";
/// A refused command stops at once; one that runs this long was not refused.
const STOPS_WITHIN: Duration = Duration::from_secs(120);

#[test]
fn a_prompt_file_any_user_can_write_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    for mode in [0o666, 0o646, 0o602] {
        let name = format!("prompt-{mode:o}.md");
        file(dir.path(), &name, "Confess what you changed.\n", mode);
        let config = config_file(
            dir.path(),
            &format!(
                "{REFUSED_SETTING}[models.dreamer.wording]\nconfession_prompt_file = \"{name}\"\n"
            ),
        );
        let error = serve_refused(dir.path(), &config);
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

/// The control of the refusals: a prompt file no other user can write is
/// read. Mode 0664 is what a hand-written file gets under umask 002, where
/// the group is the user's own.
#[test]
fn a_prompt_file_no_other_user_can_write_is_read() {
    let dir = tempfile::tempdir().unwrap();
    for mode in [0o600, 0o644, 0o664] {
        let name = format!("prompt-{mode:o}.md");
        file(dir.path(), &name, "Confess what you changed.\n", mode);
        let config = config_file(
            dir.path(),
            &format!(
                "{REFUSED_SETTING}[models.dreamer.wording]\nconfession_prompt_file = \"{name}\"\n"
            ),
        );
        let error = serve_refused(dir.path(), &config);
        assert!(error.contains(READ_AND_PARSED), "mode {mode:o}: {error}");
        assert!(!error.contains("chmod"), "mode {mode:o}: {error}");
    }
}

/// The two JSON wording files: one naming a key the engine does not read
/// names the file and the place, and not the key.
#[test]
fn a_wording_file_that_does_not_parse_names_the_file_and_the_place_only() {
    let dir = tempfile::tempdir().unwrap();
    for (key, name, text) in [
        (
            "consolidation_wording_file",
            "questions.json",
            format!("{{\n  \"resolution\": \"Which value wins?\",\n  \"{MARKER}\": \"x\"\n}}\n"),
        ),
        (
            "extraction_prompt_file",
            "extraction.json",
            format!(
                "{{\n  \"system\": \"Extract.\",\n  \"examples\": [],\n  \"{MARKER}\": 1\n}}\n"
            ),
        ),
    ] {
        file(dir.path(), name, &text, 0o644);
        let config = config_file(
            dir.path(),
            &format!("{REFUSED_SETTING}[models.dreamer.wording]\n{key} = \"{name}\"\n"),
        );
        let error = serve_refused(dir.path(), &config);
        assert!(error.contains(key), "{key}: {error}");
        assert!(error.contains(name), "{key}: {error}");
        assert!(error.contains("at line "), "{key}: {error}");
        assert!(error.contains(", column "), "{key}: {error}");
        assert!(
            !error.contains(MARKER),
            "{key} printed the parser's message: {error}"
        );
        assert!(!error.contains(READ_AND_PARSED), "{key} was taken: {error}");
    }
}

/// The decision read's recipe, a TOML file: one that does not parse names
/// the file and the line, and prints no line of it.
#[test]
fn a_decision_read_recipe_that_does_not_parse_names_the_file_and_the_line_only() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("package")).unwrap();
    file(
        &dir.path().join("package"),
        "recipe.toml",
        &format!("format = 1\ntemplate = \"{MARKER}\n"),
        0o644,
    );
    let config = config_file(
        dir.path(),
        &format!(
            "{REFUSED_SETTING}[models.providers.house]\nkind = \"local-openai-compat\"\n\
             base_url = \"http://127.0.0.1:1\"\nrevision = \"q4km\"\n\
             [models.roles.local_reasoner]\nmodel = \"house:qwen3.8-27b\"\n\
             [models.decision_read]\nrecipe = \"package/recipe.toml\"\n"
        ),
    );
    let error = serve_refused(dir.path(), &config);
    assert!(error.contains("models.decision_read.recipe"), "{error}");
    assert!(error.contains("recipe.toml"), "{error}");
    assert!(error.contains("at line 2, column "), "{error}");
    assert!(
        !error.contains(MARKER),
        "the recipe's line was printed: {error}"
    );
    assert!(
        !error.contains(READ_AND_PARSED),
        "the recipe was taken: {error}"
    );
}

/// The wake config names the programs a wake runs: one any user can write
/// is refused, and one that does not parse names the file and the line.
#[test]
fn a_wake_config_any_user_can_write_or_that_does_not_parse_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let open = file(dir.path(), "wake-open.toml", "inbox = true\n", 0o666);
    let error = refused(dir.path(), &wake_inbox(&open));
    assert!(error.contains("chmod o-w"), "{error}");
    assert!(error.contains("wake-open.toml"), "{error}");
    assert!(error.contains("mode 666"), "{error}");

    let broken = dir.path().join("broken");
    std::fs::create_dir_all(&broken).unwrap();
    let broken = file(
        &broken,
        "wake.toml",
        &format!("inbox = true\ntmux_target = \"{MARKER}\n"),
        0o644,
    );
    let error = refused(dir.path(), &wake_inbox(&broken));
    assert!(error.contains("wake.toml"), "{error}");
    assert!(error.contains("at line 2, column "), "{error}");
    assert!(
        !error.contains(MARKER),
        "the wake config's line was printed: {error}"
    );
}

/// The control: a wake config no other user can write is read, and its
/// empty inbox is printed.
#[test]
fn a_wake_config_no_other_user_can_write_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let closed = file(dir.path(), "wake.toml", "inbox = true\n", 0o644);
    let (status, _, error) = ran(dir.path(), &wake_inbox(&closed));
    assert!(status.success(), "{error}");
    assert!(!error.contains("chmod"), "{error}");
}

/// A relay room's JSON file that does not parse names the file and the
/// place, and not the key it refused.
#[test]
fn a_relay_room_file_that_does_not_parse_names_the_file_and_the_place_only() {
    let dir = tempfile::tempdir().unwrap();
    let room = file(
        dir.path(),
        "room.json",
        &format!("{{\n  \"{MARKER}\": 1\n}}\n"),
        0o600,
    );
    let error = refused(
        dir.path(),
        &["host", "relay", "--config", room.to_str().unwrap()],
    );
    assert!(error.contains("room.json"), "{error}");
    assert!(error.contains("at line 2, column "), "{error}");
    assert!(
        !error.contains(MARKER),
        "the parser's message was printed: {error}"
    );
}

/// A new file `name` in `dir` that holds `text`, its mode exactly `mode`
/// whatever the umask of the test process.
fn file(dir: &Path, name: &str, text: &str, mode: u32) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

/// The config file `oneiron.toml` in `dir`, mode 0600, holding `text`.
fn config_file(dir: &Path, text: &str) -> PathBuf {
    file(dir, "oneiron.toml", text, 0o600)
}

/// `oneiron wake --config <config> inbox`.
fn wake_inbox(config: &Path) -> [&str; 4] {
    ["wake", "--config", config.to_str().unwrap(), "inbox"]
}

/// What `oneiron serve` says when it stops on `config`.
fn serve_refused(home: &Path, config: &Path) -> String {
    refused(home, &["serve", "--config", config.to_str().unwrap()])
}

/// The standard error of `oneiron <args>`, which must stop by itself with a
/// failure.
fn refused(home: &Path, args: &[&str]) -> String {
    let (status, _, error) = ran(home, args);
    assert!(!status.success(), "oneiron {args:?} must fail: {error}");
    error
}

/// How `oneiron <args>` ended, then its standard output and its standard
/// error. Both are written to files, so no full pipe holds the command. A
/// command that was not refused would serve until it is stopped, so one that
/// outlasts [`STOPS_WITHIN`] is stopped and fails the test.
fn ran(home: &Path, args: &[&str]) -> (ExitStatus, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
    // Do not inherit vault, model or switch settings from the build host.
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("ONEIRON_") {
            command.env_remove(name);
        }
    }
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
