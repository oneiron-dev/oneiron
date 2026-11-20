//! FIX [RUNNER-SEATS-UNKNOWN-KEY-SILENT]: a key under
//! `[models.dreamer.runner_seats]` that no setting names is refused with the
//! file and the line, as in every other config section, and is never read
//! past in silence. That holds in the policy table, in a CLI seat, and in an
//! official seat, whose seat settings and endpoint bindings share one table.
//! The same settings given to `oneiron seat runner-policy` as JSON refuse an
//! unknown field, as the server's request types do. An official seat is
//! one table of named settings, and a list of bare values in its place is
//! refused in both. Public paths only: the shipped `oneiron` binary.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// A setting serve refuses once the whole config file has parsed, so a
/// config whose runner seats were read stops serve all the same.
const REFUSED_SETTING: &str = "house_role = \"no-such-role\"";
/// What that refusal says: the mark of a config that parsed.
const READ_AND_PARSED: &str = "house_role must be";
/// A refused command stops at once; one that runs this long was not refused.
const STOPS_WITHIN: Duration = Duration::from_secs(120);

/// The runner seats an owner writes under `[models]`, every key a known one:
/// the policy, one CLI seat, and one official seat (a Codex ChatGPT-plan
/// login on the owner's machine) with an endpoint binding.
const RUNNER_SEATS: [&str; 15] = [
    REFUSED_SETTING,
    "",
    "[models.dreamer.runner_seats]",
    "on_spent = \"stop\"",
    "",
    "[[models.dreamer.runner_seats.seats]]",
    "runner = \"codex\"",
    "auth = \"vendor_login\"",
    "egress_profile_ref = \"egress/test-default\"",
    "",
    "[[models.dreamer.runner_seats.official]]",
    "route = \"codex_app_server_chatgpt_plan\"",
    "account_ref = \"owner-codex\"",
    "machine_ref = \"owner-machine\"",
    "openai_hosted_plan_approved = true",
];

/// Runner seats whose one official seat is written as a list of bare values
/// (its route and account), not as a table of named settings.
const OFFICIAL_SEAT_AS_A_LIST: [&str; 9] = [
    REFUSED_SETTING,
    "",
    "[models.dreamer.runner_seats]",
    "official = [[\"codex_app_server_chatgpt_plan\", \"owner-codex\"]]",
    "",
    "[[models.dreamer.runner_seats.seats]]",
    "runner = \"codex\"",
    "auth = \"vendor_login\"",
    "egress_profile_ref = \"egress/test-default\"",
];

/// Each misspelt key, and the line of [`RUNNER_SEATS`] it is written after:
/// one in the policy table, one in the CLI seat, one among the official
/// seat's seat settings and one among its endpoint bindings.
const MISSPELT: [(&str, &str); 4] = [
    ("on_spent = \"stop\"", "on_spnt = \"next_seat\""),
    (
        "egress_profile_ref = \"egress/test-default\"",
        "credential_handle = [\"seat-key\"]",
    ),
    (
        "machine_ref = \"owner-machine\"",
        "login_store = \"/home/owner/.codex\"",
    ),
    (
        "openai_hosted_plan_approved = true",
        "base_uri = \"https://seat.invalid\"",
    ),
];

/// A misspelt key under `runner_seats` stops serve at the parse: the refusal
/// names the config file and the misspelt key's line, and serve never reads
/// past it to the rest of the file.
#[test]
fn a_misspelt_key_under_runner_seats_is_refused_with_the_file_and_the_line() {
    let dir = tempfile::tempdir().unwrap();
    for (index, (after, misspelt)) in MISSPELT.into_iter().enumerate() {
        let (text, line) = with_line_after(after, misspelt);
        let config = file(dir.path(), &format!("seats-{index}.toml"), &text);
        let error = serve_refused(dir.path(), &config);
        assert!(
            error.contains(&format!(
                "parse config file {}: invalid configuration at line {line},",
                config.display()
            )),
            "{misspelt}: {error}"
        );
        assert!(
            !error.contains(READ_AND_PARSED),
            "{misspelt} was read past: {error}"
        );
    }
}

/// The control: the same runner seats with every key a known one parse, so
/// serve reaches the house role it refuses.
#[test]
fn runner_seats_with_known_keys_only_are_read() {
    let dir = tempfile::tempdir().unwrap();
    let config = file(dir.path(), "seats.toml", &(RUNNER_SEATS.join("\n") + "\n"));
    let error = serve_refused(dir.path(), &config);
    assert!(error.contains(READ_AND_PARSED), "{error}");
    assert!(!error.contains("invalid configuration"), "{error}");
}

/// The runner policy's JSON form refuses an unknown field, in the policy, in
/// a CLI seat and in an official seat, and the same policy with known
/// fields only is folded and printed.
#[test]
fn a_runner_policy_with_an_unknown_field_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let known = serde_json::json!({
        "on_spent": "stop",
        "seats": [{
            "runner": "codex",
            "auth": "vendor_login",
            "egress_profile_ref": "egress/test-default",
        }],
        "official": [{
            "route": "codex_app_server_chatgpt_plan",
            "account_ref": "owner-codex",
            "machine_ref": "owner-machine",
            "openai_hosted_plan_approved": true,
        }],
    });
    let settings = file(dir.path(), "policy.json", &known.to_string());
    let (status, output, error) = ran(dir.path(), &runner_policy(&settings));
    assert!(status.success(), "the known policy must fold: {error}");
    assert!(output.contains("codex"), "{output}");

    let mut cases = Vec::new();
    for (pointer, field) in [
        ("", "on_spnt"),
        ("/seats/0", "credential_handle"),
        ("/official/0", "login_store"),
        ("/official/0", "base_uri"),
    ] {
        let mut policy = known.clone();
        policy
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(field.to_owned(), serde_json::json!("misspelt"));
        cases.push((field, policy));
    }
    for (index, (field, policy)) in cases.into_iter().enumerate() {
        let settings = file(
            dir.path(),
            &format!("policy-{index}.json"),
            &policy.to_string(),
        );
        let error = refused(dir.path(), &runner_policy(&settings));
        assert!(
            error.contains(&format!("unknown field `{field}`")),
            "{field}: {error}"
        );
    }
}

/// An official seat written as a list of bare values is refused, in a config
/// file at the list's line and in the runner policy's JSON. It is never read
/// by position, with every setting the list leaves out taken from its
/// default.
#[test]
fn an_official_seat_written_as_a_list_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let config = file(
        dir.path(),
        "official-list.toml",
        &(OFFICIAL_SEAT_AS_A_LIST.join("\n") + "\n"),
    );
    let line = OFFICIAL_SEAT_AS_A_LIST
        .iter()
        .position(|text| text.starts_with("official = "))
        .unwrap()
        + 1;
    let error = serve_refused(dir.path(), &config);
    assert!(
        error.contains(&format!(
            "parse config file {}: invalid configuration at line {line},",
            config.display()
        )),
        "{error}"
    );
    assert!(
        !error.contains(READ_AND_PARSED),
        "the list was read by position: {error}"
    );

    let policy = serde_json::json!({
        "seats": [{
            "runner": "codex",
            "auth": "vendor_login",
            "egress_profile_ref": "egress/test-default",
        }],
        "official": [["codex_app_server_chatgpt_plan", "owner-codex"]],
    });
    let settings = file(dir.path(), "official-list.json", &policy.to_string());
    let error = refused(dir.path(), &runner_policy(&settings));
    assert!(error.contains("invalid type: sequence"), "{error}");
}

/// [`RUNNER_SEATS`] with `inserted` written after its line `after`, and the
/// one-based line `inserted` takes.
fn with_line_after(after: &str, inserted: &str) -> (String, usize) {
    let index = RUNNER_SEATS.iter().position(|line| *line == after).unwrap();
    let mut lines = RUNNER_SEATS.to_vec();
    lines.insert(index + 1, inserted);
    (lines.join("\n") + "\n", index + 2)
}

/// `oneiron seat runner-policy --settings <settings>`.
fn runner_policy(settings: &Path) -> [&str; 4] {
    [
        "seat",
        "runner-policy",
        "--settings",
        settings.to_str().unwrap(),
    ]
}

/// A new file `name` in `dir` that holds `text`, mode 0600 whatever the
/// umask of the test process.
fn file(dir: &Path, name: &str, text: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
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
/// error, both read while it runs, so no full pipe holds the command. A
/// command that was not refused would serve until it is stopped, so one that
/// outlasts [`STOPS_WITHIN`] is killed and fails the test.
fn ran(home: &Path, args: &[&str]) -> (ExitStatus, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
    // Do not inherit vault, model or switch settings from the build host.
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("ONEIRON_") {
            command.env_remove(name);
        }
    }
    let child = command
        .args(args)
        .env("HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run oneiron");
    let pid = child.id();
    let (sender, ended) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });
    let Ok(output) = ended.recv_timeout(STOPS_WITHIN) else {
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
        panic!("oneiron {args:?} did not stop within {STOPS_WITHIN:?}: it was not refused");
    };
    let output = output.expect("wait for oneiron");
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    (output.status, text(&output.stdout), text(&output.stderr))
}
