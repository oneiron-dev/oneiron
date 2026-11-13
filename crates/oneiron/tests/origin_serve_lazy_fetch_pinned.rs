//! Census L4-32, ARCH-0068 #push-cert-open: "Pin `GIT_NO_LAZY_FETCH=1` for the
//! backend, or refuse promisor repositories."
//!
//! The smart-HTTP backend runs after `env_clear` with the closed serve
//! baseline only, and it is not spawned through GitWire, so it never had the
//! pin GitWire gives its own git children. The baseline now carries
//! `GIT_NO_LAZY_FETCH=1` beside `GIT_NO_REPLACE_OBJECTS=1`. An environment
//! variable reaches every git a git spawns, so receive-pack, the door hook and
//! every git the hook runs treat an object a served repository lacks as an
//! error, never as a fetch from a promisor remote.
//!
//! The first test drives one real receive-pack exchange through
//! [`ServeCommand::spawn`]: one ref creation at a commit the repository already
//! holds, with the empty pack a stock client sends for it, and a stand-in
//! `pre-receive` in the hooks directory that records the environment it runs
//! with.
//!
//! Runs on public paths: `cargo test -p oneiron --all-features --test
//! origin_serve_lazy_fetch_pinned`.
#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use oneiron::origin::smart_http::{SERVE_BASE_ENV_KEYS, ServeCommand, ServeRequest};

const REPO: &str = "demo.git";
const PROBE_REF: &str = "refs/heads/probe";
const ZERO_OID: &str = "0000000000000000000000000000000000000000";
const HOOK_ENV_RECORD: &str = "pre-receive.env";

fn git_bytes(dir: &Path, args: &[&str]) -> Vec<u8> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Owen")
        .env("GIT_AUTHOR_EMAIL", "owen@example.com")
        .env("GIT_COMMITTER_NAME", "Owen")
        .env("GIT_COMMITTER_EMAIL", "owen@example.com")
        .stdin(Stdio::null())
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn git(dir: &Path, args: &[&str]) -> String {
    String::from_utf8(git_bytes(dir, args))
        .expect("git prints UTF-8")
        .trim()
        .to_owned()
}

/// A bare repository under `project_root` whose `main` holds one commit of the
/// empty tree. Returns that commit.
fn seed_served_repo(project_root: &Path) -> String {
    let repo = project_root.join(REPO);
    fs::create_dir_all(&repo).expect("repository directory");
    git(&repo, &["init", "--bare", "--quiet"]);
    let tree = git(&repo, &["mktree"]);
    let commit = git(&repo, &["commit-tree", &tree, "-m", "seed"]);
    git(&repo, &["update-ref", "refs/heads/main", &commit]);
    commit
}

/// A hooks directory whose `pre-receive` records its whole environment in
/// [`HOOK_ENV_RECORD`] beside it and admits the push.
fn recording_hooks(dir: &Path) -> PathBuf {
    let hooks = dir.join("door-hooks");
    fs::create_dir(&hooks).expect("hooks directory");
    let record = hooks.join(HOOK_ENV_RECORD);
    let hook = hooks.join("pre-receive");
    fs::write(
        &hook,
        format!("#!/bin/sh\ncat >/dev/null\nenv > '{}'\n", record.display()),
    )
    .expect("write the stand-in pre-receive");
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).expect("hook mode");
    hooks
}

fn pkt_line(payload: &str) -> Vec<u8> {
    format!("{:04x}{payload}", payload.len() + 4).into_bytes()
}

/// One receive-pack request body: create [`PROBE_REF`] at `commit`, which the
/// repository already holds, then the empty pack a stock client sends for it.
fn create_ref_body(repo: &Path, commit: &str) -> Vec<u8> {
    let mut body = pkt_line(&format!("{ZERO_OID} {commit} {PROBE_REF}\0report-status\n"));
    body.extend_from_slice(b"0000");
    body.extend_from_slice(&git_bytes(repo, &["pack-objects", "--stdout"]));
    body
}

fn receive_pack_request(body_len: usize) -> ServeRequest {
    ServeRequest {
        method: "POST".to_owned(),
        path_info: format!("/{REPO}/git-receive-pack"),
        query_string: String::new(),
        content_type: Some("application/x-git-receive-pack-request".to_owned()),
        content_length: Some(u64::try_from(body_len).expect("body length")),
        content_encoding: None,
        git_protocol: None,
        remote_user: Some("owen".to_owned()),
        remote_addr: None,
    }
}

/// Runs `command` for `request` with `body`; returns the backend's whole
/// response and its stderr.
fn exchange(command: &ServeCommand, request: &ServeRequest, body: &[u8]) -> (String, String) {
    let mut child = command.spawn(request).expect("spawn git http-backend");
    let mut stdout = child.take_stdout().expect("backend stdout");
    let mut stderr = child.take_stderr().expect("backend stderr");
    let stderr_reader = thread::spawn(move || {
        let mut text = Vec::new();
        let _ = stderr.read_to_end(&mut text);
        String::from_utf8_lossy(&text).into_owned()
    });
    {
        let mut stdin = child.take_stdin().expect("backend stdin");
        stdin.write_all(body).expect("write the request body");
    }
    let mut response = Vec::new();
    stdout
        .read_to_end(&mut response)
        .expect("read the response");
    let stderr_text = stderr_reader.join().expect("stderr reader");
    let _ = child.wait();
    (String::from_utf8_lossy(&response).into_owned(), stderr_text)
}

#[test]
fn receive_pack_door_hook_runs_with_lazy_fetch_pinned_off() {
    let dir = tempfile::tempdir().expect("tempdir");
    let project_root = dir.path().join("serving");
    let commit = seed_served_repo(&project_root);
    let repo = project_root.join(REPO);
    let hooks = recording_hooks(dir.path());
    let command = ServeCommand::http_backend(&repo, &project_root, &hooks).expect("serve command");
    let body = create_ref_body(&repo, &commit);

    let (response, stderr) = exchange(&command, &receive_pack_request(body.len()), &body);

    let recorded = fs::read_to_string(hooks.join(HOOK_ENV_RECORD)).unwrap_or_else(|error| {
        panic!(
            "the stand-in pre-receive never ran ({error}); response:\n{response}\nstderr:\n{stderr}"
        )
    });
    let hook_env: BTreeMap<&str, &str> = recorded
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    assert_eq!(
        hook_env.get("GIT_NO_REPLACE_OBJECTS").copied(),
        Some("1"),
        "the door hook runs with replacement lookup off; its environment:\n{recorded}"
    );
    assert_eq!(
        hook_env.get("GIT_NO_LAZY_FETCH").copied(),
        Some("1"),
        "the door hook, and every git it runs, must not fetch a missing object from a \
         promisor remote; its environment:\n{recorded}"
    );
    assert!(
        response.contains(&format!("ok {PROBE_REF}")),
        "the admitted ref creation lands; response:\n{response}\nstderr:\n{stderr}"
    );
}

#[test]
fn serve_baseline_is_the_documented_keys_with_lazy_fetch_pinned_off() {
    let dir = tempfile::tempdir().expect("tempdir");
    let project_root = dir.path().join("serving");
    let command = ServeCommand::http_backend(
        &project_root.join(REPO),
        &project_root,
        &dir.path().join("door-hooks"),
    )
    .expect("serve command");

    let mut documented = SERVE_BASE_ENV_KEYS.to_vec();
    documented.sort_unstable();
    let baseline: Vec<&str> = command.env().keys().map(String::as_str).collect();
    assert_eq!(
        baseline, documented,
        "the closed serve baseline is SERVE_BASE_ENV_KEYS exactly"
    );
    assert_eq!(
        command.env().get("GIT_NO_LAZY_FETCH").map(String::as_str),
        Some("1"),
        "the serve baseline pins lazy fetching off"
    );
}
