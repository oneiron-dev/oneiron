//! `oneiron continue --cloud` (census L10-17 PR 3b; plan PLAN-L10-17.md, Tests
//! "PR 3"; ASK L10-17-FILES = A; L10-17-PR3-PUSH = A).
//!
//! - The hand-off commit carries git's own view of the working tree (tracked
//!   files and untracked files that are not ignored), has HEAD as its parent,
//!   and leaves HEAD, the index and the files as they were.
//! - A push that fails never says "safe to close" and never starts the run.
//! - A start that binds says "safe to close", after every step in order.
//! - A selection that is not a paired slip stops after the check and names
//!   what is missing.
//!
//! Review round 2 of #9771:
//! - A log whose last record was cut mid-write stops before the import.
//! - A start whose answer never came back says UNCONFIRMED, never "did NOT
//!   move" or "safe to close", and names the hand-off and the call.
//! - A git clean filter that never ends is stopped at the deadline, naming
//!   the git step.
//! - Discovery skips a newer log of a repo nested in this one whose path
//!   folds to the same project folder name.
//! - A FIFO named as the log is refused at once.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --test continue_command`.

#![cfg(all(unix, oneiron_test_support))]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use oneiron_server::test_doors::continue_command::{
    Script, discovered_session, hand_off_commit, run_scripted,
};

const SESSION: &str = "0b5e2c1d-7a44-4c39-9f0e-5d2a6b8c9e10";
/// Another session's id.
const OTHER_SESSION: &str = "1f2e3d4c-5b6a-4978-8a9b-0c1d2e3f4a5b";
/// The deadline every hand-off commit but the stalled one gets.
const WITHIN: Duration = Duration::from_secs(600);

/// A paired-slip selection whose push and start go through.
const SLIP: Script = Script {
    can_push: true,
    push_fails: false,
    start_unanswered: false,
};

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Oneiron")
        .env("GIT_AUTHOR_EMAIL", "oneiron@example.invalid")
        .env("GIT_COMMITTER_NAME", "Oneiron")
        .env("GIT_COMMITTER_EMAIL", "oneiron@example.invalid")
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A repo whose last commit holds `.gitignore` (naming `.env`) and
/// `tracked.txt`, and whose working tree then changed `tracked.txt`, added
/// the untracked `notes/new.txt` and the ignored `.env`.
fn repo_with_work() -> tempfile::TempDir {
    let repo = tempfile::tempdir().expect("temp repo");
    let dir = repo.path();
    git(dir, &["init", "--initial-branch=main"]);
    git(dir, &["config", "user.name", "Oneiron"]);
    git(dir, &["config", "user.email", "oneiron@example.invalid"]);
    std::fs::write(dir.join(".gitignore"), ".env\n").expect("write .gitignore");
    std::fs::write(dir.join("tracked.txt"), "one\n").expect("write tracked file");
    git(dir, &["add", "--", ".gitignore", "tracked.txt"]);
    git(dir, &["commit", "-m", "first"]);
    std::fs::write(dir.join("tracked.txt"), "one\ntwo\n").expect("change tracked file");
    std::fs::create_dir(dir.join("notes")).expect("make notes");
    std::fs::write(dir.join("notes").join("new.txt"), "new\n").expect("write untracked file");
    std::fs::write(dir.join(".env"), "SECRET=1\n").expect("write ignored file");
    repo
}

/// A Claude Code session log and one subagent log under `dir`, laid out as
/// Claude Code keeps them.
fn session_log(dir: &Path) -> PathBuf {
    let log = dir.join(format!("{SESSION}.jsonl"));
    std::fs::write(
        &log,
        format!(
            "{{\"type\":\"user\",\"sessionId\":\"{SESSION}\",\"message\":{{\"role\":\"user\",\"content\":\"go on\"}}}}\n"
        ),
    )
    .expect("write session log");
    let subagents = dir.join(SESSION).join("subagents");
    std::fs::create_dir_all(&subagents).expect("make subagents folder");
    std::fs::write(subagents.join("agent-a1b2.jsonl"), "{}\n").expect("write subagent log");
    log
}

#[test]
fn the_hand_off_commit_carries_the_working_tree_and_leaves_it_untouched() {
    let repo = repo_with_work();
    let dir = repo.path();
    let head = git(dir, &["rev-parse", "HEAD"]);
    let status = git(dir, &["status", "--porcelain=v2"]);
    let index = std::fs::read(dir.join(".git").join("index")).expect("read index");

    let (commit, parent) = hand_off_commit(dir, WITHIN).expect("the hand-off commit");
    // Read before any later git command, which may refresh the index itself.
    let index_after = std::fs::read(dir.join(".git").join("index")).expect("read index");

    assert_eq!(parent.as_deref(), Some(head.as_str()), "HEAD is its parent");
    let files = git(dir, &["ls-tree", "-r", "--name-only", &commit]);
    let files: Vec<&str> = files.lines().collect();
    assert_eq!(
        files,
        [".gitignore", "notes/new.txt", "tracked.txt"],
        "tracked and untracked files travel; the ignored .env stays"
    );
    assert_eq!(
        git(dir, &["show", &format!("{commit}:tracked.txt")]),
        "one\ntwo",
        "the tracked file travels as the working tree holds it"
    );
    assert_eq!(git(dir, &["rev-parse", "HEAD"]), head, "HEAD unchanged");
    assert_eq!(
        git(dir, &["status", "--porcelain=v2"]),
        status,
        "the working tree's status unchanged"
    );
    assert_eq!(
        index_after, index,
        "the index file unchanged, byte for byte"
    );
}

#[test]
fn a_failed_push_never_says_safe_to_close() {
    let repo = repo_with_work();
    let logs = tempfile::tempdir().expect("temp logs");
    let ran = run_scripted(
        repo.path(),
        &session_log(logs.path()),
        Script {
            push_fails: true,
            ..SLIP
        },
    );

    assert!(ran.error.is_some(), "the command fails: {}", ran.output);
    assert!(
        !ran.output.to_lowercase().contains("safe to close"),
        "no safe-to-close line: {}",
        ran.output
    );
    assert!(
        ran.output.contains("The work did NOT move"),
        "it says the work did not move: {}",
        ran.output
    );
    assert_eq!(
        ran.calls,
        [
            "vault.runners.continue.check",
            "vault.imports.hook_transcript",
            "git-receive-pack"
        ],
        "the start verb is never called"
    );
}

#[test]
fn a_bound_start_says_safe_to_close() {
    let repo = repo_with_work();
    let logs = tempfile::tempdir().expect("temp logs");
    let ran = run_scripted(repo.path(), &session_log(logs.path()), SLIP);

    assert_eq!(ran.error, None, "the command succeeds: {}", ran.output);
    assert!(
        ran.output.contains("Safe to close this machine"),
        "it says safe to close: {}",
        ran.output
    );
    assert_eq!(
        ran.calls,
        [
            "vault.runners.continue.check",
            "vault.imports.hook_transcript",
            "git-receive-pack",
            "vault.runners.continue"
        ]
    );
    assert_eq!(
        ran.sent,
        Some((SESSION.to_owned(), vec!["agent-a1b2".to_owned()])),
        "the import carries the session and its subagent log"
    );
}

#[test]
fn a_selection_without_a_slip_stops_after_the_check() {
    let repo = repo_with_work();
    let logs = tempfile::tempdir().expect("temp logs");
    let ran = run_scripted(
        repo.path(),
        &session_log(logs.path()),
        Script {
            can_push: false,
            ..SLIP
        },
    );

    let error = ran.error.expect("the command stops");
    assert!(
        error.contains("a paired slip with a git_push Grant on the repo"),
        "it names what is missing: {error}"
    );
    assert_eq!(
        ran.calls,
        ["vault.runners.continue.check"],
        "nothing is imported or pushed"
    );
    assert!(!ran.output.to_lowercase().contains("safe to close"));
}

#[test]
fn a_torn_last_record_stops_before_the_import() {
    let repo = repo_with_work();
    let logs = tempfile::tempdir().expect("temp logs");
    let log = session_log(logs.path());
    let mut text = std::fs::read_to_string(&log).expect("read session log");
    // A second record, cut mid-write.
    text.push_str(&format!(
        "{{\"type\":\"user\",\"sessionId\":\"{SESSION}\",\"mess"
    ));
    std::fs::write(&log, text).expect("write torn session log");

    let ran = run_scripted(repo.path(), &log, SLIP);

    let error = ran.error.expect("the command stops");
    assert!(
        error.contains("line 2 of") && error.contains("not a whole JSON record"),
        "it names the torn line: {error}"
    );
    assert_eq!(
        ran.calls,
        ["vault.runners.continue.check"],
        "nothing is imported, pushed or started"
    );
    assert!(
        ran.output.contains("The work did NOT move"),
        "it says the work did not move: {}",
        ran.output
    );
    assert!(!ran.output.to_lowercase().contains("safe to close"));
}

#[test]
fn a_lost_start_answer_says_unconfirmed() {
    let repo = repo_with_work();
    let logs = tempfile::tempdir().expect("temp logs");
    let ran = run_scripted(
        repo.path(),
        &session_log(logs.path()),
        Script {
            start_unanswered: true,
            ..SLIP
        },
    );

    assert!(ran.error.is_some(), "the command fails: {}", ran.output);
    assert!(
        ran.output.contains("The start is UNCONFIRMED"),
        "it says the start is unconfirmed: {}",
        ran.output
    );
    assert!(
        !ran.output.contains("The work did NOT move"),
        "it never says the work did not move: {}",
        ran.output
    );
    assert!(
        !ran.output.to_lowercase().contains("safe to close"),
        "it never says safe to close: {}",
        ran.output
    );
    for named in [
        "1".repeat(32),
        "refs/heads/oneiron/continue/".to_owned(),
        "https://vault.example".to_owned(),
    ] {
        assert!(
            ran.output.contains(&named),
            "it names {named} for the status check: {}",
            ran.output
        );
    }
    assert_eq!(
        ran.calls,
        [
            "vault.runners.continue.check",
            "vault.imports.hook_transcript",
            "git-receive-pack",
            "vault.runners.continue"
        ]
    );
}

#[test]
fn a_stalled_clean_filter_is_stopped_at_the_deadline() {
    let repo = repo_with_work();
    let dir = repo.path();
    // The changed tracked.txt goes through a clean filter that never answers
    // in time.
    std::fs::write(dir.join(".gitattributes"), "tracked.txt filter=stall\n")
        .expect("write .gitattributes");
    git(dir, &["config", "filter.stall.clean", "sleep 120"]);

    // A filter left running ends after 120 s and the commit would then
    // succeed, so the deadline error proves the stop.
    let error =
        hand_off_commit(dir, Duration::from_secs(3)).expect_err("the hand-off commit stops");

    assert!(
        error.contains("git add did not finish before the hand-off's deadline"),
        "it names the git step: {error}"
    );
}

/// `dir` as Claude Code names its project folder: each character that is not
/// an ASCII letter or digit as `-`.
fn project_folder(dir: &Path) -> String {
    dir.to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// A session log named `session` in `folder` whose records say it ran in
/// `cwd`, last written at `modified`.
fn log_in(folder: &Path, session: &str, cwd: &Path, modified: SystemTime) -> PathBuf {
    let log = folder.join(format!("{session}.jsonl"));
    let record = serde_json::json!({
        "type": "user",
        "sessionId": session,
        "cwd": cwd,
        "message": {"role": "user", "content": "go on"},
    });
    std::fs::write(&log, format!("{record}\n")).expect("write session log");
    std::fs::File::options()
        .write(true)
        .open(&log)
        .and_then(|file| file.set_modified(modified))
        .expect("set the log's time");
    log
}

#[test]
fn discovery_skips_a_nested_repos_log_that_folds_alike() {
    let root = tempfile::tempdir().expect("temp root");
    let main = root.path().join("main");
    std::fs::create_dir_all(main.join("a-b").join("c")).expect("make a-b/c");
    git(&main, &["init", "--initial-branch=main"]);
    let nested = main.join("a").join("b-c");
    std::fs::create_dir_all(&nested).expect("make a/b-c");
    git(&nested, &["init", "--initial-branch=main"]);
    let here = std::fs::canonicalize(main.join("a-b").join("c")).expect("resolve a-b/c");
    let nested = std::fs::canonicalize(&nested).expect("resolve a/b-c");
    assert_eq!(
        project_folder(&here),
        project_folder(&nested),
        "both paths fold to one project folder name"
    );

    let projects = tempfile::tempdir().expect("temp projects");
    let folder = projects.path().join(project_folder(&here));
    std::fs::create_dir_all(&folder).expect("make project folder");
    let newest = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let ours = log_in(&folder, SESSION, &here, newest - Duration::from_secs(60));
    log_in(&folder, OTHER_SESSION, &nested, newest);

    assert_eq!(
        discovered_session(projects.path(), &here),
        Ok(ours),
        "the newer log of the nested repo is not this repo's"
    );
}

#[test]
fn a_fifo_named_as_the_log_is_refused_at_once() {
    let repo = repo_with_work();
    let logs = tempfile::tempdir().expect("temp logs");
    let fifo = logs.path().join(format!("{SESSION}.jsonl"));
    let made = Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("run mkfifo");
    assert!(made.success(), "mkfifo: {made}");

    // An open that waited for a writer would never return: no one writes to
    // the FIFO.
    let ran = run_scripted(repo.path(), &fifo, SLIP);

    let error = ran.error.expect("the command stops");
    assert!(
        error.contains("is not a regular file"),
        "it names the FIFO: {error}"
    );
    assert_eq!(ran.calls, ["vault.runners.continue.check"]);
}
