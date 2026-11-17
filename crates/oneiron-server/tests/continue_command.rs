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
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --test continue_command`.

#![cfg(all(unix, oneiron_test_support))]

use std::path::{Path, PathBuf};
use std::process::Command;

use oneiron_server::test_doors::continue_command::{hand_off_commit, run_scripted};

const SESSION: &str = "0b5e2c1d-7a44-4c39-9f0e-5d2a6b8c9e10";

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

    let (commit, parent) = hand_off_commit(dir).expect("the hand-off commit");
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
    let ran = run_scripted(repo.path(), &session_log(logs.path()), true, true);

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
    let ran = run_scripted(repo.path(), &session_log(logs.path()), true, false);

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
    let ran = run_scripted(repo.path(), &session_log(logs.path()), false, false);

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
