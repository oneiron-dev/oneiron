//! `oneiron import <source> <log> --queue` refuses a misnamed or foreign log
//! itself (FIX-LIST line 280): the refusal names the log on the caller's
//! stderr, and no queue entry is written, instead of queueing it for `serve`
//! to refuse at drain, visible only in its log. A well-named log in its
//! source's format still queues.
#![cfg(unix)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/history")
}

/// A fresh vault, the config file `init` wrote for it with `[import] queue =
/// true` and roots under the home folder, and the queue folder.
struct Home {
    dir: tempfile::TempDir,
    config: PathBuf,
    queue: PathBuf,
}

impl Home {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("test fixture");
        let vault = dir.path().join("vault");
        let config = dir.path().join("oneiron.toml");
        let init = Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args(["init", vault.to_str().expect("test fixture")])
            .args([
                "--config",
                config.to_str().expect("test fixture"),
                "--embedder",
                "none",
            ])
            .output()
            .expect("test fixture");
        assert!(
            init.status.success(),
            "init: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let projects = dir.path().join("projects");
        let hooks = dir.path().join("hooks");
        let queue = dir.path().join("queue");
        std::fs::create_dir_all(projects.join("-Users-ana-code-garden-planner"))
            .expect("test fixture");
        std::fs::create_dir_all(&hooks).expect("test fixture");
        let mut config_file = std::fs::OpenOptions::new()
            .append(true)
            .open(&config)
            .expect("test fixture");
        write!(
            config_file,
            "\n[import]\nqueue = true\nqueue_dir = \"{}\"\nclaude_code_root = \"{}\"\nhook_transcript_roots = [\"{}\"]\n",
            queue.display(),
            projects.display(),
            hooks.display()
        )
        .expect("test fixture");
        drop(config_file);
        Self { dir, config, queue }
    }

    /// Runs `oneiron import <source> <log> --queue`.
    fn enqueue(&self, source: &str, log: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args(["import", source])
            .arg(log)
            .arg("--queue")
            .arg("--config")
            .arg(&self.config)
            .env_remove("ONEIRON_VAULT_PATH")
            .output()
            .expect("test fixture")
    }

    /// The queue entries' file names; none when the folder was never made.
    fn entries(&self) -> Vec<String> {
        let Ok(read) = std::fs::read_dir(&self.queue) else {
            return Vec::new();
        };
        let mut entries: Vec<String> = read
            .map(|entry| entry.expect("test fixture").file_name())
            .map(|name| name.to_str().expect("test fixture").to_owned())
            .filter(|name| name.ends_with(".json"))
            .collect();
        entries.sort();
        entries
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A log under the root whose name is not a session log's, and a log in
/// another source's naming, are refused at enqueue, with nothing queued.
#[test]
fn misnamed_log_is_refused_at_enqueue() {
    let home = Home::new();
    let session = fixtures()
        .join("claude-code/projects/-Users-ana-code-garden-planner")
        .join("5d0c0a7e-1111-4222-8333-944455556666.jsonl");
    // Well-formed session content under a name no session log has.
    let misnamed = home.dir.path().join("projects").join("notes.jsonl");
    std::fs::copy(&session, &misnamed).expect("test fixture");
    // A Codex rollout's name and content, handed over as Claude Code's.
    let foreign = home
        .dir
        .path()
        .join("projects")
        .join("rollout-2026-09-14T10-00-00-0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b.jsonl");
    std::fs::copy(
        fixtures().join(
            "codex/sessions/2026/09/14/rollout-2026-09-14T10-00-00-0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b.jsonl",
        ),
        &foreign,
    )
    .expect("test fixture");
    for log in [&misnamed, &foreign] {
        let output = home.enqueue("claude-code", log);
        let stderr = stderr(&output);
        assert!(
            !output.status.success(),
            "queueing {} must be refused; stdout: {}; stderr: {stderr}",
            log.display(),
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            stderr.contains("is not a claude-code session log"),
            "the refusal must name the log's name; stderr is: {stderr}"
        );
        assert!(
            stderr.contains(
                log.file_name()
                    .expect("test fixture")
                    .to_str()
                    .expect("test fixture")
            ),
            "the refusal must name the log; stderr is: {stderr}"
        );
    }
    assert!(
        home.entries().is_empty(),
        "nothing refused may queue: {:?}",
        home.entries()
    );
}

/// A hook transcript in neither reader's format is refused at enqueue, with
/// nothing queued.
#[test]
fn foreign_transcript_is_refused_at_enqueue() {
    let home = Home::new();
    let log = home.dir.path().join("hooks").join("session-1.jsonl");
    std::fs::write(&log, "this is not json\n{\"nope\": true}\n").expect("test fixture");
    let output = home.enqueue("hook-transcript", &log);
    let stderr = stderr(&output);
    assert!(
        !output.status.success(),
        "queueing {} must be refused; stdout: {}; stderr: {stderr}",
        log.display(),
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("expects schema `a GitHub Copilot or Cursor transcript`"),
        "the refusal must name the expected format; stderr is: {stderr}"
    );
    assert!(
        stderr.contains("session-1.jsonl"),
        "the refusal must name the log; stderr is: {stderr}"
    );
    assert!(
        home.entries().is_empty(),
        "nothing refused may queue: {:?}",
        home.entries()
    );
}

/// A well-named log in its source's format still queues, one entry per log.
#[test]
fn valid_logs_still_queue() {
    let home = Home::new();
    let session = home
        .dir
        .path()
        .join("projects")
        .join("-Users-ana-code-garden-planner")
        .join("5d0c0a7e-1111-4222-8333-944455556666.jsonl");
    std::fs::copy(
        fixtures()
            .join("claude-code/projects/-Users-ana-code-garden-planner")
            .join("5d0c0a7e-1111-4222-8333-944455556666.jsonl"),
        &session,
    )
    .expect("test fixture");
    let transcript = home.dir.path().join("hooks").join("copilot-1.jsonl");
    std::fs::write(
        &transcript,
        "{\"type\":\"user.message\",\"data\":{\"content\":\"hello\"},\"id\":\"evt1\"}\n",
    )
    .expect("test fixture");
    for (source, log) in [("claude-code", &session), ("hook-transcript", &transcript)] {
        let output = home.enqueue(source, log);
        assert!(
            output.status.success(),
            "queueing {}: {}",
            log.display(),
            stderr(&output)
        );
        let queued: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("queued JSON on stdout");
        assert_eq!(queued["source"].as_str(), Some(source));
        assert!(
            queued["queued"]
                .as_str()
                .is_some_and(|queued| queued.ends_with(
                    log.file_name()
                        .expect("test fixture")
                        .to_str()
                        .expect("test fixture")
                )),
            "stdout must name the queued log: {queued}"
        );
    }
    let entries = home.entries();
    assert_eq!(entries.len(), 2, "one entry per log: {entries:?}");
    assert!(
        entries
            .iter()
            .any(|entry| entry.starts_with("claude-code-")),
        "the session's entry: {entries:?}"
    );
    assert!(
        entries
            .iter()
            .any(|entry| entry.starts_with("hook-transcript-")),
        "the transcript's entry: {entries:?}"
    );
}
