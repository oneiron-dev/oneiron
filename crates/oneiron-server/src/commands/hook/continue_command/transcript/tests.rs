//! The folder a handed-over transcript names (FIX SESSION-PROJECT-HOOK-TRANSCRIPT-PLACEMENT):
//! the sender names the session's folder by its digests, as the local import does.

use std::path::Path;

use oneiron::ingest::history::HookTranscriptSource;

use super::*;
use crate::workspace_identity::WorkspaceIdentity;

/// A Claude Code session id: 36 hex digits and dashes.
const SESSION: &str = "0b5e55e0-3333-4444-8555-a66677778888";

/// Another session id, for the log with the other folder.
const OTHER_SESSION: &str = "1c6f66f1-4444-5555-9666-b77788889999";

/// A Claude Code session log whose records ran in `cwd`: one user turn and its answer.
fn claude_log(cwd: &str, session: &str) -> String {
    let user = serde_json::json!({
        "parentUuid": null,
        "isSidechain": false,
        "userType": "external",
        "cwd": cwd,
        "sessionId": session,
        "type": "user",
        "uuid": "d2000000-0000-4000-8000-000000000001",
        "timestamp": "2026-11-20T01:00:00.000Z",
        "message": {"role": "user", "content": "Keep the ferry timetable in pier nine order."},
    });
    let assistant = serde_json::json!({
        "parentUuid": "d2000000-0000-4000-8000-000000000001",
        "isSidechain": false,
        "userType": "external",
        "cwd": cwd,
        "sessionId": session,
        "type": "assistant",
        "uuid": "d2000000-0000-4000-8000-000000000002",
        "timestamp": "2026-11-20T01:00:05.000Z",
        "message": {
            "role": "assistant",
            "model": "claude-test",
            "content": [{"type": "text", "text": "Noted: pier nine order."}],
        },
    });
    format!("{user}\n{assistant}\n")
}

/// A Claude Code subagent log whose records ran in `cwd`. `tag` (`a1`, `b2`)
/// keeps the two logs the same length.
fn claude_subagent_log(cwd: &str, session: &str, tag: &str) -> String {
    let user = serde_json::json!({
        "parentUuid": null,
        "isSidechain": true,
        "userType": "external",
        "cwd": cwd,
        "sessionId": session,
        "type": "user",
        "uuid": format!("d3000000-0000-4000-8000-0000000000{tag}"),
        "timestamp": "2026-11-20T01:01:00.000Z",
        "message": {"role": "user", "content": format!("Check the pier nine timetable ({tag}).")},
    });
    let assistant = serde_json::json!({
        "parentUuid": format!("d3000000-0000-4000-8000-0000000000{tag}"),
        "isSidechain": true,
        "userType": "external",
        "cwd": cwd,
        "sessionId": session,
        "type": "assistant",
        "uuid": format!("d3000000-0000-4000-8000-0000000001{tag}"),
        "timestamp": "2026-11-20T01:01:05.000Z",
        "message": {
            "role": "assistant",
            "model": "claude-test",
            "content": [{"type": "text", "text": format!("Checked for {tag}: pier nine order holds.")}],
        },
    });
    format!("{user}\n{assistant}\n")
}

/// A minimal Codex rollout whose session ran in `cwd`, shaped as
/// `crates/oneiron/src/ingest/history/codex.rs` reads one: `session_meta`
/// first, then one user message and its answer.
fn codex_rollout(cwd: &str, id: &str) -> String {
    let meta = serde_json::json!({
        "timestamp": "2026-11-20T01:00:00.000Z",
        "type": "session_meta",
        "payload": {
            "id": id,
            "timestamp": "2026-11-20T01:00:00.000Z",
            "cwd": cwd,
            "originator": "codex_cli_rs",
            "cli_version": "0.50.0",
        },
    });
    let user = serde_json::json!({
        "timestamp": "2026-11-20T01:00:01.000Z",
        "type": "response_item",
        "payload": {
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": "Keep the ferry timetable in pier nine order."}],
        },
    });
    let assistant = serde_json::json!({
        "timestamp": "2026-11-20T01:00:05.000Z",
        "type": "response_item",
        "payload": {
            "type": "message",
            "role": "assistant",
            "id": "msg_pier_nine",
            "content": [{"type": "output_text", "text": "Noted: pier nine order."}],
        },
    });
    format!("{meta}\n{user}\n{assistant}\n")
}

#[test]
fn a_claude_code_log_sends_the_folder_it_records() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let work = dir.path().join("work");
    std::fs::create_dir(&work)?;
    let expected = WorkspaceIdentity::of_session_folder(&work)
        .expect("the recorded work folder should have a session identity")
        .digests;
    assert!(!expected.is_empty(), "the work folder should have digests");

    let root = dir.path().join("projects");
    let project = root.join("myproj");
    std::fs::create_dir_all(&project)?;
    let cwd = work.to_string_lossy().into_owned();
    let path = project.join(format!("{SESSION}.jsonl"));
    std::fs::write(&path, claude_log(&cwd, SESSION))?;
    let subagents = project.join(SESSION).join("subagents");
    std::fs::create_dir_all(&subagents)?;
    std::fs::write(
        subagents.join("agent-a1.jsonl"),
        claude_subagent_log(&cwd, SESSION, "a1"),
    )?;
    std::fs::write(
        subagents.join("agent-b2.jsonl"),
        claude_subagent_log(&cwd, SESSION, "b2"),
    )?;

    let logs = read_below(&root, &path)?;
    assert_eq!(
        logs.request.folder_digests, expected,
        "the sender names the folder the log records"
    );
    assert_eq!(
        logs.request.subagents.len(),
        2,
        "both subagent logs are read"
    );

    // A bound that fits the session log with one subagent log, not both: the
    // base request plus both entries, one byte short.
    let mut alone = logs.request.clone();
    alone.subagents = Vec::new();
    let base = serde_json::to_vec(&alone)?.len();
    let mut entries = Vec::new();
    for subagent in &logs.request.subagents {
        entries.push(serde_json::to_vec(subagent)?.len() + 1);
    }
    let bound = base + entries[0] + entries[1] - 1;
    let Ok(requests) = requests_within(&logs, bound)? else {
        panic!("the session log with one subagent log should fit the bound")
    };
    assert_eq!(requests.len(), 2, "the subagent logs split over two calls");
    for request in &requests {
        assert_eq!(
            request.folder_digests, expected,
            "every call names the session's folder"
        );
    }
    assert_eq!(requests[0].subagents.len(), 1);
    assert_eq!(requests[1].subagents.len(), 1);
    assert_eq!(requests[0].subagents[0].stem, "agent-a1");
    assert_eq!(requests[1].subagents[0].stem, "agent-b2");
    Ok(())
}

#[test]
fn a_log_whose_recorded_folder_is_not_here_or_relative_sends_no_folder() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("projects");
    let project = root.join("myproj");
    std::fs::create_dir_all(&project)?;

    // An absolute folder that is not here.
    let missing = dir.path().join("missing");
    assert!(!missing.exists(), "the missing folder should not exist");
    let path = project.join(format!("{SESSION}.jsonl"));
    std::fs::write(&path, claude_log(&missing.to_string_lossy(), SESSION))?;
    let logs = read_below(&root, &path)?;
    assert!(
        logs.request.folder_digests.is_empty(),
        "a folder that is not here sends no folder"
    );

    // A relative folder: "." names this test's own working directory, which
    // has a session identity, so an empty list proves the relative guard.
    assert!(
        WorkspaceIdentity::of_session_folder(Path::new(".")).is_some(),
        "the test's own working directory should have a session identity"
    );
    let other = project.join(format!("{OTHER_SESSION}.jsonl"));
    std::fs::write(&other, claude_log(".", OTHER_SESSION))?;
    let logs = read_below(&root, &other)?;
    assert!(
        logs.request.folder_digests.is_empty(),
        "a relative folder sends no folder"
    );
    Ok(())
}

#[test]
fn a_codex_rollout_sends_its_session_meta_folder() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let work = dir.path().join("work");
    std::fs::create_dir(&work)?;
    let expected = WorkspaceIdentity::of_session_folder(&work)
        .expect("the recorded work folder should have a session identity")
        .digests;
    assert!(!expected.is_empty(), "the work folder should have digests");

    let root = dir.path().join("sessions");
    std::fs::create_dir_all(&root)?;
    let stem = format!("rollout-2026-11-20T01-00-00-{SESSION}");
    let path = root.join(format!("{stem}.jsonl"));
    std::fs::write(&path, codex_rollout(&work.to_string_lossy(), SESSION))?;

    let logs = read_one_below(&root, &path, stem, HookTranscriptSource::Codex)?;
    assert_eq!(
        logs.request.folder_digests, expected,
        "the sender names the rollout's session meta folder"
    );
    assert!(
        logs.request.subagents.is_empty(),
        "a rollout carries no subagent logs"
    );
    Ok(())
}
