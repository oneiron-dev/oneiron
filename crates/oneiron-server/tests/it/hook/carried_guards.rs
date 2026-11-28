//! Guards for the carried-context fixes: the bridge's origin record and the
//! refresh's vault check (CRED-1), the local query's vault check (LEAK-1),
//! and the shown-keys file (STATE-3).

use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use oneiron::ingest::history::carried_headers::CARRIED_CONTEXT_HEADER;
use serde_json::json;

use super::{
    Home, LiveBridge, TOOL_CLAIM, TOOL_SESSION, ToolHookFixture, answering_vault,
    board_setup_event, compact_event, lines, mcp_bridge_ask, recorded_query, recording_bridge,
    setup_board_via_live_bridge, tool_hook_session, tool_read_event, vault_id_via_stdio,
};

/// This bridge's origin records: entries of `origins` named `*.<pid>`.
fn records_for(origins: &Path, pid: u32) -> Vec<PathBuf> {
    let suffix = format!(".{pid}");
    std::fs::read_dir(origins)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .is_some_and(|name| name.to_string_lossy().ends_with(suffix.as_str()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Sets the fixture's board up through a bridge left running, and marks the
/// session as one that had a board, as the board tool's result does.
fn board_with_live_bridge(fixture: &ToolHookFixture) -> LiveBridge {
    let (setup, live) = setup_board_via_live_bridge(
        &fixture.home,
        &fixture.url,
        &fixture.credential,
        &fixture.folder,
    );
    assert!(setup.get("error").is_none(), "setup was refused: {setup:?}");
    let structured = &setup["result"]["structuredContent"];
    let event = board_setup_event(&fixture.folder, TOOL_SESSION, json!(structured.to_string()));
    assert!(
        fixture
            .home
            .hook("tool-result", &[], &event)
            .stdout
            .is_empty()
    );
    live
}

/// The focus-refresh hook after a compaction, on the fixture's credential
/// with no `--url`, plus `args`.
fn focus_refresh(fixture: &ToolHookFixture, args: &[&str]) -> Output {
    let mut all = vec![
        "--credential-file",
        fixture.credential.to_str().expect("UTF-8 path"),
    ];
    all.extend_from_slice(args);
    fixture
        .home
        .hook("focus-refresh", &all, &compact_event(&fixture.folder))
}

/// Whether the refresh printed the carried board.
fn refreshed(output: &Output) -> bool {
    lines(output).first().map(String::as_str) == Some(CARRIED_CONTEXT_HEADER)
}

/// `id` with its first hex digit changed: another vault's id.
fn another_vault_id(id: &str) -> String {
    let mut other = id.to_owned();
    other.replace_range(0..1, if id.starts_with('f') { "e" } else { "f" });
    other
}

#[test]
fn a_bridge_records_its_origin_only_after_the_vault_admits_it() {
    let fixture = ToolHookFixture::new("open");
    let origins = fixture.home.run_dir().join("mcp-origins");
    let mut child = fixture
        .home
        .oneiron(&["mcp", "--url", &fixture.url, "--surface", "primary"])
        .arg("--credential-file")
        .arg(&fixture.credential)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn oneiron mcp");
    let pid = child.id();
    let mut stdin = child.stdin.take().expect("bridge stdin");
    let stdout = child.stdout.take().expect("bridge stdout");
    let (send, answers) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if send.send(line).is_err() {
                break;
            }
        }
    });
    // The bridge runs and answers, but the vault refused the request: no
    // record yet.
    let refused = mcp_bridge_ask(&mut stdin, &answers, 1, "oneiron/no-such-method", json!({}));
    assert!(refused.get("error").is_some(), "refused: {refused:?}");
    assert!(
        records_for(&origins, pid).is_empty(),
        "no record before the vault admits the bridge"
    );
    let answer = mcp_bridge_ask(
        &mut stdin,
        &answers,
        2,
        "initialize",
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "hook-test", "version": "1"},
        }),
    );
    assert!(
        answer.get("error").is_none(),
        "the bridge is admitted: {answer:?}"
    );
    // After the vault admitted the bridge, one record names the vault's origin.
    let records = records_for(&origins, pid);
    assert_eq!(records.len(), 1, "one record for this bridge");
    assert_eq!(
        std::fs::read_to_string(&records[0]).expect("the record reads"),
        fixture.url.trim_end_matches('/')
    );
    // Closing stdin ends the bridge, which forgets its record.
    drop(stdin);
    child.wait().expect("the bridge exits");
    assert!(records_for(&origins, pid).is_empty());
}

#[test]
fn focus_refresh_sends_nothing_when_the_recording_bridge_has_ended() {
    let fixture = ToolHookFixture::new("open");
    let live = board_with_live_bridge(&fixture);
    // While the bridge runs, the refresh reaches the origin it recorded.
    let output = focus_refresh(&fixture, &[]);
    assert!(refreshed(&output), "{:?}", lines(&output));
    // Killed, as a crash would: its record stays behind for a dead pid,
    // which no hook uses.
    drop(live);
    let output = focus_refresh(&fixture, &[]);
    assert!(output.stdout.is_empty(), "{:?}", lines(&output));
}

#[test]
fn focus_refresh_sends_nothing_when_running_bridges_recorded_different_origins() {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let fixture = ToolHookFixture::new("open");
    let live = board_with_live_bridge(&fixture);
    let output = focus_refresh(&fixture, &[]);
    assert!(refreshed(&output), "{:?}", lines(&output));
    // A second running bridge on the same credential file recorded another
    // spelling of the vault's origin (a trailing slash). Either record
    // reaches the vault, but they disagree, so the refresh sends nothing.
    // This test's own process stands in for that bridge: its pid is live.
    let origins = fixture.home.run_dir().join("mcp-origins");
    let recorded = records_for(&origins, live.server.0.id());
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    let name = recorded[0]
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a UTF-8 record name");
    let (digest, _) = name.rsplit_once('.').expect("<digest>.<pid>");
    let spelling = format!("{}/", fixture.url.trim_end_matches('/'));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(origins.join(format!("{digest}.{}", std::process::id())))
        .and_then(|mut file| file.write_all(spelling.as_bytes()))
        .expect("a second live record");
    let output = focus_refresh(&fixture, &[]);
    assert!(output.stdout.is_empty(), "{:?}", lines(&output));
}

/// A bridge stub for focus-refresh: answers `initialize` naming `vault_id`,
/// lists `self.focus.refresh`, then keeps the one call it is sent in
/// `<stub>.call` and answers it with nothing. It exits when its stdin ends,
/// so a hook that bails before `tools/call` leaves no `.call` file.
fn refresh_stub(home: &Home, vault_id: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let stub = home.path("refresh-oneiron");
    let script = format!(
        "#!/bin/sh\nIFS= read -r _ || exit 0\nprintf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"vault_id\":\"{vault_id}\"}}}}'\nIFS= read -r _ || exit 0\nIFS= read -r _ || exit 0\nprintf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"tools\":[{{\"name\":\"self.focus.refresh\"}}]}}}}'\nIFS= read -r call || exit 0\nprintf '%s\\n' \"$call\" > \"$0.call\"\nprintf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{{}}}}'\n"
    );
    std::fs::write(&stub, script).expect("the refresh stub");
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o700))
        .expect("the refresh stub runs");
    stub
}

#[test]
fn focus_refresh_sends_nothing_to_a_vault_that_answers_another_vault_id() {
    let fixture = ToolHookFixture::new("open");
    let _live = board_with_live_bridge(&fixture);
    let own = vault_id_via_stdio(&fixture.home, &fixture.url, &fixture.credential);

    // Another vault's id on `initialize`: no `tools/call` goes.
    let stub = refresh_stub(&fixture.home, &another_vault_id(&own));
    let stub_arg = stub.to_str().expect("UTF-8 path").to_owned();
    let output = focus_refresh(&fixture, &["--oneiron", stub_arg.as_str()]);
    assert!(output.stdout.is_empty(), "{:?}", lines(&output));
    assert!(
        !Path::new(&format!("{stub_arg}.call")).exists(),
        "no tools/call goes to another vault"
    );

    // The credential's own vault id: the refresh calls the tool.
    let stub = refresh_stub(&fixture.home, &own);
    let stub_arg = stub.to_str().expect("UTF-8 path").to_owned();
    let _ = focus_refresh(&fixture, &["--oneiron", stub_arg.as_str()]);
    let called =
        std::fs::read_to_string(format!("{stub_arg}.call")).expect("the refresh called the tool");
    assert!(called.contains("self.focus.refresh"), "{called:?}");
}

#[test]
fn a_local_tool_result_sends_its_full_query_only_to_the_credentials_vault() {
    let tool = ToolHookFixture::new("open");
    let own = vault_id_via_stdio(&tool.home, &tool.url, &tool.credential);
    let origin = answering_vault();
    let mut event = tool_read_event(&tool.home.path("home"));
    event["tool_name"] = json!("Bash");
    event["tool_input"] = json!({"command": "echo input-marker-7f3a", "description": "show it"});
    event["tool_response"] =
        json!({"stdout": "output-marker-9c1e", "stderr": "", "interrupted": false});
    let credential = tool.credential.to_str().expect("UTF-8 path").to_owned();

    // Another vault's id: the hook prints nothing and sends no `tools/call`.
    let stub = recording_bridge(&tool.home, Some(&another_vault_id(&own)));
    let stub_arg = stub.to_str().expect("UTF-8 path").to_owned();
    let args = [
        "--url",
        origin.as_str(),
        "--oneiron",
        stub_arg.as_str(),
        "--credential-file",
        credential.as_str(),
    ];
    let output = tool.home.hook("tool-result", &args, &event);
    assert!(output.stdout.is_empty(), "{:?}", lines(&output));
    assert!(
        !Path::new(&format!("{stub_arg}.call")).exists(),
        "no tools/call goes to another vault"
    );

    // The credential's own vault id: the kept query holds the full text.
    let stub = recording_bridge(&tool.home, Some(&own));
    let stub_arg = stub.to_str().expect("UTF-8 path").to_owned();
    let args = [
        "--url",
        origin.as_str(),
        "--oneiron",
        stub_arg.as_str(),
        "--credential-file",
        credential.as_str(),
    ];
    assert!(
        tool.home
            .hook("tool-result", &args, &event)
            .stdout
            .is_empty()
    );
    let sent = recorded_query(&stub);
    assert!(sent.contains("input-marker-7f3a"), "{sent:?}");
    assert!(sent.contains("output-marker-9c1e"), "{sent:?}");
}

#[test]
fn a_carrier_lines_file_others_may_read_is_refused() {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

    let fixture = ToolHookFixture::new("open");
    let folder = tool_hook_session(&fixture.home, TOOL_SESSION);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&folder)
        .expect("the session folder");
    let shown = folder.join("carrier-lines");
    let before = "seed-key-00\n";
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&shown)
        .and_then(|mut file| file.write_all(before.as_bytes()))
        .expect("the shown keys");
    let output = fixture.hook("tool-result", &tool_read_event(&fixture.folder));
    assert!(output.stdout.is_empty(), "{:?}", lines(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("chmod 600"), "{stderr:?}");
    assert_eq!(
        std::fs::read_to_string(&shown).expect("the shown file"),
        before
    );
}

#[test]
fn carrier_lines_keeps_digests_not_recalled_text() {
    let fixture = ToolHookFixture::new("direct_match");
    let event = tool_read_event(&fixture.folder);
    let said = lines(&fixture.hook("tool-result", &event));
    assert_eq!(said.len(), 1, "one JSON line: {said:?}");
    let shown = std::fs::read_to_string(
        tool_hook_session(&fixture.home, TOOL_SESSION).join("carrier-lines"),
    )
    .expect("the shown file is written");
    assert!(!shown.contains(TOOL_CLAIM), "{shown:?}");
    assert!(!shown.contains(&said[0]), "{shown:?} vs {said:?}");
    assert!(fixture.hook("tool-result", &event).stdout.is_empty());
}
