//! The MCP stdio transport under the runner fence (canon `#runner-fence`,
//! row L8-27): an `mcp_stdio` connector's child answers its `tools/call`,
//! cannot read the vault or the key custody directory beside it, keeps only
//! a few of this process's variables, is restarted after it exits with a
//! new session manifest, and is not sent anything when it never answers
//! `initialize`; its endpoint names its settings, and a credential is never
//! put in its environment.
//!
//! The child is a Python stand-in, written to a temp directory beside the
//! vault. Run the tests with `--test-threads=1`: the process environment
//! changes once, before any child starts.
#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use oneiron_container::{GuestSeccomp, RunnerFence, RunnerFenceMechanism, SessionManifest};
use oneiron_server::config::ConnectorHostConfig;
use oneiron_server::connector_call_host::stdio::{
    ConnectorStdioRegistry, STDIO_RUNNER_BACKEND, StdioChild, StdioDelivery, StdioStart,
    StdioToolCall,
};
use oneiron_server::runtime::runner_fence::HostRunnerFence;
use serde_json::{Value, json};

/// The revision the tests pin.
const REVISION: &str = "2025-11-25";

/// A variable of this process a child must not see.
const LEAK: &str = "ONEIRON_STDIO_TEST_LEAK";

/// An MCP stdio server: it writes a log line on its standard output first,
/// answers `initialize` (never, with `PROBE_SILENT=1`) and `tools/list`, and
/// for `tools/call probe` says for each path whether it could read it,
/// whether it could make a temp file, the variables it got, and how its
/// own `roots/list` request was answered; `tools/call exit` exits unanswered.
const STAND_IN: &str = r#"import json, os, sys, tempfile

def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()

def read():
    line = sys.stdin.readline()
    if not line:
        sys.exit(0)
    return json.loads(line)

def probe(arguments):
    lines = []
    for path in arguments.get("paths", []):
        try:
            with open(path) as handle:
                handle.read()
            lines.append("read " + path)
        except OSError:
            lines.append("refused " + path)
    try:
        handle, name = tempfile.mkstemp()
        os.close(handle)
        os.unlink(name)
        lines.append("temp made")
    except OSError:
        lines.append("temp refused")
    lines.append("greeting " + os.environ.get("PROBE_GREETING", "none"))
    lines.append("leak " + os.environ.get("ONEIRON_STDIO_TEST_LEAK", "none"))
    send({"jsonrpc": "2.0", "id": "asks-roots", "method": "roots/list"})
    answer = read()
    lines.append("roots answered " + str(answer.get("error", {}).get("code")))
    return lines

sys.stdout.write("probe server starting\n")
sys.stdout.flush()
while True:
    message = read()
    method = message.get("method")
    if method == "initialize":
        if os.environ.get("PROBE_SILENT") == "1":
            continue
        send({"jsonrpc": "2.0", "id": message["id"], "result": {
            "protocolVersion": message["params"]["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "probe", "version": "1"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": message["id"], "result": {
            "tools": [{"name": "probe", "inputSchema": {"type": "object"}}]}})
    elif method == "tools/call":
        if message["params"]["name"] == "exit":
            os._exit(3)
        send({"jsonrpc": "2.0", "method": "notifications/message",
              "params": {"level": "info", "data": "probing"}})
        lines = probe(message["params"].get("arguments", {}))
        send({"jsonrpc": "2.0", "id": message["id"], "result": {
            "content": [{"type": "text", "text": "\n".join(lines)}],
            "structuredContent": {"lines": lines, "pid": os.getpid()}}})
"#;

/// Sets [`LEAK`] in this process once, before any child starts.
fn leak_set() {
    static SET: OnceLock<()> = OnceLock::new();
    SET.get_or_init(|| {
        // SAFETY: the tests run on one thread (`--test-threads=1`), and this
        // runs once, before any of them starts a process.
        unsafe { std::env::set_var(LEAK, "leaked") };
    });
}

/// A vault directory and the key custody directory beside it, each holding
/// a probe file, and beside them the stand-in and a file it may read.
struct Layout {
    _root: tempfile::TempDir,
    vault: PathBuf,
    vault_probe: PathBuf,
    custody_probe: PathBuf,
    outside: PathBuf,
    stand_in: PathBuf,
}

fn layout() -> Layout {
    leak_set();
    let root = tempfile::tempdir().expect("temp root");
    let vault = root.path().join("vault");
    let custody = oneiron::store::custody_container_path(&vault).expect("custody path");
    let beside = root.path().join("beside");
    for dir in [&vault, &custody, &beside] {
        fs::create_dir_all(dir).expect("layout directory");
    }
    let vault_probe = vault.join("probe");
    let custody_probe = custody.join("probe");
    let outside = beside.join("outside-file");
    let stand_in = beside.join("probe_server.py");
    fs::write(&vault_probe, "vault-secret").expect("vault probe");
    fs::write(&custody_probe, "custody-secret").expect("custody probe");
    fs::write(&outside, "outside").expect("outside file");
    fs::write(&stand_in, STAND_IN).expect("stand-in");
    Layout {
        _root: root,
        vault,
        vault_probe,
        custody_probe,
        outside,
        stand_in,
    }
}

/// The `[connectors.notes]` section that starts the stand-in, with `extra`
/// lines of TOML after its own.
fn section(layout: &Layout, extra: &str) -> ConnectorHostConfig {
    let text = format!(
        "transport = \"mcp_stdio\"\ncommand = [\"python3\", {:?}]\n{extra}\n",
        layout.stand_in.display().to_string(),
    );
    let connector: ConnectorHostConfig = toml::from_str(&text).expect("the section parses");
    connector.validate("notes").expect("the section is valid");
    connector
}

/// The paths the stand-in probes.
fn paths(layout: &Layout) -> Value {
    json!({
        "paths": [
            layout.vault_probe.display().to_string(),
            layout.custody_probe.display().to_string(),
            layout.outside.display().to_string(),
        ]
    })
}

/// One `tools/call` of `tool` through `registry`: what the stand-in said
/// (its lines and pid), or `None` when it gave no answer, and the session
/// manifest of the child it went to.
fn call(
    registry: &ConnectorStdioRegistry,
    connector: &ConnectorHostConfig,
    fence: &HostRunnerFence,
    tool: &str,
    arguments: Value,
) -> (Option<(Vec<String>, u64)>, Option<SessionManifest>) {
    let outcome = registry.call_tool(StdioToolCall {
        name: "notes",
        connector,
        fence: Some(fence),
        revision: REVISION,
        tool,
        arguments,
    });
    let said = match outcome.delivery {
        StdioDelivery::Answered { message, .. } => {
            let structured = &message["result"]["structuredContent"];
            let lines = structured["lines"]
                .as_array()
                .expect("the stand-in's lines")
                .iter()
                .map(|line| line.as_str().expect("a line").to_owned())
                .collect();
            Some((
                lines,
                structured["pid"].as_u64().expect("the stand-in's pid"),
            ))
        }
        StdioDelivery::NotSent => panic!("the call was not sent (is python3 on PATH?)"),
        StdioDelivery::NoAnswer => None,
    };
    (said, outcome.session_manifest)
}

#[test]
fn a_stdio_connector_answers_under_the_fence_and_cannot_read_the_vault_or_its_key_custody() {
    let layout = layout();
    let fence = HostRunnerFence::for_vault(&layout.vault).expect("runner fence");
    let outcome = fence.outcome().clone();
    eprintln!("runner_fence_stdio: mechanism {:?}", outcome.mechanism);
    if outcome.mechanism == RunnerFenceMechanism::Unavailable {
        assert!(!outcome.proven, "a host with no mechanism proves nothing");
        return;
    }
    assert!(outcome.proven, "proof failed: {outcome:?}");
    let registry = ConnectorStdioRegistry::default();
    let connector = section(&layout, "env = { PROBE_GREETING = \"hello\" }");
    let (said, manifest) = call(&registry, &connector, &fence, "probe", paths(&layout));
    let (lines, _) = said.expect("the stand-in answered");
    eprintln!("runner_fence_stdio: the stand-in said: {lines:?}");
    for probe in [&layout.vault_probe, &layout.custody_probe] {
        assert!(
            lines.contains(&format!("refused {}", probe.display())),
            "the child read {}: {lines:?}",
            probe.display()
        );
    }
    for line in [
        format!("read {}", layout.outside.display()),
        // The test's vault lies below the system temp directory: the child
        // writes in its own TMPDIR.
        "temp made".to_owned(),
        "greeting hello".to_owned(),
        "leak none".to_owned(),
        // Its own `roots/list` was refused: this client serves none.
        "roots answered -32601".to_owned(),
    ] {
        assert!(lines.contains(&line), "missing {line:?}: {lines:?}");
    }
    let manifest = manifest.expect("a fenced child's call carries its session manifest");
    assert_eq!(manifest.backend, STDIO_RUNNER_BACKEND);
    assert_eq!(manifest.runtime, "python3");
    assert_eq!(manifest.network, "host");
    assert_eq!(manifest.seccomp, GuestSeccomp::Unfiltered);
    assert!(!manifest.fence_unproven);
    let proof = manifest
        .fence_proof
        .expect("a proven session carries its proof");
    assert_eq!(proof.ruleset_hash, outcome.ruleset_hash);
    assert_eq!(proof.sandbox_generation, outcome.sandbox_generation);
    registry.stop();
}

#[test]
fn a_stdio_child_serves_the_next_call_and_is_started_again_after_it_exits() {
    let layout = layout();
    let fence = HostRunnerFence::for_vault(&layout.vault).expect("runner fence");
    let registry = ConnectorStdioRegistry::default();
    let connector = section(&layout, "");
    let (first, first_manifest) = call(&registry, &connector, &fence, "probe", json!({}));
    let (second, second_manifest) = call(&registry, &connector, &fence, "probe", json!({}));
    let (_, first_pid) = first.expect("the first call answered");
    let (_, second_pid) = second.expect("the second call answered");
    let first_manifest = first_manifest.expect("a manifest");
    assert_eq!(first_pid, second_pid, "one child serves both calls");
    assert_eq!(
        Some(&first_manifest.generation),
        second_manifest
            .as_ref()
            .map(|manifest| &manifest.generation),
        "one child session, one manifest"
    );
    let started = Instant::now();
    let (exited, _) = call(&registry, &connector, &fence, "exit", json!({}));
    assert!(
        exited.is_none(),
        "a child that exits unanswered gives no answer"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "its exit ends the call at once, not at the call's bound"
    );
    let (third, third_manifest) = call(&registry, &connector, &fence, "probe", json!({}));
    let (_, third_pid) = third.expect("a new child answered");
    assert_ne!(third_pid, first_pid, "a new child serves the call");
    let third_manifest = third_manifest.expect("the new child's manifest");
    assert_ne!(
        third_manifest.generation, first_manifest.generation,
        "a new child session has a new manifest"
    );
    assert_eq!(third_manifest.fence_proof, first_manifest.fence_proof);
    registry.stop();
    let outcome = registry.call_tool(StdioToolCall {
        name: "notes",
        connector: &connector,
        fence: Some(&fence),
        revision: REVISION,
        tool: "probe",
        arguments: json!({}),
    });
    assert!(
        matches!(outcome.delivery, StdioDelivery::NotSent),
        "a stopped registry starts no child"
    );
}

#[test]
fn a_stdio_child_that_never_answers_initialize_is_not_sent_the_call() {
    let layout = layout();
    let fence = HostRunnerFence::for_vault(&layout.vault).expect("runner fence");
    let registry = ConnectorStdioRegistry::default();
    let connector = section(&layout, "env = { PROBE_SILENT = \"1\" }");
    let started = Instant::now();
    let outcome = registry.call_tool(StdioToolCall {
        name: "notes",
        connector: &connector,
        fence: Some(&fence),
        revision: REVISION,
        tool: "probe",
        arguments: json!({}),
    });
    assert!(
        matches!(outcome.delivery, StdioDelivery::NotSent),
        "nothing is sent before the handshake"
    );
    assert!(outcome.session_manifest.is_none());
    let took = started.elapsed();
    eprintln!("runner_fence_stdio: a silent child was given up after {took:?}");
    assert!(
        took < Duration::from_secs(25),
        "the handshake is bounded: {took:?}"
    );
}

#[test]
fn a_stdio_child_on_a_host_without_the_fence_runs_with_an_unproven_manifest() {
    let layout = layout();
    let fence = HostRunnerFence::proved(
        RunnerFence::unavailable([layout.vault.clone()]).expect("runner fence"),
    );
    let registry = ConnectorStdioRegistry::default();
    let connector = section(&layout, "");
    let (said, manifest) = call(&registry, &connector, &fence, "probe", paths(&layout));
    let (lines, _) = said.expect("the stand-in answered");
    assert!(
        lines.contains(&format!("read {}", layout.vault_probe.display())),
        "the call goes on, unfenced: {lines:?}"
    );
    let manifest = manifest.expect("an unfenced child still carries its session manifest");
    assert_eq!(manifest.backend, STDIO_RUNNER_BACKEND);
    assert!(manifest.fence_unproven);
    assert!(manifest.fence_proof.is_none(), "no ruleset hash is claimed");
    registry.stop();
}

#[test]
fn a_stdio_child_lists_its_tools_at_the_revision_both_sides_speak() {
    let layout = layout();
    let fence = HostRunnerFence::for_vault(&layout.vault).expect("runner fence");
    let connector = section(&layout, "");
    let accepts = |answered: &str| answered == REVISION;
    let mut child = StdioChild::start(&StdioStart {
        name: "notes",
        connector: &connector,
        fence: Some(&fence),
        requested_revision: REVISION,
        accepts_revision: &accepts,
    })
    .expect("the child starts");
    assert_eq!(child.revision(), REVISION);
    let listed = child
        .request("tools/list", json!({}), Duration::from_secs(15))
        .expect("tools/list");
    assert_eq!(listed["tools"][0]["name"], "probe");
    assert_eq!(
        child
            .session_manifest()
            .map(|manifest| manifest.backend.as_str()),
        Some(STDIO_RUNNER_BACKEND)
    );
    let refuses = |_: &str| false;
    let refused = StdioChild::start(&StdioStart {
        name: "notes",
        connector: &connector,
        fence: Some(&fence),
        requested_revision: REVISION,
        accepts_revision: &refuses,
    });
    assert!(
        refused.is_err(),
        "a revision this client does not take ends the start"
    );
}

#[test]
fn a_stdio_connectors_endpoint_names_its_settings_and_its_env_holds_no_credential() {
    let layout = layout();
    let plain = section(&layout, "");
    let greeting = section(&layout, "env = { PROBE_GREETING = \"hello\" }");
    let endpoint = plain.installed_endpoint("Notes");
    assert!(
        endpoint.starts_with("stdio:notes:"),
        "the endpoint names the connector: {endpoint}"
    );
    assert_eq!(endpoint.len(), "stdio:notes:".len() + 16);
    assert_eq!(endpoint, plain.installed_endpoint("notes"));
    assert_ne!(
        endpoint,
        greeting.installed_endpoint("notes"),
        "a changed environment is a new endpoint the owner grants again"
    );
    assert_eq!(plain.http_endpoint(), None);
    let parsed = |text: &str| {
        toml::from_str::<ConnectorHostConfig>(text)
            .map_err(|error| error.to_string())
            .and_then(|connector| {
                connector
                    .validate("notes")
                    .map_err(|error| error.to_string())
            })
    };
    for refused in [
        "transport = \"mcp_stdio\"\ncommand = [\"x\"]\nenv = { GITHUB_TOKEN = \"t\" }",
        "transport = \"mcp_stdio\"\ncommand = [\"x\"]\nenv = { OPENAI_API_KEY = \"k\" }",
        "transport = \"mcp_stdio\"\ncommand = [\"x\"]\nenv = { ACCESSTOKEN = \"k\" }",
        "transport = \"mcp_stdio\"\ncommand = []",
        "transport = \"mcp_stdio\"\ncommand = [\"x\"]\ncwd = \"relative\"",
        "transport = \"mcp_stdio\"\ncommand = [\"x\"]\nendpoint = \"https://mcp.example.com/mcp\"",
        "transport = \"mcp_http\"",
        "transport = \"mcp_http\"\nendpoint = \"https://mcp.example.com/mcp\"\ncommand = [\"x\"]",
    ] {
        assert!(parsed(refused).is_err(), "accepted: {refused}");
    }
    for accepted in [
        "transport = \"mcp_stdio\"\ncommand = [\"x\"]\nenv = { TOKENIZERS_PARALLELISM = \"false\" }",
        "transport = \"mcp_stdio\"\ncommand = [\"x\", \"--flag\"]\ncwd = \"/opt/notes\"",
        "transport = \"mcp_http\"\nendpoint = \"https://mcp.example.com/mcp\"",
    ] {
        assert!(
            parsed(accepted).is_ok(),
            "refused: {accepted}: {:?}",
            parsed(accepted)
        );
    }
    let http: ConnectorHostConfig =
        toml::from_str("transport = \"mcp_http\"\nendpoint = \"https://mcp.example.com/mcp\"")
            .expect("http section");
    assert_eq!(
        http.installed_endpoint("github"),
        "https://mcp.example.com/mcp"
    );
    assert_eq!(http.http_endpoint(), Some("https://mcp.example.com/mcp"));
}
