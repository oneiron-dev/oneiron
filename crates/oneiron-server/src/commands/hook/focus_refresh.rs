//! Restore a board after Claude Code compacts a session that already had it.
//!
//! The credential is the plugin MCP server's own, so the refresh goes only to
//! the origin that server forwards to ([`mcp_bridge_origin`]), never to a vault
//! the hooks' discovery would bind (REVIEW-10587 P1 1).

use std::process::Stdio;
use std::time::Instant;

use oneiron::ingest::history::carried_headers::{
    CARRIED_CONTEXT_HEADER, FOCUS_REFRESH_CONTEXT_LEAD,
};
use serde_json::{Value, json};

use super::recall::{Bridge, RecallAuth};
use super::session_binding::{self, BOARD_KEYFRAME};
use super::{deadline, oneiron, project_dir, read_event, session_id};
use crate::cli::{HookHost, HookRecallArgs};
use crate::commands::local_servers;
use crate::commands::mcp_bridge::{INVOCATION_META, mint_invocation};
use crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION;

const TOOL: &str = "self.focus.refresh";
/// The origin `oneiron mcp` forwards to when the plugin starts it with no
/// `--url` (cli.rs `McpArgs::url`).
const MCP_BRIDGE_DEFAULT_URL: &str = "http://127.0.0.1:9090";

pub(super) fn focus_refresh(host: HookHost, args: &HookRecallArgs) -> Option<String> {
    if host != HookHost::ClaudeCode {
        return None;
    }
    let credential = args.credential_file.as_deref()?;
    let event = read_event()?;
    let session = session_id(host, &event)?;
    let folder = session_binding::session_folder(host, session)?;
    local_servers::open_own(&folder.join(BOARD_KEYFRAME))?;

    let deadline = deadline(args.common.timeout);
    let url = mcp_bridge_origin(args.url.as_deref());
    let mut bridge = Bridge::start(
        &oneiron(args.common.oneiron.as_deref()),
        &url,
        RecallAuth::Slip(credential),
        project_dir(&event).as_deref(),
        deadline,
        Stdio::null(),
    )
    .ok()?;
    let frame = refresh(&mut bridge, host);
    bridge.close();
    let frame = frame?;
    (Instant::now() < deadline)
        .then(|| format!("{CARRIED_CONTEXT_HEADER}\n{FOCUS_REFRESH_CONTEXT_LEAD}\n{frame}"))
}

/// The origin the plugin's MCP server reaches, as `oneiron mcp` resolves it:
/// `--url`, else `ONEIRON_URL`, else [`MCP_BRIDGE_DEFAULT_URL`]. No hook pin,
/// running local vault or hosted selection is consulted: the credential this
/// hook sends was paired with that server's vault alone.
fn mcp_bridge_origin(flag: Option<&str>) -> String {
    flag.map(str::to_owned)
        .or_else(|| {
            std::env::var("ONEIRON_URL")
                .ok()
                .filter(|url| !url.trim().is_empty())
        })
        .unwrap_or_else(|| MCP_BRIDGE_DEFAULT_URL.to_owned())
}

fn refresh(bridge: &mut Bridge, host: HookHost) -> Option<String> {
    bridge.initialize().ok()?;
    let listed = bridge.call(2, "tools/list", json!({})).ok()?;
    let tool = listed
        .get("tools")?
        .as_array()?
        .iter()
        .find(|tool| tool.get("name").and_then(Value::as_str) == Some(TOOL))?;
    let version = tool
        .pointer("/inputSchema/properties/schema_version/const")
        .cloned()
        .unwrap_or_else(|| json!(MCP_TOOL_ARGS_SCHEMA_VERSION));
    let mut meta = serde_json::Map::new();
    meta.insert(INVOCATION_META.to_owned(), Value::String(mint_invocation()));
    let result = bridge
        .call(
            3,
            "tools/call",
            json!({
                "name": TOOL,
                "arguments": {
                    "schema_version": version,
                    "consent": {
                        "policy_ref": format!("policy:{}-hooks", host.as_str()),
                        "purpose": "refresh the context board after compaction",
                    },
                    "arguments": {},
                },
                "_meta": meta,
            }),
        )
        .ok()?;
    if result.get("isError") == Some(&Value::Bool(true)) {
        return None;
    }
    let kind = result.pointer("/structuredContent/output/frame/kind")?;
    if kind.get("kind").and_then(Value::as_str) != Some("keyframe") {
        return None;
    }
    kind.get("payload")?
        .as_str()
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}
