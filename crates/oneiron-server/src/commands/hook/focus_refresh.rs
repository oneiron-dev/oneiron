//! Restore a board after Claude Code compacts a session that already had it.

use std::process::Stdio;
use std::time::Instant;

use oneiron::ingest::history::carried_headers::{
    CARRIED_CONTEXT_HEADER, FOCUS_REFRESH_CONTEXT_LEAD,
};
use serde_json::{Value, json};

use super::recall::{Bridge, RecallAuth};
use super::session_binding::{self, BOARD_KEYFRAME};
use super::{bind, deadline, oneiron, project_dir, read_event, session_id};
use crate::cli::{HookHost, HookRecallArgs};
use crate::commands::local_servers;
use crate::commands::mcp_bridge::{INVOCATION_META, mint_invocation};
use crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION;

const TOOL: &str = "self.focus.refresh";

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
    let url = bind::quietly(args.url.as_deref(), deadline).url?;
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
