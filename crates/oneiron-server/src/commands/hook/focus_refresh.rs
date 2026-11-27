//! Restore a board after Claude Code compacts a session that already had it.
//!
//! The credential is the plugin MCP server's own, so the refresh goes only to
//! the origin a running Oneiron MCP server recorded for the same credential
//! file after the vault first admitted it ([`credential_origin`]), and only
//! when that vault answers the credential's own vault id: never to a vault
//! the hooks' discovery would bind or to a default (REVIEW-10587 P1 1,
//! round 2 P1 1).
//!
//! What Claude Code is given is the whole keyframe or none of it: a board
//! longer than a hook may add is named, never cut (round 2 P1 3).

use std::process::Stdio;
use std::time::Instant;

use oneiron::ingest::history::carried_headers::{
    CARRIED_CONTEXT_HEADER, FOCUS_REFRESH_CONTEXT_LEAD, FOCUS_REFRESH_TOO_LONG,
};
use serde_json::{Value, json};

use super::hosted_command::slip_vault_id;
use super::recall::{Bridge, RecallAuth, answers_vault};
use super::session_binding::{self, BOARD_KEYFRAME};
use super::{deadline, oneiron, project_dir, read_event, session_id};
use crate::cli::{HookHost, HookRecallArgs};
use crate::commands::local_servers;
use crate::commands::mcp_bridge::credential_origin;
use crate::commands::mcp_bridge::{INVOCATION_META, mint_invocation};
use crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION;

const TOOL: &str = "self.focus.refresh";
/// The most a hook may add to a Claude Code session's context, in
/// characters (docs/ops/claude-code-hooks.md, Limits). Claude Code counts a
/// JavaScript string's length, UTF-16 code units.
const HOOK_CONTEXT_CHARS: usize = 10_000;
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
    // The credential's own vault: the refresh goes only where that vault
    // answers, and nothing is sent when the slip names none.
    let vault = slip_vault_id(credential).ok()?;
    // No record, or a pin naming another origin than the bridge's, is no
    // origin this credential may go to: nothing is sent.
    let url = credential_origin::recorded(credential)?;
    if args
        .url
        .as_deref()
        .is_some_and(|pin| pin.trim_end_matches('/') != url)
    {
        return None;
    }
    let mut bridge = Bridge::start(
        &oneiron(args.common.oneiron.as_deref()),
        &url,
        RecallAuth::Slip(credential),
        project_dir(&event).as_deref(),
        deadline,
        Stdio::null(),
    )
    .ok()?;
    let frame = refresh(&mut bridge, host, &vault);
    bridge.close();
    let frame = frame?;
    (Instant::now() < deadline).then(|| refreshed_context(&frame))
}

/// The context the hook adds for the refreshed keyframe `frame`: the headers
/// and the whole keyframe when they fit in [`HOOK_CONTEXT_CHARS`] with the
/// line's end, else the headers' first line and [`FOCUS_REFRESH_TOO_LONG`].
/// A keyframe cut short would read as the whole board.
fn refreshed_context(frame: &str) -> String {
    let board = format!("{CARRIED_CONTEXT_HEADER}\n{FOCUS_REFRESH_CONTEXT_LEAD}\n{frame}");
    if board.encode_utf16().count() < HOOK_CONTEXT_CHARS {
        board
    } else {
        format!("{CARRIED_CONTEXT_HEADER}\n{FOCUS_REFRESH_TOO_LONG}")
    }
}

fn refresh(bridge: &mut Bridge, host: HookHost, vault: &str) -> Option<String> {
    let initialized = bridge.initialize().ok()?;
    if !answers_vault(&initialized, vault) {
        return None;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn notice() -> String {
        format!("{CARRIED_CONTEXT_HEADER}\n{FOCUS_REFRESH_TOO_LONG}")
    }

    #[test]
    fn a_board_that_fits_goes_in_whole_and_a_longer_one_is_named_not_cut() {
        let small = "<memory surface=\"board\" epoch=\"1\">\nTASKS\none task\n</memory>";
        assert_eq!(
            refreshed_context(small),
            format!("{CARRIED_CONTEXT_HEADER}\n{FOCUS_REFRESH_CONTEXT_LEAD}\n{small}")
        );
        // An owner cap of 20,000 tokens lets one TASK label run to 11,000
        // characters (REVIEW-10587 round 2 P1 3).
        let label = "x".repeat(11_000);
        let large = format!("<memory surface=\"board\" epoch=\"2\">\nTASKS\n{label}\n</memory>");
        assert_eq!(refreshed_context(&large), notice());
        assert!(notice().encode_utf16().count() < HOOK_CONTEXT_CHARS);
    }

    #[test]
    fn the_cap_counts_utf16_units_and_the_printed_line_end() {
        let lead = format!("{CARRIED_CONTEXT_HEADER}\n{FOCUS_REFRESH_CONTEXT_LEAD}\n")
            .encode_utf16()
            .count();
        // One unit under the cap leaves room for the line's end.
        let fits = "y".repeat(HOOK_CONTEXT_CHARS - 1 - lead);
        assert_eq!(
            refreshed_context(&fits).encode_utf16().count(),
            HOOK_CONTEXT_CHARS - 1
        );
        let at_cap = "y".repeat(HOOK_CONTEXT_CHARS - lead);
        assert_eq!(refreshed_context(&at_cap), notice());
        // A character outside the BMP is two units where Claude Code counts.
        let wide = "\u{1f980}".repeat((HOOK_CONTEXT_CHARS - lead).div_ceil(2));
        assert!(wide.chars().count() + lead < HOOK_CONTEXT_CHARS);
        assert_eq!(refreshed_context(&wide), notice());
    }
}
