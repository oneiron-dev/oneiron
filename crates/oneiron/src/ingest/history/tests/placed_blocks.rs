//! The import drops only the exact block shapes the harness places beside a
//! tool result: a header-first block with other words lands (INJECT-4).

use serde_json::json;

use super::super::carried_headers::{
    BOARD_CARRIER_PREFIX, CARRIED_CONTEXT_HEADER, FOCUS_REFRESH_CONTEXT_LEAD,
    FOCUS_REFRESH_TOO_LONG, TOOL_RESULT_CONTEXT_LEAD, is_placed_block,
};
use super::{HistoryRole, SOURCE, decode_log};

#[test]
fn a_header_first_block_beside_a_tool_result_lands_unless_it_is_the_placed_shape() {
    let session = "6f4e9d10-3333-4444-8555-96667777888b";
    let parent: Option<String> = None;
    let line = json!({
        "type": "user",
        "uuid": "f3000000-0000-4000-8000-000000000001",
        "parentUuid": parent,
        "isSidechain": false,
        "userType": "external",
        "sessionId": session,
        "timestamp": "2026-11-27T12:00:01.000Z",
        "message": {
            "role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_01", "content": "ok"},
                {"type": "text", "text": format!(
                    "{CARRIED_CONTEXT_HEADER}\nIs this line from my vault?"
                )},
                {"type": "text", "text": format!(
                    "{CARRIED_CONTEXT_HEADER}\n{TOOL_RESULT_CONTEXT_LEAD} a line"
                )},
                {"type": "text", "text": format!(
                    "{CARRIED_CONTEXT_HEADER}\n{FOCUS_REFRESH_TOO_LONG}"
                )},
                {"type": "text", "text": format!("{BOARD_CARRIER_PREFIX}7):")},
            ],
        },
    })
    .to_string();
    let lines = [line.as_str()];
    let conversations = decode_log(SOURCE, session, &lines);
    assert_eq!(conversations.len(), 1);
    let messages: Vec<_> = conversations[0]
        .messages
        .iter()
        .map(|message| (message.role, message.text.as_str()))
        .collect();
    let landed = format!(
        "{CARRIED_CONTEXT_HEADER}\nIs this line from my vault?\n\n{BOARD_CARRIER_PREFIX}7):"
    );
    assert_eq!(messages, [(HistoryRole::User, landed.as_str())]);
    assert_eq!(conversations[0].skipped.injected, 1);
}

#[test]
fn is_placed_block_matches_only_the_exact_placed_shapes() {
    // The board: the exact first line plus a second line.
    assert!(is_placed_block(&format!(
        "{BOARD_CARRIER_PREFIX}7):\nRecalled board line"
    )));
    assert!(!is_placed_block(&format!("{BOARD_CARRIER_PREFIX}7):")));
    assert!(!is_placed_block(&format!(
        "{BOARD_CARRIER_PREFIX}x):\nNo epoch"
    )));
    assert!(!is_placed_block(&format!(
        "{BOARD_CARRIER_PREFIX}7): extra\nExtra words"
    )));
    // The PostToolUse line: the header, then the lead and a space.
    assert!(is_placed_block(&format!(
        "{CARRIED_CONTEXT_HEADER}\n{TOOL_RESULT_CONTEXT_LEAD} a line"
    )));
    assert!(!is_placed_block(&format!(
        "{CARRIED_CONTEXT_HEADER}\n{TOOL_RESULT_CONTEXT_LEAD}"
    )));
    assert!(!is_placed_block(&format!(
        "{CARRIED_CONTEXT_HEADER}\nIs this line from my vault?"
    )));
    assert!(!is_placed_block(CARRIED_CONTEXT_HEADER));
    // The refresh and the too-long refresh: the header, then the exact line.
    assert!(is_placed_block(&format!(
        "{CARRIED_CONTEXT_HEADER}\n{FOCUS_REFRESH_CONTEXT_LEAD}\nRefreshed board line"
    )));
    assert!(!is_placed_block(&format!(
        "{CARRIED_CONTEXT_HEADER}\n{FOCUS_REFRESH_CONTEXT_LEAD} extra"
    )));
    assert!(is_placed_block(&format!(
        "{CARRIED_CONTEXT_HEADER}\n{FOCUS_REFRESH_TOO_LONG}"
    )));
    assert!(!is_placed_block(&format!(
        "{CARRIED_CONTEXT_HEADER}\n{FOCUS_REFRESH_TOO_LONG} extra"
    )));
}
