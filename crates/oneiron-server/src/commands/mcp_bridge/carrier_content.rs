//! `--carrier-in-content`: fold a `tools/call` answer's board carrier frame
//! into its text content, for a client that reads `content` alone.
//!
//! The gateway carries a board stream frame BESIDE a tool result, as
//! `result.carrier.frame`, never inside its content. A client that reads
//! only `content` never sees the board. With the flag the bridge appends
//! one text block after the tool's own content and drops `result.carrier`
//! from that answer; without the flag nothing changes. The block's first
//! line is the shared carried header part 5's importer strips, so the
//! frame never re-enters the vault as the session's own words.

use oneiron::context_board::{BoardStreamFrame, FrameKind};
use oneiron::ingest::history::carried_headers::BOARD_CARRIER_PREFIX;
use serde_json::{Value, json};

/// Moves `answer`'s board carrier frame into its text content: one
/// `{"type":"text","text":...}` block appended at the end of
/// `result.content`, then no `result.carrier` key. The block's text is the
/// lead `Oneiron board (carried with this result, epoch <N>):`, a newline,
/// then the keyframe's text, or each delta row's `line` on its own line.
///
/// Only a successful `tools/call` result with a valid frame and an array
/// of content blocks can change. The caller opts in with the bridge flag.
/// Returns whether a frame moved.
pub(super) fn place_carrier_frame(answer: &mut Value, tools_call: bool) -> bool {
    if !tools_call
        || answer.get("error").is_some()
        || answer.pointer("/result/isError") == Some(&Value::Bool(true))
    {
        return false;
    }
    // Every check reads; nothing is written until all of them pass, so a
    // refusal leaves the answer, carrier included, exactly as it was.
    let frame: BoardStreamFrame = {
        let Some(frame) = answer.pointer("/result/carrier/frame").cloned() else {
            return false;
        };
        if !matches!(answer.pointer("/result/content"), Some(Value::Array(_))) {
            return false;
        }
        match serde_json::from_value(frame) {
            Ok(frame) => frame,
            Err(_) => return false,
        }
    };
    let body = match &frame.kind {
        FrameKind::Keyframe(text) => text.clone(),
        // No shared delta-to-text render exists: the board's only join of
        // delta lines counts tokens, so each row's `line` goes on its own
        // line here.
        FrameKind::Delta(rows) => rows
            .iter()
            .map(|row| row.line.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
    };
    let text = format!("{}{}):\n{}", BOARD_CARRIER_PREFIX, frame.epoch, body);
    // Both keys were verified above; a `None` here is unreachable, and
    // still leaves the answer as it was.
    let Some(result) = answer.pointer_mut("/result").and_then(Value::as_object_mut) else {
        return false;
    };
    {
        let Some(Value::Array(content)) = result.get_mut("content") else {
            return false;
        };
        content.push(json!({ "type": "text", "text": text }));
    }
    result.remove("carrier");
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `tools/call` success answer carrying `frame` beside its result, as
    /// the gateway's `mcp_endpoint_result` writes one.
    fn carried(frame: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    { "type": "text", "text": "done" },
                    { "type": "text", "text": "{\"ok\":true}" },
                ],
                "structuredContent": { "ok": true },
                "isError": false,
                "carrier": { "class": "carrier", "frame": frame },
            },
        })
    }

    #[test]
    fn keyframe_frame_becomes_one_more_text_block_and_no_carrier_key_is_left() {
        let mut answer = carried(json!({
            "epoch": 7,
            "kind": { "kind": "keyframe", "payload": "WORLDS\nlegend: x" },
        }));
        assert!(place_carrier_frame(&mut answer, true));
        let content = answer
            .pointer("/result/content")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(content.len(), 3);
        assert_eq!(
            content[2],
            json!({
                "type": "text",
                "text": "Oneiron board (carried with this result, epoch 7):\nWORLDS\nlegend: x",
            })
        );
        assert!(answer.pointer("/result/carrier").is_none());
        // The tool's own blocks and data stay as they were.
        assert_eq!(content[0]["text"], json!("done"));
        assert_eq!(
            answer.pointer("/result/structuredContent"),
            Some(&json!({ "ok": true }))
        );
    }

    #[test]
    fn delta_frame_lines_become_one_block() {
        let mut answer = carried(json!({
            "epoch": 9,
            "kind": { "kind": "delta", "payload": [
                { "key": "tasks:aa", "line": "first line" },
                { "key": "changed", "line": "second line" },
            ]},
        }));
        assert!(place_carrier_frame(&mut answer, true));
        let content = answer
            .pointer("/result/content")
            .and_then(Value::as_array)
            .unwrap();
        assert_eq!(content.len(), 3);
        assert_eq!(
            content[2]["text"],
            json!("Oneiron board (carried with this result, epoch 9):\nfirst line\nsecond line")
        );
        assert!(answer.pointer("/result/carrier").is_none());
    }

    #[test]
    fn answer_without_carrier_is_left_byte_identical() {
        let mut answer = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "content": [{ "type": "text", "text": "done" }],
                "structuredContent": { "ok": true },
                "isError": false,
            },
        });
        let before = serde_json::to_string(&answer).unwrap();
        assert!(!place_carrier_frame(&mut answer, true));
        assert_eq!(serde_json::to_string(&answer).unwrap(), before);
    }

    #[test]
    fn error_answer_is_left_unchanged() {
        let mut answer = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "error": {
                "code": -32000,
                "message": "no",
                "data": { "kind": "server_error" },
            },
        });
        let before = answer.clone();
        assert!(!place_carrier_frame(&mut answer, true));
        assert_eq!(answer, before);
    }

    #[test]
    fn answer_to_another_method_is_left_unchanged() {
        let mut answer = carried(json!({
            "epoch": 7,
            "kind": { "kind": "keyframe", "payload": "board" },
        }));
        let before = answer.clone();
        assert!(!place_carrier_frame(&mut answer, false));
        assert_eq!(answer, before);
    }

    #[test]
    fn tool_error_with_a_valid_carrier_is_left_unchanged() {
        let mut answer = carried(json!({
            "epoch": 7,
            "kind": { "kind": "keyframe", "payload": "board" },
        }));
        answer["result"]["isError"] = json!(true);
        let before = answer.clone();
        assert!(!place_carrier_frame(&mut answer, true));
        assert_eq!(answer, before);
    }

    #[test]
    fn frame_that_does_not_parse_is_left_as_it_was() {
        let mut answer = carried(json!({ "epoch": "seven", "kind": "keyframe" }));
        let before = answer.clone();
        assert!(!place_carrier_frame(&mut answer, true));
        assert_eq!(answer, before);
        // The carrier stays: the client still reads the frame as before.
        assert!(answer.pointer("/result/carrier").is_some());
    }

    #[test]
    fn answer_without_content_array_keeps_its_carrier() {
        let mut answer = json!({
            "jsonrpc": "2.0",
            "id": 5,
            "result": {
                "structuredContent": { "ok": true },
                "isError": false,
                "carrier": {
                    "class": "carrier",
                    "frame": {
                        "epoch": 7,
                        "kind": { "kind": "keyframe", "payload": "board" },
                    },
                },
            },
        });
        let before = answer.clone();
        assert!(!place_carrier_frame(&mut answer, true));
        assert_eq!(answer, before);
    }
}
