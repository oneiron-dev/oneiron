//! Fixed headers for text the harness carries into a Claude Code session, shared by the bridge, the hooks and the history import.
//!
//! Three outputs enter the transcript and must not return as the session's own words:
//! part 1's board block inside an Oneiron tool result, part 2's PostToolUse line and
//! part 3's SessionStart keyframe. The import drops any block whose first line is one
//! of these headers, keeping other blocks and lines.

/// Lead of part 1's block appended to an Oneiron tool result: the full first line is
/// this prefix, a decimal epoch, then `):`, followed by the board text.
pub const BOARD_CARRIER_PREFIX: &str = "Oneiron board (carried with this result, epoch ";

/// First line parts 2 and 3 share, marking text the session did not write.
pub const CARRIED_CONTEXT_HEADER: &str =
    "Oneiron, carried into this session (not the session's own words):";

/// Second line of part 2's PostToolUse context, naming the recall line for this tool result.
pub const TOOL_RESULT_CONTEXT_LEAD: &str =
    "From your Oneiron vault, for this tool result (may be dated):";

/// Second line of part 3's SessionStart context, naming the refreshed board after a compaction.
pub const FOCUS_REFRESH_CONTEXT_LEAD: &str = "Your Oneiron board, refreshed after the compaction:";

/// Whether `text` is a carried block: its first line is exactly [`CARRIED_CONTEXT_HEADER`],
/// or exactly [`BOARD_CARRIER_PREFIX`] plus a decimal `u64` plus `):`. A line that merely
/// mentions a header with other words is not carried.
pub fn is_carried_block(text: &str) -> bool {
    let first = text.trim_start().lines().next().unwrap_or("").trim_end();
    if first == CARRIED_CONTEXT_HEADER {
        return true;
    }
    if let Some(rest) = first.strip_prefix(BOARD_CARRIER_PREFIX)
        && let Some(digits) = rest.strip_suffix("):")
        && !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
    {
        return digits.parse::<u64>().is_ok();
    }
    false
}
