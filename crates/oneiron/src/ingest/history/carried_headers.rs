//! Fixed headers for text the harness carries into a Claude Code session, shared by the bridge, the hooks and the history import.
//!
//! Three outputs enter the transcript and must not return as the session's own words:
//! part 1's board block inside an Oneiron tool result, part 2's PostToolUse line and
//! part 3's SessionStart keyframe. The host marks where each lands (a tool result, a hook
//! attachment line, a meta turn), and the import skips those. In a message the host wrote
//! (one carrying a tool result) it also drops any text block in exactly the shape the
//! harness places ([`is_placed_block`]), keeping other blocks; text a person typed is kept
//! whole, header or not. Only the exact placed shape drops: a header-first block with
//! other words lands.

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

/// Said in place of a board that does not fit in a hook's context budget.
pub const FOCUS_REFRESH_TOO_LONG: &str = "Your Oneiron board is longer than a Claude Code hook may add \
     (10,000 characters), so it is not shown here; call the Oneiron tool \
     self.focus.refresh for the whole board.";

/// Mark put before a tool's own text that opens like a carried block, so it
/// no longer reads as the block the bridge appends (INJECT-1). A text
/// channel cannot be made unforgeable; this keeps a tool's own words from
/// posing as Oneiron's.
pub const TOOL_TEXT_MARK: &str = "Tool text, not carried by Oneiron: ";

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

/// Whether `text` opens like a carried block: its trimmed first line starts
/// with [`BOARD_CARRIER_PREFIX`] or with [`CARRIED_CONTEXT_HEADER`]. A
/// prefix test, wider than [`is_carried_block`]: anything shaped like the
/// block the bridge appends, exact or not, reads as forged tool text.
pub fn opens_like_carried(text: &str) -> bool {
    let first = text.trim_start().lines().next().unwrap_or("");
    first.starts_with(BOARD_CARRIER_PREFIX) || first.starts_with(CARRIED_CONTEXT_HEADER)
}

/// Whether `text` is exactly a block the harness places: the board (first
/// line exactly [`BOARD_CARRIER_PREFIX`] plus a decimal `u64` plus `):`,
/// with a second line), the PostToolUse line (the header, then
/// [`TOOL_RESULT_CONTEXT_LEAD`] and a space), the refresh (the header, then
/// [`FOCUS_REFRESH_CONTEXT_LEAD`]), or the too-long refresh (the header,
/// then [`FOCUS_REFRESH_TOO_LONG`]). A header-first block with other words
/// is not placed, and lands.
pub fn is_placed_block(text: &str) -> bool {
    let mut lines = text.trim_start().lines();
    let first = lines.next().unwrap_or("").trim_end();
    let second = lines.next().map(|line| line.trim_end());
    if let Some(rest) = first.strip_prefix(BOARD_CARRIER_PREFIX) {
        let exact = rest.strip_suffix("):").is_some_and(|digits| {
            !digits.is_empty()
                && digits.bytes().all(|b| b.is_ascii_digit())
                && digits.parse::<u64>().is_ok()
        });
        return exact && second.is_some();
    }
    if first != CARRIED_CONTEXT_HEADER {
        return false;
    }
    match second {
        Some(line) if line == FOCUS_REFRESH_CONTEXT_LEAD => true,
        Some(line) if line == FOCUS_REFRESH_TOO_LONG => true,
        Some(line) => line
            .strip_prefix(TOOL_RESULT_CONTEXT_LEAD)
            .is_some_and(|rest| rest.starts_with(' ')),
        None => false,
    }
}
