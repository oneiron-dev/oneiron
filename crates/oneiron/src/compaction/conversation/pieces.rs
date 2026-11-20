//! A first turn past the writer's input room, read in pieces (FIX-LIST
//! COMPACTION-FIRST-TURN-PAST-INPUT-ROOM-STALLS; Engine ruling
//! COMPACTION-OVER-ROOM-TURN-INTENT = CHUNKED, 21 Nov). A window holds whole
//! turns, so a turn whose text alone does not fit the writer's input would
//! head every later window, and its conversation would never compact again.
//! Such a turn flies alone. Its window text is cut into byte ranges that each
//! fit the writer beside a marker naming them; each piece is summarised by a
//! pass of its own; and the turn's entry is the flight's sealed request
//! re-sealed with the piece summaries as the turn's text, each under the byte
//! range it covers. No summary claims bytes it was not given, and none of the
//! turn is cut away. The whole turn's pins (FIX 9837) ride the entry. When a
//! piece pass does not end accepted, or the entry does not fit, the entry
//! falls back to the turn's head that fits, with a marker naming the cut.

use std::fmt::Write as _;
use std::ops::Range;

use super::{Pass, file_pass, run_pass};
use crate::compaction::{
    CompactionBackend, CompactionDriver, CompactionGatePolicy, CompactionRequest,
    CompactionWindowMessage, compaction_input_tokens,
};
use crate::error::{Error, Result};
use crate::{EntityId, Vault, count_context_pack_tokens};

/// The most bytes a piece search reads past its start per token of room: no
/// token of the pack tokenizer runs longer, so the search never tokenizes
/// more of a long turn than one piece can hold.
const BYTES_PER_TOKEN_BOUND: usize = 32;

/// How a turn past the writer's input room is read: its pieces, each piece
/// summary's ceiling, and the head its entry falls back to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TurnPieces {
    /// Byte ranges of the turn's window text, in order, covering all of it.
    ranges: Vec<Range<usize>>,
    /// The token ceiling of each piece's summary: every piece summary under
    /// its marker, with the pins, fits the entry.
    piece_budget: u64,
    /// The end of the head the entry falls back to: the longest prefix that
    /// fits beside its cut marker and the pins.
    head_end: usize,
    /// The tokens of the turn's whole window text, as its cut marker names
    /// them.
    total_tokens: u64,
    /// The writer's input room the plan was sized on.
    room: u64,
}

impl TurnPieces {
    /// The plan for `message`, a turn whose text alone does not fit `room`
    /// beside a reply of `budget`, with the whole turn's `pins`. `None` when
    /// no plan fits: the room holds no piece beside its marker, the piece
    /// summaries cannot fit one entry above the gate's `floor`, or no head
    /// fits beside its cut marker and the pins.
    pub(super) fn plan(
        message: &CompactionWindowMessage,
        pins: &[String],
        budget: u64,
        room: u64,
        floor: u64,
    ) -> Option<Self> {
        let text = message.content.as_str();
        let reach = usize::try_from(room)
            .ok()?
            .saturating_mul(BYTES_PER_TOKEN_BOUND);
        let mut ranges = Vec::new();
        let mut start = 0;
        while start < text.len() {
            let limit = start.saturating_add(reach).min(text.len());
            let end = longest_fit(text, start, limit, |end| {
                input_tokens(message, piece_text(text, &(start..end)), &[], budget) <= room
            })?;
            ranges.push(start..end);
            start = end;
        }
        let pieces = u64::try_from(ranges.len()).ok()?;
        let unwritten: Vec<(Range<usize>, String)> = ranges
            .iter()
            .map(|range| (range.clone(), String::new()))
            .collect();
        let overhead = input_tokens(message, entry_text(text.len(), &unwritten), pins, budget);
        // A tenth is kept back for each summary's escapes inside the entry.
        let piece_budget = budget.min((room.checked_sub(overhead)? / 10 * 9).checked_div(pieces)?);
        if piece_budget <= floor {
            return None;
        }
        let total_tokens = count_context_pack_tokens(text) as u64;
        let head_end = longest_fit(text, 0, reach.min(text.len()), |end| {
            input_tokens(
                message,
                head_text(text, end, total_tokens, total_tokens),
                pins,
                budget,
            ) <= room
        })?;
        Some(Self {
            ranges,
            piece_budget,
            head_end,
            total_tokens,
            room,
        })
    }

    /// Whether `pins` fit this plan beside a reply of `budget`: the entry
    /// with every piece summary at its ceiling, and the head it falls back
    /// to, each beside them.
    pub(super) fn fits(
        &self,
        message: &CompactionWindowMessage,
        pins: &[String],
        budget: u64,
    ) -> bool {
        let text = message.content.as_str();
        let unwritten: Vec<(Range<usize>, String)> = self
            .ranges
            .iter()
            .map(|range| (range.clone(), String::new()))
            .collect();
        let pieces = u64::try_from(self.ranges.len()).unwrap_or(u64::MAX);
        let entry = input_tokens(message, entry_text(text.len(), &unwritten), pins, budget)
            .saturating_add(self.piece_budget.saturating_mul(pieces));
        let head = input_tokens(
            message,
            head_text(text, self.head_end, self.total_tokens, self.total_tokens),
            pins,
            budget,
        );
        entry <= self.room && head <= self.room
    }
}

/// The turn's entry request for `sealed`, a flight over one turn read in
/// pieces by `plan`: one pass per piece on `backend`, each judged by
/// `policy`, then `sealed` re-sealed with the piece summaries as the turn's
/// text. A piece pass that does not end accepted, or an entry that does not
/// fit the plan's room beside the pins, re-seals it with the turn's head and
/// the cut instead. Every pass's paid calls are filed as `job`'s steps.
///
/// # Errors
///
/// A sealed flight over more than one turn, and a piece request or a re-seal
/// the driver refuses.
pub(super) fn entry_request(
    vault: &Vault,
    driver: &mut CompactionDriver,
    backend: &dyn CompactionBackend,
    sealed: &CompactionRequest,
    plan: &TurnPieces,
    policy: &CompactionGatePolicy,
    job: EntityId,
) -> Result<CompactionRequest> {
    let [message] = sealed.window.as_slice() else {
        return Err(Error::InvariantViolation(
            "a turn read in pieces flies alone",
        ));
    };
    let text = message.content.as_str();
    let mut summaries = Vec::with_capacity(plan.ranges.len());
    for range in &plan.ranges {
        let piece = sealed.for_piece(vault, piece_text(text, range), plan.piece_budget)?;
        let (pass, execution) = run_pass(backend, &piece, policy);
        if let Some(mut execution) = execution {
            file_pass(vault, job, &mut execution);
        }
        let Pass::Accepted(gated, _) = pass else {
            break;
        };
        summaries.push((range.clone(), gated.summary_text().to_owned()));
    }
    let entry = (summaries.len() == plan.ranges.len())
        .then(|| entry_text(text.len(), &summaries))
        .filter(|entry| {
            input_tokens(
                message,
                entry.clone(),
                &sealed.pins,
                sealed.summary_token_budget,
            ) <= plan.room
        });
    let content = entry.unwrap_or_else(|| {
        let head = &text[..plan.head_end];
        head_text(
            text,
            plan.head_end,
            plan.total_tokens,
            count_context_pack_tokens(head) as u64,
        )
    });
    driver.reseal_window_texts(vec![content])
}

/// The rendered input of one request over `message` with `content` as its
/// text, beside `pins` and a reply of `budget`, on its costliest try.
fn input_tokens(
    message: &CompactionWindowMessage,
    content: String,
    pins: &[String],
    budget: u64,
) -> u64 {
    let window = [CompactionWindowMessage {
        message_id: message.message_id,
        turn_id: message.turn_id,
        content,
        turn: message.turn,
        tokens: 0,
    }];
    compaction_input_tokens(message.turn, &window, pins, None, budget)
}

/// One piece's text: the marker naming its bytes, then those bytes.
fn piece_text(text: &str, range: &Range<usize>) -> String {
    format!(
        "[bytes {}..{} of {} of this turn's text; summarise only these bytes]\n{}",
        range.start,
        range.end,
        text.len(),
        &text[range.clone()]
    )
}

/// The turn's entry: each piece summary under the byte range it covers.
fn entry_text(total: usize, summaries: &[(Range<usize>, String)]) -> String {
    let mut entry = format!(
        "[this turn's text is {total} bytes, read in {} pieces; each summary below covers exactly \
         the bytes it names]",
        summaries.len()
    );
    for (range, summary) in summaries {
        let _ = write!(
            entry,
            "\n[bytes {}..{} of {total}] {summary}",
            range.start, range.end
        );
    }
    entry
}

/// The turn's head through `end`, then the marker naming the cut: the kept
/// and the total bytes and tokens.
fn head_text(text: &str, end: usize, total_tokens: u64, head_tokens: u64) -> String {
    format!(
        "{}\n[cut: this turn's text is {} bytes (about {total_tokens} tokens); only bytes 0..{end} \
         (about {head_tokens} tokens) were given]",
        &text[..end],
        text.len()
    )
}

/// The largest end in `start..=limit`, on a char boundary, whose prefix
/// `fits`, backed off to just past the last whitespace of its second half
/// when it ends inside the text, so a piece ends between words. `None` when
/// no end past `start` fits.
fn longest_fit(
    text: &str,
    start: usize,
    limit: usize,
    fits: impl Fn(usize) -> bool,
) -> Option<usize> {
    let limit = floor_boundary(text, limit);
    if limit <= start {
        return None;
    }
    let end = if fits(limit) {
        limit
    } else {
        // `held` fits (or is `start`), `over` does not.
        let (mut held, mut over) = (start, limit);
        while over - held > 1 {
            let mut mid = floor_boundary(text, held + (over - held) / 2);
            if mid <= held {
                match (held + 1..over).find(|at| text.is_char_boundary(*at)) {
                    Some(next) => mid = next,
                    None => break,
                }
            }
            if fits(mid) {
                held = mid;
            } else {
                over = mid;
            }
        }
        held
    };
    if end <= start {
        return None;
    }
    if end == text.len() {
        return Some(end);
    }
    let half = floor_boundary(text, start + (end - start) / 2);
    Some(
        text[half..end]
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_whitespace())
            .map_or(end, |(at, c)| half + at + c.len_utf8()),
    )
}

/// The char boundary at or before `at`.
fn floor_boundary(text: &str, at: usize) -> usize {
    let mut at = at.min(text.len());
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}
