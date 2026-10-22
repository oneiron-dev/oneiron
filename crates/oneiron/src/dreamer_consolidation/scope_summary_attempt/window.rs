//! What one summary call may hold on its model (FIX 7509 P7b, shared with
//! the Arc's parts in PR3): the window the host counts, how a framed call
//! is counted (its whole serialized request, once: FIX 8286), and the
//! deterministic tiling of a text too big for a call.
//! A sitting's pages and an Arc's children each frame their own calls on
//! these; neither changes the other.

use super::ScopeSummaryExecutor;
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::dreamer_consolidation::turn_text::TurnText;
use crate::error::Result;
use crate::{EntityId, Vault};
use std::collections::BTreeMap;

impl<E> ScopeSummaryExecutor<'_, E> {
    /// The tokens one call's input may fill on the model: the host's count,
    /// else the vault's own row for the model, its context less the output
    /// it reserves where that is below it, as the host counts. `None` when
    /// neither is known: a zero context, or a row that did not read.
    pub(super) fn session_window(&self, vault: &Vault) -> Option<u64> {
        if let Some(window) = self.window_tokens.filter(|window| *window > 0) {
            return Some(window);
        }
        let row = match vault.model_registry_row(&self.model) {
            Ok(row) => row?,
            Err(error) => {
                tracing::warn!(
                    model = %self.model,
                    %error,
                    "a session summary's model row did not read; its window is unknown"
                );
                return None;
            }
        };
        let context = row.catalog.context_window_tokens;
        if context == 0 {
            return None;
        }
        let output = row
            .catalog
            .max_output_tokens
            .filter(|output| *output < context)
            .unwrap_or(0);
        Some(context - output)
    }
}

/// The tokens a call costs as framed (FIX 8286): its complete request as
/// the model reads it, the instruction, the input as sent and the output
/// contract as serialized, joined in that order into one text and counted
/// once as a resident's window counts, never as separately counted pieces
/// summed.
pub(super) fn framed_tokens(
    instruction: &str,
    user: &str,
    schema: &serde_json::Value,
) -> Result<u64> {
    let schema = serde_json::to_string(schema)
        .map_err(|_| invalid_consolidation("summary policy did not encode"))?;
    Ok(tokens(&[instruction, user, schema.as_str()].join("\n")))
}

/// The ranges `words` is cut into, in order, each one `fits` admits: runs
/// of whole `units` (byte ranges of `words`, in order) first, and a unit
/// alone too big for one cut at characters. `fits` reads the 0-based index
/// of the range it sizes and the slice it would hold. A range holds whole
/// units or one unit's characters; bytes between two units are in none.
/// `None` when not even one character's range fits, or there is no unit.
pub(super) fn tile(
    words: &str,
    units: &[(usize, usize)],
    mut fits: impl FnMut(usize, &str) -> Result<bool>,
) -> Result<Option<Vec<(usize, usize)>>> {
    let mut ranges = Vec::new();
    let mut next = 0;
    while let Some(&(start, _)) = units.get(next) {
        let index = ranges.len();
        let run = longest_fit(units.len() - next, |run| {
            fits(index, &words[start..units[next + run - 1].1])
        })?;
        if run > 0 {
            ranges.push((start, units[next + run - 1].1));
            next += run;
            continue;
        }
        // One unit alone fits no empty range: it is cut at characters.
        let (mut at, end) = units[next];
        while at < end {
            let index = ranges.len();
            let bytes = longest_fit(end - at, |bytes| {
                let cut = words.floor_char_boundary(at + bytes);
                // A prefix short of one character holds none, so fits.
                Ok(cut == at || fits(index, &words[at..cut])?)
            })?;
            let cut = words.floor_char_boundary(at + bytes);
            if cut == at {
                return Ok(None);
            }
            ranges.push((at, cut));
            at = cut;
        }
        next += 1;
    }
    Ok((!ranges.is_empty()).then_some(ranges))
}

/// Each MESSAGE of a projected TURN that holds words, as its byte range in
/// the TURN's text, in projection order: from each MESSAGE's whole span and
/// the `"\n"` that joins one MESSAGE to the next. An empty MESSAGE holds
/// none.
pub(super) fn message_ranges(text: &TurnText, words: &str) -> Result<Vec<(usize, usize)>> {
    let lengths: BTreeMap<EntityId, usize> = text
        .spans(None)?
        .into_iter()
        .map(|span| (span.message, span.end - span.start))
        .collect();
    let mut ranges = Vec::new();
    let mut offset = 0_usize;
    for (index, message) in text.projection().into_iter().enumerate() {
        if index != 0 {
            offset += 1;
        }
        let len = lengths.get(&message).copied().unwrap_or(0);
        if len != 0 {
            ranges.push((offset, offset + len));
        }
        offset += len;
    }
    if offset != words.len() {
        return Err(invalid_consolidation(
            "a projected turn's messages do not tile its text",
        ));
    }
    Ok(ranges)
}

/// The largest `n` in `1..=max` that `fits`, or 0 when 1 does not: doubling
/// from 1 to the first `n` that does not fit, then halving the gap below it.
fn longest_fit(max: usize, mut fits: impl FnMut(usize) -> Result<bool>) -> Result<usize> {
    let (mut good, mut bad) = (0, max.saturating_add(1));
    let mut probe = 1;
    while probe < bad {
        if fits(probe)? {
            good = probe;
            probe = if probe == max {
                bad
            } else {
                probe.saturating_mul(2).min(max)
            };
        } else {
            bad = probe;
        }
    }
    while bad - good > 1 {
        let mid = good + (bad - good) / 2;
        if fits(mid)? {
            good = mid;
        } else {
            bad = mid;
        }
    }
    Ok(good)
}

/// The tokens `rendered` costs where a call carries it, inside one of its
/// JSON input strings: counted over its escaping, without the quotes.
pub(super) fn escaped_cost(rendered: &str) -> Result<u64> {
    let escaped = serde_json::to_string(rendered)
        .map_err(|_| invalid_consolidation("summary input encoding"))?;
    let inner = escaped
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(&escaped);
    Ok(tokens(inner))
}

/// The tokens `text` counts, as a resident's window counts them.
fn tokens(text: &str) -> u64 {
    crate::count_context_pack_tokens(text) as u64
}
