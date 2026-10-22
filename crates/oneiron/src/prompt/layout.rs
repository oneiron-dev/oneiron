//! Where one fresh turn's context goes, by the layout resolved once for that
//! turn (FIX 9442, FIX 9443).
//!
//! [`PromptLayout::EarlySystem`] keeps a turn's context where its assembler
//! always put it. [`PromptLayout::StableHistoryThenTurnContext`] puts it,
//! already rendered, in one request-only message right before the latest
//! user turn ([`place_turn_context`]), after the stable instructions and the
//! append-only history. Activated memory keeps its heading and every block,
//! already fenced and attributed by its own renderer, in order, in either
//! place ([`render_activated_memory`]): nothing is fenced twice and no
//! accepted block is refused. An exact saved request sent again is never
//! laid out anew; this is for fresh assembly only.

use super::{PromptLayout, place_turn_context};
use crate::LlmMessage;

/// The heading activated memory rides under, in the system text or in the
/// turn's context.
pub(super) const ACTIVATED_MEMORY_HEADING: &str = "# Activated Memory";

/// A turn's activated memory as one text: its heading, then each nonempty
/// block, trimmed, in order, each ending its own line, as the system text
/// has always carried it. `None` when every block is empty. Nothing is
/// added around a block.
#[must_use]
pub fn render_activated_memory<S: AsRef<str>>(blocks: &[S]) -> Option<String> {
    let mut text = String::new();
    for block in blocks
        .iter()
        .map(|block| block.as_ref().trim())
        .filter(|block| !block.is_empty())
    {
        if text.is_empty() {
            text.push_str(ACTIVATED_MEMORY_HEADING);
            text.push_str("\n\n");
        }
        text.push_str(block);
        text.push('\n');
    }
    (!text.is_empty()).then_some(text)
}

/// Places a fresh turn's already-rendered context `blocks` in `messages` as
/// `layout`, read once for the turn, says. Under the stable layout they are
/// the turn's context message ([`place_turn_context`]) and where it went is
/// returned; under the early layout nothing moves, `None` is returned, and
/// the caller keeps its blocks where it always put them.
pub fn place_context_for_layout<S: AsRef<str>>(
    messages: &mut Vec<LlmMessage>,
    layout: PromptLayout,
    blocks: &[S],
) -> Option<usize> {
    match layout {
        PromptLayout::EarlySystem => None,
        PromptLayout::StableHistoryThenTurnContext => place_turn_context(messages, blocks),
    }
}
