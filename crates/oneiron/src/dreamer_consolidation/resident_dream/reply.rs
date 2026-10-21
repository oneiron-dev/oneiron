//! What a resident's dreaming reply must hold to land: a diary entry. The
//! step's check and the landing read it alike, so they cannot disagree
//! (FIX 7431).

use crate::actor_claims::ResidentCraftCandidate;
use crate::llm::LlmResponse;

/// Why a dreaming reply is refused: it holds no diary entry.
const EMPTY_ENTRY: &str = "the model wrote an empty diary entry";

/// A dreaming reply's diary entry and the craft notes it proposes; refused
/// when the entry is empty.
pub(super) fn diary_entry(
    response: &LlmResponse,
) -> Result<(String, Vec<ResidentCraftCandidate>), &'static str> {
    let reply = super::super::step_charge::reply_text(response);
    let (entry, craft) = super::split_craft_notes(reply.trim());
    if entry.is_empty() {
        Err(EMPTY_ENTRY)
    } else {
        Ok((entry.to_owned(), craft))
    }
}

/// The step's check on a dreaming reply: an empty entry is refused inside
/// the step, paid and never memoized, so its Retry asks again.
pub(super) fn check_diary_reply(response: &LlmResponse) -> Result<(), String> {
    diary_entry(response).map(|_| ()).map_err(str::to_owned)
}
