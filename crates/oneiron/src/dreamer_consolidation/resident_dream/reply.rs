//! What a resident's dreaming reply must hold to land: a diary entry. The
//! step's check and the landing read it alike, so they cannot disagree
//! (FIX 7431).

use serde::Deserialize;

use crate::actor_claims::ResidentCraftCandidate;
use crate::llm::LlmResponse;

/// Why a dreaming reply is refused: it holds no diary entry.
const EMPTY_ENTRY: &str = "the model wrote an empty diary entry";
/// The fence that opens a dreaming reply's ask for another round of its own
/// time (FIX 7763): the free-time fence, as the for-human reply's.
const ROUND_FENCE: &str = "```oneiron-free-time";

/// A dreaming reply's diary entry, the craft notes it proposes and whether
/// it asks for another round of its own time; refused when the entry is
/// empty.
pub(super) struct DreamReply {
    pub(super) entry: String,
    pub(super) craft: Vec<ResidentCraftCandidate>,
    pub(super) another_round: bool,
}

/// A dreaming reply's diary entry and the craft notes it proposes; refused
/// when the entry is empty.
pub(super) fn diary_entry(response: &LlmResponse) -> Result<DreamReply, &'static str> {
    let reply = super::super::step_charge::reply_text(response);
    let (reply, another_round) = split_round_ask(reply.trim());
    let (entry, craft) = super::split_craft_notes(&reply);
    if entry.is_empty() {
        Err(EMPTY_ENTRY)
    } else {
        Ok(DreamReply {
            entry: entry.to_owned(),
            craft,
            another_round,
        })
    }
}

/// The step's check on a dreaming reply: an empty entry is refused inside
/// the step, paid and never memoized, so its Retry asks again.
pub(super) fn check_diary_reply(response: &LlmResponse) -> Result<(), String> {
    diary_entry(response).map(|_| ()).map_err(str::to_owned)
}

/// A reply without its round ask, and whether it asked for another round:
/// the first ```oneiron-free-time block, before or after the craft block,
/// is cut out whatever it holds, and only `{"another_round": true}` asks.
fn split_round_ask(reply: &str) -> (String, bool) {
    #[derive(Deserialize)]
    struct RoundBlock {
        #[serde(default)]
        another_round: bool,
    }
    let Some(start) = reply.find(ROUND_FENCE) else {
        return (reply.to_owned(), false);
    };
    let body = start + ROUND_FENCE.len();
    let Some(len) = reply[body..].find("```") else {
        return (reply.to_owned(), false);
    };
    let another_round = serde_json::from_str::<RoundBlock>(reply[body..body + len].trim())
        .is_ok_and(|block| block.another_round);
    let rest = format!(
        "{}\n{}",
        reply[..start].trim_end(),
        reply[body + len + 3..].trim_start()
    );
    (rest.trim().to_owned(), another_round)
}
