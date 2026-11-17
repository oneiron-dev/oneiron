//! The drafting model's reply, read against the request it answers.
//!
//! The contract: one JSON object, `{"follow_ups": [{"recipient": "P<n>",
//! "text": "...", "evidence_turn_refs": ["T<n>", ...]}, ...]}`. Labels are
//! the call's own, never ids: each binds back to the row the request showed
//! under it, and a label the request did not show binds nothing.

use serde_json::Value;

use super::MEETING_FOLLOW_UP_MAX_DRAFTS;
use super::source::MeetingFollowUpSource;
use crate::calendar::follow_up::{MEETING_FOLLOW_UP_TEXT_MAX_BYTES, MeetingFollowUpDraft};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

const KEY_FOLLOW_UPS: &str = "follow_ups";
const KEY_RECIPIENT: &str = "recipient";
const KEY_TEXT: &str = "text";
const KEY_EVIDENCE: &str = "evidence_turn_refs";

/// The drafts `reply` asks for, in reply order, at most
/// [`MEETING_FOLLOW_UP_MAX_DRAFTS`]. An item that cannot be read as a draft
/// of the owner's is skipped: a recipient label the request did not list,
/// words that are empty or past [`MEETING_FOLLOW_UP_TEXT_MAX_BYTES`] (never
/// cut), no cited TURN label the request showed, or no cited TURN of the
/// owner's.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when `reply` is not one JSON object with a
/// `follow_ups` array.
pub(super) fn decode_reply(
    source: &MeetingFollowUpSource,
    reply: &str,
) -> Result<Vec<MeetingFollowUpDraft>> {
    let reply: Value = serde_json::from_str(unfenced(reply)).map_err(|_| not_contract())?;
    let items = reply
        .get(KEY_FOLLOW_UPS)
        .and_then(Value::as_array)
        .ok_or_else(not_contract)?;
    Ok(items
        .iter()
        .filter_map(|item| read_item(source, item))
        .take(MEETING_FOLLOW_UP_MAX_DRAFTS)
        .collect())
}

fn not_contract() -> Error {
    Error::InvalidClaimBody("meeting follow-up reply is not the reply contract")
}

/// `reply` without one surrounding Markdown code fence, when it has one.
fn unfenced(reply: &str) -> &str {
    let reply = reply.trim();
    let Some(inner) = reply
        .strip_prefix("```")
        .and_then(|rest| rest.strip_suffix("```"))
    else {
        return reply;
    };
    // The fence's info string ("json") runs to the first line break.
    inner
        .split_once('\n')
        .map_or(inner, |(_, body)| body)
        .trim()
}

fn read_item(source: &MeetingFollowUpSource, item: &Value) -> Option<MeetingFollowUpDraft> {
    let recipient = item
        .get(KEY_RECIPIENT)
        .and_then(Value::as_str)
        .and_then(|label| bound(label, 'P', &source.recipient_refs))?;
    let text = item.get(KEY_TEXT).and_then(Value::as_str)?.trim();
    if text.is_empty() || text.len() > MEETING_FOLLOW_UP_TEXT_MAX_BYTES {
        return None;
    }
    let mut turn_refs = Vec::new();
    let mut cites_owner = false;
    for label in item.get(KEY_EVIDENCE)?.as_array()? {
        let Some(label) = label.as_str() else {
            continue;
        };
        let Some(index) = label_index(label, 'T', source.turn_refs.len()) else {
            continue;
        };
        let turn = source.turn_refs[index];
        if turn_refs.contains(&turn) {
            continue;
        }
        cites_owner |= source.request.turns[index].owner;
        turn_refs.push(turn);
    }
    if turn_refs.is_empty() || !cites_owner {
        return None;
    }
    Some(MeetingFollowUpDraft {
        session_ref: source.session_ref,
        recipient,
        text: text.to_owned(),
        turn_refs,
    })
}

/// The row `label` stands for among `rows`, when the request showed it.
fn bound(label: &str, prefix: char, rows: &[EntityId]) -> Option<EntityId> {
    label_index(label, prefix, rows.len()).map(|index| rows[index])
}

/// The zero-based index `<prefix><n>` names, for `n` in `1..=len`.
fn label_index(label: &str, prefix: char, len: usize) -> Option<usize> {
    let digits = label.trim().strip_prefix(prefix)?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let number: usize = digits.parse().ok()?;
    number.checked_sub(1).filter(|index| *index < len)
}
