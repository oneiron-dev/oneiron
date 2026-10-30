//! What a conversation's page text shows of a sent message (FIX 12329). The
//! installed LinkedIn connector's `get_conversation` returns its thread as
//! page text, one turn per sender, each headed by the sender's name and a
//! time label, and names no message ids. Every match compares
//! whitespace-normalised lines ([`normalize_whitespace`]).

use serde_json::Value;

use super::connector_call_transport::{LINKEDIN_MEMBER_KEY_PREFIX, profile_member};
use super::conversation_parse::looks_like_linkedin_time;
use super::inbox_sync::mcp_payload;
use super::normalize_keys::{
    first_conversation_thread_id, optional_section_text, section_references,
    thread_id_from_payload_url,
};
use super::verified_send::{LinkedInVerifiedSendPlan, normalize_whitespace};

/// One sender turn of a page: the name heading it, when the page shows one,
/// and its lines after the time label.
struct SenderTurn {
    sender: Option<String>,
    lines: Vec<String>,
}

/// How often the page text of `plan`'s thread in `output` shows its message
/// in a turn that is not the counterparty's. A turn headed by a name a
/// conversation link carries, other than the seat `self_key`'s own profile
/// link, is the counterparty's, however its words read: the recipient can
/// write the same words. `None` when `output` is no page text of that
/// thread; a structured transcript is none.
pub(super) fn page_text_occurrences(
    output: &Value,
    plan: &LinkedInVerifiedSendPlan,
    self_key: &str,
) -> Option<usize> {
    let expected_thread_id = plan.thread_id.as_str();
    let payload = mcp_payload(output).ok()?;
    if payload.get("messages").is_some() {
        return None;
    }
    let observed_thread_id = match thread_id_from_payload_url(&payload).ok()? {
        Some(thread_id) => thread_id,
        None => first_conversation_thread_id(&section_references(&payload, "conversation"))
            .ok()?
            .unwrap_or_else(|| expected_thread_id.to_owned()),
    };
    if observed_thread_id != expected_thread_id {
        return None;
    }
    let page = optional_section_text(&payload, "conversation").ok()??;
    let (_, counterparties) = conversation_link_names(&payload, self_key);
    Some(
        sender_turns(page)
            .into_iter()
            .filter(|turn| {
                turn.sender
                    .as_deref()
                    .is_none_or(|sender| !matches_any_name(&counterparties, sender))
            })
            .map(|turn| {
                conversation_message_occurrence_count(&turn.lines.join("\n"), &plan.message_text)
            })
            .sum(),
    )
}

/// The names the page's conversation links carry, split by whom they link
/// to: first those of links to the seat `self_key`'s own profile, the names
/// the seat's own turns are headed by; then every other, the names a turn
/// of another member is headed by.
pub(super) fn conversation_link_names(
    payload: &Value,
    self_key: &str,
) -> (Vec<String>, Vec<String>) {
    let own_member = self_key
        .strip_prefix(LINKEDIN_MEMBER_KEY_PREFIX)
        .unwrap_or(self_key);
    let mut seat = Vec::new();
    let mut others = Vec::new();
    for reference in section_references(payload, "conversation") {
        let Some(name) = reference
            .get("text")
            .and_then(Value::as_str)
            .map(normalize_whitespace)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        let links_to_seat = reference
            .get("url")
            .and_then(Value::as_str)
            .and_then(profile_member)
            .is_some_and(|member| member.eq_ignore_ascii_case(own_member));
        if links_to_seat {
            seat.push(name);
        } else {
            others.push(name);
        }
    }
    (seat, others)
}

/// Whether `sender`, a turn's heading, is one of `names`.
pub(super) fn matches_any_name(names: &[String], sender: &str) -> bool {
    let sender = normalize_whitespace(sender);
    names.iter().any(|name| name.eq_ignore_ascii_case(&sender))
}

/// A page's sender turns in page order. A line followed by a time label
/// heads a turn; lines before the first heading are a turn with no sender.
fn sender_turns(page: &str) -> Vec<SenderTurn> {
    let lines = page
        .lines()
        .map(normalize_whitespace)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let mut turns = vec![SenderTurn {
        sender: None,
        lines: Vec::new(),
    }];
    let mut index = 0;
    while index < lines.len() {
        if index + 1 < lines.len() && looks_like_linkedin_time(&lines[index + 1]) {
            turns.push(SenderTurn {
                sender: Some(lines[index].clone()),
                lines: Vec::new(),
            });
            index += 2;
            continue;
        }
        if let Some(turn) = turns.last_mut() {
            turn.lines.push(lines[index].clone());
        }
        index += 1;
    }
    turns
}

pub(super) fn conversation_message_occurrence_count(
    conversation_text: &str,
    message_text: &str,
) -> usize {
    let message = normalize_whitespace(message_text);
    if message.is_empty() {
        return 0;
    }
    let conversation_lines = conversation_text
        .lines()
        .map(normalize_whitespace)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if conversation_lines.is_empty() {
        return 0;
    }
    let message_line_count = message_text
        .lines()
        .map(normalize_whitespace)
        .filter(|line| !line.is_empty())
        .count()
        .max(1);
    if message_line_count > conversation_lines.len() {
        return 0;
    }
    conversation_lines
        .windows(message_line_count)
        .filter(|window| normalize_whitespace(&window.join(" ")) == message)
        .count()
}

pub(super) fn conversation_ends_with_message(conversation_text: &str, message_text: &str) -> bool {
    let message = normalize_whitespace(message_text);
    if message.is_empty() {
        return false;
    }
    let conversation_lines = conversation_text
        .lines()
        .map(normalize_whitespace)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let message_line_count = message_text
        .lines()
        .map(normalize_whitespace)
        .filter(|line| !line.is_empty())
        .count()
        .max(1);
    if message_line_count > conversation_lines.len() {
        return false;
    }
    let tail = conversation_lines[conversation_lines.len() - message_line_count..].join(" ");
    normalize_whitespace(&tail) == message
}
