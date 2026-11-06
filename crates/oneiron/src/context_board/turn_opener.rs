//! The now-time turn opener (ARCH-0067 §2: the log closes with a now-time
//! turn opener the model completes; I1 = C turn order: committed history,
//! state-only board, new user message, recalled memories and found skills,
//! opener). The clock sits here, at the very end of the turn, so nothing
//! before it carries the time.
//!
//! A session born from an event opens with the wake variant instead
//! (FIX 15011): the same clock, the event's closed cause and
//! `response="optional"`, a claim-before-speaking frame where silence is a
//! valid outcome. The frame is not the claim: who holds a room's turn is
//! live board state, never a mark inside a turn.
//!
//! Engine-owned protocol text, like the board's wrapper: a structural tag
//! whose leaves are the instant and the cause, never an English sentence.
//! What the wake form asks of the model is stated once, in
//! [`TURN_WAKE_GRAMMAR`], in each surface's stable grammar.

use super::WakeEnvelope;

/// What started a session the wake opener closes: a closed set of
/// engine-derived causes, never read from a briefing or a sender's words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnWake {
    /// A message reached a resident's inbox.
    Inbox,
    /// A reader waits on the agent's review of a read of its diary.
    Review,
    /// A TASK assigned to the agent, or a STREAM wake that names one.
    Task,
    /// A room turn that addresses the agent, or whose thread's open TASK the
    /// agent holds (FIX 15647).
    Room,
    /// A subscribed Slack or LINE message the agent's reply worker answers.
    Channel,
}

impl TurnWake {
    /// The tag's `wake` value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inbox => "inbox",
            Self::Review => "review",
            Self::Task => "task",
            Self::Room => "room",
            Self::Channel => "channel",
        }
    }
}

/// The wake form's protocol, stated once for every stable grammar a woken
/// model reads: the executor's system prompt, the reply worker's engine
/// lines and the MCP setup instructions. The tag carries none of it.
pub const TURN_WAKE_GRAMMAR: &str = "A turn that an event started closes with \
<turn now=\"…\" wake=\"…\" response=\"optional\"/>; wake names the event: inbox, review, task, \
room or channel. Read the live state first. To answer in a room, take the eligible claim first \
(rooms.claim, or the turn an accepted offer binds). HeldBy or NotAddressed means no ordinary \
room reply. response=\"optional\" is about speech only: no room output and an empty channel \
reply are valid completions.";

/// The opener line for a turn admitted at `now_ms`, wall milliseconds from
/// the vault's own clock: the instant in UTC to the second.
#[must_use]
pub fn turn_opener_line(now_ms: u64) -> String {
    format!("<turn now=\"{}\"/>", utc_second(now_ms))
}

/// The wake opener for a session `wake` started, sampled at `now_ms` at
/// the call's final boundary: the ordinary opener's clock, its cause and
/// the optional response.
#[must_use]
pub fn turn_wake_line(now_ms: u64, wake: TurnWake) -> String {
    format!(
        "<turn now=\"{}\" wake=\"{}\" response=\"optional\"/>",
        utc_second(now_ms),
        wake.as_str()
    )
}

/// The wake opener for one delivered batch of STREAM wakes, rendered when
/// the batch is handed over, never stored with its notices. A batch that
/// names a TASK is a task wake; else one that names a room turn is a room
/// wake (FIX 15647); one of reviews only is a review wake; an empty batch
/// has none.
#[must_use]
pub fn wake_batch_opener(wakes: &[WakeEnvelope], now_ms: u64) -> Option<String> {
    if wakes.is_empty() {
        return None;
    }
    let wake = if wakes
        .iter()
        .any(|wake| wake.review_ref.is_none() && wake.room_ref.is_none())
    {
        TurnWake::Task
    } else if wakes.iter().any(|wake| wake.room_ref.is_some()) {
        TurnWake::Room
    } else {
        TurnWake::Review
    };
    Some(turn_wake_line(now_ms, wake))
}

/// `now_ms` in UTC to the second, RFC 3339 with a `Z` suffix.
fn utc_second(now_ms: u64) -> String {
    let seconds = i64::try_from(now_ms / 1_000).unwrap_or(i64::MAX);
    chrono::DateTime::from_timestamp(seconds, 0).map_or_else(
        || "1970-01-01T00:00:00Z".to_owned(),
        |stamp| stamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    )
}

/// Whether `text` is one opener line exactly as [`turn_opener_line`]
/// renders it: `<turn now="…"/>` around an RFC 3339 instant.
#[must_use]
pub fn is_turn_opener_line(text: &str) -> bool {
    text.strip_prefix("<turn now=\"")
        .and_then(|rest| rest.strip_suffix("\"/>"))
        .is_some_and(|now| chrono::DateTime::parse_from_rfc3339(now).is_ok())
}
