//! A STOP written as a message (FIX 12101). A Slack or LINE counterparty
//! opts out by writing a stop keyword as their whole message; a Slack
//! message may lead with user mentions (`<@U123> stop`). An email sender
//! opts out with a stop keyword as the reply's whole subject, after its
//! `Re:`/`Fwd:` prefixes, or as its whole own text above the quoted block
//! (FIX 12240). The surface-event drain reads the message's words before
//! any dispatcher wakes anyone on it, and a STOP becomes the typed OptOut
//! interaction an adapter or `/v1/core` admits, through the same admission:
//! it holds sends to the sender on the channel from that write, and the comm
//! projector makes it their standing opt-out. The message itself still
//! wakes its actor as any other message does.

use unicode_normalization::UnicodeNormalization;

use crate::Vault;
use crate::channel_identity_provider::{
    EMAIL_CHANNEL, LINE_CHANNEL, SLACK_CHANNEL, is_line_chat_audience_key, line_source_audience_key,
};
use crate::error::{Error, Result};

use super::handoff::admit_surface_event_once_in_txn;
use super::{
    SurfaceCounterpartyStamp, SurfaceEvent, SurfaceEventAction, SurfaceEventDispatchDisposition,
    SurfaceInteractionKind,
};

/// The words that opt a sender out of a channel when they are the whole
/// message: trimmed, NFKC-folded (full-width letters read as ASCII) and
/// compared ignoring ASCII case.
pub const STOP_REPLY_KEYWORDS: &[&str] = &[
    "STOP",
    "STOPALL",
    "UNSUBSCRIBE",
    "CANCEL",
    "END",
    "QUIT",
    "配信停止",
    "停止",
];

/// What the OptOut a STOP message becomes adds to the message's correlation
/// id: one OptOut per message, however often the drain reads it.
const STOP_REPLY_CORRELATION_SUFFIX: &str = ":stop_reply";

/// Where an archived LINE event names the member who wrote it.
const LINE_SOURCE_USER_POINTER: &str = "/event/source/userId";

/// How long a STOP message's dispatch waits before it retries, after a
/// transient failure to admit its OptOut.
const STOP_REPLY_RETRY_BACKOFF_SECS: u64 = 30;

/// Where a Slack user mention token starts: `<@U123>` or `<@U123|name>`.
const SLACK_USER_MENTION_OPEN: &str = "<@";

/// The reply and forward prefixes an email subject may lead with, compared
/// ignoring ASCII case.
const EMAIL_SUBJECT_REPLY_PREFIXES: &[&str] = &["Re:", "Fwd:", "Fw:"];

/// The lines that open the quoted block of an email reply, each read on a
/// trimmed line as (how it starts, how it ends): a `>` quote line, and an
/// `On <date>, <sender> wrote:` attribution, which a client may wrap onto a
/// second line.
const EMAIL_QUOTE_MARKERS: &[(&str, &str)] = &[(">", ""), ("On ", "wrote:")];

/// Whether `text` is one of [`STOP_REPLY_KEYWORDS`] and nothing else.
#[must_use]
pub fn is_stop_reply(text: &str) -> bool {
    let folded: String = text.nfkc().collect();
    let folded = folded.trim();
    STOP_REPLY_KEYWORDS
        .iter()
        .any(|keyword| folded.eq_ignore_ascii_case(keyword))
}

/// A Slack message's text without the user mentions and whitespace that
/// lead it, so `<@U123> stop` and `<@U123|name> stop` read as `stop`. The
/// text from the first word that is not a mention on is kept as written.
fn slack_text_for_stop(text: &str) -> &str {
    let mut rest = text.trim_start();
    while let Some(mention) = rest.strip_prefix(SLACK_USER_MENTION_OPEN) {
        let Some((user, after)) = mention.split_once('>') else {
            break;
        };
        let id = user.split_once('|').map_or(user, |(id, _)| id);
        if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            break;
        }
        rest = after.trim_start();
    }
    rest
}

/// An email's subject without the reply and forward prefixes that lead it,
/// NFKC-folded, so `Re: Fwd: STOP` reads as `STOP`.
fn email_subject_for_stop(subject: &str) -> String {
    let folded: String = subject.nfkc().collect();
    let mut rest = folded.trim_start();
    while let Some(prefix) = EMAIL_SUBJECT_REPLY_PREFIXES.iter().find(|prefix| {
        rest.get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    }) {
        rest = rest[prefix.len()..].trim_start();
    }
    rest.to_owned()
}

/// An email reply's own top text: its body above the first line that opens
/// a quoted block ([`EMAIL_QUOTE_MARKERS`]).
fn email_top_text(body: &str) -> &str {
    let mut at = 0;
    let mut lines = body.split_inclusive('\n').peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        let wrapped = lines.peek().map(|next| next.trim());
        let opens = EMAIL_QUOTE_MARKERS.iter().any(|&(start, end)| {
            trimmed.starts_with(start)
                && (trimmed.ends_with(end) || wrapped.is_some_and(|next| next.ends_with(end)))
        });
        if opens {
            break;
        }
        at += line.len();
    }
    &body[..at]
}

/// Whether the message `payload_ref` archives is a STOP, each text compared
/// whole with [`is_stop_reply`]: a Slack message's text after its leading
/// mentions, a LINE message's text, and an email's subject after its reply
/// prefixes or its own top text.
fn message_is_stop_reply(vault: &Vault, channel: &str, payload_ref: &str) -> Result<bool> {
    if channel == EMAIL_CHANNEL {
        let Some(email) = vault.read_provider_email(payload_ref)? else {
            return Ok(false);
        };
        let subject = email
            .subject
            .as_deref()
            .is_some_and(|subject| is_stop_reply(&email_subject_for_stop(subject)));
        let top_text = email
            .text_body
            .as_deref()
            .is_some_and(|body| is_stop_reply(email_top_text(body)));
        return Ok(subject || top_text);
    }
    let Some(text) = vault.read_provider_event_text(channel, payload_ref)? else {
        return Ok(false);
    };
    let text = if channel == SLACK_CHANNEL {
        slack_text_for_stop(&text)
    } else {
        text.as_str()
    };
    Ok(is_stop_reply(text))
}

/// Admits `event`'s STOP as its sender's OptOut ahead of its dispatch
/// (FIX 12240), whatever dispatcher is installed, so a reply the message
/// wakes is already held. `None` lets the dispatch go on: the message wakes
/// its actor either way, and an opt-out the admission refuses is logged.
/// `Some` is the retry a transient failure to admit it settles on.
pub(super) fn admit_stop_reply_before_dispatch(
    vault: &Vault,
    event: &SurfaceEvent,
    now: u64,
) -> Option<SurfaceEventDispatchDisposition> {
    match admit_stop_reply_opt_out(vault, event, now) {
        Ok(_) => None,
        Err(Error::InvalidConfig(reason)) => {
            tracing::warn!(%reason, "a STOP message's opt-out was refused; the message goes on");
            None
        }
        Err(err) => Some(SurfaceEventDispatchDisposition::Retry {
            backoff_until: now.saturating_add(STOP_REPLY_RETRY_BACKOFF_SECS),
            reason: err.to_string(),
        }),
    }
}

/// Admits the OptOut interaction a STOP message becomes, for `event`'s
/// sender on its channel, beside the message. `false` when `event` is not a
/// message, carries no words the vault holds, is not a STOP, or is a chat
/// message that names no member. A second call for the same message replays
/// the first admission.
fn admit_stop_reply_opt_out(vault: &Vault, event: &SurfaceEvent, now: u64) -> Result<bool> {
    if !matches!(event.action, SurfaceEventAction::Message) {
        return Ok(false);
    }
    let Some(payload_ref) = event.payload_ref.as_deref() else {
        return Ok(false);
    };
    if !message_is_stop_reply(vault, &event.channel, payload_ref)? {
        return Ok(false);
    }
    let Some(sender) = stop_reply_sender(vault, event, payload_ref)? else {
        return Ok(false);
    };
    let mut opt_out = event.clone();
    opt_out.correlation_id = format!("{}{STOP_REPLY_CORRELATION_SUFFIX}", event.correlation_id);
    opt_out.action = SurfaceEventAction::Interaction {
        interaction: SurfaceInteractionKind::OptOut,
        target_ref: None,
        reaction: None,
    };
    if sender != event.counterparty {
        opt_out.source.user_ref = sender.reference_key();
        opt_out.counterparty = sender;
    }
    vault.with_write_txn_grouped(|txn| {
        admit_surface_event_once_in_txn(vault, txn, &opt_out, None, now)
    })?;
    Ok(true)
}

/// Who a STOP message opts out: its party, and for a LINE group or room
/// message the member who wrote it, never the whole chat. `None` for a chat
/// message whose member neither its stamp nor its archived body names.
fn stop_reply_sender(
    vault: &Vault,
    event: &SurfaceEvent,
    payload_ref: &str,
) -> Result<Option<SurfaceCounterpartyStamp>> {
    let chat_party = matches!(
        &event.counterparty,
        SurfaceCounterpartyStamp::Unknown { counterparty_key }
            if event.channel == LINE_CHANNEL && is_line_chat_audience_key(counterparty_key)
    );
    if !chat_party {
        return Ok(Some(event.counterparty.clone()));
    }
    if !is_line_chat_audience_key(&event.source.user_ref) {
        return Ok(Some(SurfaceCounterpartyStamp::unknown(
            event.source.user_ref.clone(),
        )));
    }
    let member = vault
        .read_provider_event(payload_ref)?
        .and_then(|body| serde_json::from_slice::<serde_json::Value>(&body).ok())
        .and_then(|value| {
            value
                .pointer(LINE_SOURCE_USER_POINTER)
                .and_then(serde_json::Value::as_str)
                .and_then(|user| line_source_audience_key(None, Some(user)))
        });
    Ok(member.map(SurfaceCounterpartyStamp::unknown))
}
