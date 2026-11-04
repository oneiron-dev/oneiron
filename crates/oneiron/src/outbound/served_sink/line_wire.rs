//! LINE's wire spellings for the served sink: the text cut to LINE's limit,
//! where a push goes, whose chat an archived event was written in, its
//! reply token while fresh, and the retry key of one logical send.

use super::{
    LINE_GROUP_TARGET_PREFIX, LINE_MAX_TEXT_UNITS, LINE_REPLY_TOKEN_FRESH_SECS,
    LINE_ROOM_TARGET_PREFIX, LINE_USER_TARGET_PREFIX,
};
use crate::channel_identity_provider::{LineChat, LineChatKind, line_source_audience_key};

/// A send's text cut to LINE's text-message limit, whole characters only.
pub(super) fn line_text(text: &str) -> String {
    let mut units = 0;
    text.chars()
        .take_while(|c| {
            units += c.len_utf16();
            units <= LINE_MAX_TEXT_UNITS
        })
        .collect()
}

/// Where a LINE push goes: the target's user (`line:user:<id>`), group
/// (`line:group:<id>`), room (`line:room:<id>`) or bare LINE id. `None` for
/// a target LINE cannot address. A push never takes its chat from an
/// answered event: that event answers only the audience that is the target
/// (FIX 10809), and a fresh reply token already answers in its chat.
pub(super) fn line_destination(target: &str) -> Option<String> {
    let to = [
        LINE_USER_TARGET_PREFIX,
        LINE_GROUP_TARGET_PREFIX,
        LINE_ROOM_TARGET_PREFIX,
    ]
    .iter()
    .find_map(|prefix| target.strip_prefix(prefix))
    .unwrap_or(target);
    (!to.is_empty() && !to.contains(':')).then(|| to.to_owned())
}

/// The audience of an archived LINE event, normalized and spelled by
/// [`line_source_audience_key`] as intake spelled the reply target: the
/// group or room it was written in, else its sender.
pub(super) fn line_archived_audience(answered: &serde_json::Value) -> Option<String> {
    let source = answered.pointer("/event/source")?;
    let chat = source
        .get("type")
        .and_then(serde_json::Value::as_str)
        .and_then(LineChatKind::parse)
        .and_then(|kind| Some(LineChat::new(kind, source.get(kind.id_field())?.as_str()?)));
    let user = source.get("userId").and_then(serde_json::Value::as_str);
    line_source_audience_key(chat.as_ref(), user)
}

/// The reply token an archived LINE event carries, while the event is
/// younger than [`LINE_REPLY_TOKEN_FRESH_SECS`] by its own `timestamp` (ms).
pub(super) fn fresh_line_reply_token(value: &serde_json::Value, now: u64) -> Option<String> {
    let token = value.pointer("/event/replyToken")?.as_str()?.trim();
    let at = value.pointer("/event/timestamp")?.as_u64()? / 1000;
    (!token.is_empty() && now.saturating_sub(at) < LINE_REPLY_TOKEN_FRESH_SECS)
        .then(|| token.to_owned())
}

/// LINE's retry key for one logical send: a UUID derived from its stable
/// idempotency key, so a retried push carries the same key and LINE sends
/// it once.
pub(super) fn line_retry_key(idempotency_key: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.line-retry-key.v1\0");
    hasher.update(idempotency_key.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    // An RFC 4122 version-4 shape: LINE takes any UUID in hex form.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}
