//! The now-time turn opener (ARCH-0067 §2: the log closes with a now-time
//! turn opener the model completes; I1 = C turn order: committed history,
//! state-only board, new user message, recalled memories and found skills,
//! opener). The clock sits here, at the very end of the turn, so nothing
//! before it carries the time.
//!
//! Engine-owned protocol text, like the board's wrapper: a structural tag
//! whose one leaf is the instant, never an English sentence.

/// The opener line for a turn admitted at `now_ms`, wall milliseconds from
/// the vault's own clock: the instant in UTC to the second.
#[must_use]
pub fn turn_opener_line(now_ms: u64) -> String {
    let seconds = i64::try_from(now_ms / 1_000).unwrap_or(i64::MAX);
    let now = chrono::DateTime::from_timestamp(seconds, 0).map_or_else(
        || "1970-01-01T00:00:00Z".to_owned(),
        |stamp| stamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    );
    format!("<turn now=\"{now}\"/>")
}

/// Whether `text` is one opener line exactly as [`turn_opener_line`]
/// renders it: `<turn now="…"/>` around an RFC 3339 instant.
#[must_use]
pub fn is_turn_opener_line(text: &str) -> bool {
    text.strip_prefix("<turn now=\"")
        .and_then(|rest| rest.strip_suffix("\"/>"))
        .is_some_and(|now| chrono::DateTime::parse_from_rfc3339(now).is_ok())
}
