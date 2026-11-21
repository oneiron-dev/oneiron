//! The words a call with other people writes into its conversation
//! (UNBUILT-02 PR 3), all in this one place: the owner has not seen them yet,
//! so they change here and nowhere else (Engine, 15 Nov 22:55; the UI
//! session's section 10 of WORDS-FOR-ENGINE.md).

use crate::owner::stamp::rfc3339_secs;

/// The row a call's conversation shows where the call starts.
const CALL_STARTED: &str = "call with {name or number} · {time}";
/// The row it shows where the call ends.
const CALL_ENDED: &str = "call ended · {length}";
/// The divider's `{name or number}` when the caller's number is withheld.
const WITHHELD_NUMBER: &str = "a withheld number";
/// What the other speaker's words are labelled with while no speaker match
/// names them.
pub(crate) const ANOTHER_SPEAKER: &str = "Another speaker";

/// The row where a call with `caller` (its normalised number; `None` when
/// withheld) starts at `started_at` (Unix seconds).
pub(crate) fn call_started(caller: Option<&str>, started_at: u64) -> String {
    CALL_STARTED
        .replace("{name or number}", caller.unwrap_or(WITHHELD_NUMBER))
        .replace("{time}", &clock_minutes(started_at))
}

/// The row where a call that lasted `seconds` ends.
pub(crate) fn call_ended(seconds: u64) -> String {
    CALL_ENDED.replace("{length}", &call_length(seconds))
}

/// `2026-11-16 00:31 UTC`: the call's start to the minute. Each row also
/// carries its own time, which a reader shows in the owner's zone.
fn clock_minutes(unix_seconds: u64) -> String {
    let stamp = rfc3339_secs(unix_seconds);
    let minutes = stamp.get(..16).unwrap_or(&stamp);
    format!("{} UTC", minutes.replacen('T', " ", 1))
}

/// `4:07` under an hour, `1:02:07` from an hour.
fn call_length(seconds: u64) -> String {
    let (hours, minutes, seconds) = (seconds / 3_600, seconds / 60 % 60, seconds % 60);
    if hours == 0 {
        format!("{minutes}:{seconds:02}")
    } else {
        format!("{hours}:{minutes:02}:{seconds:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_divider_rows_fill_their_slots() {
        // 2026-11-16T00:31:00Z
        assert_eq!(
            call_started(Some("+819012345678"), 1_794_789_060),
            "call with +819012345678 · 2026-11-16 00:31 UTC"
        );
        assert_eq!(
            call_started(None, 1_794_789_060),
            "call with a withheld number · 2026-11-16 00:31 UTC"
        );
        assert_eq!(call_ended(247), "call ended · 4:07");
        assert_eq!(call_ended(3_727), "call ended · 1:02:07");
    }
}
