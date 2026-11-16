//! The words a call with other people writes into its conversation
//! (UNBUILT-02 PR 3), and the line the agent opens it with (PR 3B), all in
//! this one place: the owner has not seen them yet, so they change here and
//! nowhere else (Engine, 15 Nov 22:55; the UI session's section 10 of
//! WORDS-FOR-ENGINE.md).
//!
//! A room call with other people writes its own line after its start row
//! (UNBUILT-02 PR 4): the room line is written, not spoken, and only in a
//! call with other people.
//!
//! A call the agent places itself will open with "Hello, this is {agent},
//! calling for {owner}. This call is transcribed."; no call is placed yet,
//! so that line joins the code with the first one that is.

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
/// The line a room call with other people writes after its start row, when
/// the owner's `voice.call_transcripts.announce` is on (UNBUILT-02 PR 4).
const ROOM_ANNOUNCEMENT: &str = "This call is transcribed, like the rest of this room.";
/// The divider's `{name or number}` when a room call names no other member.
const ROOM_WITHOUT_NAMES: &str = "the room";
/// How many other members a room call's start row names before it counts
/// the rest.
const MAX_DIVIDER_NAMES: usize = 3;
/// What the agent says first on a call it answered, when the owner's
/// `voice.call_transcripts.announce` is on.
const ANSWERED_ANNOUNCEMENT: &str =
    "Hello, this is {agent}, {owner}'s assistant. This call is transcribed.";
/// The same line when the vault names no owner.
const ANSWERED_ANNOUNCEMENT_UNNAMED_OWNER: &str =
    "Hello, this is {agent}, an assistant. This call is transcribed.";

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

/// What the agent `agent` (its display name) says first on a call it
/// answered for `owner` (the owner's display name; `None` when the vault
/// names none).
pub(crate) fn answered_announcement(agent: &str, owner: Option<&str>) -> String {
    match owner {
        Some(owner) => ANSWERED_ANNOUNCEMENT
            .replace("{agent}", agent)
            .replace("{owner}", owner),
        None => ANSWERED_ANNOUNCEMENT_UNNAMED_OWNER.replace("{agent}", agent),
    }
}

/// The line a room call with other people writes after its start row: the
/// room line is written, not spoken, and only in a call with other people.
pub(crate) fn room_announcement() -> String {
    ROOM_ANNOUNCEMENT.to_owned()
}

/// What the `ordinal`th unplaced speaker's words are labelled with, by
/// first-heard order in the call: the first is "Another speaker", the next
/// "Another speaker 2", and so on. Zero names the first, as one does.
pub(crate) fn another_speaker(ordinal: usize) -> String {
    if ordinal <= 1 {
        ANOTHER_SPEAKER.to_owned()
    } else {
        format!("{ANOTHER_SPEAKER} {ordinal}")
    }
}

/// The row where a room call with `names` starts at `started_at` (Unix
/// seconds): the room's other members by name, at most three, then how many
/// more, or the room when none read.
pub(crate) fn room_call_started(names: &[String], started_at: u64) -> String {
    let who = match names {
        [] => ROOM_WITHOUT_NAMES.to_owned(),
        [one] => one.clone(),
        [one, two] => format!("{one} and {two}"),
        [one, two, three] => format!("{one}, {two} and {three}"),
        _ => {
            let head = names[..MAX_DIVIDER_NAMES].join(", ");
            let more = names.len() - MAX_DIVIDER_NAMES;
            format!("{head} and {more} more")
        }
    };
    CALL_STARTED
        .replace("{name or number}", &who)
        .replace("{time}", &clock_minutes(started_at))
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

    #[test]
    fn the_announcement_names_the_agent_and_its_owner() {
        assert_eq!(
            answered_announcement("Eiri", Some("Alex")),
            "Hello, this is Eiri, Alex's assistant. This call is transcribed."
        );
        assert_eq!(
            answered_announcement("Eiri", None),
            "Hello, this is Eiri, an assistant. This call is transcribed."
        );
    }

    #[test]
    fn the_room_line_is_written_not_spoken() {
        assert_eq!(
            room_announcement(),
            "This call is transcribed, like the rest of this room."
        );
    }

    #[test]
    fn unplaced_speakers_number_by_first_heard() {
        assert_eq!(another_speaker(0), "Another speaker");
        assert_eq!(another_speaker(1), "Another speaker");
        assert_eq!(another_speaker(2), "Another speaker 2");
        assert_eq!(another_speaker(3), "Another speaker 3");
    }

    #[test]
    fn the_room_divider_names_the_rooms_other_members() {
        // 2026-11-16T00:31:00Z
        let at = 1_794_789_060;
        assert_eq!(
            room_call_started(&[], at),
            "call with the room · 2026-11-16 00:31 UTC"
        );
        assert_eq!(
            room_call_started(&["A".to_owned()], at),
            "call with A · 2026-11-16 00:31 UTC"
        );
        assert_eq!(
            room_call_started(&["A".to_owned(), "B".to_owned()], at),
            "call with A and B · 2026-11-16 00:31 UTC"
        );
        assert_eq!(
            room_call_started(&["A".to_owned(), "B".to_owned(), "C".to_owned()], at),
            "call with A, B and C · 2026-11-16 00:31 UTC"
        );
        assert_eq!(
            room_call_started(
                &[
                    "A".to_owned(),
                    "B".to_owned(),
                    "C".to_owned(),
                    "D".to_owned(),
                ],
                at,
            ),
            "call with A, B, C and 1 more · 2026-11-16 00:31 UTC"
        );
    }
}
