//! The `{at}:{id}` cursor (UC-13 PR 1): written byte for byte as the mail
//! inbox and the conversation transcript wrote it, and read back from the
//! same texts their own parsers took.

use oneiron_contracts::EntityId;
use oneiron_contracts::cursor_text::{join_at_id, split_at_id};

const ID: &str = "0123456789abcdef0123456789abcdef";

fn id() -> EntityId {
    EntityId::from_hex(ID).expect("a valid entity id")
}

/// The inbox's parser before UC-13 (`mail_pack/inbox.rs` `parse_cursor`).
fn inbox_parser(cursor: &str) -> Option<(u64, EntityId)> {
    let (at, turn) = cursor.split_once(':')?;
    let at = at.parse::<u64>().ok()?;
    let turn = EntityId::from_hex(turn).ok()?;
    Some((at, turn))
}

/// The transcript's parser before UC-13 (`memory/transcript.rs` `parse_cursor`).
fn transcript_parser(cursor: &str) -> Option<(u64, EntityId)> {
    cursor
        .split_once(':')
        .and_then(|(at, id)| Some((at.parse().ok()?, EntityId::from_hex(id).ok()?)))
}

/// Each cursor text, and whether the inbox and transcript took it.
fn table() -> Vec<(String, bool)> {
    let upper = ID.to_uppercase();
    vec![
        (format!("1700000000:{ID}"), true),
        (format!("0:{ID}"), true),
        (format!("{}:{ID}", u64::MAX), true),
        (format!("1700000000:{upper}"), true),
        (
            "1700000000:0123456789ABCDEF0123456789abcdef".to_owned(),
            true,
        ),
        (format!("+5:{ID}"), true),
        (format!("007:{ID}"), true),
        (format!("18446744073709551616:{ID}"), false),
        (format!("-1:{ID}"), false),
        (format!(" 5:{ID}"), false),
        (format!("5:{ID} "), false),
        (format!("5 :{ID}"), false),
        (format!(":{ID}"), false),
        ("5:".to_owned(), false),
        ("5".to_owned(), false),
        (String::new(), false),
        (":".to_owned(), false),
        (format!("5:{ID}:6"), false),
        (format!("5::{ID}"), false),
        (format!("5:{}", &ID[..31]), false),
        (format!("5:{ID}0"), false),
        (format!("5:{}g", &ID[..31]), false),
        (format!("5;{ID}"), false),
        (format!("5.{ID}"), false),
        ("5:00000000000000000000000000000000".to_owned(), false),
        ("5:ffffffffffffffffffffffffffffffff".to_owned(), false),
    ]
}

#[test]
fn join_at_id_writes_the_inbox_and_transcript_bytes() {
    for at in [0, 1, 1_700_000_000, u64::MAX] {
        let text = join_at_id(at, id());
        assert_eq!(text, format!("{}:{}", at, id().to_hex()));
        assert_eq!(text, format!("{at}:{ID}"));
    }
}

#[test]
fn split_at_id_takes_the_texts_the_old_parsers_took() {
    for (text, taken) in table() {
        let read = split_at_id(&text);
        assert_eq!(read.is_some(), taken, "{text:?}");
        assert_eq!(read, inbox_parser(&text), "inbox: {text:?}");
        assert_eq!(read, transcript_parser(&text), "transcript: {text:?}");
    }
}

#[test]
fn a_cursor_reads_back_as_it_was_written() {
    for at in [0, 1_700_000_000, u64::MAX] {
        assert_eq!(split_at_id(&join_at_id(at, id())), Some((at, id())));
    }
    let upper = format!("5:{}", ID.to_uppercase());
    assert_eq!(split_at_id(&upper), Some((5, id())));
    assert_eq!(join_at_id(5, id()), format!("5:{ID}"));
}
