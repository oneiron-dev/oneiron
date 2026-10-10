//! A conversation's transcript is what its reader may read of it, in order:
//! never an erased message, never one outside the reader's grants.

use super::*;
use crate::edge::EdgeActorClass;
use crate::memory::{SafeDeleteReason, WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::test_util::entity;
use crate::{TimeRange, Vault, VaultConfig};

const AT: u64 = 1_790_000_000;

fn said(order: u32, author: WitnessAuthor, content: &str) -> WitnessMessage {
    WitnessMessage {
        id: None,
        author,
        message_type: "dialogue".to_owned(),
        content: content.to_owned(),
        metadata: None,
        is_visible: true,
        order,
    }
}

/// Witnesses one turn as `actor`; returns its messages' short refs.
fn witness(
    vault: &Vault,
    actor: EntityId,
    conversation: EntityId,
    turn: EntityId,
    at: u64,
    messages: Vec<WitnessMessage>,
) -> Vec<String> {
    vault
        .memory(actor, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            messages,
            occurred_at: at,
        })
        .expect("witness a turn")
        .message_short_ids
}

/// Each returned turn's id and its messages' `(role, text)`.
fn read(page: &TranscriptPage) -> Vec<(String, Vec<(String, String)>)> {
    page.turns
        .iter()
        .map(|turn| {
            (
                turn.id.clone(),
                turn.messages
                    .iter()
                    .map(|message| (message.role.clone(), message.text.clone()))
                    .collect(),
            )
        })
        .collect()
}

fn transcript(
    vault: &Vault,
    actor: EntityId,
    conversation: EntityId,
    after: Option<&str>,
    limit: usize,
) -> TranscriptPage {
    vault
        .memory(actor, EdgeActorClass::Human)
        .conversation_transcript(&conversation, after, limit)
        .expect("read the transcript")
        .value
}

fn turn(id: EntityId, messages: &[(&str, &str)]) -> (String, Vec<(String, String)>) {
    (
        id.to_hex(),
        messages
            .iter()
            .map(|(role, text)| ((*role).to_owned(), (*text).to_owned()))
            .collect(),
    )
}

/// ARCH-0006a: a conversation reads back as its turns in the order they
/// occurred (not the order of their ids, nor of their writes), each with its
/// messages in order, a page at a time. ARCH-0038: an erased message, hard or
/// soft, never comes back, and a turn left with nothing to show is left out.
#[test]
fn a_transcript_reads_turns_in_order_and_never_returns_an_erased_message() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let room = entity(0xD0);
    let (first, second, third) = (entity(0xD3), entity(0xD1), entity(0xD2));
    let last = witness(
        &vault,
        owner,
        room,
        third,
        AT + 20,
        vec![said(0, WitnessAuthor::User, "last words")],
    );
    let opening = witness(
        &vault,
        owner,
        room,
        first,
        AT,
        // Given out of order: the transcript reads them by their order.
        vec![
            said(1, WitnessAuthor::User, "and more"),
            said(0, WitnessAuthor::User, "first words"),
        ],
    );
    witness(
        &vault,
        owner,
        room,
        second,
        AT + 10,
        vec![said(0, WitnessAuthor::Companion, "a reply")],
    );

    let whole = vec![
        turn(first, &[("user", "first words"), ("user", "and more")]),
        turn(second, &[("companion", "a reply")]),
        turn(third, &[("user", "last words")]),
    ];
    let page = transcript(&vault, owner, room, None, 50);
    assert_eq!(read(&page), whole);
    assert_eq!(page.next, None);
    let times: Vec<u64> = page
        .turns
        .iter()
        .flat_map(|turn| turn.messages.iter().map(|message| message.occurred))
        .collect();
    assert_eq!(times, [AT, AT, AT + 10, AT + 20]);

    // One turn a page, each page after the cursor the last one gave.
    let mut paged = Vec::new();
    let mut after = None;
    loop {
        let page = transcript(&vault, owner, room, after.as_deref(), 1);
        paged.extend(read(&page));
        match page.next {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    assert_eq!(paged, whole);

    let memory = vault.memory(owner, EdgeActorClass::Human);
    memory
        // The receipt names the messages as given: "and more" first.
        .safe_delete(&opening[0], SafeDeleteReason::UserHardDelete)
        .expect("erase one message of the first turn");
    memory
        .safe_delete(&last[0], SafeDeleteReason::UserDelete)
        .expect("delete the third turn's only message");
    let page = transcript(&vault, owner, room, None, 2);
    assert_eq!(
        read(&page),
        [
            turn(first, &[("user", "first words")]),
            turn(second, &[("companion", "a reply")]),
        ]
    );
    assert_eq!(page.next, None, "no page holds the erased turn");
}

/// A turn whose time moves between the listing of a conversation's turns and
/// their read is served where it now is: the pages stay in order, each cursor
/// names a time a page served, and the walk passes no turn over.
#[test]
fn a_turn_that_moves_while_a_page_is_read_is_served_where_it_now_is() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let room = entity(0xD9);
    let (early, later) = (entity(0xDA), entity(0xDB));
    witness(
        &vault,
        owner,
        room,
        early,
        AT,
        vec![said(0, WitnessAuthor::User, "early words")],
    );
    witness(
        &vault,
        owner,
        room,
        later,
        AT + 20,
        vec![said(0, WitnessAuthor::Companion, "later words")],
    );
    let raw = vault.get_raw(&early).expect("read the turn").expect("turn");
    let body = raw[crate::batch::ENTITY_METADATA_HEADER_LEN..].to_vec();
    let learned = vault.get_learned_at(&early).expect("learned at");

    // The first page lists the early turn first; before it is read, the turn
    // moves past the later one.
    let mut moved = false;
    let first = vault
        .memory(owner, EdgeActorClass::Human)
        .conversation_transcript_listed(&room, None, 1, || {
            if !moved {
                moved = true;
                vault
                    .put_entity(
                        &early,
                        ENTITY_TYPE_TURN,
                        TimeRange {
                            start: AT + 30,
                            end: AT + 30,
                        },
                        learned,
                        &body,
                    )
                    .expect("move the early turn");
            }
        })
        .expect("read the first page")
        .value;
    assert!(moved);
    assert_eq!(read(&first), [turn(later, &[("companion", "later words")])]);
    assert_eq!(
        first.next.as_deref(),
        Some(format!("{}:{}", AT + 20, later.to_hex()).as_str())
    );
    let second = transcript(&vault, owner, room, first.next.as_deref(), 1);
    assert_eq!(read(&second), [turn(early, &[("user", "early words")])]);
    assert_eq!(second.turns[0].occurred_start, AT + 30);
    assert_eq!(second.next, None);
}

/// A rooted vault whose owner witnessed three turns in one room: the first
/// holds a message in a space a scoped reader holds a Messages grant on and
/// one outside it, the second only one outside it, the third only one in it.
struct ScopedRoom {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    scoped: EntityId,
    room: EntityId,
    turns: [EntityId; 3],
}

fn scoped_room() -> ScopedRoom {
    use crate::access_grant::{
        AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
    };
    use ed25519_dalek::{Signer, SigningKey};

    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let scoped = entity(0x67);
    vault
        .put_entity(
            &scoped,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"scoped reader",
        )
        .expect("put the scoped reader");
    let space = entity(0x68);
    let granted = |order, author, content| {
        let mut message = said(order, author, content);
        message.metadata = Some(serde_json::json!({"rel": space.to_hex()}));
        message
    };
    let room = entity(0xD8);
    let (first, second, third) = (entity(0xD4), entity(0xD5), entity(0xD6));
    witness(
        &vault,
        owner,
        room,
        first,
        AT,
        vec![
            granted(0, WitnessAuthor::User, "harbor view table for two"),
            said(1, WitnessAuthor::User, "harbor locker code is 4471"),
        ],
    );
    witness(
        &vault,
        owner,
        room,
        second,
        AT + 10,
        vec![said(0, WitnessAuthor::Companion, "noted the locker code")],
    );
    witness(
        &vault,
        owner,
        room,
        third,
        AT + 20,
        vec![granted(0, WitnessAuthor::User, "book it for friday")],
    );

    let issuer = crate::authority::HostSlipIssuer::from_secret(b"transcript pairing secret")
        .expect("issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let holder = SigningKey::from_bytes(&[0x6a; 32]);
    let public = holder.verifying_key().to_bytes();
    let link = vault
        .issue_pairing_link(&issuer, crate::federation::Scope::top(), 3_600)
        .expect("pairing link");
    let binding =
        crate::authority::pairing_binding_transcript(&link.code, &public, "transcript-holder")
            .expect("binding transcript");
    vault
        .redeem_pairing_link(
            &issuer,
            &link.code,
            "transcript-holder",
            public,
            &holder.sign(&binding).to_bytes(),
        )
        .expect("slip mint");
    vault.authority_fold().expect("authority log fold");
    vault
        .install_read_permit_for_test(crate::WriteActor::new(scoped, EdgeActorClass::Human))
        .expect("scoped read permit");
    vault
        .create_access_grant(
            &entity(0x6b),
            &AccessGrant {
                authority_scope: crate::federation::scope_codec::read_preset(),
                principal_ref: scoped,
                scope: AccessGrantScope::Messages { space_ref: space },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: crate::unix_seconds_now(),
                revoked_at: None,
                expires_at: None,
            },
        )
        .expect("scoped message grant");
    ScopedRoom {
        _dir: dir,
        vault,
        owner,
        scoped,
        room,
        turns: [first, second, third],
    }
}

/// The reader recall reads as (ARCH-0004, ARCH-0040): a reader whose grants
/// admit some of a conversation's messages gets exactly those, each in its
/// turn; a turn with none of them is left out. The owner reads them all.
#[test]
fn a_scoped_reader_gets_exactly_the_messages_it_may_read() {
    let ScopedRoom {
        _dir,
        vault,
        owner,
        scoped,
        room,
        turns: [first, second, third],
    } = scoped_room();

    assert_eq!(
        read(&transcript(&vault, owner, room, None, 50)),
        [
            turn(
                first,
                &[
                    ("user", "harbor view table for two"),
                    ("user", "harbor locker code is 4471"),
                ]
            ),
            turn(second, &[("companion", "noted the locker code")]),
            turn(third, &[("user", "book it for friday")]),
        ]
    );
    assert_eq!(
        read(&transcript(&vault, scoped, room, None, 50)),
        [
            turn(first, &[("user", "harbor view table for two")]),
            turn(third, &[("user", "book it for friday")]),
        ]
    );
}

/// DEC-0005, a read never silently narrows: when a conversation's turns keep
/// moving while a page is read, the refusal carries the receipt of the reads
/// that were made, with what they withheld from the reader.
#[test]
fn a_page_refused_for_moving_turns_says_what_its_reads_withheld() {
    let ScopedRoom {
        _dir,
        vault,
        scoped,
        room,
        turns: [first, ..],
        ..
    } = scoped_room();
    let raw = vault.get_raw(&first).expect("read the turn").expect("turn");
    let body = raw[crate::batch::ENTITY_METADATA_HEADER_LEN..].to_vec();
    let learned = vault.get_learned_at(&first).expect("learned at");
    let mut at = AT;
    let error = vault
        .memory(scoped, EdgeActorClass::Human)
        .conversation_transcript_listed(&room, None, 50, || {
            at += 1;
            vault
                .put_entity(
                    &first,
                    ENTITY_TYPE_TURN,
                    TimeRange { start: at, end: at },
                    learned,
                    &body,
                )
                .expect("move the first turn");
        })
        .expect_err("the turns kept moving");
    assert_eq!(error.code, MEMORY_CODE_INVALID_STATE, "{error:?}");
    let receipt = error.read_receipt.expect("the refusal's receipt");
    assert!(
        receipt.suppressed_count > 0,
        "the withheld message is counted: {receipt:?}"
    );
}
