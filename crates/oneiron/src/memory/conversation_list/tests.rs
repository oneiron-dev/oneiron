//! The conversation list is what its reader may read of the vault
//! (ARCH-0006a, DEC-0005): only the conversations it may read, each previewed
//! by a message it may read and never an erased one, with a receipt that
//! counts the conversations withheld. Nothing a reader may not read, nor
//! where it falls, changes the list or its receipt. The owner's list is the
//! one it always was.

use super::*;
use crate::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use crate::edge::EdgeActorClass;
use crate::federation::ScopeAxis;
use crate::federation::scope_codec::read_preset;
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::test_util::entity;
use crate::{DeleteReason, TimeRange, Vault, VaultConfig, WriteActor};

const AT: u64 = 1_790_000_000;

/// A visible message; one in `space` is relationship data its grant opens.
fn said(author: WitnessAuthor, content: &str, space: Option<EntityId>) -> WitnessMessage {
    WitnessMessage {
        id: None,
        author,
        message_type: "dialogue".to_owned(),
        content: content.to_owned(),
        metadata: space.map(|space| serde_json::json!({"rel": space.to_hex()})),
        is_visible: true,
        order: 0,
    }
}

fn witness(
    vault: &Vault,
    owner: EntityId,
    room: EntityId,
    turn: EntityId,
    at: u64,
    message: WitnessMessage,
) {
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            messages: vec![message],
            occurred_at: at,
        })
        .expect("witness a turn");
}

/// One list read: each row's id and preview, the next cursor, the count and
/// how many rows the reads withheld.
struct Listed {
    rows: Vec<(EntityId, Option<String>)>,
    next: Option<EntityId>,
    total: Option<u64>,
    withheld: usize,
}

fn list(vault: &Vault, reader: EntityId, limit: usize) -> Listed {
    let read = vault
        .memory(reader, EdgeActorClass::Human)
        .conversation_list(ConversationListFilter::default(), None, limit, true)
        .expect("list conversations");
    Listed {
        rows: read
            .value
            .rows
            .into_iter()
            .map(|row| (row.row.id, row.last_message_snippet))
            .collect(),
        next: read.value.next,
        total: read.value.total,
        withheld: read.receipt.suppressed_count,
    }
}

/// One witnessed turn: its conversation, its id, when it occurred and its
/// one message.
type Witnessed = (EntityId, EntityId, u64, WitnessMessage);

/// The space the reader holds a Messages grant on.
const SPACE: u8 = 0x68;

/// A rooted vault whose owner witnessed `witnessed`, and a reader who holds
/// a Messages grant on the space. Its read ceiling takes in the `readable`
/// conversations and turns, and each readable turn's messages.
struct ReaderVault {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    reader: EntityId,
}

fn reader_vault(witnessed: &[Witnessed], readable: &[EntityId]) -> ReaderVault {
    use ed25519_dalek::{Signer, SigningKey};

    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let reader = entity(0x67);
    vault
        .put_entity(
            &reader,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"scoped reader",
        )
        .expect("put the reader");
    for (room, turn, at, message) in witnessed {
        witness(&vault, owner, *room, *turn, *at, message.clone());
    }

    // In a vault with no authority root every human PERSON reads as its
    // owner, so the vault is rooted first.
    let issuer =
        crate::authority::HostSlipIssuer::from_secret(b"conversation list secret").expect("issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let holder = SigningKey::from_bytes(&[0x6a; 32]);
    let public = holder.verifying_key().to_bytes();
    let link = vault
        .issue_pairing_link(&issuer, crate::federation::Scope::top(), 3_600)
        .expect("pairing link");
    let binding = crate::authority::pairing_binding_transcript(&link.code, &public, "list-holder")
        .expect("binding transcript");
    vault
        .redeem_pairing_link(
            &issuer,
            &link.code,
            "list-holder",
            public,
            &holder.sign(&binding).to_bytes(),
        )
        .expect("slip mint");
    vault.authority_fold().expect("authority log fold");

    vault
        .create_access_grant(
            &entity(0x6b),
            &AccessGrant {
                authority_scope: read_preset(),
                principal_ref: reader,
                scope: AccessGrantScope::Messages {
                    space_ref: entity(SPACE),
                },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: crate::unix_seconds_now(),
                revoked_at: None,
                expires_at: None,
            },
        )
        .expect("the reader's message grant");
    let mut ceiling = read_preset();
    let mut facets = std::collections::BTreeSet::new();
    let txn = vault.store.env.read_txn().expect("read txn");
    let mut rows = Vec::new();
    for id in readable {
        rows.push(*id);
        rows.extend(vault.turn_message_ids_in(&txn, id).expect("messages"));
    }
    drop(txn);
    for row in rows {
        match vault
            .record_scope(&row)
            .expect("record scope")
            .expect("stamped")
            .facets
        {
            ScopeAxis::Some(own) => facets.extend(own),
            axis => panic!("a row's own facet, not {axis:?}"),
        }
    }
    ceiling.facets = ScopeAxis::Some(facets);
    crate::conversation_dag::test_support::put_test_policy_manifest(
        &vault,
        WriteActor::new(owner, EdgeActorClass::Human),
        entity(0x6c),
        &serde_json::json!({
            "schema_version": "1.2", "pack_id": "conversation-list-ceiling",
            "pack_version": "1", "min_engine_version": "0.0.0",
            "defaults": {}, "rules": [], "actor_ceilings": [],
            "scoped_grants": [{
                "actor_ref": reader.to_hex(), "actor_class": "human",
                "effector": "core:read", "scope": ceiling, "receipt_required": false,
            }],
        }),
    )
    .expect("the reader's read ceiling");
    ReaderVault {
        _dir: dir,
        vault,
        owner,
        reader,
    }
}

/// Two conversations. The first has a turn whose message is in the space, a
/// later turn whose message is outside it, and a last turn in it again; the
/// second has one turn in the space. The reader's read ceiling takes in the
/// first conversation, its turns and its messages, and not the second.
struct ScopedVault {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    reader: EntityId,
    kept: EntityId,
    other: EntityId,
    last_turn: EntityId,
}

fn scoped_vault() -> ScopedVault {
    let space = Some(entity(SPACE));
    let (kept, other) = (entity(0xD8), entity(0xD9));
    let turns = [entity(0xD4), entity(0xD5), entity(0xD6)];
    let (user, companion) = (WitnessAuthor::User, WitnessAuthor::Companion);
    let ReaderVault {
        _dir,
        vault,
        owner,
        reader,
    } = reader_vault(
        &[
            (
                kept,
                turns[0],
                AT,
                said(user, "a table for two by the window", space),
            ),
            (
                kept,
                turns[1],
                AT + 10,
                said(user, "the locker code is 4471", None),
            ),
            (
                kept,
                turns[2],
                AT + 20,
                said(companion, "booked for friday at eight", space),
            ),
            (
                other,
                entity(0xDA),
                AT + 30,
                said(user, "the spare key is under the mat", space),
            ),
        ],
        &[kept, turns[0], turns[1], turns[2]],
    );
    ScopedVault {
        _dir,
        vault,
        owner,
        reader,
        kept,
        other,
        last_turn: turns[2],
    }
}

/// A reader lists only the conversations it may read, each previewed by the
/// latest message it may read, and the receipt counts every row withheld. A
/// next cursor never points past the last conversation it may read. An
/// erased message previews no row for anyone. The owner lists everything,
/// previewed as before.
#[test]
fn a_reader_lists_only_what_it_may_read() {
    let ScopedVault {
        _dir,
        vault,
        owner,
        reader,
        kept,
        other,
        last_turn,
    } = scoped_vault();
    let preview = |listed: &Listed, id: EntityId| {
        listed
            .rows
            .iter()
            .find(|(row, _)| *row == id)
            .and_then(|(_, preview)| preview.clone())
    };

    let all = list(&vault, owner, 50);
    for (id, preview) in &all.rows {
        let before = vault
            .conversation_last_message_snippet(id)
            .expect("snippet");
        assert_eq!(*preview, before, "the owner's preview is unchanged");
    }
    assert!(all.rows.iter().any(|(id, _)| *id == other));
    assert_eq!(
        preview(&all, kept).as_deref(),
        Some("booked for friday at eight")
    );
    assert_eq!(all.total, Some(all.rows.len() as u64));
    assert_eq!(all.withheld, 0);

    let read = list(&vault, reader, 50);
    assert_eq!(
        read.rows,
        [(kept, Some("booked for friday at eight".to_owned()))]
    );
    assert_eq!(read.total, Some(1));
    // Every other conversation; a preview adds no count.
    assert_eq!(read.withheld, all.rows.len() - 1);

    // A filter sees only rows the reader may read: the receipt withholds
    // every conversation it may not read, whatever kind the filter names.
    let unlike = ConversationKind::Mirror;
    let filtered = |reader| {
        let filter = ConversationListFilter {
            kind: Some(unlike),
            external_id: None,
        };
        vault
            .memory(reader, EdgeActorClass::Human)
            .conversation_list(filter, None, 50, true)
            .expect("list conversations")
    };
    assert!(filtered(owner).value.rows.is_empty(), "no mirror here");
    assert_eq!(
        filtered(reader).receipt.suppressed_count,
        all.rows.len() - 1
    );

    let first = list(&vault, reader, 1);
    assert_eq!(first.rows.len(), 1);
    assert_eq!(
        first.next, None,
        "no cursor to a conversation it may not read"
    );
    assert!(list(&vault, owner, 1).next.is_some());

    let booked = {
        let txn = vault.store.env.read_txn().expect("read txn");
        vault
            .turn_message_ids_in(&txn, &last_turn)
            .expect("messages")[0]
    };
    vault
        .delete_room_record(
            kept,
            booked,
            WriteActor::new(owner, EdgeActorClass::Human),
            DeleteReason::UserDelete,
        )
        .expect("erase the last message");
    let all = list(&vault, owner, 50);
    assert_eq!(
        preview(&all, kept).as_deref(),
        Some("the locker code is 4471")
    );
    assert_eq!(
        preview(&all, kept),
        vault
            .conversation_last_message_snippet(&kept)
            .expect("snippet")
    );
    let read = list(&vault, reader, 50);
    assert_eq!(
        read.rows,
        [(kept, Some("a table for two by the window".to_owned()))]
    );
    // The preview now passes over the message outside the reader's grant,
    // and still counts nothing of it.
    assert_eq!(read.withheld, all.rows.len() - 1);
}

/// How many conversations the owner lists beside `shown`, each one the
/// reader may not read.
fn others(vault: &Vault, owner: EntityId, shown: usize) -> usize {
    list(vault, owner, 50).rows.len() - shown
}

/// Two vaults the reader reads alike: one conversation with one turn it may
/// read among four it may not. They differ only in whether one hidden turn
/// was learned before or after the readable one. The list, its preview and
/// its receipt are the same in both: what a read withholds never says where
/// a hidden turn falls.
#[test]
fn where_a_hidden_turn_falls_never_shows() {
    let (room, shown) = (entity(0xE0), entity(0xE2));
    let space = Some(entity(SPACE));
    let listed = [AT - 10, AT + 40].map(|last| {
        let mut witnessed = vec![(
            room,
            shown,
            AT,
            said(WitnessAuthor::User, "the turn it may read", space),
        )];
        for (hidden, at) in [
            (0xE3, AT + 30),
            (0xE4, AT + 20),
            (0xE5, AT + 10),
            (0xE6, last),
        ] {
            witnessed.push((
                room,
                entity(hidden),
                at,
                said(WitnessAuthor::User, "a turn it may not read", space),
            ));
        }
        let ReaderVault {
            _dir,
            vault,
            owner,
            reader,
        } = reader_vault(&witnessed, &[room, shown]);
        let listed = list(&vault, reader, 50);
        let others = others(&vault, owner, 1);
        (
            listed.rows,
            listed.next,
            listed.total,
            listed.withheld,
            others,
        )
    });
    assert_eq!(
        listed[0].0,
        [(room, Some("the turn it may read".to_owned()))]
    );
    assert_eq!(listed[0].3, listed[0].4, "only the other conversations");
    assert_eq!(listed[0], listed[1]);
}

/// Two vaults the reader reads alike: two conversations it may read, and two
/// it may not that sit before the first in one vault and after the second in
/// the other. Every page, from the start or after a cursor, with or without
/// a count, withholds the same: what a list withholds never says where a
/// hidden conversation falls beside the page.
#[test]
fn where_a_hidden_conversation_falls_never_shows() {
    let (first, second) = (entity(0xB1), entity(0xB2));
    let space = Some(entity(SPACE));
    let pages = [[0xA7, 0xA8], [0xC1, 0xC2]].map(|hidden| {
        let mut witnessed = vec![
            (
                first,
                entity(0xB3),
                AT,
                said(WitnessAuthor::User, "the first it may read", space),
            ),
            (
                second,
                entity(0xB4),
                AT + 10,
                said(WitnessAuthor::User, "the second it may read", space),
            ),
        ];
        for (room, at) in hidden.into_iter().zip([AT + 20, AT + 30]) {
            witnessed.push((
                entity(room),
                entity(room + 0x10),
                at,
                said(WitnessAuthor::User, "one it may not read", space),
            ));
        }
        let ReaderVault {
            _dir,
            vault,
            owner,
            reader,
        } = reader_vault(&witnessed, &[first, entity(0xB3), second, entity(0xB4)]);
        let memory = vault.memory(reader, EdgeActorClass::Human);
        let page = |after: Option<&EntityId>, count| {
            let read = memory
                .conversation_list(ConversationListFilter::default(), after, 1, count)
                .expect("list a page");
            let rows: Vec<_> = read.value.rows.into_iter().map(|row| row.row.id).collect();
            (
                rows,
                read.value.next,
                read.value.total,
                read.receipt.suppressed_count,
            )
        };
        let pages = [
            page(None, false),
            page(Some(&first), false),
            page(None, true),
            page(Some(&first), true),
        ];
        (pages, others(&vault, owner, 2))
    });
    let (read, others) = &pages[0];
    assert_eq!(read[0], (vec![first], Some(first), None, *others));
    assert_eq!(read[1], (vec![second], None, None, *others));
    assert_eq!(read[3], (vec![second], None, Some(2), *others));
    assert_eq!(pages[0], pages[1]);
}

/// Two vaults the reader reads alike: one conversation with a turn it may
/// read and a later one it may not. In one, the hidden turn carries DAG
/// state its room never selected, as a received record does before its
/// parent lands. The reader's list is the same in both: a turn it may not
/// read never decides its preview, nor fails its list. The owner, who reads
/// that turn, gets no preview for the room rather than a failed list.
#[test]
fn a_hidden_turns_topology_never_decides_a_preview() {
    let (room, shown, hidden) = (entity(0xF0), entity(0xF1), entity(0xF2));
    let space = Some(entity(SPACE));
    let listed = [false, true].map(|unselected| {
        let ReaderVault {
            _dir,
            vault,
            owner,
            reader,
        } = reader_vault(
            &[
                (
                    room,
                    shown,
                    AT,
                    said(WitnessAuthor::User, "the turn it may read", space),
                ),
                (
                    room,
                    hidden,
                    AT + 10,
                    said(WitnessAuthor::User, "a turn it may not read", space),
                ),
            ],
            &[room, shown],
        );
        if unselected {
            crate::conversation_dag::fixtures::mark_canonical(&vault, &hidden, &shown);
            assert!(
                vault.conversation_last_message_snippet(&room).is_err(),
                "the owner's own preview refuses an unselected DAG"
            );
            assert!(list(&vault, owner, 50).rows.contains(&(room, None)));
        }
        let listed = list(&vault, reader, 50);
        (listed.rows, listed.next, listed.total, listed.withheld)
    });
    assert_eq!(
        listed[0].0,
        [(room, Some("the turn it may read".to_owned()))]
    );
    assert_eq!(listed[0], listed[1]);
}

/// Two vaults the reader reads alike: one conversation whose two turns it may
/// read, neither with text it may read. A message outside its grant is part
/// of the earlier turn, and in one vault part of the later one as well. The
/// list and its receipt are the same in both: nothing says which turns a
/// hidden message belongs to.
#[test]
fn a_hidden_message_in_two_turns_changes_nothing() {
    let (room, earlier, later) = (entity(0xF4), entity(0xF5), entity(0xF6));
    let space = Some(entity(SPACE));
    let listed = [false, true].map(|twice| {
        let ReaderVault {
            _dir,
            vault,
            owner,
            reader,
        } = reader_vault(
            &[
                (
                    room,
                    earlier,
                    AT,
                    said(WitnessAuthor::User, "outside the grant", None),
                ),
                (
                    room,
                    later,
                    AT + 10,
                    WitnessMessage {
                        is_visible: false,
                        ..said(WitnessAuthor::Companion, "never shown", space)
                    },
                ),
            ],
            &[room, earlier, later],
        );
        if twice {
            let hidden = {
                let txn = vault.store.env.read_txn().expect("read txn");
                vault.turn_message_ids_in(&txn, &earlier).expect("messages")[0]
            };
            vault
                .batch()
                .edge(&hidden, crate::EdgeKind::PartOf, &later, 1.0)
                .commit()
                .expect("a second membership");
        }
        let listed = list(&vault, reader, 50);
        let others = others(&vault, owner, 1);
        (
            listed.rows,
            listed.next,
            listed.total,
            listed.withheld,
            others,
        )
    });
    assert_eq!(listed[0].0, [(room, None)]);
    assert_eq!(listed[0].3, listed[0].4, "only the other conversations");
    assert_eq!(listed[0], listed[1]);
}
