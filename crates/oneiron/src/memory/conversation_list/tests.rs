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
    receipt: ScopedReadReceipt,
}

fn list(vault: &Vault, owner: EntityId, limit: usize) -> Listed {
    listed(
        vault
            .memory(owner, EdgeActorClass::Human)
            .conversation_list(ConversationListFilter::default(), None, limit, true)
            .expect("list conversations"),
    )
}

fn listed(read: ScopedReadResult<ConversationListPage>) -> Listed {
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
        receipt: read.receipt,
    }
}

/// One witnessed turn: its conversation, its id, when it occurred and its
/// one message.
type Witnessed = (EntityId, EntityId, u64, WitnessMessage);

/// The space the reader holds a Messages grant on.
const SPACE: u8 = 0x68;

/// The scoped reader, and the credential it reads with when it has one.
#[derive(Clone)]
struct Reader {
    id: EntityId,
    credential: Option<crate::authority::VerifiedSlip>,
}

impl Reader {
    fn memory<'v>(&self, vault: &'v Vault) -> Memory<'v> {
        let memory = vault.memory(self.id, EdgeActorClass::Human);
        match &self.credential {
            Some(credential) => memory.with_read_proof(credential),
            None => memory,
        }
    }
}

fn reader_list(vault: &Vault, reader: &Reader, limit: usize) -> Listed {
    listed(
        reader
            .memory(vault)
            .conversation_list(ConversationListFilter::default(), None, limit, true)
            .expect("list conversations"),
    )
}

/// The vault's root project room: a channel only the owner is in.
fn root_room(vault: &Vault) -> EntityId {
    let project = vault.root_project().expect("root project");
    let record = vault
        .project(project)
        .expect("read the project")
        .expect("the root project");
    EntityId::from_hex(&record.home_room).expect("its room")
}

/// How many of `listed`'s conversations are groups, channels or mirrors
/// `reader` is not a member of, such as the vault's root project room.
fn rooms_outside(vault: &Vault, listed: &Listed, reader: EntityId) -> usize {
    listed
        .rows
        .iter()
        .filter(|(id, _)| {
            vault.conversation_body(*id).is_ok_and(|body| {
                matches!(
                    body.kind,
                    ConversationKind::Group | ConversationKind::Channel | ConversationKind::Mirror
                )
            }) && !vault
                .room_audience_members(*id)
                .unwrap_or_default()
                .contains(&reader)
        })
        .count()
}

/// A rooted vault whose owner witnessed `witnessed`, and a reader who holds
/// a Messages grant on the space. It reads with a credential that names the
/// `readable` conversations and turns, and each one's messages its grant
/// admits: it may read nothing else.
struct ReaderVault {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    reader: Reader,
}

fn reader_vault(witnessed: &[Witnessed], readable: &[EntityId]) -> ReaderVault {
    let (rooted, issuer) = rooted_reader(witnessed);
    let credential = credential(&rooted.vault, &issuer, rooted.reader.id, readable);
    ReaderVault {
        reader: Reader {
            credential: Some(credential),
            ..rooted.reader
        },
        ..rooted
    }
}

/// As [`reader_vault`], with no credential: the reader reads every
/// conversation and turn, and its grant alone decides which messages.
fn grant_reader_vault(witnessed: &[Witnessed]) -> ReaderVault {
    rooted_reader(witnessed).0
}

fn rooted_reader(witnessed: &[Witnessed]) -> (ReaderVault, crate::authority::HostSlipIssuer) {
    rooted_reader_with(|vault, owner, _| {
        for (room, turn, at, message) in witnessed {
            witness(vault, owner, *room, *turn, *at, message.clone());
        }
    })
}

/// As [`rooted_reader`], where `setup` writes the owner's conversations
/// before the vault is rooted, given the vault, the owner and the reader.
fn rooted_reader_with(
    setup: impl FnOnce(&Vault, EntityId, EntityId),
) -> (ReaderVault, crate::authority::HostSlipIssuer) {
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
    setup(&vault, owner, reader);

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
    crate::conversation_dag::test_support::put_test_policy_manifest(
        &vault,
        WriteActor::new(owner, EdgeActorClass::Human),
        entity(0x6c),
        &serde_json::json!({
            "schema_version": "1.2", "pack_id": "conversation-list-reader",
            "pack_version": "1", "min_engine_version": "0.0.0",
            "defaults": {}, "rules": [], "actor_ceilings": [],
            "scoped_grants": [{
                "actor_ref": reader.to_hex(), "actor_class": "human",
                "effector": "core:read", "scope": read_preset(), "receipt_required": false,
            }],
        }),
    )
    .expect("the reader's read grant");
    let rooted = ReaderVault {
        _dir: dir,
        vault,
        owner,
        reader: Reader {
            id: reader,
            credential: None,
        },
    };
    (rooted, issuer)
}

/// The reader's credential: it names the `readable` conversations and
/// turns and every message of those turns, so the reader's relationship
/// grants alone decide which of those messages in a space it reads, and it
/// reads every one in none. A record a
/// credential does not name is withheld from every read made with it; a
/// record facet never is a boundary (`Scope::admits`).
fn credential(
    vault: &Vault,
    issuer: &crate::authority::HostSlipIssuer,
    reader: EntityId,
    readable: &[EntityId],
) -> crate::authority::VerifiedSlip {
    let messages: Vec<EntityId> = {
        let txn = vault.store.env.read_txn().expect("read txn");
        readable
            .iter()
            .flat_map(|id| vault.turn_message_ids_in(&txn, id).expect("messages"))
            .collect()
    };
    let records = readable.iter().copied().chain(messages).collect();
    reader_slip(vault, issuer, reader, read_preset(), records)
}

/// A live credential for `reader` over `scope`, naming `records` (none: no
/// record bound).
fn reader_slip(
    vault: &Vault,
    issuer: &crate::authority::HostSlipIssuer,
    reader: EntityId,
    scope: crate::federation::Scope,
    records: Vec<EntityId>,
) -> crate::authority::VerifiedSlip {
    let mut claims = vault
        .ensure_host_root_slip(issuer)
        .expect("host root")
        .claims;
    let tag = format!("conversation-list-reader {scope:?} {records:?}");
    claims.slip_id = *blake3::hash(tag.as_bytes()).as_bytes();
    claims.parent_id = None;
    claims.holder_ref = reader.to_hex();
    claims.actor_class = Some("human".into());
    claims.scope = scope;
    claims.records = records.into_iter().map(|id| id.to_hex()).collect();
    let slip = vault.mint_capability_slip(issuer, claims).expect("mint");
    let tag = b"conversation-list-reader";
    let proof = issuer.binding_proof(&slip, tag).expect("binding proof");
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, tag, &proof)
        .expect("verify")
}

/// Two conversations. The first has a turn whose message is in the space, a
/// later turn whose message is in a space the reader holds no grant on, and
/// a last turn in the first space again; the
/// second has one turn in the space. The reader's read ceiling takes in the
/// first conversation, its turns and its messages, and not the second.
struct ScopedVault {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    reader: Reader,
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
                said(user, "the locker code is 4471", Some(entity(0x69))),
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

    let read = reader_list(&vault, &reader, 50);
    assert_eq!(
        read.rows,
        [(kept, Some("booked for friday at eight".to_owned()))]
    );
    assert_eq!(read.total, Some(1));
    // Every other conversation but a room the reader is not in; a preview
    // adds no count.
    let counted = all.rows.len() - 1 - rooms_outside(&vault, &all, reader.id);
    assert_eq!(read.withheld, counted);

    // A filter sees only rows the reader may read: the receipt withholds
    // every conversation it may not read, whatever kind the filter names.
    let unlike = ConversationKind::Mirror;
    let filtered = |memory: Memory<'_>| {
        let filter = ConversationListFilter {
            kind: Some(unlike),
            external_id: None,
        };
        memory
            .conversation_list(filter, None, 50, true)
            .expect("list conversations")
    };
    assert!(
        filtered(vault.memory(owner, EdgeActorClass::Human))
            .value
            .rows
            .is_empty(),
        "no mirror here"
    );
    assert_eq!(
        filtered(reader.memory(&vault)).receipt.suppressed_count,
        counted
    );

    let first = reader_list(&vault, &reader, 1);
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
    let read = reader_list(&vault, &reader, 50);
    assert_eq!(
        read.rows,
        [(kept, Some("a table for two by the window".to_owned()))]
    );
    // The preview now passes over the message outside the reader's grant,
    // and still counts nothing of it.
    assert_eq!(read.withheld, counted);
}

/// How many conversations the owner lists beside `shown`, each one `reader`
/// may not read, but for a room it is not in: those add no count.
fn others(vault: &Vault, owner: EntityId, reader: EntityId, shown: usize) -> usize {
    let all = list(vault, owner, 50);
    all.rows.len() - shown - rooms_outside(vault, &all, reader)
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
        let listed = reader_list(&vault, &reader, 50);
        let others = others(&vault, owner, reader.id, 1);
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
        let memory = reader.memory(&vault);
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
        (pages, others(&vault, owner, reader.id, 2))
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
        let listed = reader_list(&vault, &reader, 50);
        (listed.rows, listed.next, listed.total, listed.withheld)
    });
    assert_eq!(
        listed[0].0,
        [(room, Some("the turn it may read".to_owned()))]
    );
    assert_eq!(listed[0], listed[1]);
}

/// Two vaults the reader reads alike: with no credential it may read every
/// conversation and turn, and its grant decides the messages (ARCH-0006a).
/// One conversation's later turn has a message it may read. A message
/// outside its grant is part of the earlier turn, and in one vault part of
/// the later one as well. The list and its whole receipt are the same
/// in both, and the receipt withholds nothing: nothing, not even a narrowed
/// axis, says which turns a hidden message belongs to.
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
        } = grant_reader_vault(&[
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
                said(WitnessAuthor::Companion, "the latest it may read", space),
            ),
        ]);
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
        let listed = reader_list(&vault, &reader, 50);
        // Each vault seeds its own root project, so only the room's row is
        // compared between them.
        let all = list(&vault, owner, 50);
        assert_eq!(
            listed.rows.len(),
            all.rows.len() - rooms_outside(&vault, &all, reader.id),
            "the reader reads every conversation but a room it is not in"
        );
        let row = listed.rows.into_iter().find(|(id, _)| *id == room);
        (row, listed.receipt)
    });
    let (row, receipt) = &listed[0];
    assert_eq!(
        *row,
        Some((room, Some("the latest it may read".to_owned())))
    );
    assert_eq!(receipt.suppressed_count, 0);
    assert!(
        !receipt
            .narrowed_axes
            .iter()
            .any(|axis| axis == "row_authority")
    );
    assert_eq!(listed[0], listed[1]);
}

/// `room`'s preview in one list read by `memory`.
fn preview_of(memory: &Memory<'_>, room: EntityId) -> Option<String> {
    memory
        .conversation_list(ConversationListFilter::default(), None, 50, false)
        .expect("list conversations")
        .value
        .rows
        .into_iter()
        .find(|row| row.row.id == room)
        .expect("the room is listed")
        .last_message_snippet
}

/// A room with no selected HEAD whose latest turn sits in an ordinary
/// session the owner deleted. The turn still previews the room for the
/// owner, as the owner's own preview always has, whether it reads as itself
/// or with its own full credential (Sol R4 F16, R5 F21). The owner's
/// narrower credential reads the turn but may not judge a session it may
/// not read, so it leaves the turn out.
#[test]
fn a_deleted_session_keeps_the_owners_preview() {
    use crate::authority::HostSlipIssuer;
    use crate::federation::ScopeAxis;
    use crate::registry::{ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};

    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let (room, older, turn, session) = (entity(0x91), entity(0x92), entity(0x93), entity(0x94));
    witness(
        &vault,
        owner,
        room,
        older,
        AT,
        said(WitnessAuthor::User, "the older turn", None),
    );
    let msgpack = |body: serde_json::Value| rmp_serde::to_vec_named(&body).expect("msgpack");
    let at = TimeRange { start: 1, end: 1 };
    vault
        .batch()
        .put(
            &session,
            ENTITY_TYPE_SESSION,
            at,
            1,
            &msgpack(serde_json::json!({})),
        )
        .commit()
        .expect("an ordinary session");
    vault
        .batch()
        .put(
            &turn,
            ENTITY_TYPE_TURN,
            at,
            AT + 10,
            &msgpack(serde_json::json!({
                "txt": "still-live conversation text",
                "dag_session_ref": session.to_hex(),
            })),
        )
        .edge(&turn, crate::EdgeKind::ChildOf, &room, 1.0)
        .commit()
        .expect("a live turn in the session");
    assert!(vault.delete_entity(&session).expect("delete the session"));
    let still_live = Some("still-live conversation text".to_owned());
    assert_eq!(
        preview_of(&vault.memory(owner, EdgeActorClass::Human), room),
        still_live
    );

    let issuer = HostSlipIssuer::from_secret(b"conversation list owner").expect("issuer");
    let root = vault.ensure_host_root_slip(&issuer).expect("host root");
    let credential = |tag: &[u8], verbs: Option<&str>| {
        let mut claims = root.claims.clone();
        claims.slip_id = *blake3::hash(tag).as_bytes();
        claims.parent_id = None;
        claims.holder_ref = owner.to_hex();
        claims.actor_class = Some("human".into());
        if let Some(verb) = verbs {
            claims.scope.verbs = ScopeAxis::Some(std::collections::BTreeSet::from([verb.into()]));
        }
        let slip = vault.mint_capability_slip(&issuer, claims).expect("mint");
        let proof = issuer.binding_proof(&slip, tag).expect("binding proof");
        vault
            .verify_capability_slip(&issuer.public_key(), &slip, tag, &proof)
            .expect("verify")
    };
    let full = credential(b"conversation-list-owner-full", None);
    assert!(full.is_full_vault_owner_grade());
    let memory = vault.memory(owner, EdgeActorClass::Human);
    assert_eq!(preview_of(&memory.with_read_proof(&full), room), still_live);

    let narrow = credential(b"conversation-list-owner-read", Some("read"));
    assert!(!narrow.is_full_vault_owner_grade());
    let memory = vault
        .memory(owner, EdgeActorClass::Human)
        .with_read_proof(&narrow);
    let read = memory
        .read_lane(ClaimReadStatus::Recorded)
        .expect("lane")
        .read(&[PointRead::id(turn)], None)
        .expect("read the turn");
    assert!(
        read.value[0].as_ref().is_some_and(|row| row.body.is_some()),
        "the narrower credential reads the turn"
    );
    assert_ne!(preview_of(&memory, room), still_live);
}

/// A group is relationship data (ARCH-0006a rule 2; Astra #1388 P1). A
/// reader who may read every conversation, as itself or with a credential
/// naming no record, never sees a group it is not in, nor the vault's root
/// project room: no row, no title or roster, no words, and no count. A
/// member who joined late with no history sees the group but nothing said
/// before it joined. A member whose join shares the history previews it. A
/// room the lane withholds counts only when the reader is in it (Sol F2),
/// whether the credential names no other room or reads no conversation.
#[test]
fn a_group_shows_only_to_its_members_and_only_what_they_were_shown() {
    use crate::conversation::{ConversationBody, HistoryChoice};
    use crate::federation::ScopeAxis;
    use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};

    let (outside, late, shared) = (entity(0xB1), entity(0xB2), entity(0xB3));
    let words = "said only in the room";
    let (rooted, issuer) = rooted_reader_with(|vault, owner, reader| {
        let member = entity(0xB4);
        vault
            .put_entity(
                &member,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"a member",
            )
            .expect("put the member");
        let actor = WriteActor::new(owner, EdgeActorClass::Human);
        for (room, turn) in [(outside, 0xC1), (late, 0xC2), (shared, 0xC3)] {
            let body = ConversationBody {
                kind: ConversationKind::Group,
                member_ids: vec![member],
                title: Some("the planning room".to_owned()),
                ..ConversationBody::default()
            };
            vault
                .create_conversation(room, &body, actor, AT - 100)
                .expect("create the group");
            witness(
                vault,
                owner,
                room,
                entity(turn),
                AT,
                said(WitnessAuthor::User, words, Some(entity(SPACE))),
            );
        }
        for (room, history) in [(late, HistoryChoice::None), (shared, HistoryChoice::Share)] {
            vault
                .join_member(room, reader, actor, AT + 5, history)
                .expect("the reader joins");
        }
    });
    let all = list(&rooted.vault, rooted.owner, 50);
    assert!(
        all.rows
            .iter()
            .any(|row| *row == (outside, Some(words.to_owned()))),
        "the owner sees every group"
    );
    let root = root_room(&rooted.vault);
    assert!(all.rows.iter().any(|(id, _)| *id == root));
    assert_eq!(rooms_outside(&rooted.vault, &all, rooted.reader.id), 2);
    let unbounded = Reader {
        credential: Some(reader_slip(
            &rooted.vault,
            &issuer,
            rooted.reader.id,
            read_preset(),
            Vec::new(),
        )),
        ..rooted.reader.clone()
    };
    for reader in [&rooted.reader, &unbounded] {
        let read = reader_list(&rooted.vault, reader, 50);
        assert!(
            !read
                .rows
                .iter()
                .any(|(id, _)| *id == outside || *id == root)
        );
        assert!(read.rows.contains(&(late, None)), "{:?}", read.rows);
        assert!(read.rows.contains(&(shared, Some(words.to_owned()))));
        assert_eq!(
            read.rows.len(),
            all.rows.len() - rooms_outside(&rooted.vault, &all, rooted.reader.id)
        );
        assert_eq!(read.total, Some(read.rows.len() as u64));
        assert_eq!(read.withheld, 0, "a group it is not in adds no count");
    }

    let named_rooms = Reader {
        credential: Some(credential(
            &rooted.vault,
            &issuer,
            rooted.reader.id,
            &[late, shared],
        )),
        ..rooted.reader.clone()
    };
    let read = reader_list(&rooted.vault, &named_rooms, 50);
    let ids: Vec<EntityId> = read.rows.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, [late, shared]);
    assert_eq!(read.withheld, 0, "the rooms it is not in add no count");
    let mut words_only = read_preset();
    words_only.bands = ScopeAxis::Some(std::collections::BTreeSet::from([
        ENTITY_TYPE_TURN,
        ENTITY_TYPE_MESSAGE,
    ]));
    let no_conversation = Reader {
        credential: Some(reader_slip(
            &rooted.vault,
            &issuer,
            rooted.reader.id,
            words_only,
            Vec::new(),
        )),
        ..rooted.reader.clone()
    };
    let read = reader_list(&rooted.vault, &no_conversation, 50);
    assert!(read.rows.is_empty());
    assert_eq!(
        read.withheld, 2,
        "only the two rooms the reader is in count"
    );
}

/// A member's sight of a room is judged in the snapshot of each read that
/// takes a turn's words, never carried over from the list's own read (Sol
/// F4). A history narrowed to the reader's join between the list's rows and
/// their previews hides the turn said before the join, and so does a leave.
#[test]
fn a_room_narrowed_during_a_list_narrows_its_preview() {
    use crate::conversation::{ConversationBody, HistoryChoice};

    let room = entity(0xB5);
    let words = "said before the reader joined";
    let (rooted, _) = rooted_reader_with(|vault, owner, reader| {
        let member = entity(0xB4);
        vault
            .put_entity(
                &member,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"a member",
            )
            .expect("put the member");
        let actor = WriteActor::new(owner, EdgeActorClass::Human);
        let body = ConversationBody {
            kind: ConversationKind::Group,
            member_ids: vec![member],
            ..ConversationBody::default()
        };
        vault
            .create_conversation(room, &body, actor, AT - 100)
            .expect("create the group");
        witness(
            vault,
            owner,
            room,
            entity(0xC4),
            AT,
            said(WitnessAuthor::User, words, Some(entity(SPACE))),
        );
        vault
            .join_member(room, reader, actor, AT + 5, HistoryChoice::Share)
            .expect("the reader joins");
    });
    let (vault, owner, reader) = (&rooted.vault, rooted.owner, rooted.reader.id);
    let memory = rooted.reader.memory(vault);
    let during_list = |change: Box<dyn FnOnce(&Vault)>| {
        BEFORE_PREVIEWS.with(|hook| *hook.borrow_mut() = Some(change));
        preview_of(&memory, room)
    };
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    assert_eq!(preview_of(&memory, room).as_deref(), Some(words));
    let narrowed = during_list(Box::new(move |vault: &Vault| {
        vault
            .set_history_visibility(room, reader, actor, AT + 6, AT + 5)
            .expect("narrow the reader's history to its join");
    }));
    assert_eq!(narrowed, None);
    let shared = during_list(Box::new(move |vault: &Vault| {
        vault
            .set_history_visibility(room, reader, actor, AT + 7, 0)
            .expect("share the history again");
    }));
    assert_eq!(shared.as_deref(), Some(words));
    let left = during_list(Box::new(move |vault: &Vault| {
        vault
            .leave_member(room, reader, actor, AT + 8)
            .expect("the reader leaves");
    }));
    assert_eq!(left, None);
}

/// A room listed as a room keeps the room's bound when its body names
/// another kind before the preview reads it: a late joiner still sees no
/// turn from before it joined (Sol R2-F1).
#[test]
fn a_room_turned_direct_during_a_list_keeps_its_bound() {
    use crate::conversation::{ConversationBody, HistoryChoice};

    let room = entity(0xB6);
    let (rooted, _) = rooted_reader_with(|vault, owner, reader| {
        let member = entity(0xB4);
        vault
            .put_entity(
                &member,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"a member",
            )
            .expect("put the member");
        let actor = WriteActor::new(owner, EdgeActorClass::Human);
        let body = ConversationBody {
            kind: ConversationKind::Group,
            member_ids: vec![member],
            ..ConversationBody::default()
        };
        vault
            .create_conversation(room, &body, actor, AT - 100)
            .expect("create the group");
        witness(
            vault,
            owner,
            room,
            entity(0xC5),
            AT,
            said(
                WitnessAuthor::User,
                "said before the reader joined",
                Some(entity(SPACE)),
            ),
        );
        vault
            .join_member(room, reader, actor, AT + 5, HistoryChoice::None)
            .expect("the reader joins without history");
    });
    let vault = &rooted.vault;
    let memory = rooted.reader.memory(vault);
    assert_eq!(preview_of(&memory, room), None);
    BEFORE_PREVIEWS.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |vault: &Vault| {
            let mut direct = vault.conversation_body(room).expect("the room's body");
            direct.kind = ConversationKind::Direct;
            vault
                .batch()
                .put(
                    &room,
                    ENTITY_TYPE_CONVERSATION,
                    TimeRange {
                        start: AT + 6,
                        end: AT + 6,
                    },
                    AT + 6,
                    &direct.to_bytes().expect("encode the body"),
                )
                .commit()
                .expect("the room now names itself direct");
        }));
    });
    assert_eq!(preview_of(&memory, room), None);
}

/// A message keeps its own place in a room's history whatever turn quotes
/// it: a later turn that also links a message from before the reader joined
/// never previews it for the late joiner, though the owner's preview quotes
/// it (Astra #1388b P1). One that also sits in another room, or whose
/// links pass the audience walk's bound, is not quoted either, and the list
/// still reads (Sol R4-F1, R5-F1).
#[test]
fn a_pre_join_message_a_later_turn_links_stays_hidden() {
    use crate::conversation::{ConversationBody, HistoryChoice};

    let (room, old, new) = (entity(0xB7), entity(0xC6), entity(0xC7));
    let words = "said before the reader joined";
    let (rooted, _) = rooted_reader_with(|vault, owner, reader| {
        let member = entity(0xB4);
        vault
            .put_entity(
                &member,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"a member",
            )
            .expect("put the member");
        let actor = WriteActor::new(owner, EdgeActorClass::Human);
        let body = ConversationBody {
            kind: ConversationKind::Group,
            member_ids: vec![member],
            ..ConversationBody::default()
        };
        vault
            .create_conversation(room, &body, actor, AT - 100)
            .expect("create the group");
        witness(
            vault,
            owner,
            room,
            old,
            AT,
            said(WitnessAuthor::User, words, Some(entity(SPACE))),
        );
        vault
            .join_member(room, reader, actor, AT + 5, HistoryChoice::None)
            .expect("the reader joins without history");
        let unseen = WitnessMessage {
            is_visible: false,
            ..said(WitnessAuthor::Companion, "never shown", Some(entity(SPACE)))
        };
        witness(vault, owner, room, new, AT + 10, unseen);
    });
    let vault = &rooted.vault;
    let memory = rooted.reader.memory(vault);
    assert_eq!(preview_of(&memory, room), None);
    let quoted = {
        let txn = vault.store.env.read_txn().expect("read txn");
        vault.turn_message_ids_in(&txn, &old).expect("messages")[0]
    };
    vault
        .batch()
        .edge(&quoted, crate::EdgeKind::PartOf, &new, 1.0)
        .commit()
        .expect("the later turn links the message");
    let owner = vault.memory(rooted.owner, EdgeActorClass::Human);
    assert_eq!(preview_of(&owner, room).as_deref(), Some(words));
    assert_eq!(preview_of(&memory, room), None);
    // A message another room's turn holds, linked to the same later turn,
    // has no one room: it is not quoted, and the list still reads (Sol
    // R4-F1).
    let (elsewhere, there) = (entity(0xB3), entity(0xC8));
    witness(
        vault,
        rooted.owner,
        elsewhere,
        there,
        AT + 20,
        said(
            WitnessAuthor::User,
            "said in another room",
            Some(entity(SPACE)),
        ),
    );
    let foreign = {
        let txn = vault.store.env.read_txn().expect("read txn");
        vault.turn_message_ids_in(&txn, &there).expect("messages")[0]
    };
    vault
        .batch()
        .edge(&foreign, crate::EdgeKind::PartOf, &new, 1.0)
        .commit()
        .expect("the later turn links another room's message");
    assert_eq!(preview_of(&memory, room), None);
    // Past the audience walk's edge bound the message has no one room
    // either (Sol R5-F1).
    let mut links = vault.batch();
    for n in 0..crate::limits::MAX_ANCESTOR_DEPTH as u128 {
        let elsewhere =
            EntityId::from_bytes(((0x82_u128 << 120) | n).to_be_bytes()).expect("a turn id");
        links = links.edge(&foreign, crate::EdgeKind::PartOf, &elsewhere, 1.0);
    }
    links
        .commit()
        .expect("the message is linked past the walk's bound");
    assert_eq!(preview_of(&memory, room), None);
}

/// A credential that cannot read base reality learns nothing about it: no
/// row, no count and no row-authority hint, however many conversations base
/// holds (DEC-0005: no name, no count; Astra #1388 P2), a conversation
/// replayed with no disclosure stamp included (Astra #1388b P2).
#[test]
fn a_world_the_credential_cannot_read_adds_no_count() {
    use crate::conversation::ConversationBody;
    use crate::federation::{ScopeAxis, ScopeId};

    let listed_with = |rooms: &[u8], replayed: &[u8]| {
        let witnessed: Vec<Witnessed> = rooms
            .iter()
            .map(|room| {
                (
                    entity(*room),
                    entity(room + 0x10),
                    AT,
                    said(WitnessAuthor::User, "base words", Some(entity(SPACE))),
                )
            })
            .collect();
        let (rooted, issuer) = rooted_reader(&witnessed);
        let body = ConversationBody::default()
            .to_bytes()
            .expect("encode the body");
        for room in replayed {
            rooted
                .vault
                .batch()
                .put_replicated(
                    &entity(*room),
                    ENTITY_TYPE_CONVERSATION,
                    TimeRange { start: AT, end: AT },
                    AT,
                    &body,
                )
                .commit()
                .expect("replay a conversation");
        }
        let mut scope = read_preset();
        scope.worlds = ScopeAxis::Some(std::collections::BTreeSet::from([ScopeId(entity(0x7A))]));
        let reader = Reader {
            credential: Some(reader_slip(
                &rooted.vault,
                &issuer,
                rooted.reader.id,
                scope,
                Vec::new(),
            )),
            ..rooted.reader
        };
        let read = reader_list(&rooted.vault, &reader, 50);
        let hinted = read
            .receipt
            .narrowed_axes
            .iter()
            .any(|axis| axis == "row_authority");
        (read.rows, read.total, read.withheld, hinted)
    };
    let one = listed_with(&[0x33], &[]);
    assert_eq!(one, (Vec::new(), Some(0), 0, false));
    assert_eq!(listed_with(&[0x33, 0x34], &[]), one);
    assert_eq!(listed_with(&[0x33], &[0x3A]), one);
    assert_eq!(listed_with(&[0x33], &[0x3A, 0x3B]), one);
}

/// The owner's own full credential reads as the owner: a manifest that
/// narrows the owner's `core:read` to messages never drops a conversation
/// from its list, the root project's room included (ARCH-0057; Astra #1388
/// P2). The owner's narrower credential stays bounded by the manifest. The
/// full credential still binds every read (Sol F1): a lane built with it
/// reads nothing once it is revoked.
#[test]
fn the_owners_full_credential_lists_what_the_owner_lists() {
    use crate::authority::HostSlipIssuer;
    use crate::federation::ScopeAxis;
    use crate::registry::ENTITY_TYPE_MESSAGE;

    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let room = entity(0xB8);
    witness(
        &vault,
        owner,
        room,
        entity(0xB9),
        AT,
        said(WitnessAuthor::User, "the owner's words", None),
    );
    let issuer = HostSlipIssuer::from_secret(b"conversation list owner manifest").expect("issuer");
    let root = vault.ensure_host_root_slip(&issuer).expect("host root");
    let mut messages_only = read_preset();
    messages_only.bands = ScopeAxis::Some(std::collections::BTreeSet::from([ENTITY_TYPE_MESSAGE]));
    crate::conversation_dag::test_support::put_test_policy_manifest(
        &vault,
        WriteActor::new(owner, EdgeActorClass::Human),
        entity(0x6d),
        &serde_json::json!({
            "schema_version": "1.2", "pack_id": "conversation-list-owner",
            "pack_version": "1", "min_engine_version": "0.0.0",
            "defaults": {}, "rules": [], "actor_ceilings": [],
            "scoped_grants": [{
                "actor_ref": owner.to_hex(), "actor_class": "human",
                "effector": "core:read", "scope": messages_only,
                "receipt_required": false,
            }],
        }),
    )
    .expect("the owner's narrowed read grant");
    let credential = |tag: &[u8], verbs: Option<&str>| {
        let mut claims = root.claims.clone();
        claims.slip_id = *blake3::hash(tag).as_bytes();
        claims.parent_id = None;
        claims.holder_ref = owner.to_hex();
        claims.actor_class = Some("human".into());
        if let Some(verb) = verbs {
            claims.scope.verbs = ScopeAxis::Some(std::collections::BTreeSet::from([verb.into()]));
        }
        let slip = vault.mint_capability_slip(&issuer, claims).expect("mint");
        let proof = issuer.binding_proof(&slip, tag).expect("binding proof");
        vault
            .verify_capability_slip(&issuer.public_key(), &slip, tag, &proof)
            .expect("verify")
    };
    let owner_list = |proof: Option<&crate::authority::VerifiedSlip>| {
        let memory = vault.memory(owner, EdgeActorClass::Human);
        let memory = match proof {
            Some(proof) => memory.with_read_proof(proof),
            None => memory,
        };
        listed(
            memory
                .conversation_list(ConversationListFilter::default(), None, 50, true)
                .expect("list conversations"),
        )
    };
    let plain = owner_list(None);
    assert!(
        plain
            .rows
            .contains(&(room, Some("the owner's words".to_owned())))
    );
    let root = root_room(&vault);
    assert!(plain.rows.iter().any(|(id, _)| *id == root));
    let full = credential(b"conversation-list-owner-manifest-full", None);
    assert!(full.is_full_vault_owner_grade());
    let with_full = owner_list(Some(&full));
    assert!(with_full.rows.iter().any(|(id, _)| *id == root));
    assert_eq!((with_full.rows, with_full.total), (plain.rows, plain.total));
    let narrow = credential(b"conversation-list-owner-manifest-read", Some("read"));
    assert!(owner_list(Some(&narrow)).rows.is_empty());

    let memory = vault
        .memory(owner, EdgeActorClass::Human)
        .with_read_proof(&full);
    let lane = memory
        .read_lane(ClaimReadStatus::Recorded)
        .expect("the owner's lane");
    let reads_room = || {
        lane.read(&[PointRead::id(room)], None)
            .is_ok_and(|read| read.value[0].is_some())
    };
    assert!(reads_room());
    vault
        .revoke_capability_slip(&issuer, full.claims().slip_id)
        .expect("revoke the full credential");
    assert!(!reads_room(), "a revoked credential reads nothing");
    assert!(owner_list(None).rows.iter().any(|(id, _)| *id == room));
}

/// A credential reads relationship words only on its holder's live grant
/// (ARCH-0006a rule 2; Astra #1388 P1, on main before this). A message in a
/// space the reader holds no grant for never previews. Revoking the grant
/// while the credential stays live takes the preview away. A message in no
/// space is the vault's own: the credential alone decides it, so the reader
/// still previews and recalls it.
#[test]
fn a_credential_reads_relationship_words_only_on_a_live_grant() {
    use crate::memory::{Effort, RecallScope};

    let (granted, ungranted, unscoped) = (entity(0xBA), entity(0xBB), entity(0xBE));
    let (granted_turn, ungranted_turn, unscoped_turn) = (entity(0xBC), entity(0xBD), entity(0xBF));
    let kettle = "the kettle hums by the stove";
    let ReaderVault {
        _dir,
        vault,
        reader,
        ..
    } = reader_vault(
        &[
            (
                granted,
                granted_turn,
                AT,
                said(
                    WitnessAuthor::User,
                    "words in the space",
                    Some(entity(SPACE)),
                ),
            ),
            (
                ungranted,
                ungranted_turn,
                AT + 10,
                said(WitnessAuthor::User, "words elsewhere", Some(entity(0x69))),
            ),
            (
                unscoped,
                unscoped_turn,
                AT + 20,
                said(WitnessAuthor::User, kettle, None),
            ),
        ],
        &[
            granted,
            granted_turn,
            ungranted,
            ungranted_turn,
            unscoped,
            unscoped_turn,
        ],
    );
    let read = reader_list(&vault, &reader, 50);
    assert!(
        read.rows
            .contains(&(granted, Some("words in the space".to_owned())))
    );
    assert!(read.rows.contains(&(ungranted, None)), "{:?}", read.rows);

    vault
        .revoke_access_grant(&entity(0x6b), crate::unix_seconds_now())
        .expect("revoke the grant");
    let read = reader_list(&vault, &reader, 50);
    assert!(read.rows.contains(&(granted, None)), "{:?}", read.rows);
    assert!(
        read.rows.contains(&(unscoped, Some(kettle.to_owned()))),
        "{:?}",
        read.rows
    );
    let pack = reader
        .memory(&vault)
        .recall(
            "kettle",
            Effort::Light,
            &RecallScope::default(),
            20,
            None,
            None,
        )
        .expect("recall");
    assert!(
        pack.items.iter().any(|item| item
            .cited_messages
            .iter()
            .any(|message| message.value_text == kettle)),
        "{:?}",
        pack.items
    );
}
