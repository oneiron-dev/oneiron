//! The conversation list is what its reader may read of the vault
//! (ARCH-0006a, DEC-0005): only the conversations it may read, each previewed
//! by a message it may read and never an erased one, with a receipt that
//! counts what was withheld. The owner's list is the one it always was.

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

/// A rooted vault whose owner witnessed two conversations. The first has a
/// turn whose message is in a space the reader holds a Messages grant on, a
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
    let space = entity(0x68);
    let (kept, other) = (entity(0xD8), entity(0xD9));
    let turns = [entity(0xD4), entity(0xD5), entity(0xD6)];
    let (user, companion) = (WitnessAuthor::User, WitnessAuthor::Companion);
    for (room, turn, at, message) in [
        (
            kept,
            turns[0],
            AT,
            said(user, "a table for two by the window", Some(space)),
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
            said(companion, "booked for friday at eight", Some(space)),
        ),
        (
            other,
            entity(0xD7),
            AT + 30,
            said(user, "the spare key is under the mat", Some(space)),
        ),
    ] {
        witness(&vault, owner, room, turn, at, message);
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
                scope: AccessGrantScope::Messages { space_ref: space },
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
    let mut rows = vec![kept];
    for turn in turns {
        rows.push(turn);
        rows.extend(vault.turn_message_ids_in(&txn, &turn).expect("messages"));
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
    ScopedVault {
        _dir: dir,
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
    // Every other conversation, and the message outside the reader's grant
    // that the preview read passed over.
    assert_eq!(read.withheld, all.rows.len() - 1 + 1);

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
}
