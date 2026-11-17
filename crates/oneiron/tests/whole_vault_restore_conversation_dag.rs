//! Fix list row WHOLE-VAULT-IMPORT-REFUSES-CONVERSATION-DAG: a whole-vault
//! archive of a vault holding a CONVERSATION of two witnessed TURNs imports,
//! and the second TURN keeps its `parent` edge to the first.
//!
//! * `owner_restore_keeps_the_second_turn_parent`: the owner's restore into a
//!   fresh vault lands the `parent` edge with the TURNs; the restored
//!   conversation's HEAD, adopted at the first read, is the second TURN.
//! * `actor_import_keeps_the_second_turn_parent`: the same through the
//!   actor-taking door.
//! * `actorless_import_again_is_an_exact_repeat`: the actorless door lands
//!   the conversation, and the same archive again, after the first read
//!   adopted the restored conversation, is an exact repeat.
//!
//! Red on main (cc184ff09aea): each test fails at its first import, which
//! refuses the archived `parent` edge with
//! `Registry(ReservedEdgeKind("conversation_dag"))`; the source preconditions
//! pass.
//!
//! Vaults in tempdirs, every step through public doors. Each destination
//! opens at least one wall-clock second after its source (sleep 1100 ms), as
//! in `whole_vault_restore_seeds.rs`. Run with `cargo test --locked -p
//! oneiron --all-features --test whole_vault_restore_conversation_dag`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeKind;
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// A fresh SEEDED destination whose engine-seed seconds differ from the
/// source's: any 1100 ms interval crosses a second boundary.
fn open_later_vault() -> (tempfile::TempDir, Vault) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    open_vault()
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

fn message(author: WitnessAuthor, content: &str) -> WitnessMessage {
    WitnessMessage {
        id: None,
        author,
        message_type: "dialogue".to_owned(),
        content: content.to_owned(),
        parts: None,
        metadata: None,
        is_visible: true,
        order: 0,
        quote: None,
    }
}

/// What the source vault holds: one CONVERSATION, its two TURNs in witness
/// order, and its whole-vault archive.
struct Conversation {
    archive: Vec<u8>,
    conversation: EntityId,
    first: EntityId,
    second: EntityId,
}

/// A source vault where the owner spoke one TURN and the companion answered
/// in a second TURN of the same CONVERSATION (a witnessed TURN carries one
/// non-system speaker). The second TURN joins the conversation DAG by a
/// `parent` edge to the first.
fn two_turn_archive() -> Conversation {
    let (_dir, source) = open_vault();
    let owner = source
        .ensure_embedded_owner_actor()
        .expect("embedded owner");
    let memory = source.memory(owner, EdgeActorClass::Human);
    let occurred_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let conversation = EntityId::now();
    let witness = |author, content, at| {
        memory
            .witness(&WitnessTurn {
                conversation_ref: conversation.to_hex(),
                turn_ref: None,
                thread_audience: None,
                messages: vec![message(author, content)],
                occurred_at: Some(at),
                assertions: WitnessAssertions::default(),
                project: None,
            })
            .expect("witness the turn")
            .turn_id
    };
    let first = witness(
        WitnessAuthor::User,
        "Repot the basil on Sunday.",
        occurred_at,
    );
    let second = witness(WitnessAuthor::Companion, "Sunday it is.", occurred_at + 1);
    assert!(
        source
            .edge_exists(&second, EdgeKind::Parent, &first)
            .expect("read the source parent edge"),
        "precondition: the second TURN joins the source DAG by a parent edge"
    );
    assert_eq!(
        source.head(&conversation).expect("source HEAD"),
        Some(second),
        "precondition: the source HEAD is the second TURN"
    );
    let archive = source
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    Conversation {
        archive,
        conversation,
        first,
        second,
    }
}

/// The restored conversation keeps its DAG: the second TURN's one `parent`
/// edge names the first, the first has none, and the HEAD this vault adopts
/// is the second TURN.
fn assert_restored_dag(dest: &Vault, restored: &Conversation) {
    assert_eq!(
        dest.targets(&restored.second, EdgeKind::Parent, None)
            .expect("read the second TURN's parent"),
        [restored.first],
        "the second TURN keeps its one parent edge"
    );
    assert!(
        dest.targets(&restored.first, EdgeKind::Parent, None)
            .expect("read the first TURN's parent")
            .is_empty(),
        "the first TURN is the root"
    );
    assert_eq!(
        dest.head(&restored.conversation).expect("restored HEAD"),
        Some(restored.second),
        "the restored conversation's HEAD is the second TURN"
    );
}

#[test]
fn owner_restore_keeps_the_second_turn_parent() {
    let restored = two_turn_archive();
    let (_dir, dest) = open_later_vault();
    let owner = owner_proof(&dest);
    dest.import_whole_vault_archive_from_as_owner(Cursor::new(&restored.archive), &owner)
        .expect("the owner's restore lands the conversation");
    assert_restored_dag(&dest, &restored);
}

#[test]
fn actor_import_keeps_the_second_turn_parent() {
    let restored = two_turn_archive();
    let (_dir, dest) = open_later_vault();
    let owner = dest.ensure_embedded_owner_actor().expect("embedded owner");
    dest.import_whole_vault_archive_with_actor(
        &restored.archive,
        &WriteActor::new(owner, EdgeActorClass::Human),
    )
    .expect("the actor import lands the conversation");
    assert_restored_dag(&dest, &restored);
}

#[test]
fn actorless_import_again_is_an_exact_repeat() {
    let restored = two_turn_archive();
    let (_dir, dest) = open_later_vault();
    dest.import_whole_vault_archive_from(Cursor::new(&restored.archive))
        .expect("the actorless import lands the conversation");
    assert_restored_dag(&dest, &restored);
    dest.import_whole_vault_archive_from(Cursor::new(&restored.archive))
        .expect("the same archive again is an exact repeat");
    assert_restored_dag(&dest, &restored);
}
