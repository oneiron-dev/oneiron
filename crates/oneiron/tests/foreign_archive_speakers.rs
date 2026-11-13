//! Fix list row 15412, slice 3b (archive half): the import door names whose
//! words a whole-vault archive's conversations hold (`ArchiveSpeakers`), and
//! nothing in the archive decides it.
//!
//! * `foreign_archive_speech_lands_counterparty`: an archive of a vault where
//!   the owner and the companion spoke, imported with foreign speakers into a
//!   fresh vault, lands each MESSAGE as a `counterparty`'s, its original
//!   author kept as `metadata.import.source_author`, and marks the MESSAGE
//!   (`metadata.import.speakers`), each TURN and the CONVERSATION
//!   (`import_speakers`) as a foreign archive's words.
//! * `own_import_of_foreign_restored_speech_is_refused_by_name`: the same
//!   archive again with foreign speakers is an exact repeat; with own
//!   speakers it is refused, naming the choice already here.
//! * `own_archive_speech_keeps_its_authors`: a guard. With own speakers every
//!   MESSAGE keeps its author and carries no foreign mark.
//!
//! Red at the red pin (the PR's base plus doors that take the choice and
//! import as own): the first two fail at their asserts; the guard passes.
//!
//! Public doors only; vaults in tempdirs. Each destination opens at least one
//! wall-clock second after its source (sleep 1100 ms), as in
//! `whole_vault_restore_seeds.rs`. Run with
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test foreign_archive_speakers`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::batch::export::ArchiveSpeakers;
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_MESSAGE;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use rmpv::Value;

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

fn message(author: WitnessAuthor, content: &str, order: u32) -> WitnessMessage {
    WitnessMessage {
        id: None,
        author,
        message_type: "dialogue".to_owned(),
        content: content.to_owned(),
        parts: None,
        metadata: None,
        is_visible: true,
        order,
        quote: None,
    }
}

/// What the source vault holds: one CONVERSATION in which the owner spoke a
/// TURN and the companion answered in the next.
struct Spoken {
    archive: Vec<u8>,
    turns: Vec<EntityId>,
    conversation: EntityId,
    messages: Vec<EntityId>,
}

/// A source vault where the owner spoke one TURN and the companion answered
/// in the next (a witnessed TURN carries one non-system speaker), and its
/// whole-vault archive.
fn spoken_archive() -> Spoken {
    let (_dir, source) = open_vault();
    let owner = source
        .ensure_embedded_owner_actor()
        .expect("embedded owner");
    let memory = source.memory(owner, EdgeActorClass::Human);
    let conversation = EntityId::now();
    let occurred_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let turns: Vec<EntityId> = [
        (WitnessAuthor::User, "Repot the basil on Sunday."),
        (WitnessAuthor::Companion, "Sunday it is."),
    ]
    .into_iter()
    .map(|(author, content)| {
        memory
            .witness(&WitnessTurn {
                conversation_ref: conversation.to_hex(),
                turn_ref: None,
                thread_audience: None,
                messages: vec![message(author, content, 0)],
                occurred_at,
                assertions: WitnessAssertions::default(),
            })
            .expect("witness the turn")
            .turn_id
    })
    .collect();
    let messages = source
        .entities_by_type(ENTITY_TYPE_MESSAGE)
        .expect("list MESSAGE rows");
    assert_eq!(messages.len(), 2, "the source holds the two MESSAGE rows");
    let archive = source
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    Spoken {
        archive,
        turns,
        conversation,
        messages,
    }
}

fn decode(body: &[u8]) -> Value {
    rmpv::decode::read_value(&mut &body[..]).expect("a msgpack body")
}

fn field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_map()?
        .iter()
        .find_map(|(name, value)| (name.as_str() == Some(key)).then_some(value))
}

fn text(value: &Value, key: &str) -> Option<String> {
    field(value, key).and_then(Value::as_str).map(str::to_owned)
}

/// The stored body of `id` in `vault`, decoded.
fn stored(vault: &Vault, id: &EntityId) -> Value {
    decode(
        &vault
            .get(id)
            .expect("read the row")
            .unwrap_or_else(|| panic!("row {} is stored", id.to_hex())),
    )
}

/// Each archived MESSAGE as `vault` holds it: (author, the author its
/// import provenance keeps, its admission mark), sorted.
fn message_authors(
    vault: &Vault,
    messages: &[EntityId],
) -> Vec<(String, Option<String>, Option<String>)> {
    let mut authors: Vec<_> = messages
        .iter()
        .map(|id| {
            let body = stored(vault, id);
            let import = field(&body, "metadata")
                .and_then(|metadata| field(metadata, "import"))
                .unwrap_or_else(|| panic!("MESSAGE {} carries its import provenance", id.to_hex()));
            (
                text(&body, "author").expect("a MESSAGE names its author"),
                text(import, "source_author"),
                text(import, "speakers"),
            )
        })
        .collect();
    authors.sort();
    authors
}

fn foreign(author: &str) -> (String, Option<String>, Option<String>) {
    (
        "counterparty".to_owned(),
        Some(author.to_owned()),
        Some("foreign".to_owned()),
    )
}

#[test]
fn foreign_archive_speech_lands_counterparty() {
    let spoken = spoken_archive();
    let (_dir, dest) = open_later_vault();
    let receipt = dest
        .import_whole_vault_archive_from_with_speakers(
            Cursor::new(&spoken.archive),
            ArchiveSpeakers::Foreign,
        )
        .expect("the foreign import lands");
    assert_eq!(receipt.speakers, ArchiveSpeakers::Foreign);
    assert_eq!(
        message_authors(&dest, &spoken.messages),
        [foreign("companion"), foreign("user")],
        "each MESSAGE speaks as a counterparty, its author kept inert"
    );
    let rows = spoken
        .turns
        .iter()
        .map(|turn| (turn, "TURN"))
        .chain([(&spoken.conversation, "CONVERSATION")]);
    for (row, name) in rows {
        assert_eq!(
            text(&stored(&dest, row), "import_speakers").as_deref(),
            Some("foreign"),
            "the {name} carries the foreign admission mark"
        );
    }
}

#[test]
fn own_import_of_foreign_restored_speech_is_refused_by_name() {
    let spoken = spoken_archive();
    let (_dir, dest) = open_later_vault();
    dest.import_whole_vault_archive_from_with_speakers(
        Cursor::new(&spoken.archive),
        ArchiveSpeakers::Foreign,
    )
    .expect("the foreign import lands");
    dest.import_whole_vault_archive_from_with_speakers(
        Cursor::new(&spoken.archive),
        ArchiveSpeakers::Foreign,
    )
    .expect("the same choice again is an exact repeat");
    let refusal = dest
        .import_whole_vault_archive_from_with_speakers(
            Cursor::new(&spoken.archive),
            ArchiveSpeakers::Own,
        )
        .expect_err("the other choice is refused");
    assert!(
        refusal
            .to_string()
            .contains("already here with foreign speakers"),
        "the refusal names the choice already here: {refusal}"
    );
    assert_eq!(
        message_authors(&dest, &spoken.messages),
        [foreign("companion"), foreign("user")],
        "the refused import rewrote nothing"
    );
}

#[test]
fn own_archive_speech_keeps_its_authors() {
    let spoken = spoken_archive();
    let (_dir, dest) = open_later_vault();
    let receipt = dest
        .import_whole_vault_archive_from_with_speakers(
            Cursor::new(&spoken.archive),
            ArchiveSpeakers::Own,
        )
        .expect("the own import lands");
    assert_eq!(receipt.speakers, ArchiveSpeakers::Own);
    assert_eq!(
        message_authors(&dest, &spoken.messages),
        [
            ("companion".to_owned(), None, None),
            ("user".to_owned(), None, None),
        ],
        "each MESSAGE keeps its author and carries no foreign mark"
    );
}
