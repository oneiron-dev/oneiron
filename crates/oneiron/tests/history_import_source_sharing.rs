//! L2-18 PR 1 (ARCH-0027 #import-audience): a history import keeps a
//! source's own sharing. A conversation the source shared reads to the
//! members the owner mapped to a PERSON and to the importer, through the
//! read judge every scoped read applies (`readable_with_read_in`); a later
//! import that names fewer members takes the read away from the ones it no
//! longer names. On main the import binds no row, so every row reads to
//! everyone the vault's other rules let read.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test history_import_source_sharing`
#![cfg(oneiron_test_support)]

use oneiron::ingest::history::{
    HistoryConversation, HistoryImportReport, HistoryMember, HistoryMessage, HistoryRole,
    HistorySharing, HistorySkips, HistorySource, HistoryThreadKind,
};
use oneiron::test_doors::history_import_rows::{ImportedMessageRows, imported_message_rows};
use oneiron::test_doors::source_audience_binding::reads;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SOURCE: HistorySource = HistorySource::Chatgpt;
const IMPORTED_AT: u64 = 1_700_100_000;

struct Fixture {
    _dir: TempDir,
    vault: Vault,
    owner_actor: EntityId,
    owen: EntityId,
    yuki: EntityId,
}

/// A vault whose embedded owner imports, with two PERSONs, owen and yuki.
fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's import door asks for.
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner_actor = vault.ensure_embedded_owner_actor()?;
    let person = |body: &[u8]| -> Result<EntityId, Box<dyn std::error::Error>> {
        let id = EntityId::now();
        vault.put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            body,
        )?;
        Ok(id)
    };
    let owen = person(b"owen")?;
    let yuki = person(b"yuki")?;
    Ok(Fixture {
        _dir: dir,
        vault,
        owner_actor,
        owen,
        yuki,
    })
}

fn message(native_id: &str, role: HistoryRole, text: &str, at_ms: u64) -> HistoryMessage {
    HistoryMessage {
        native_id: native_id.to_owned(),
        parent_id: None,
        role,
        text: text.to_owned(),
        at_ms: Some(at_ms),
        said_by: None,
        tools: Vec::new(),
        alias: None,
    }
}

fn member(provider_id: &str, person: Option<EntityId>) -> HistoryMember {
    HistoryMember {
        provider_id: provider_id.to_owned(),
        person,
    }
}

/// One conversation of two one-speaker turns. Its own start is earlier than
/// its first message, so each import also puts its CONVERSATION again with
/// that start (`settle`).
fn conversation(sharing: Option<HistorySharing>) -> HistoryConversation {
    HistoryConversation {
        native_id: "chan-venue".to_owned(),
        kind: HistoryThreadKind::Main,
        parent: None,
        title: Some("venue".to_owned()),
        started_at_ms: Some(1_699_990_000_000),
        own_started_at_ms: Some(1_699_990_000_000),
        cwd: None,
        messages: vec![
            message(
                "m1",
                HistoryRole::User,
                "the venue is booked for Friday",
                1_700_000_000_000,
            ),
            message(
                "m2",
                HistoryRole::Assistant,
                "noted: Friday at the venue",
                1_700_000_060_000,
            ),
        ],
        skipped: HistorySkips::default(),
        sharing,
    }
}

fn shared_with(members: Vec<HistoryMember>) -> Option<HistorySharing> {
    Some(HistorySharing {
        container: "test:team:chan-venue".to_owned(),
        members,
    })
}

fn import(
    fixture: &Fixture,
    conversation: &HistoryConversation,
) -> Result<HistoryImportReport, Box<dyn std::error::Error>> {
    let owner = fixture
        .vault
        .memory(fixture.owner_actor, EdgeActorClass::Human)
        .embedded_owner("vault.import")?;
    Ok(fixture
        .vault
        .import_history(&owner, SOURCE, conversation, IMPORTED_AT)?)
}

fn rows(
    fixture: &Fixture,
    native_id: &str,
) -> Result<ImportedMessageRows, Box<dyn std::error::Error>> {
    imported_message_rows(&fixture.vault, SOURCE, native_id)?
        .ok_or_else(|| format!("message {native_id} did not land").into())
}

/// Every row the import landed: the CONVERSATION, both TURNs and both
/// MESSAGEs.
fn landed(fixture: &Fixture) -> Result<Vec<EntityId>, Box<dyn std::error::Error>> {
    let first = rows(fixture, "m1")?;
    let second = rows(fixture, "m2")?;
    Ok(vec![
        first.conversation,
        first.turn,
        first.message,
        second.turn,
        second.message,
    ])
}

#[test]
fn an_import_carrying_source_sharing_binds_its_rows_to_the_members_policy() -> TestResult {
    let fixture = fixture()?;
    let report = import(
        &fixture,
        &conversation(shared_with(vec![
            member("U1", Some(fixture.owen)),
            member("U2", None),
        ])),
    )?;
    assert_eq!((report.new, report.refused, report.pending), (2, 0, 0));
    // The CONVERSATION put again with its own start keeps its stamp.
    assert!(
        report.refusal_reasons.is_empty(),
        "{:?}",
        report.refusal_reasons
    );
    for row in landed(&fixture)? {
        assert!(
            reads(&fixture.vault, row, &[fixture.owen])?,
            "the mapped member reads {row:?}"
        );
        assert!(
            reads(&fixture.vault, row, &[fixture.owner_actor])?,
            "the importer reads {row:?}"
        );
        assert!(
            !reads(&fixture.vault, row, &[fixture.yuki])?,
            "a person the source did not share with reads nothing of {row:?}"
        );
    }
    Ok(())
}

#[test]
fn a_reimport_without_a_member_takes_that_members_read_away() -> TestResult {
    let fixture = fixture()?;
    import(
        &fixture,
        &conversation(shared_with(vec![
            member("U1", Some(fixture.owen)),
            member("U2", Some(fixture.yuki)),
        ])),
    )?;
    let message = rows(&fixture, "m1")?.message;
    assert!(reads(&fixture.vault, message, &[fixture.yuki])?);

    let report = import(
        &fixture,
        &conversation(shared_with(vec![member("U1", Some(fixture.owen))])),
    )?;
    assert_eq!((report.new, report.skipped), (0, 2), "nothing lands again");
    assert_eq!(fixture.vault.history_import_ledger_len(SOURCE)?, 2);
    for row in landed(&fixture)? {
        assert!(
            !reads(&fixture.vault, row, &[fixture.yuki])?,
            "a member the source no longer names reads nothing of {row:?}"
        );
        assert!(reads(&fixture.vault, row, &[fixture.owen])?);
    }
    Ok(())
}

#[test]
fn a_member_mapped_to_no_live_person_refuses_the_import() -> TestResult {
    let fixture = fixture()?;
    let refused = import(
        &fixture,
        &conversation(shared_with(vec![member("U1", Some(EntityId::now()))])),
    );
    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(fixture.vault.history_import_ledger_len(SOURCE)?, 0);
    assert!(imported_message_rows(&fixture.vault, SOURCE, "m1")?.is_none());
    Ok(())
}

/// Control, green on main too: a conversation its source did not share
/// lands unbound, as every history import did before.
#[test]
fn an_import_without_sharing_lands_unbound() -> TestResult {
    let fixture = fixture()?;
    let report = import(&fixture, &conversation(None))?;
    assert_eq!(report.new, 2);
    for row in landed(&fixture)? {
        assert!(reads(&fixture.vault, row, &[fixture.yuki])?);
    }
    Ok(())
}
