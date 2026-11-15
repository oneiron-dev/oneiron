//! L2-18 PR 2, review round 1: what a later import of a Slack workspace does
//! to what an earlier one landed.
//! - A listed conversation with no messages still sets its readers again,
//!   so a member the later export no longer shares it with reads none of it
//!   (PR 1's rule: each later import sets a container's readers again).
//! - A message's id carries its workspace, so the same folder and Slack time
//!   in two workspaces land as two messages.
//! - A member map that moves a member to or from the owner lands the
//!   member's words again, as a revision under their new author.
//!
//! At the head before the fix, the empty conversation is dropped, the
//! second workspace's message is taken for the first's, and the remapped
//! words are skipped as already landed.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test history_import_slack_reimport`
#![cfg(oneiron_test_support)]

use oneiron::ingest::history::slack::{self, SlackExport, SlackExportFile, SlackWorkspace};
use oneiron::ingest::history::{HistoryImportReport, HistorySource};
use oneiron::test_doors::history_import_rows::imported_message_rows;
use oneiron::test_doors::source_audience_binding::reads;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const IMPORTED_AT: u64 = 1_800_000_000;

struct Fixture {
    _dir: TempDir,
    vault: Vault,
    owner_actor: EntityId,
    yuki: EntityId,
}

/// A vault whose embedded owner imports, with one PERSON, yuki.
fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's import door asks for.
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner_actor = vault.ensure_embedded_owner_actor()?;
    let yuki = EntityId::now();
    vault.put_entity(
        &yuki,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"yuki",
    )?;
    Ok(Fixture {
        _dir: dir,
        vault,
        owner_actor,
        yuki,
    })
}

/// An export of workspace `team`, whose members are owen (U0) and yuki (U1),
/// with the further files `files` (by path under the export's folder).
fn export(team: &str, files: &[(&str, &str)]) -> SlackExport {
    let users = format!(
        r#"[
          {{"id": "U0", "team_id": "{team}", "name": "owen", "profile": {{}}}},
          {{"id": "U1", "team_id": "{team}", "name": "yuki", "profile": {{}}}}
        ]"#
    );
    SlackExport {
        workspace: "Example".to_owned(),
        files: std::iter::once(("users.json", users.as_str()))
            .chain(files.iter().copied())
            .map(|(path, text)| SlackExportFile {
                path: path.to_owned(),
                text: text.to_owned(),
            })
            .collect(),
    }
}

/// Decodes `export`, applies the member map `map` (JSON) and imports every
/// conversation as `oneiron import slack` does. Returns the decoded workspace
/// and the report of each conversation, in the workspace's order.
fn import(
    fixture: &Fixture,
    export: &SlackExport,
    map: &str,
) -> Result<(SlackWorkspace, Vec<HistoryImportReport>), Box<dyn std::error::Error>> {
    let mut workspace = slack::decode(export)?;
    workspace.map_members(&slack::parse_member_map(map)?)?;
    let owner = fixture
        .vault
        .memory(fixture.owner_actor, EdgeActorClass::Human)
        .embedded_owner("vault.import")?;
    let mut reports = Vec::new();
    for conversation in &workspace.conversations {
        reports.push(fixture.vault.import_history(
            &owner,
            HistorySource::Slack,
            conversation,
            IMPORTED_AT,
        )?);
    }
    Ok((workspace, reports))
}

/// The id of the one message `workspace` decoded.
fn only_message(workspace: &SlackWorkspace) -> Result<String, Box<dyn std::error::Error>> {
    let mut ids = workspace
        .conversations
        .iter()
        .flat_map(|conversation| &conversation.messages)
        .map(|message| message.native_id.clone());
    let id = ids.next().ok_or("the export decodes one message")?;
    assert!(ids.next().is_none(), "the export decodes one message");
    Ok(id)
}

/// The MESSAGE the latest text of the message `native_id` landed as.
fn latest_message(
    fixture: &Fixture,
    native_id: &str,
) -> Result<EntityId, Box<dyn std::error::Error>> {
    Ok(
        imported_message_rows(&fixture.vault, HistorySource::Slack, native_id)?
            .ok_or_else(|| format!("message {native_id} did not land"))?
            .message,
    )
}

/// The author a MESSAGE row names (`user` for the owner's words).
fn author(fixture: &Fixture, message: EntityId) -> Result<String, Box<dyn std::error::Error>> {
    let body = fixture
        .vault
        .get(&message)?
        .ok_or("a landed MESSAGE has a body")?;
    let value = rmpv::decode::read_value(&mut &body[..]).map_err(|error| format!("{error:?}"))?;
    value
        .as_map()
        .and_then(|fields| {
            fields.iter().find_map(|(field, value)| {
                (field.as_str() == Some("author"))
                    .then(|| value.as_str().map(str::to_owned))
                    .flatten()
            })
        })
        .ok_or_else(|| "a MESSAGE names its author".into())
}

/// How many messages the import landed new, and how many as a revision.
fn landed(reports: &[HistoryImportReport]) -> (u32, u32) {
    reports.iter().fold((0, 0), |(new, changed), report| {
        (new + report.new, changed + report.changed)
    })
}

const BOARD: (&str, &str) = (
    "board/2026-11-01.json",
    r#"[{"type": "message", "user": "U1", "text": "budget is set", "ts": "1761955600.000100"}]"#,
);

const DM: (&str, &str) = (
    "dms.json",
    r#"[{"id": "D1", "created": 1761955000, "members": ["U0", "U1"]}]"#,
);

const DM_DAY: (&str, &str) = (
    "D1/2026-11-01.json",
    r#"[{"type": "message", "user": "U0", "text": "see you at noon", "ts": "1761955700.000100"}]"#,
);

#[test]
fn a_reimport_listing_a_conversation_with_no_messages_takes_an_unshared_members_read_away()
-> TestResult {
    let fixture = fixture()?;
    let map = format!(r#"{{"U0": "owner", "U1": "{}"}}"#, fixture.yuki.to_hex());
    let shared = (
        "groups.json",
        r#"[{"id": "G1", "name": "board", "created": 1761955100, "members": ["U0", "U1"]}]"#,
    );
    let (workspace, _) = import(&fixture, &export("T1", &[shared, BOARD]), &map)?;
    let message = latest_message(&fixture, &only_message(&workspace)?)?;
    assert!(
        reads(&fixture.vault, message, &[fixture.yuki])?,
        "board reads to yuki, whom the export shares it with"
    );

    // A later export lists board without yuki, and holds no day of it.
    let unshared = (
        "groups.json",
        r#"[{"id": "G1", "name": "board", "created": 1761955100, "members": ["U0"]}]"#,
    );
    let (_, reports) = import(&fixture, &export("T1", &[unshared]), &map)?;
    assert_eq!(landed(&reports), (0, 0), "nothing lands again");
    assert!(
        !reads(&fixture.vault, message, &[fixture.yuki])?,
        "a member the later export no longer shares board with reads none of it"
    );
    Ok(())
}

#[test]
fn two_workspaces_with_one_folder_name_land_one_message_each() -> TestResult {
    let fixture = fixture()?;
    // No list names `general`: each export keeps it as a folder of its own
    // workspace. Same Slack time, same words.
    let day = (
        "general/2026-11-01.json",
        r#"[{"type": "message", "user": "U1", "text": "the venue is booked", "ts": "1761955300.000100"}]"#,
    );
    let (first, reports) = import(&fixture, &export("T1", &[day]), "{}")?;
    assert_eq!(landed(&reports), (1, 0));
    let (second, reports) = import(&fixture, &export("T2", &[day]), "{}")?;
    assert_ne!(only_message(&first)?, only_message(&second)?);
    assert_eq!(
        landed(&reports),
        (1, 0),
        "the second workspace's message lands as its own"
    );
    assert_eq!(
        fixture
            .vault
            .history_import_ledger_len(HistorySource::Slack)?,
        2
    );
    Ok(())
}

#[test]
fn a_reimport_that_maps_a_member_to_the_owner_lands_its_words_as_the_owners() -> TestResult {
    let fixture = fixture()?;
    let files = [DM, DM_DAY];
    let (workspace, _) = import(&fixture, &export("T1", &files), "{}")?;
    let native_id = only_message(&workspace)?;
    let as_contact = latest_message(&fixture, &native_id)?;
    assert_eq!(author(&fixture, as_contact)?, "counterparty");

    let (_, reports) = import(&fixture, &export("T1", &files), r#"{"U0": "owner"}"#)?;
    assert_eq!(
        landed(&reports),
        (0, 1),
        "the owner's words land again, as a revision under their new author"
    );
    let as_owner = latest_message(&fixture, &native_id)?;
    assert_ne!(as_owner, as_contact);
    assert_eq!(author(&fixture, as_owner)?, "user");

    // And back: the map no longer names the owner.
    let (_, reports) = import(&fixture, &export("T1", &files), "{}")?;
    assert_eq!(landed(&reports), (0, 1), "a contact's words land again");
    assert_eq!(
        author(&fixture, latest_message(&fixture, &native_id)?)?,
        "counterparty"
    );
    Ok(())
}

#[test]
fn a_reimport_with_the_same_map_lands_nothing_again() -> TestResult {
    let files = [DM, DM_DAY];
    for map in [r#"{"U0": "owner"}"#, "{}"] {
        let fixture = fixture()?;
        let (workspace, reports) = import(&fixture, &export("T1", &files), map)?;
        assert_eq!(landed(&reports), (1, 0));
        let native_id = only_message(&workspace)?;
        let first = latest_message(&fixture, &native_id)?;
        let (_, reports) = import(&fixture, &export("T1", &files), map)?;
        assert_eq!(landed(&reports), (0, 0), "map {map}: nothing lands again");
        assert_eq!(latest_message(&fixture, &native_id)?, first);
    }
    Ok(())
}
