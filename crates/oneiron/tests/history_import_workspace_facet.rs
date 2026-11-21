//! L2-18 PR 2b (Engine rulings L2-18-WORKSPACE-SCOPE = A and
//! L2-18-WORKSPACE-FACET-CARRIER = A, 15 Nov): a shared workspace's import
//! lands its TURNs under the workspace's own FACET, named after it, worn by
//! the importer, made once and found again by name. The CONVERSATION and
//! MESSAGE rows keep their substrate facet, as for every source (the FacetOf
//! table admits neither, ONE-1645). The owner's default recall is not
//! narrowed by it ("The owner is never limited by a facet", ARCH-0022:125):
//! a TURN under the workspace facet is recalled as its twin under the vault
//! default is. On the base there is no workspace facet and no import into
//! one.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test history_import_workspace_facet`
#![cfg(oneiron_test_support)]

use oneiron::consent::AuthenticatedOwner;
use oneiron::ingest::history::{
    HistoryConversation, HistoryMember, HistoryMessage, HistoryRole, HistorySharing, HistorySkips,
    HistorySource, HistoryThreadKind,
};
use oneiron::memory::{Effort, RecallScope};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::test_doors::history_import_rows::{ImportedMessageRows, imported_message_rows};
use oneiron::{EdgeActorClass, EdgeKind, EntityId, Vault, VaultConfig};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SOURCE: HistorySource = HistorySource::Slack;
const IMPORTED_AT: u64 = 1_700_100_000;
const WORKSPACE: &str = "Example";

struct Fixture {
    _dir: TempDir,
    vault: Vault,
    owner_actor: EntityId,
    owner: AuthenticatedOwner,
}

/// A vault whose embedded owner imports; the owner is a live PERSON, so it
/// wears the workspace's facet.
fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's import door asks for.
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner_actor = vault.ensure_embedded_owner_actor()?;
    let owner = vault
        .memory(owner_actor, EdgeActorClass::Human)
        .embedded_owner("vault.import")?;
    Ok(Fixture {
        _dir: dir,
        vault,
        owner_actor,
        owner,
    })
}

/// One shared channel's conversation of two messages, each carrying `marker`.
fn conversation(native_id: &str, marker: &str) -> HistoryConversation {
    let message = |id: &str, role, text: String, at_ms| HistoryMessage {
        native_id: format!("{native_id}:{id}"),
        parent_id: None,
        role,
        text,
        at_ms: Some(at_ms),
        said_by: None,
        tools: Vec::new(),
        alias: None,
    };
    HistoryConversation {
        native_id: native_id.to_owned(),
        kind: HistoryThreadKind::Main,
        parent: None,
        title: Some("general".to_owned()),
        started_at_ms: Some(1_699_990_000_000),
        own_started_at_ms: None,
        cwd: None,
        messages: vec![
            message(
                "1",
                HistoryRole::User,
                format!("the deploy needs a {marker} review"),
                1_700_000_000_000,
            ),
            message(
                "2",
                HistoryRole::Assistant,
                format!("noted: the {marker} review is booked"),
                1_700_000_060_000,
            ),
        ],
        skipped: HistorySkips::default(),
        sharing: Some(HistorySharing {
            container: native_id.to_owned(),
            members: vec![HistoryMember {
                provider_id: "U0".to_owned(),
                name: Some("owen".to_owned()),
                person: None,
                importer: true,
            }],
        }),
    }
}

fn landed_rows(
    fixture: &Fixture,
    native_id: &str,
) -> Result<ImportedMessageRows, Box<dyn std::error::Error>> {
    imported_message_rows(&fixture.vault, SOURCE, native_id)?
        .ok_or_else(|| format!("message {native_id} did not land").into())
}

/// The FACET a row was born under: its one FacetOf edge.
fn birth_facets(
    vault: &Vault,
    row: &EntityId,
) -> Result<Vec<EntityId>, Box<dyn std::error::Error>> {
    Ok(vault.targets(row, EdgeKind::FacetOf, Some(ENTITY_TYPE_FACET))?)
}

#[test]
fn a_workspace_facet_is_made_once_and_found_again_by_name() -> TestResult {
    let fixture = fixture()?;
    let facet = fixture
        .vault
        .history_import_facet(&fixture.owner, WORKSPACE, IMPORTED_AT)?
        .ok_or("the owner is a live PERSON, so the workspace gets a facet")?;
    assert_eq!(
        fixture
            .vault
            .history_import_facet(&fixture.owner, WORKSPACE, IMPORTED_AT + 1)?,
        Some(facet),
        "a later import finds the workspace's facet by name"
    );
    assert!(
        fixture
            .vault
            .facets_of(&fixture.owner_actor)?
            .contains(&facet),
        "the importer wears it"
    );
    let other = fixture
        .vault
        .history_import_facet(&fixture.owner, "Another", IMPORTED_AT)?;
    assert!(
        other.is_some_and(|other| other != facet),
        "another workspace gets a facet of its own"
    );
    Ok(())
}

#[test]
fn an_import_in_a_workspace_facet_births_its_turns_under_it() -> TestResult {
    let fixture = fixture()?;
    let facet = fixture
        .vault
        .history_import_facet(&fixture.owner, WORKSPACE, IMPORTED_AT)?
        .ok_or("the workspace gets a facet")?;
    let faceted = fixture.vault.import_history_in_facet(
        &fixture.owner,
        SOURCE,
        &conversation("T1:C1", "facetmark7q3"),
        IMPORTED_AT,
        Some(facet),
    )?;
    let plain = fixture.vault.import_history(
        &fixture.owner,
        SOURCE,
        &conversation("T1:C2", "plainmark7q3"),
        IMPORTED_AT,
    )?;
    assert_eq!((faceted.new, faceted.refused), (2, 0), "{faceted:?}");
    assert_eq!((plain.new, plain.refused), (2, 0), "{plain:?}");

    let default = fixture.vault.default_facet()?;
    assert_ne!(facet, default);
    for id in ["T1:C1:1", "T1:C1:2"] {
        let rows = landed_rows(&fixture, id)?;
        assert_eq!(
            birth_facets(&fixture.vault, &rows.turn)?,
            vec![facet],
            "the TURN of {id} is born under the workspace's facet"
        );
        for row in [rows.conversation, rows.message] {
            assert!(
                birth_facets(&fixture.vault, &row)?.is_empty(),
                "{id}: a CONVERSATION or MESSAGE keeps its substrate facet"
            );
        }
    }
    let rows = landed_rows(&fixture, "T1:C2:1")?;
    assert_eq!(
        birth_facets(&fixture.vault, &rows.turn)?,
        vec![default],
        "an import with no facet births its TURN under the vault default, as before"
    );
    Ok(())
}

#[test]
fn the_owners_default_recall_returns_what_lands_under_a_workspace_facet() -> TestResult {
    let fixture = fixture()?;
    let facet = fixture
        .vault
        .history_import_facet(&fixture.owner, WORKSPACE, IMPORTED_AT)?
        .ok_or("the workspace gets a facet")?;
    fixture.vault.import_history_in_facet(
        &fixture.owner,
        SOURCE,
        &conversation("T1:C1", "facetmark7q3"),
        IMPORTED_AT,
        Some(facet),
    )?;
    fixture.vault.import_history(
        &fixture.owner,
        SOURCE,
        &conversation("T1:C2", "plainmark7q3"),
        IMPORTED_AT,
    )?;
    let memory = fixture
        .vault
        .memory(fixture.owner_actor, EdgeActorClass::Human);
    for marker in ["facetmark7q3", "plainmark7q3"] {
        let pack = memory.recall(
            marker,
            Effort::Light,
            &RecallScope::default(),
            10,
            None,
            None,
        )?;
        assert!(
            pack.items.iter().any(|item| item.kind == "TURN"
                && (item.value_text.contains(marker)
                    || item
                        .cited_messages
                        .iter()
                        .any(|message| message.value_text.contains(marker)))),
            "the owner's default recall returns the {marker} turn: {:?}",
            pack.items
                .iter()
                .map(|item| (&item.kind, &item.value_text))
                .collect::<Vec<_>>()
        );
    }
    Ok(())
}

#[test]
fn an_import_into_a_row_that_is_no_facet_is_refused() -> TestResult {
    let fixture = fixture()?;
    let refused = fixture.vault.import_history_in_facet(
        &fixture.owner,
        SOURCE,
        &conversation("T1:C1", "facetmark7q3"),
        IMPORTED_AT,
        Some(fixture.owner_actor),
    );
    assert!(refused.is_err(), "a PERSON is no facet");
    assert!(
        imported_message_rows(&fixture.vault, SOURCE, "T1:C1:1")?.is_none(),
        "nothing landed"
    );
    Ok(())
}
