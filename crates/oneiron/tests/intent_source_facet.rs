//! The owner's stated intent is born under the facet of the TURN its words
//! came from (FIX INTENT-FACET-FROM-SOURCE-TURN; ARCH-0022:139: "A derivation
//! is born under its source's facet, not the active mask's. A claim the
//! Dreamer draws from a turn spoken under a private mask takes that turn's
//! facet.").
//!
//! A MESSAGE has no stored FACET of its own (ONE-1645), but its TURN does: a
//! history import into a workspace's FACET W births its TURNs under W
//! (L2-18-WORKSPACE-FACET-CARRIER = A). The owner then states the words of
//! one of its MESSAGEs as his intent at `/v1/owner/intents`
//! ([`oneiron::Vault::record_owner_intent`]), citing that MESSAGE. The intent
//! must be born under W, so a door limited to the vault default facet D does
//! not read through it words he spoke in W. Before the fix it was born under
//! D.
//!
//! Each `FIXTURE:` assertion checks the setup, never the fix. The last
//! assertion is the check.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test intent_source_facet`
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::consent::AuthenticatedOwner;
use oneiron::ingest::history::{
    HistoryConversation, HistoryMessage, HistoryRole, HistorySkips, HistorySource,
    HistoryThreadKind,
};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::test_doors::history_import_rows::{ImportedMessageRows, imported_message_rows};
use oneiron::{EdgeActorClass, EdgeKind, EntityId, Vault, VaultConfig};
use oneiron_authority::federation::{ScopeAxis, ScopeId};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SOURCE: HistorySource = HistorySource::Slack;
const IMPORTED_AT: u64 = 1_700_100_000;
const WORKSPACE: &str = "Example";
const WORDS: &str = "I'll send the budget to the board on Friday.";

struct Fixture {
    _dir: TempDir,
    vault: Vault,
    owner: AuthenticatedOwner,
}

/// A vault whose embedded owner imports and states intents.
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
        owner,
    })
}

/// One conversation in which the owner says `words` once.
fn conversation(native_id: &str, words: &str) -> HistoryConversation {
    HistoryConversation {
        native_id: native_id.to_owned(),
        kind: HistoryThreadKind::Main,
        parent: None,
        title: Some("planning".to_owned()),
        started_at_ms: Some(1_699_990_000_000),
        own_started_at_ms: None,
        cwd: None,
        messages: vec![HistoryMessage {
            native_id: format!("{native_id}:1"),
            parent_id: None,
            role: HistoryRole::User,
            text: words.to_owned(),
            at_ms: Some(1_700_000_000_000),
            said_by: None,
            tools: Vec::new(),
            alias: None,
        }],
        skipped: HistorySkips::default(),
        sharing: None,
    }
}

/// Imports `words` as the owner's one MESSAGE of conversation `native_id`,
/// its TURN born under `facet` (the vault default when `None`); the rows it
/// landed as.
fn import_owner_words(
    fixture: &Fixture,
    native_id: &str,
    words: &str,
    facet: Option<EntityId>,
) -> Result<ImportedMessageRows, Box<dyn std::error::Error>> {
    let report = fixture.vault.import_history_in_facet(
        &fixture.owner,
        SOURCE,
        &conversation(native_id, words),
        IMPORTED_AT,
        facet,
    )?;
    assert_eq!(
        (report.new, report.refused),
        (1, 0),
        "FIXTURE: the owner's one message of {native_id} lands: {report:?}"
    );
    imported_message_rows(&fixture.vault, SOURCE, &format!("{native_id}:1"))?
        .ok_or_else(|| format!("FIXTURE: message {native_id}:1 did not land").into())
}

/// The FACETs a row was born under: its FacetOf edges.
fn birth_facets(
    vault: &Vault,
    row: &EntityId,
) -> Result<Vec<EntityId>, Box<dyn std::error::Error>> {
    Ok(vault.targets(row, EdgeKind::FacetOf, Some(ENTITY_TYPE_FACET))?)
}

/// Where the stored claim `claim` stands on the facet axis: the facets every
/// scoped door reads it at ([`Vault::record_scope`]), its body's facet
/// stamp, and the FACETs its birth edge names.
fn claim_facets(
    vault: &Vault,
    claim: &EntityId,
) -> Result<(BTreeSet<EntityId>, EntityId, Vec<EntityId>), Box<dyn std::error::Error>> {
    let read = match vault
        .record_scope(claim)?
        .ok_or("FIXTURE: the claim has a read position")?
        .facets
    {
        ScopeAxis::Some(facets) => facets.into_iter().map(|ScopeId(facet)| facet).collect(),
        _ => BTreeSet::new(),
    };
    let stamped = vault
        .get_claim(claim)?
        .ok_or("FIXTURE: the claim landed")?
        .scope_facet;
    Ok((read, stamped, birth_facets(vault, claim)?))
}

#[test]
fn an_intent_from_a_message_of_a_turn_under_a_workspace_facet_is_born_under_it() -> TestResult {
    let fixture = fixture()?;
    let vault = &fixture.vault;
    let workspace = vault
        .history_import_facet(&fixture.owner, WORKSPACE, IMPORTED_AT)?
        .ok_or("FIXTURE: the owner is a live PERSON, so the workspace gets a facet")?;
    let default = vault.default_facet()?;
    assert_ne!(
        workspace, default,
        "FIXTURE: the workspace facet is not the vault default"
    );

    // The same writer over a MESSAGE whose TURN stands under the vault
    // default: the intent is born under it, before the fix and after.
    let plain = import_owner_words(&fixture, "T1:C2", "I will water the plants.", None)?;
    assert_eq!(
        birth_facets(vault, &plain.turn)?,
        vec![default],
        "FIXTURE: a plain import births its TURN under the vault default"
    );
    let plain_intent = vault.record_owner_intent(
        &fixture.owner,
        "I will water the plants.",
        None,
        Some(plain.message),
    )?;
    assert_eq!(
        claim_facets(vault, &plain_intent)?,
        (BTreeSet::from([default]), default, vec![default]),
        "FIXTURE: an intent citing a MESSAGE of a TURN under the vault default stands under it"
    );

    let rows = import_owner_words(&fixture, "T1:C1", WORDS, Some(workspace))?;
    assert_eq!(
        birth_facets(vault, &rows.turn)?,
        vec![workspace],
        "FIXTURE: the TURN is born under the workspace facet"
    );
    assert!(
        birth_facets(vault, &rows.message)?.is_empty(),
        "FIXTURE: the MESSAGE has no stored FACET of its own (ONE-1645)"
    );

    let intent = vault.record_owner_intent(&fixture.owner, WORDS, None, Some(rows.message))?;
    let (read, stamped, born) = claim_facets(vault, &intent)?;
    assert_eq!(
        (&read, stamped, &born),
        (&BTreeSet::from([workspace]), workspace, &vec![workspace]),
        "LEAK: the intent quoting a MESSAGE of a TURN under the workspace facet is read at \
         {read:?} (stamped {stamped:?}, born under {born:?}), not the workspace facet"
    );
    Ok(())
}
