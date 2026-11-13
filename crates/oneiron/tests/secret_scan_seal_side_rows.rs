//! L7-30, the side-row half (ARCH-0038 #secret-scan-target, ARCH-0040
//! #content-check; owner, 2026-10-07 and 2026-10-17): the secret scan never
//! refuses a write. Text and rows a writer stores outside the batch (a
//! NOTE's text, a stream's text, a side table's row) pass the side-row
//! wall, which now seals a hit no span places as the batch door does: the
//! smallest value that reads as the hit alone goes to custody whole, a text
//! whole, and its handle takes its place. The history import's plan
//! predicts that seal, so it no longer counts such a turn as refused while
//! the import lands it.
//!
//! `cargo test --locked -p oneiron --all-features --test secret_scan_seal_side_rows`.

use oneiron::consent::AuthenticatedOwner;
use oneiron::ingest::history::{
    HistoryConversation, HistoryDryRun, HistoryLedgerSnapshot, HistoryMessage, HistoryRole,
    HistorySkips, HistorySource, HistoryThreadKind,
};
use oneiron::registry::ENTITY_TYPE_SECRET_CUSTODY;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A provider token under a credential name: as text the door's rules
/// place it; as a document's byte values only the door's whole read of
/// that document finds it.
const TOKEN: &str = "TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz";

const SOURCE: HistorySource = HistorySource::ClaudeCode;
/// The import's clock, as the history library tests set it.
const IMPORTED_AT: u64 = 1_800_000_000;
const SAID_AT_MS: u64 = 1_700_000_000_000;

/// A JSON document that holds the token as byte values: no span of the
/// door's text rules places it, and the door's read of the document finds
/// it.
fn token_document() -> Result<String, serde_json::Error> {
    serde_json::to_string(&serde_json::json!({
        "name": "owen",
        "notes": TOKEN.as_bytes(),
    }))
}

/// A vault with the owner's scan switch at its default (on), its embedded
/// owner as a human writer, and the authenticated owner, who reads the
/// found-key notices.
fn open_vault(
    dir: &tempfile::TempDir,
) -> Result<(Vault, WriteActor, AuthenticatedOwner), Box<dyn std::error::Error>> {
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let actor = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())?;
    Ok((vault, WriteActor::new(actor, EdgeActorClass::Human), owner))
}

fn custody_records(vault: &Vault) -> oneiron::Result<usize> {
    vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)
}

fn note_text(vault: &Vault, note: EntityId) -> Result<String, Box<dyn std::error::Error>> {
    Ok(vault
        .note_program_document(note)?
        .ok_or("the NOTE has a document")?
        .text())
}

/// Whether `text` is one custody handle whole, as a text sealed whole
/// keeps it: `[secret sc12]`.
fn is_text_handle(text: &str) -> bool {
    text.strip_prefix("[secret sc")
        .and_then(|rest| rest.strip_suffix(']'))
        .is_some_and(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Each place the owner's found-key notice names for `record`.
fn notice_places(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    record: &EntityId,
) -> oneiron::Result<Vec<String>> {
    Ok(vault
        .found_keys(owner, false, 100)?
        .into_iter()
        .filter(|notice| notice.record == *record)
        .flat_map(|notice| notice.keys)
        .map(|key| key.place)
        .collect())
}

/// A NOTE whose text holds a hit no span places: the side-row wall seals
/// the text whole and the NOTE is born. Before, its birth was refused.
#[test]
fn a_note_whose_text_holds_a_hit_no_span_places_is_born_sealed_whole() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, writer, owner) = open_vault(&dir)?;
    let text = token_document()?;
    let before = custody_records(&vault)?;
    let note = vault
        .create_note("research", &text, writer)
        .unwrap_or_else(|error| {
            panic!("a NOTE text's hit no span places no longer refuses: {error:?}")
        });
    assert_eq!(
        custody_records(&vault)?,
        before + 1,
        "one custody record holds the NOTE's text"
    );
    let stored = note_text(&vault, note)?;
    assert!(
        is_text_handle(&stored),
        "the text keeps one handle whole: {stored}"
    );
    assert_eq!(
        notice_places(&vault, &owner, &note)?,
        vec!["text:markdown".to_owned()],
        "the owner hears of the sealed text"
    );
    Ok(())
}

/// Control: a hit a span places in a NOTE's text keeps its span's handle,
/// and the text before it stays as written; nothing is sealed whole.
#[test]
fn a_note_text_span_the_rules_place_keeps_the_rest_of_the_text() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, writer, _owner) = open_vault(&dir)?;
    let note = vault.create_note("research", &format!("call owen back. {TOKEN}"), writer)?;
    let stored = note_text(&vault, note)?;
    assert!(
        stored.starts_with("call owen back. "),
        "the text before the span is kept: {stored}"
    );
    assert!(
        stored.contains("[secret sc") && !stored.contains("ghp_"),
        "the span takes its handle: {stored}"
    );
    Ok(())
}

/// The history import's plan predicts the door's seal: a turn whose text
/// holds a hit no span places is planned as landing, as the import lands
/// it. Before, the plan counted it refused.
#[test]
fn the_history_plan_counts_a_turn_the_door_seals_as_landing() -> TestResult {
    let conversation = HistoryConversation {
        native_id: "session-owen".to_owned(),
        kind: HistoryThreadKind::Main,
        parent: None,
        title: None,
        started_at_ms: None,
        own_started_at_ms: None,
        cwd: None,
        messages: vec![HistoryMessage {
            native_id: "u1".to_owned(),
            parent_id: None,
            role: HistoryRole::User,
            text: token_document()?,
            at_ms: Some(SAID_AT_MS),
            said_by: None,
            tools: Vec::new(),
            alias: None,
        }],
        skipped: HistorySkips::default(),
    };
    // The plan reads a vault no writer holds open.
    let planned_dir = tempfile::tempdir()?;
    drop(open_vault(&planned_dir)?);
    let snapshot = HistoryLedgerSnapshot::open(planned_dir.path())?;
    let plan = snapshot.plan(SOURCE, &conversation, &mut HistoryDryRun::default())?;
    // The import lands the same conversation in a vault of its own.
    let landed_dir = tempfile::tempdir()?;
    let (vault, _writer, owner) = open_vault(&landed_dir)?;
    let landed = vault.import_history(&owner, SOURCE, &conversation, IMPORTED_AT)?;
    assert_eq!(
        (landed.new, landed.refused),
        (1, 0),
        "the import lands the turn: {landed:?}"
    );
    assert_eq!(
        (plan.new, plan.refused),
        (landed.new, landed.refused),
        "the plan predicts what the import lands: plan {plan:?}, import {landed:?}"
    );
    Ok(())
}
