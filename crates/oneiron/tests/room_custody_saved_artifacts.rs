//! ROOM-CUSTODY-SAVED-ARTIFACTS (the lead's ruling of 21 Nov on
//! ROOM-LOCAL-CUSTODY, "fingerprint only on save"): saving the room moves
//! each secret a saved row names into the vault's normal custody, and only
//! then does the known-value index learn its fingerprint. A selected save
//! (`vault.off_record.artifacts.save`) lands a NOTE or a CLAIM the room
//! holds; one that quotes the room handle of a key the room keeps lands
//! naming the handle of a base custody record that holds the key, never the
//! room handle or the key. A later save of a row quoting the same room
//! handle takes the same base record.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test room_custody_saved_artifacts`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::off_record::{OffRecordBackendClass, OffRecordSession};
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::off_record_side_row::{
    base_custody_handle_in_rows, base_rows_hold, put_room_replay_row, room_replay_row,
    vault_custody_record_count, vault_custody_value, vault_knows_value,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A GitHub token, in a shape the side-row wall reads as a secret.
const KEY: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

/// An owned vault, its embedded owner PERSON and that owner's proof
/// (tests/room_custody_save.rs).
struct Owned {
    _dir: tempfile::TempDir,
    vault: Vault,
    actor: EntityId,
    owner: AuthenticatedOwner,
}

fn owned() -> TestResult<Owned> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let actor = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())?;
    Ok(Owned {
        _dir: dir,
        vault,
        actor,
        owner,
    })
}

/// The room handle the room keeps [`KEY`] under: a code run's row there
/// holds the key, which the room keeps in its own custody.
fn room_keeps_key(session: &OffRecordSession<'_>) -> TestResult<String> {
    let run = EntityId::now();
    put_room_replay_row(session, run, format!("step output: {KEY}\n").as_bytes())?;
    let row = room_replay_row(session, run)?.ok_or("the room keeps the row")?;
    let row = String::from_utf8(row)?;
    let start = row
        .find("[secret r")
        .ok_or("the row holds no room handle")?;
    let len = row[start..].find(']').ok_or("the handle has no bracket")?;
    Ok(row[start..=start + len].to_owned())
}

/// The first vault custody handle (`[secret sc12]`) `text` holds.
fn base_custody_handle_in(text: &str) -> Option<String> {
    let start = text.find("[secret sc")?;
    let len = text[start..].find(']')?;
    Some(text[start..=start + len].to_owned())
}

/// A row of `kind` named `name` at a fresh id, in base
/// (tests/gate_pins_put_pipeline.rs).
fn named_row(vault: &Vault, kind: u8, name: &str) -> TestResult<EntityId> {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({ "name": name }))?;
    vault
        .put_entity(&id, kind, TimeRange { start: 1, end: 1 }, 1, &body)
        .map_err(at("put a fixture row"))?;
    Ok(id)
}

/// A scoped claim about `subject` whose value says `words`, in `facet` and
/// `project` (tests/gate_pins_put_pipeline.rs).
fn scoped_claim(
    id: EntityId,
    subject: EntityId,
    facet: EntityId,
    project: EntityId,
    words: &str,
) -> ScopedClaimInput {
    ScopedClaimInput {
        id: Some(id.to_hex()),
        predicate: "profile.hobby".to_owned(),
        subject_ref: subject.to_hex(),
        value: json!(words),
        confidence: 1.0,
        source: "user_stated".to_owned(),
        scope: ClaimScope {
            world_id: base_world_id().to_hex(),
            scope_facet_id: facet.to_hex(),
            scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
            scope_project_id: project.to_hex(),
        }
        .into(),
        sensitivity: None,
        evidence_turn_refs: Vec::new(),
        valid_from: None,
        valid_to: None,
        occurred_at: Some(1),
        learned_at: Some(1),
        salience: None,
    }
}

#[test]
fn a_saved_note_names_the_base_record_of_the_room_secret_it_quotes() -> TestResult {
    let owned = owned()?;
    let vault = &owned.vault;
    let session = vault
        .off_record_session_vault()
        .enter("sess-room-custody-note", OffRecordBackendClass::Local)?;
    let handle = room_keeps_key(&session)?;
    let receipt = vault
        .memory(owned.actor, EdgeActorClass::Human)
        .create_note_in_session(&session, "research", &format!("The key is {handle}."), &[])
        .map_err(at("stage the room NOTE"))?;
    let note = EntityId::from_hex(&receipt.id_hex)?;
    assert_eq!(
        vault_custody_record_count(vault)?,
        0,
        "FIXTURE: before the save"
    );
    assert!(
        !vault_knows_value(vault, KEY.as_bytes())?,
        "FIXTURE: base knows no fingerprint before the save"
    );

    let saved = session
        .save_artifact_as(&owned.owner, &receipt.entity_ref)
        .map_err(at("the owner's room save"))?;

    assert!(saved.replayed.contains(&note), "the save names the NOTE");
    let markdown = vault
        .note_document(note)
        .map_err(at("read the saved NOTE"))?
        .markdown;
    assert!(
        !markdown.contains(&handle),
        "the saved NOTE keeps no room handle {handle}: {markdown:?}"
    );
    assert!(!markdown.contains(KEY), "the saved NOTE holds no key");
    let base = base_custody_handle_in(&markdown)
        .ok_or_else(|| format!("the saved NOTE names a vault custody handle: {markdown:?}"))?;
    assert_eq!(
        vault_custody_value(vault, &base)?.as_deref(),
        Some(KEY.as_bytes()),
        "{base} holds the key the room kept under {handle}"
    );
    assert_eq!(vault_custody_record_count(vault)?, 1);
    assert!(
        vault_knows_value(vault, KEY.as_bytes())?,
        "the save teaches base's known-value index the fingerprint"
    );
    Ok(())
}

#[test]
fn a_saved_claim_names_the_base_record_of_the_room_secret_it_quotes() -> TestResult {
    let owned = owned()?;
    let vault = &owned.vault;
    let facet = named_row(vault, ENTITY_TYPE_FACET, "room custody facet")?;
    let project = named_row(vault, ENTITY_TYPE_EVENT, "room custody project")?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-room-custody-claim", OffRecordBackendClass::Local)?;
    let handle = room_keeps_key(&session)?;
    let memory = vault.memory(owned.actor, EdgeActorClass::Human);
    let claim = EntityId::now();
    memory
        .claim_upsert_in_session(
            &session,
            &scoped_claim(
                claim,
                owned.actor,
                facet,
                project,
                &format!("the key is {handle}"),
            ),
        )
        .map_err(at("stage the room CLAIM"))?;
    assert_eq!(
        vault_custody_record_count(vault)?,
        0,
        "FIXTURE: before the save"
    );

    let saved = session
        .save_artifact_as(&owned.owner, &claim.to_hex())
        .map_err(at("the owner's room save"))?;

    assert!(saved.replayed.contains(&claim), "the save names the CLAIM");
    assert!(
        !base_rows_hold(vault, &[claim], &handle)?,
        "the saved CLAIM keeps no room handle {handle}"
    );
    assert!(
        !base_rows_hold(vault, &[claim], KEY)?,
        "the saved CLAIM holds no key"
    );
    let base = base_custody_handle_in_rows(vault, &[claim])?
        .ok_or("the saved CLAIM names a vault custody handle")?;
    assert_eq!(
        vault_custody_value(vault, &base)?.as_deref(),
        Some(KEY.as_bytes()),
        "{base} holds the key the room kept under {handle}"
    );
    assert_eq!(vault_custody_record_count(vault)?, 1);
    assert!(
        vault_knows_value(vault, KEY.as_bytes())?,
        "the save teaches base's known-value index the fingerprint"
    );

    // A later save of a claim quoting the same room handle takes the same
    // base record.
    let again = EntityId::now();
    memory
        .claim_upsert_in_session(
            &session,
            &scoped_claim(
                again,
                owned.actor,
                facet,
                project,
                &format!("again: {handle}"),
            ),
        )
        .map_err(at("stage the second room CLAIM"))?;
    session
        .save_artifact_as(&owned.owner, &again.to_hex())
        .map_err(at("the owner's second room save"))?;
    assert_eq!(
        base_custody_handle_in_rows(vault, &[again])?.as_deref(),
        Some(base.as_str()),
        "the value keeps its one base record"
    );
    assert_eq!(vault_custody_record_count(vault)?, 1);

    // A claim whose whole value is the bare room handle, as a field the
    // wall lifts whole holds it, lands holding the bare base handle of the
    // same record (REVIEW-10003).
    let bare = handle
        .strip_prefix("[secret ")
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or("a bracketed room handle")?
        .to_owned();
    let whole = EntityId::now();
    memory
        .claim_upsert_in_session(
            &session,
            &scoped_claim(whole, owned.actor, facet, project, &bare),
        )
        .map_err(at("stage the bare-handle room CLAIM"))?;
    session
        .save_artifact_as(&owned.owner, &whole.to_hex())
        .map_err(at("the owner's bare-handle room save"))?;
    let saved_whole = vault
        .get_claim(&whole)
        .map_err(at("read the bare-handle CLAIM"))?
        .ok_or("the bare-handle CLAIM landed")?;
    let base_bare = base
        .strip_prefix("[secret ")
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or("a bracketed base handle")?;
    assert_eq!(
        saved_whole.value.as_str(),
        Some(base_bare),
        "the saved whole value is the bare base handle, never {bare}"
    );
    assert_eq!(vault_custody_record_count(vault)?, 1);
    Ok(())
}
