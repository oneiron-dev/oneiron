//! Owner whole-vault restore replaces an owner-edited seeded AGENT_DEF and PERSON.
//!
//! T1 edits `sys.team_lead` (new instructions, version "2", enabled false),
//! the embedded owner PERSON and the team lead's model PERSON in a source
//! vault, then restores the archive into a later fresh vault through the
//! owner door: the destination rows equal the archive's rows. T2 and T3 pin
//! the guards: a used destination and the actorless door keep the seed
//! collision. T4 pins the refusal of an archived AGENT_DEF edited at the
//! seed version.
//!
//! Base behaviour (this file on base `57cf6baf418`):
//! * `owner_restore_replaces_edited_seed_agent_and_people` is red: the
//!   restore fails with "import ID collides with different entity data".
//!   On the head the receipt counts 3 replaced seeds.
//! * `owner_restore_into_used_vault_still_collides` is green: the same
//!   collision, on base and head.
//! * `actorless_restore_of_edited_seed_still_collides` is green: the
//!   actorless door collides on base and head.
//! * `owner_restore_refuses_edited_agent_at_seed_version` is red: the base
//!   refuses with the collision text, not the seed-version refusal.
//!
//! Public doors only; vaults in tempdirs; neutral fixtures (`owen`, `yuki`).
//! Each destination opens at least one wall-clock second after its source
//! (sleep 1100 ms), copied from `whole_vault_restore_seeds.rs`.

use std::io::Cursor;

use oneiron::agent_def::AgentDefinition;
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::subject_model::PersonSubstrate;
use oneiron::{EntityId, Result, TimeRange, Vault, VaultConfig};
use rmpv::Value;

/// The owner restore, returning the receipt's Debug text: base `57cf6baf418`
/// has no `replaced_seed_entities` field, so T1 reads that count by name from
/// the text, and this file still builds on base.
fn restore_as_owner(dest: &Vault, archive: &[u8], owner: &AuthenticatedOwner) -> Result<String> {
    let receipt = dest.import_whole_vault_archive_from_as_owner(Cursor::new(archive), owner)?;
    Ok(format!("{receipt:?}"))
}

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

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).expect("encode fixture");
    bytes
}

fn person_body(name: &str) -> Vec<u8> {
    encode(&Value::Map(vec![(Value::from("name"), Value::from(name))]))
}

struct EditedSeeds {
    team_lead: EntityId,
    edited: AgentDefinition,
    owner: EntityId,
    model_person: EntityId,
}

/// A source vault whose owner edited the `sys.team_lead` AGENT_DEF (new
/// instructions, version "2", enabled false), the embedded owner PERSON and
/// the team lead's model PERSON, plus the whole-vault archive carrying them.
fn seed_source_with_edited_seeds() -> (tempfile::TempDir, Vault, EditedSeeds, Vec<u8>) {
    let (dir, source) = open_vault();
    let (team_lead, seed) = source
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")
        .expect("seeded team lead read")
        .expect("sys.team_lead row");
    assert_eq!(seed.version, "1", "the seed stands at version 1");
    // The model PERSON behind `sys.team_lead`, through the public anchor
    // door; `u64::MAX` keeps the seed-time anchor eligible.
    let model_person = source
        .actor_subject_anchor(&team_lead, u64::MAX)
        .expect("team lead anchor read")
        .expect("sys.team_lead holds a subject anchor")
        .subject_ref;
    assert_eq!(
        source
            .person_substrate(&model_person, u64::MAX)
            .expect("substrate read"),
        Some(PersonSubstrate::Model),
        "the anchored subject is the team lead's model PERSON"
    );
    let owner = source
        .ensure_embedded_owner_actor()
        .expect("embedded owner");
    let proof = owner_proof(&source);
    let mut edited = seed.clone();
    edited.instructions = Some(
        "Lead the restored team: read the board, delegate within scope, report once.".to_owned(),
    );
    edited.version = "2".to_owned();
    edited.enabled = false;
    source
        .update_agent_definition_as(
            &proof,
            &team_lead,
            &edited,
            TimeRange {
                start: 400,
                end: 400,
            },
            400,
        )
        .expect("owner edits the seeded team lead");
    source
        .put_persona_baseline(
            &owner,
            &serde_json::json!({"note": "owen keeps this baseline"}),
            410,
        )
        .expect("owner baseline on the owner PERSON");
    source
        .put_persona_baseline(
            &model_person,
            &serde_json::json!({"note": "yuki keeps this baseline"}),
            420,
        )
        .expect("owner baseline on the model PERSON");
    let archive = source
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    (
        dir,
        source,
        EditedSeeds {
            team_lead,
            edited,
            owner,
            model_person,
        },
        archive,
    )
}

/// One carried row's exported header times, by id hex, from a whole-vault archive.
fn exported_row_header(vault: &Vault, archive: &[u8], id: &EntityId) -> (u64, u64, u64) {
    let document = vault
        .read_whole_vault_archive(archive)
        .expect("read archive");
    let row = document
        .evidence_ledger
        .entities
        .iter()
        .find(|row| row.id == id.to_hex())
        .expect("row in export");
    (row.occurred_start, row.occurred_end, row.learned_at)
}

/// The owner restore into a fresh vault replaces the edited seeded AGENT_DEF
/// and both PERSONs with the archive's rows, headers included, durably.
#[test]
fn owner_restore_replaces_edited_seed_agent_and_people() -> Result<()> {
    let (_source_dir, source, seeds, archive) = seed_source_with_edited_seeds();
    let stored = source
        .get_agent_definition(&seeds.team_lead)?
        .expect("edited team lead row");
    assert_eq!(stored, seeds.edited, "the source holds the owner edit");
    let source_header = exported_row_header(&source, &archive, &seeds.team_lead);
    let source_owner_body = source.get(&seeds.owner)?.expect("owner PERSON row");
    let source_model_body = source.get(&seeds.model_person)?.expect("model PERSON row");
    let (dest_dir, dest) = open_later_vault();
    let proof = owner_proof(&dest);
    let receipt = restore_as_owner(&dest, &archive, &proof)?;
    assert!(
        receipt.contains("replaced_seed_entities: 3,"),
        "the receipt counts the AGENT_DEF and both PERSONs as replaced seeds: {receipt}"
    );
    assert_eq!(
        dest.get_agent_definition(&seeds.team_lead)?.as_ref(),
        Some(&seeds.edited),
        "the destination AGENT_DEF equals the source's edited one"
    );
    let dest_export = dest.export_whole_vault(true)?;
    assert_eq!(
        exported_row_header(&dest, dest_export.bytes(), &seeds.team_lead),
        source_header,
        "the restored AGENT_DEF keeps the archive's header times"
    );
    assert_eq!(
        dest.get(&seeds.owner)?.as_deref(),
        Some(source_owner_body.as_slice()),
        "the owner PERSON body equals the source's"
    );
    assert_eq!(
        dest.get(&seeds.model_person)?.as_deref(),
        Some(source_model_body.as_slice()),
        "the model PERSON body equals the source's"
    );
    let path = dest_dir.path().to_path_buf();
    drop(dest);
    drop(proof);
    let dest = Vault::open_owned(&path, VaultConfig::default())?;
    assert_eq!(
        dest.get_agent_definition(&seeds.team_lead)?.as_ref(),
        Some(&seeds.edited),
        "the edited AGENT_DEF survives a reopen"
    );
    Ok(())
}

/// The same archive into a used destination still collides: the owner door
/// replaces edited seeds only in a fresh vault.
#[test]
fn owner_restore_into_used_vault_still_collides() -> Result<()> {
    let (_source_dir, _source, _seeds, archive) = seed_source_with_edited_seeds();
    let (_dest_dir, dest) = open_later_vault();
    let owen = EntityId::now();
    dest.put_entity(
        &owen,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
        &person_body("owen"),
    )?;
    let proof = owner_proof(&dest);
    let error =
        restore_as_owner(&dest, &archive, &proof).expect_err("a used destination still collides");
    assert!(
        error
            .to_string()
            .contains("import ID collides with different entity data"),
        "unexpected refusal: {error}"
    );
    Ok(())
}

/// The same archive through the actorless door still collides: only the
/// owner door replaces edited seeds.
#[test]
fn actorless_restore_of_edited_seed_still_collides() -> Result<()> {
    let (_source_dir, _source, _seeds, archive) = seed_source_with_edited_seeds();
    let (_dest_dir, dest) = open_later_vault();
    let error = dest
        .import_whole_vault_archive_from(Cursor::new(archive.as_slice()))
        .expect_err("the actorless door still collides");
    assert!(
        error
            .to_string()
            .contains("import ID collides with different entity data"),
        "unexpected refusal: {error}"
    );
    Ok(())
}

/// An archived AGENT_DEF edited at the seed version is refused: the same
/// version string with a different body is not the seed.
#[test]
fn owner_restore_refuses_edited_agent_at_seed_version() -> Result<()> {
    let (_dir, source) = open_vault();
    let (team_lead, seed) = source
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")?
        .expect("sys.team_lead row");
    let proof = owner_proof(&source);
    let mut second = seed.clone();
    second.instructions = Some("Second revision of the team lead instructions.".to_owned());
    second.version = "2".to_owned();
    source.update_agent_definition_as(
        &proof,
        &team_lead,
        &second,
        TimeRange {
            start: 400,
            end: 400,
        },
        400,
    )?;
    let mut reverted = second.clone();
    reverted.instructions =
        Some("Seed-version instructions that differ from the original seed text.".to_owned());
    reverted.version = "1".to_owned();
    assert_ne!(
        reverted.instructions, seed.instructions,
        "the reverted edit differs from the seed"
    );
    source.update_agent_definition_as(
        &proof,
        &team_lead,
        &reverted,
        TimeRange {
            start: 410,
            end: 410,
        },
        410,
    )?;
    let archive = source.export_whole_vault(true)?.bytes().to_vec();
    let (_dest_dir, dest) = open_later_vault();
    let proof = owner_proof(&dest);
    let error =
        restore_as_owner(&dest, &archive, &proof).expect_err("the seed-version edit is refused");
    assert!(
        error
            .to_string()
            .contains("differs from the fresh seed at the same version"),
        "unexpected refusal: {error}"
    );
    Ok(())
}
