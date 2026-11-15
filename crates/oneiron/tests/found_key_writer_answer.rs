//! L6-03-WRITER-MARK = B (ARCH-0038 #secret-scan-target: "The writer may
//! mark a hit 'not a secret', with a receipt"; ARCH-0069 #mask-on-write: "A
//! person may instead mark a span 'kept as text by choice' ... Agent writes
//! keep automatic mask on write"): the person who wrote a value that mask on
//! write lifted may answer its found key, as the owner may. Another person may
//! not, and an agent writer's keys stay the owner's to answer.
//!
//! `cargo test --locked -p oneiron --all-features --test found_key_writer_answer`.

use std::sync::Arc;

use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::StructuralPutInput;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::{FoundKeyAction, FoundKeySettled};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A GitHub token the door's text rules place by its span.
const TOKEN: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// A vault with the owner's scan switch at its default (on), a device
/// keystore, its embedded owner and the owner's proof.
fn open_vault() -> Result<(tempfile::TempDir, Vault, AuthenticatedOwner), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    Ok((dir, vault, owner))
}

/// A live PERSON who does not own the vault, and their own proof, which
/// holds at the person tier only.
fn person(
    vault: &Vault,
    body: &[u8],
) -> Result<(EntityId, AuthenticatedOwner), Box<dyn std::error::Error>> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        body,
    )?;
    let proof = vault.authenticate_owner(id, &id.to_hex(), true, GateDecisionId::now())?;
    Ok((id, proof))
}

/// An EVENT `writer` writes in their own name, whose notes hold the token.
fn write_event(vault: &Vault, writer: EntityId) -> EntityId {
    let receipt = vault
        .memory(writer, EdgeActorClass::Human)
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "EVENT".to_owned(),
            body: serde_json::json!({
                "name": "release",
                "notes": format!("deploy with token={TOKEN}"),
            }),
            text_fields: None,
            edges: None,
            occurred_at: 1,
            learned_at: None,
        })
        .unwrap_or_else(|error| panic!("FIXTURE: the person writes an EVENT: {error:?}"));
    EntityId::from_hex(&receipt.id_hex).expect("FIXTURE: the EVENT's id")
}

/// Whether the stored body of `id` holds the token as written.
fn holds_token(vault: &Vault, id: &EntityId) -> Result<bool, Box<dyn std::error::Error>> {
    let body = vault.get(id)?.ok_or("FIXTURE: a stored body")?;
    Ok(body
        .windows(TOKEN.len())
        .any(|window| window == TOKEN.as_bytes()))
}

/// The handle of the key the mask lifted out of `record`, from the owner's
/// found-key list.
fn found_handle(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    record: &EntityId,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(vault
        .found_keys(owner, true, 10)?
        .into_iter()
        .find(|notice| notice.record == *record)
        .and_then(|notice| notice.keys.into_iter().next())
        .map(|key| key.handle)
        .ok_or("FIXTURE: the mask lifted the token into a found key")?)
}

/// How `record`'s key is settled, as the owner's found-key list reads it.
fn settled(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    record: &EntityId,
) -> Result<Option<FoundKeySettled>, Box<dyn std::error::Error>> {
    Ok(vault
        .found_keys(owner, false, 10)?
        .into_iter()
        .find(|notice| notice.record == *record)
        .and_then(|notice| notice.keys.into_iter().next())
        .and_then(|key| key.settled))
}

fn refused_as_not_the_owner(result: oneiron::Result<FoundKeySettled>) {
    match result {
        Err(oneiron::Error::Gate(oneiron::error::GateError::ConsentOwnerNotAuthenticated(_))) => {}
        other => panic!("expected the owner door's refusal, got {other:?}"),
    }
}

#[test]
fn the_person_who_wrote_a_record_may_rule_its_key_not_a_secret() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (writer, writer_proof) = person(&vault, b"human")?;
    let record = write_event(&vault, writer);
    assert!(
        !holds_token(&vault, &record)?,
        "FIXTURE: the mask on write lifts the token out of the stored body"
    );
    let handle = found_handle(&vault, &owner, &record)?;

    let ruled = vault
        .rule_found_key_not_a_secret(&writer_proof, ActSurface::ThisInstall, &handle)
        .unwrap_or_else(|error| panic!("the writer rules their own key not a secret: {error:?}"));

    assert_eq!(ruled.action, FoundKeyAction::NotASecret);
    assert_eq!(
        ruled.by,
        Some(writer),
        "the settled receipt names the writer"
    );
    assert!(
        ruled.receipt.starts_with("gate:"),
        "the ruling keeps its Gate receipt: {}",
        ruled.receipt
    );
    assert!(
        holds_token(&vault, &record)?,
        "the record reads the value as written again"
    );
    assert_eq!(
        settled(&vault, &owner, &record)?.and_then(|settled| settled.by),
        Some(writer),
        "the owner's list shows the key settled by its writer"
    );
    Ok(())
}

#[test]
fn the_person_who_wrote_a_note_may_keep_its_key_as_text() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (writer, writer_proof) = person(&vault, b"human")?;
    let note = vault
        .create_note(
            "research",
            &format!("Release notes: deploy with token={TOKEN}."),
            WriteActor::new(writer, EdgeActorClass::Human),
        )
        .unwrap_or_else(|error| panic!("FIXTURE: the person writes a NOTE: {error:?}"));
    let handle = found_handle(&vault, &owner, &note)?;

    let kept = vault
        .keep_found_key_as_text(&writer_proof, ActSurface::ThisInstall, &handle)
        .unwrap_or_else(|error| panic!("the writer keeps their own key as text: {error:?}"));

    assert_eq!(kept.action, FoundKeyAction::KeptAsText);
    assert_eq!(
        kept.by,
        Some(writer),
        "the settled receipt names the writer"
    );
    Ok(())
}

#[test]
fn another_person_may_not_rule_a_key_they_did_not_write() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (writer, _) = person(&vault, b"human")?;
    let (_, other_proof) = person(&vault, b"human")?;
    let record = write_event(&vault, writer);
    let handle = found_handle(&vault, &owner, &record)?;

    refused_as_not_the_owner(vault.rule_found_key_not_a_secret(
        &other_proof,
        ActSurface::ThisInstall,
        &handle,
    ));
    refused_as_not_the_owner(vault.keep_found_key_as_text(
        &other_proof,
        ActSurface::ThisInstall,
        &handle,
    ));
    assert!(
        !holds_token(&vault, &record)?,
        "the refused rulings leave the value lifted"
    );
    assert_eq!(
        settled(&vault, &owner, &record)?,
        None,
        "the key stays open"
    );
    Ok(())
}

#[test]
fn an_agent_writer_may_not_rule_its_key_not_a_secret() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (agent, agent_proof) = person(&vault, b"agent")?;
    let note = vault
        .create_note(
            "research",
            &format!("Release notes: deploy with token={TOKEN}."),
            WriteActor::new(agent, EdgeActorClass::Agent),
        )
        .unwrap_or_else(|error| panic!("FIXTURE: the agent writes a NOTE: {error:?}"));
    let handle = found_handle(&vault, &owner, &note)?;

    refused_as_not_the_owner(vault.rule_found_key_not_a_secret(
        &agent_proof,
        ActSurface::ThisInstall,
        &handle,
    ));
    assert_eq!(settled(&vault, &owner, &note)?, None, "the key stays open");
    // The owner still answers it.
    let ruled = vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &handle)?;
    assert_eq!(ruled.action, FoundKeyAction::NotASecret);
    Ok(())
}
