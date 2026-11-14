//! FIX [L6-03-NOTE-RULING-KEEPS-DOC-HANDLE] (Engine RULING 14 Nov 13:01,
//! NEXT-ROW-21 B): every NOTE read serves the NOTE's document, and the mask
//! on write stored a found key's handle there. The owner's "not a secret"
//! answer, or the writer's own "kept as text", puts the value back into the
//! document, so a NOTE read shows the value, not "[secret scN]".
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test found_key_note_restore`.

use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::note::NoteActor;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A GitHub token the door's text rules place by its span.
const TOKEN: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// How a found key's handle opens where the mask left it in a text.
const HANDLE_OPEN: &str = "[secret ";

/// A vault with a device keystore, its embedded owner, a live PERSON who
/// does not own it, and this install's live machine profile, so a ruling
/// carries its revoke to the owner's other machines (the
/// `found_key_audit_author.rs` fixture).
fn open_vault() -> Result<(tempfile::TempDir, Vault, EntityId, EntityId), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let writer = EntityId::now();
    vault.put_entity(
        &writer,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"human",
    )?;
    let issuer = HostSlipIssuer::from_secret(b"found key note restore host")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    Ok((dir, vault, owner, writer))
}

/// `person`'s own proof: the owner tier for the owner, the person tier for
/// anyone else.
fn proof_of(
    vault: &Vault,
    person: EntityId,
) -> Result<AuthenticatedOwner, Box<dyn std::error::Error>> {
    Ok(vault.authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())?)
}

/// A NOTE `writer` writes in their own name.
fn write_note(vault: &Vault, writer: EntityId, markdown: &str) -> EntityId {
    vault
        .create_note(
            "research",
            markdown,
            WriteActor::new(writer, EdgeActorClass::Human),
        )
        .unwrap_or_else(|error| panic!("FIXTURE: the NOTE is written: {error:?}"))
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

/// The NOTE's markdown as `Vault::read_note` and `Vault::note_document`
/// serve it: both read its document.
fn markdown_reads(
    vault: &Vault,
    note: EntityId,
) -> Result<[String; 2], Box<dyn std::error::Error>> {
    let read = vault
        .read_note(&note)?
        .ok_or("FIXTURE: the NOTE reads")?
        .markdown;
    Ok([read, vault.note_document(note)?.markdown])
}

/// Whether `text` holds a key's handle where the token was written.
fn handled(text: &str) -> bool {
    text.contains(HANDLE_OPEN) && !text.contains(TOKEN)
}

#[test]
fn a_note_body_ruled_not_a_secret_reads_back_with_its_value() -> TestResult {
    let (_dir, vault, owner, _) = open_vault()?;
    let owner_proof = proof_of(&vault, owner)?;
    let written = format!("Release notes: deploy with token={TOKEN}.");
    let note = write_note(&vault, owner, &written);
    for markdown in markdown_reads(&vault, note)? {
        assert!(
            handled(&markdown),
            "FIXTURE: the mask left the key's handle in the NOTE: {markdown}"
        );
    }
    let handle = found_handle(&vault, &owner_proof, &note)?;

    vault.rule_found_key_not_a_secret(&owner_proof, ActSurface::ThisInstall, &handle)?;

    for markdown in markdown_reads(&vault, note)? {
        assert_eq!(
            markdown, written,
            "not a secret puts the value back in the NOTE's document"
        );
    }
    Ok(())
}

#[test]
fn a_note_body_its_writer_kept_as_text_reads_back_with_its_value() -> TestResult {
    let (_dir, vault, owner, writer) = open_vault()?;
    let owner_proof = proof_of(&vault, owner)?;
    let written = format!("Release notes: deploy with token={TOKEN}.");
    let note = write_note(&vault, writer, &written);
    let handle = found_handle(&vault, &owner_proof, &note)?;
    let writer_proof = proof_of(&vault, writer)?;

    vault.keep_found_key_as_text(&writer_proof, ActSurface::ThisInstall, &handle)?;

    for markdown in markdown_reads(&vault, note)? {
        assert_eq!(
            markdown, written,
            "kept as text puts the value back in the NOTE's document"
        );
    }
    // The birth record names the writer too, so only a later record counts
    // (REVIEW-7876 F3).
    let document = vault.note_document(note)?;
    assert!(
        document
            .authorship
            .iter()
            .any(|record| record.operation != note && record.actor == NoteActor::Actor(writer)),
        "the restore is an edit by the person who answered: {:?}",
        document.authorship
    );
    Ok(())
}

#[test]
fn a_note_title_kept_as_text_reads_back_with_its_value() -> TestResult {
    let (_dir, vault, owner, _) = open_vault()?;
    let owner_proof = proof_of(&vault, owner)?;
    let note = write_note(&vault, owner, "Deploy checklist.");
    let title = format!("Deploy with token={TOKEN}");
    vault
        .memory(owner, EdgeActorClass::Human)
        .set_note_title(note, title.clone())
        .unwrap_or_else(|error| panic!("FIXTURE: the owner titles the NOTE: {error:?}"));
    let masked = vault
        .note_document(note)?
        .title
        .ok_or("FIXTURE: the NOTE has a title")?;
    assert!(
        handled(&masked),
        "FIXTURE: the mask left the key's handle in the title: {masked}"
    );
    let handle = found_handle(&vault, &owner_proof, &note)?;

    vault.keep_found_key_as_text(&owner_proof, ActSurface::ThisInstall, &handle)?;

    let document = vault.note_document(note)?;
    assert_eq!(
        document.title.as_deref(),
        Some(title.as_str()),
        "kept as text puts the value back in the NOTE's title"
    );
    assert_eq!(document.markdown, "Deploy checklist.");
    Ok(())
}

#[test]
fn a_value_in_a_note_body_and_title_reads_back_in_both() -> TestResult {
    let (_dir, vault, owner, _) = open_vault()?;
    let owner_proof = proof_of(&vault, owner)?;
    let written = format!("Release notes: deploy with token={TOKEN}.");
    let note = write_note(&vault, owner, &written);
    let handle = found_handle(&vault, &owner_proof, &note)?;
    let title = format!("Deploy with token={TOKEN}");
    vault
        .memory(owner, EdgeActorClass::Human)
        .set_note_title(note, title.clone())
        .unwrap_or_else(|error| panic!("FIXTURE: the owner titles the NOTE: {error:?}"));
    let masked = vault
        .note_document(note)?
        .title
        .ok_or("FIXTURE: the NOTE has a title")?;
    assert!(
        masked.contains(&format!("{HANDLE_OPEN}{handle}]")),
        "FIXTURE: custody knows the value, so the title takes the body key's handle: {masked}"
    );

    vault.rule_found_key_not_a_secret(&owner_proof, ActSurface::ThisInstall, &handle)?;

    let document = vault.note_document(note)?;
    assert_eq!(
        document.markdown, written,
        "not a secret puts the value back in the body"
    );
    assert_eq!(
        document.title.as_deref(),
        Some(title.as_str()),
        "and in the title, where the same handle stands"
    );
    Ok(())
}
