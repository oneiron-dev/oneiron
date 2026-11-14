//! L6-03-SEALED-FILE-NO-NOTICE (Engine RULING 14 Nov 13:01: "a notice for a
//! whole sealed file, plus an owner answer that clears the seal"; ARCH-0069
//! #binary-secrets: "A notice tells the owner which file holds which key. It
//! names the handle if the key is already in custody"): a file the write
//! door seals whole raises the owner's found-key notice, placed `file` and
//! named by the file's own id, since no custody record holds any of it. The
//! owner's not-a-secret answer clears the seal: a masked reader is served the
//! file, and a put of the same bytes is not sealed again. Only the owner
//! answers it, and only not a secret: no value left the file.

use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::secret_custody::{FoundKeyAction, FoundKeyCard, SecretSight};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, ErrorKind, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A private key block one line per item: no line reads as a key alone, and
/// the lines read one per line do, so only the file's whole tree holds the
/// key and the door seals it whole. The body lines are filler, no key.
const KEY_LINES: [&str; 4] = [
    "-----BEGIN PRIVATE KEY-----",
    "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC",
    "-----END PRIVATE KEY-----",
];

/// A vault with the owner's scan switch at its default (on), a device
/// keystore, a serving install profile and the authenticated owner, who
/// reads the found-key notices.
fn open_vault() -> Result<(tempfile::TempDir, Vault, AuthenticatedOwner), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"secret scan sealed file notice host")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    Ok((dir, vault, owner))
}

fn put_asset(vault: &Vault, id: &EntityId, version: u64, body: &[u8]) -> oneiron::Result<()> {
    vault
        .batch()
        .put(
            id,
            ENTITY_TYPE_ASSET,
            TimeRange { start: 1, end: 1 },
            version,
            body,
        )
        .commit()
}

/// A file the door seals whole, stored under a new id.
fn put_sealed_file(vault: &Vault) -> Result<(EntityId, Vec<u8>), Box<dyn std::error::Error>> {
    let body = serde_json::to_vec(&KEY_LINES)?;
    let id = EntityId::now();
    put_asset(vault, &id, 1, &body)?;
    Ok((id, body))
}

/// The cards of `record`'s notice: open ones only when `open_only`.
fn notice_cards(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    record: &EntityId,
    open_only: bool,
) -> oneiron::Result<Vec<FoundKeyCard>> {
    Ok(vault
        .found_keys(owner, open_only, 100)?
        .into_iter()
        .filter(|notice| notice.record == *record)
        .flat_map(|notice| notice.keys)
        .collect())
}

/// The seal's card in `record`'s notice: placed `file`, named by no custody
/// record.
fn seal_card(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    record: &EntityId,
) -> Result<FoundKeyCard, Box<dyn std::error::Error>> {
    let mut seals: Vec<FoundKeyCard> = notice_cards(vault, owner, record, false)?
        .into_iter()
        .filter(|card| card.place == "file" && card.name.is_empty())
        .collect();
    assert_eq!(seals.len(), 1, "one seal is noted for the file: {seals:?}");
    Ok(seals.remove(0))
}

/// What a masked reader is served of `record`'s stored bytes.
fn masked_read(
    vault: &Vault,
    record: &EntityId,
) -> Result<Result<Vec<u8>, ErrorKind>, Box<dyn std::error::Error>> {
    let stored = vault.get(record)?.ok_or("the file is stored")?;
    Ok(vault
        .sighted_asset_bytes(stored, SecretSight::Masked)
        .map_err(|error| error.kind()))
}

/// A sealed file raises an open notice: one card placed `file`, named by
/// the file's own id (no custody handle), whose one action is not a secret.
#[test]
fn a_file_sealed_whole_raises_an_open_notice_the_owner_lists() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (id, _body) = put_sealed_file(&vault)?;
    assert!(
        matches!(
            masked_read(&vault, &id)?,
            Err(ErrorKind::SealedFileWithheld)
        ),
        "FIXTURE: the door sealed the file whole"
    );
    let open = notice_cards(&vault, &owner, &id, true)?;
    assert_eq!(open.len(), 1, "the sealed file's notice is open: {open:?}");
    let card = &open[0];
    assert_eq!(card.place, "file");
    assert!(
        card.name.is_empty(),
        "no custody record holds a sealed file"
    );
    assert!(
        !card.handle.is_empty() && !card.handle.starts_with("sc"),
        "the card is named by the file's own id, not a key handle: {card:?}"
    );
    assert!(!card.kind.is_empty(), "the card names the scan's kind");
    assert!(card.settled.is_none());
    assert_eq!(card.actions, vec![FoundKeyAction::NotASecret]);
    Ok(())
}

/// The owner's not a secret settles the seal, with a Gate receipt, and a
/// masked reader is then served the stored bytes.
#[test]
fn the_owners_not_a_secret_clears_the_seal() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (id, body) = put_sealed_file(&vault)?;
    let card = seal_card(&vault, &owner, &id)?;
    let settled =
        vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &card.handle)?;
    assert_eq!(settled.action, FoundKeyAction::NotASecret);
    assert!(settled.by.is_some(), "the answer names the owner");
    assert!(settled.receipt.starts_with("gate:"), "{settled:?}");
    assert_eq!(
        masked_read(&vault, &id)?,
        Ok(body),
        "a masked reader is served the file once its seal is cleared"
    );
    assert!(
        notice_cards(&vault, &owner, &id, true)?.is_empty(),
        "no open notice is left for the file"
    );
    let ruled = seal_card(&vault, &owner, &id)?;
    assert_eq!(
        ruled.settled.map(|settled| settled.action),
        Some(FoundKeyAction::NotASecret)
    );
    assert!(ruled.actions.is_empty(), "a ruled seal offers no action");
    let again = vault
        .rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &card.handle)
        .map_err(|error| error.kind());
    assert!(
        matches!(again, Err(ErrorKind::InvalidConsentBound)),
        "a seal is ruled once: {again:?}"
    );
    Ok(())
}

/// The ruling holds for the bytes: the same bytes put again, in the same
/// record or a new one, are not sealed again and raise no open notice.
#[test]
fn a_put_of_the_same_bytes_after_the_ruling_is_not_sealed_again() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (id, body) = put_sealed_file(&vault)?;
    let card = seal_card(&vault, &owner, &id)?;
    vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &card.handle)?;
    put_asset(&vault, &id, 2, &body)?;
    let other = EntityId::now();
    put_asset(&vault, &other, 1, &body)?;
    for record in [id, other] {
        assert_eq!(
            masked_read(&vault, &record)?,
            Ok(body.clone()),
            "a masked reader is served the ruled bytes"
        );
        assert!(
            notice_cards(&vault, &owner, &record, true)?.is_empty(),
            "the ruled bytes raise no open notice"
        );
    }
    Ok(())
}

/// Only the owner answers a sealed file, and only not a secret: another
/// person's proof and kept as text are refused, and the seal stays.
#[test]
fn a_person_and_kept_as_text_cannot_clear_the_seal() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let person = EntityId::now();
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"human",
    )?;
    let proof = vault.authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())?;
    let (id, _body) = put_sealed_file(&vault)?;
    let card = seal_card(&vault, &owner, &id)?;
    let by_person = vault
        .rule_found_key_not_a_secret(&proof, ActSurface::ThisInstall, &card.handle)
        .map_err(|error| error.kind());
    assert!(
        matches!(by_person, Err(ErrorKind::ConsentOwnerNotAuthenticated)),
        "a person meets the owner door's refusal: {by_person:?}"
    );
    let kept = vault
        .keep_found_key_as_text(&owner, ActSurface::ThisInstall, &card.handle)
        .map_err(|error| error.kind());
    assert!(
        matches!(kept, Err(ErrorKind::InvalidConsentBound)),
        "a sealed file is not kept as text: {kept:?}"
    );
    assert_eq!(
        notice_cards(&vault, &owner, &id, true)?.len(),
        1,
        "the seal stays open"
    );
    assert!(
        matches!(
            masked_read(&vault, &id)?,
            Err(ErrorKind::SealedFileWithheld)
        ),
        "the file stays sealed"
    );
    Ok(())
}
