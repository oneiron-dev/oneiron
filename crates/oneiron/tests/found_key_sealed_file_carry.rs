//! Engine RULING 14 Nov 16:48 (PLAN-SEALED-FILE-RULING-CARRY = A; row 22 E
//! [SEALED-FILE-RULING-LOCAL]): the owner's not a secret on a file the write
//! door sealed whole reaches every install of his vault, not only the one he
//! answered on. It travels as his own act, an owner work request of kind
//! `file_ruling` that names the file by a keyed digest alone. On another
//! install, which got the bytes by sync and holds no mark of them, the
//! carried ruling serves the file as written, a put of the same bytes is not
//! sealed again, and a seal that install made itself is settled, a seal
//! made while its vault key was locked too. A locked vault key never
//! refuses the ruling: it stands at once, and its act is recorded once the
//! key is held again, once.
//!
//! The owner's other install is this vault with the file's notice and mark
//! moved away (`forget_found_keys_of`, `forget_file_mark_of`), as an install
//! that got the bytes by sync holds neither; its owner work drain then folds
//! the ruling.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test found_key_sealed_file_carry`.

use std::sync::Arc;

use oneiron::authority::{
    ActBy, ActSurface, AuthorityOp, HostSlipIssuer, MachineRole, encode_authority_log_entry_body,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_AUTHORITY_LOG};
use oneiron::secret_custody::{FoundKeyAction, FoundKeyCard, SecretSight};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::found_key_forget::forget_found_keys_of;
use oneiron::test_doors::sealed_file_carry::{forget_file_mark_of, served_masked_file_bytes};
use oneiron::{EntityId, ErrorKind, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A private key block one line per item: no line reads as a key alone, and
/// the lines read one per line do, so only the file's whole tree holds the
/// key and the door seals it whole, with no key placed.
const KEY_LINES: [&str; 4] = [
    "-----BEGIN PRIVATE KEY-----",
    "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC",
    "-----END PRIVATE KEY-----",
];

/// A vault on an install with a device keystore, a live machine profile and
/// its data key held, and its embedded owner's proof: an install that can
/// carry the owner's act to his other installs.
fn open_vault() -> Result<(tempfile::TempDir, Vault, AuthenticatedOwner), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"found key sealed file carry host")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    vault.ensure_vault_key()?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    Ok((dir, vault, owner))
}

fn put_asset(vault: &Vault, id: &EntityId, body: &[u8]) -> oneiron::Result<()> {
    vault
        .batch()
        .put(
            id,
            ENTITY_TYPE_ASSET,
            TimeRange { start: 1, end: 1 },
            1,
            body,
        )
        .commit()
}

/// A file the door seals whole, stored under a new id.
fn put_sealed_file(vault: &Vault) -> Result<(EntityId, Vec<u8>), Box<dyn std::error::Error>> {
    let body = serde_json::to_vec(&KEY_LINES)?;
    let id = EntityId::now();
    put_asset(vault, &id, &body)?;
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

/// Drops the vault data key, and with it the screen key.
fn lock_vault_key(vault: &Vault) -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(vault.lock_vault_key());
    Ok(())
}

/// A sealed file of `vault`, and the owner's not a secret on it.
fn ruled_file(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> Result<(EntityId, Vec<u8>), Box<dyn std::error::Error>> {
    let (id, body) = put_sealed_file(vault)?;
    let card = seal_card(vault, owner, &id)?;
    vault.rule_found_key_not_a_secret(owner, ActSurface::ThisInstall, &card.handle)?;
    assert_eq!(
        masked_read(vault, &id)?,
        Ok(body.clone()),
        "FIXTURE: a masked reader is served the file where the owner ruled it"
    );
    Ok((id, body))
}

/// This vault as the owner's other install, which got `body` by sync in
/// `record`: it holds no notice of the file and no mark of its bytes.
fn as_other_install(vault: &Vault, record: EntityId, body: &[u8]) -> TestResult {
    forget_found_keys_of(vault, record)?;
    forget_file_mark_of(vault, body)?;
    Ok(())
}

/// One sealed-file ruling this vault carried, as its request entry names it.
#[derive(Debug)]
struct CarriedRuling {
    act: String,
    by: ActBy,
    target: EntityId,
    digest: Vec<u8>,
    entry: Vec<u8>,
}

/// Each sealed-file ruling this vault carried: every owner work request of
/// kind `file_ruling` in its main log.
fn carried_rulings(vault: &Vault) -> Result<Vec<CarriedRuling>, Box<dyn std::error::Error>> {
    let mut rulings = Vec::new();
    for id in vault.entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)? {
        let entry = vault
            .get_authority_log_entry(&id)?
            .ok_or("FIXTURE: a listed authority entry exists")?;
        let AuthorityOp::OwnerWorkRequest(request) = &entry.op else {
            continue;
        };
        if request.kind().as_str() != "file_ruling" {
            continue;
        }
        let work = serde_json::to_value(&request.work)?;
        let digest = work["digest"]
            .as_array()
            .ok_or("the work names a digest")?
            .iter()
            .map(|byte| byte.as_u64().and_then(|byte| u8::try_from(byte).ok()))
            .collect::<Option<Vec<u8>>>()
            .ok_or("the digest is bytes")?;
        rulings.push(CarriedRuling {
            act: request.act.act.as_str().to_owned(),
            by: request.act.by,
            target: request.act.target,
            digest,
            entry: encode_authority_log_entry_body(&entry)?,
        });
    }
    Ok(rulings)
}

fn holds(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

#[test]
fn a_ruling_on_a_sealed_file_is_carried_as_the_owners_act_naming_a_keyed_digest() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (id, body) = ruled_file(&vault, &owner)?;

    let carried = carried_rulings(&vault)?;
    assert_eq!(
        carried.len(),
        1,
        "the ruling is carried as one request: {carried:?}"
    );
    let ruling = &carried[0];
    assert_eq!(ruling.act, "sealed_file_ruling");
    assert_eq!(ruling.by, ActBy::Owner, "the act is the owner's own");
    assert_eq!(ruling.target, id, "on the file's record");
    let hash = *blake3::hash(&body).as_bytes();
    assert_eq!(ruling.digest.len(), 32);
    assert_ne!(ruling.digest, vec![0; 32]);
    assert_ne!(
        ruling.digest,
        hash.to_vec(),
        "the digest is keyed, never the file's plain hash a guess is tested against"
    );
    assert!(
        !holds(&ruling.entry, &hash),
        "the entry holds no plain hash of the file"
    );
    for line in KEY_LINES {
        assert!(
            !holds(&ruling.entry, line.as_bytes()),
            "the entry holds none of the file's bytes"
        );
    }
    Ok(())
}

#[test]
fn a_carried_ruling_serves_the_file_where_it_arrived_with_no_mark() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (id, body) = ruled_file(&vault, &owner)?;
    as_other_install(&vault, id, &body)?;
    assert!(
        masked_read(&vault, &id)?.is_err(),
        "FIXTURE: bytes with no mark that the scan reads a key in are withheld"
    );
    assert_eq!(
        served_masked_file_bytes(&vault, &body)?,
        None,
        "FIXTURE: a door that answers with an optional file serves none of them"
    );

    vault.run_pending_owner_work(|| true)?;
    assert_eq!(
        masked_read(&vault, &id)?,
        Ok(body.clone()),
        "the owner's ruling, carried, serves the file as written there too"
    );
    assert_eq!(
        served_masked_file_bytes(&vault, &body)?,
        Some(body),
        "a door that answers with an optional file serves it by the carried ruling too"
    );
    Ok(())
}

#[test]
fn a_put_of_the_ruled_bytes_where_the_ruling_was_carried_is_not_sealed_again() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (id, body) = ruled_file(&vault, &owner)?;
    as_other_install(&vault, id, &body)?;
    vault.run_pending_owner_work(|| true)?;

    let again = EntityId::now();
    put_asset(&vault, &again, &body)?;
    assert!(
        notice_cards(&vault, &owner, &again, false)?.is_empty(),
        "bytes the owner ruled no secret raise no notice there"
    );
    assert_eq!(masked_read(&vault, &again)?, Ok(body));
    Ok(())
}

#[test]
fn a_carried_ruling_settles_the_seal_the_other_install_made_of_the_same_bytes() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (id, body) = ruled_file(&vault, &owner)?;
    as_other_install(&vault, id, &body)?;
    let again = EntityId::now();
    put_asset(&vault, &again, &body)?;
    assert_eq!(
        notice_cards(&vault, &owner, &again, true)?.len(),
        1,
        "FIXTURE: before the ruling reaches it, the other install seals the bytes itself"
    );

    vault.run_pending_owner_work(|| true)?;
    assert!(
        notice_cards(&vault, &owner, &again, true)?.is_empty(),
        "the carried ruling answers that seal: no open notice is left"
    );
    let settled = seal_card(&vault, &owner, &again)?;
    assert_eq!(
        settled.settled.map(|settled| settled.action),
        Some(FoundKeyAction::NotASecret)
    );
    assert_eq!(masked_read(&vault, &again)?, Ok(body));
    Ok(())
}

#[test]
fn a_ruling_while_the_vault_key_is_locked_stands_and_is_carried_once_at_unlock() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (id, body) = put_sealed_file(&vault)?;
    let card = seal_card(&vault, &owner, &id)?;
    lock_vault_key(&vault)?;

    vault.rule_found_key_not_a_secret(&owner, ActSurface::ThisInstall, &card.handle)?;
    assert_eq!(
        masked_read(&vault, &id)?,
        Ok(body),
        "the ruling stands here at once, key locked or not"
    );
    assert!(
        carried_rulings(&vault)?.is_empty(),
        "no act is recorded while the screen key is locked"
    );
    vault.run_pending_owner_work(|| true)?;
    assert!(
        carried_rulings(&vault)?.is_empty(),
        "nor by a drain that holds no screen key"
    );

    vault.unlock_vault_key()?;
    assert_eq!(
        carried_rulings(&vault)?.len(),
        1,
        "the unlock carries the ruling"
    );
    vault.run_pending_owner_work(|| true)?;
    assert_eq!(
        carried_rulings(&vault)?.len(),
        1,
        "the ruling is carried once"
    );
    Ok(())
}

#[test]
fn a_seal_put_while_the_vault_key_is_locked_after_the_ruling_arrived_is_settled_after_unlock()
-> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let (id, body) = ruled_file(&vault, &owner)?;
    as_other_install(&vault, id, &body)?;
    vault.run_pending_owner_work(|| true)?;
    lock_vault_key(&vault)?;
    let again = EntityId::now();
    put_asset(&vault, &again, &body)?;

    vault.unlock_vault_key()?;
    assert_eq!(
        notice_cards(&vault, &owner, &again, true)?.len(),
        1,
        "FIXTURE: with the screen key locked, the door tests no digest and seals the bytes"
    );
    vault.run_pending_owner_work(|| true)?;
    assert!(
        notice_cards(&vault, &owner, &again, true)?.is_empty(),
        "the first drain after the unlock settles that seal: no open notice is left"
    );
    assert_eq!(masked_read(&vault, &again)?, Ok(body));
    Ok(())
}
