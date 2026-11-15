//! L6-03 R1 (ARCH-0069 #binary-secrets: "The file is stored, not refused";
//! ARCH-0038 #secret-scan-target: "The scan never rejects a write"; owner
//! ruling G04 binary = C2): a file whose hit no span places is stored and
//! marked. Its bytes stay as written. The smallest value of a file the door
//! decodes that reads as the hit alone is marked as one key, which one
//! custody record holds; a file whose hit only its whole tree holds is
//! sealed whole, and a masked reader is served none of it.

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_SECRET_CUSTODY};
use oneiron::secret_custody::SecretSight;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, ErrorKind, TimeRange, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A provider token under a credential name: as text the door's rules
/// place it; as a file's byte values only the door's whole read finds it.
const TOKEN: &str = "TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// A private key block one line per item: no line reads as a key alone,
/// and the lines read one per line do. The body lines are filler, no key.
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
    let issuer = HostSlipIssuer::from_secret(b"secret scan seal file host")?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    Ok((dir, vault, owner))
}

fn put_asset(vault: &Vault, body: &[u8]) -> oneiron::Result<EntityId> {
    let id = EntityId::now();
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_ASSET,
            TimeRange { start: 1, end: 1 },
            1,
            body,
        )
        .commit()?;
    Ok(id)
}

fn custody_records(vault: &Vault) -> oneiron::Result<usize> {
    vault.count_entities_by_type(ENTITY_TYPE_SECRET_CUSTODY)
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

fn holds(bytes: &[u8], part: &str) -> bool {
    bytes
        .windows(part.len())
        .any(|window| window == part.as_bytes())
}

/// A token written as a file's byte values: no span places it, so the array
/// that holds it is marked as one key. The file is stored as written, the
/// owner reads it whole, and a masked reader is served the array
/// overwritten. Before, the write was refused.
#[test]
fn a_file_whose_token_is_byte_values_is_stored_and_marked() -> TestResult {
    let (_dir, vault, owner) = open_vault()?;
    let values = serde_json::to_string(&TOKEN.as_bytes())?;
    let body = serde_json::to_vec(&serde_json::json!({ "notes": TOKEN.as_bytes() }))?;
    assert!(holds(&body, &values), "the fixture writes the byte values");
    let before = custody_records(&vault)?;
    let id = put_asset(&vault, &body).unwrap_or_else(|error| {
        panic!("a file whose hit no span places is no longer refused: {error:?}")
    });
    assert_eq!(
        custody_records(&vault)?,
        before + 1,
        "one custody record holds the marked value"
    );
    let stored = vault.get(&id)?.ok_or("the file is stored")?;
    assert_eq!(stored, body, "the file keeps its bytes as written");
    assert_eq!(
        vault.sighted_asset_bytes(stored.clone(), SecretSight::Owner)?,
        body,
        "the owner reads the stored bytes"
    );
    let served = vault.sighted_asset_bytes(stored, SecretSight::Masked)?;
    let digits = &values[1..values.len() - 1];
    assert!(
        !holds(&served, digits),
        "a masked reader is served no byte value of the token: {}",
        String::from_utf8_lossy(&served)
    );
    assert!(
        holds(&served, "notes"),
        "the rest of the file is served: {}",
        String::from_utf8_lossy(&served)
    );
    assert_eq!(
        notice_places(&vault, &owner, &id)?,
        vec!["file".to_owned()],
        "the owner hears of the marked value in the file"
    );
    Ok(())
}

/// A key block one line per item, beside a name: the array that holds the
/// whole block is marked as one key, never one line, and the name is
/// served as written.
#[test]
fn a_file_whose_key_block_is_split_over_items_marks_the_array_that_holds_it() -> TestResult {
    let (_dir, vault, _owner) = open_vault()?;
    let body = serde_json::to_vec(&serde_json::json!({ "name": "owen", "key": KEY_LINES }))?;
    let before = custody_records(&vault)?;
    let id = put_asset(&vault, &body).unwrap_or_else(|error| {
        panic!("a file whose key is split over items is no longer refused: {error:?}")
    });
    assert_eq!(
        custody_records(&vault)?,
        before + 1,
        "one custody record holds the whole block"
    );
    let stored = vault.get(&id)?.ok_or("the file is stored")?;
    assert_eq!(stored, body, "the file keeps its bytes as written");
    let served = vault.sighted_asset_bytes(stored, SecretSight::Masked)?;
    for line in KEY_LINES {
        assert!(
            !holds(&served, line),
            "a masked reader is served no line of the block: {}",
            String::from_utf8_lossy(&served)
        );
    }
    assert!(
        holds(&served, "owen"),
        "the name is served as written: {}",
        String::from_utf8_lossy(&served)
    );
    Ok(())
}

/// A key block whose lines are the file's whole tree: only the whole file
/// reads as the key, so the file is sealed whole. It is stored as written,
/// no copy of it goes into custody, the owner reads it, and a masked reader
/// is served none of it. Before, the write was refused.
#[test]
fn a_file_whose_key_only_its_whole_tree_holds_is_sealed_whole() -> TestResult {
    let (_dir, vault, _owner) = open_vault()?;
    let body = serde_json::to_vec(&KEY_LINES)?;
    let before = custody_records(&vault)?;
    let id = put_asset(&vault, &body).unwrap_or_else(|error| {
        panic!("a file whose whole tree holds a key is no longer refused: {error:?}")
    });
    assert_eq!(
        custody_records(&vault)?,
        before,
        "no copy of a file sealed whole goes into custody"
    );
    let stored = vault.get(&id)?.ok_or("the file is stored")?;
    assert_eq!(stored, body, "the file keeps its bytes as written");
    assert_eq!(
        vault.sighted_asset_bytes(stored.clone(), SecretSight::Owner)?,
        body,
        "the owner reads the stored bytes"
    );
    let served = vault
        .sighted_asset_bytes(stored, SecretSight::Masked)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .map_err(|error| error.kind());
    assert!(
        matches!(served, Err(ErrorKind::SealedFileWithheld)),
        "a masked reader is served none of a file sealed whole: {served:?}"
    );
    Ok(())
}
