//! The owner's erase of a world says, in plain words, what its old backups
//! keep (ARCH-0038 #erase-sealed-bundles, owner ruling 2026-10-18; census
//! L6-36, Engine ruling 16:51 13 Nov): the shared preview of
//! `vault.records.erase_confirm` (`vault.owner_confirm.preview`, the confirm
//! screen) and `vault.records.erase_confirm` itself (the receipt) carry "the
//! world is erased now, and old backups keep only an unreadable copy of it
//! until they expire", with the days within which they expire. Every other
//! record's preview keeps the fields it had before.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test erase_world_backup_notice`.

use std::sync::Arc;

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    OwnerConfirmPreviewRequest, RecordEraseConfirmRequest, confirm_record_erase,
    preview_owner_confirm,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The owner-ruled words, with the 90 daily sealed-bundle generations.
const NOTICE: &str = "This world is erased now. Old backups keep only an unreadable copy of it \
                      until they expire, within 90 days.";

/// The fields a preview of any record but a world carries, as before L6-36
/// (less `preview_digest`, which the shared confirm replaced in L8-49).
const PLAIN_PREVIEW_FIELDS: [&str; 6] = [
    "held_bytes",
    "lfs_chunks",
    "record",
    "remote_copies_may_remain",
    "same_bytes",
    "shared_with",
];

struct OwnedVault {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner_id: EntityId,
    owner: AuthenticatedOwner,
}

fn owned_vault() -> TestResult<OwnedVault> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    Ok(OwnedVault {
        _dir: dir,
        vault,
        owner_id,
        owner,
    })
}

/// The shared preview of erasing `record`: what the confirm screen shows,
/// and the confirm the erase passes back.
fn preview(fixture: &OwnedVault, record: EntityId) -> TestResult<(Value, String)> {
    let memory = fixture
        .vault
        .memory(fixture.owner_id, EdgeActorClass::Human);
    let shown = preview_owner_confirm(
        &memory,
        &fixture.owner,
        OwnerConfirmPreviewRequest {
            verb: "vault.records.erase_confirm".to_owned(),
            input: serde_json::to_value(RecordEraseConfirmRequest {
                record,
                confirm: None,
                also_same_bytes: false,
                check_in_ref: None,
            })?,
        },
    )?;
    let takes = shown
        .takes
        .ok_or("a record erase preview shows what the erase takes")?;
    Ok((takes, shown.confirm))
}

#[test]
fn a_world_erase_preview_and_receipt_say_old_backups_keep_an_unreadable_copy() -> TestResult {
    let fixture = owned_vault()?;
    let world = fixture.vault.create_world(
        &fixture.owner,
        "World the owner erases",
        fixture.vault.now_recorded_at(),
    )?;

    let (shown, confirm) = preview(&fixture, world)?;
    assert_eq!(
        shown.get("old_backups_notice"),
        Some(&Value::from(NOTICE)),
        "the confirm screen's preview of a world erase carries the ruled words: {shown}"
    );
    assert_eq!(
        shown.get("old_backups_expire_within_days"),
        Some(&Value::from(90)),
        "beside them, the days within which the old backups expire: {shown}"
    );

    let memory = fixture
        .vault
        .memory(fixture.owner_id, EdgeActorClass::Human);
    let outcome = confirm_record_erase(
        &memory,
        &fixture.owner,
        RecordEraseConfirmRequest {
            record: world,
            confirm: Some(confirm),
            also_same_bytes: false,
            check_in_ref: None,
        },
    )?;
    assert_eq!(
        outcome.first.state.as_str(),
        "applied",
        "a personal vault's owner erases the world at once"
    );
    assert!(
        fixture
            .vault
            .world_key_destructions()?
            .iter()
            .any(|destroyed| destroyed.world == world.to_hex()),
        "the erase destroyed the world's keys, so old bundles hold only an unreadable copy"
    );
    let receipt = serde_json::to_value(&outcome)?;
    assert_eq!(
        receipt.get("old_backups_notice"),
        Some(&Value::from(NOTICE)),
        "the erase receipt carries the ruled words: {receipt}"
    );
    assert_eq!(
        receipt.get("old_backups_expire_within_days"),
        Some(&Value::from(90)),
        "and the days within which the old backups expire: {receipt}"
    );
    Ok(())
}

#[test]
fn a_claim_erase_preview_keeps_its_fields() -> TestResult {
    let fixture = owned_vault()?;
    let at = fixture.vault.now_recorded_at();
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(fixture.owner_id),
        rmpv::Value::from("green"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    let claim = EntityId::now();
    fixture
        .vault
        .put_claim(&claim, &body, TimeRange { start: at, end: at }, at)?;

    let (shown, _) = preview(&fixture, claim)?;
    let mut fields: Vec<&str> = shown
        .as_object()
        .ok_or("the preview is a JSON object")?
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields, PLAIN_PREVIEW_FIELDS,
        "a claim's erase preview carries no backup notice: {shown}"
    );
    Ok(())
}
