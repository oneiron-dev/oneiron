//! The native `vault.delete` carries the check-in it runs on (FIX
//! [CHECK-IN-DELETE-SURFACES-NO-CHECK-IN-REF], the uniffi part; ROLES-CHECKIN
//! 2k5, P25-SHAPE Q1 = A): `vault_delete` takes `check_in_ref` and hands it to
//! the engine's door, and its `DeleteReceipt` names the decision the delete
//! ran on, as the verb's receipt does. A person whose delete waits finishes
//! the approved delete through the native call that names the check-in.
//!
//! Fixture: an owned vault the embedded owner wrote one claim in, closed,
//! then opened through the native handle, which acts as that owner.
//!
//! On the base (0aedc807c526) this file does not build: `vault_delete` takes
//! no `check_in_ref`, and the native `DeleteReceipt` has no `check_in`.
//!
//! `cargo test --locked -p oneiron-uniffi --test uniffi_delete_check_in` (default features).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use oneiron::memory::ClaimInput;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_uniffi::{CheckInDecision, DeleteRequestState, Oneiron, SafeDeleteReason};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A fresh vault directory under the system temp dir, unique per call.
fn fresh_dir(tag: &str) -> TestResult<PathBuf> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "oneiron-uniffi-delete-check-in-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// An owned vault whose embedded owner wrote one claim, closed again: the
/// claim's id.
fn vault_with_owner_claim(dir: &Path) -> TestResult<String> {
    let vault = Vault::open_owned(dir, VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let claim = EntityId::now().to_hex();
    memory.claim_upsert(&ClaimInput {
        id: Some(claim.clone()),
        predicate: "decision.practical".to_owned(),
        subject_ref: owner.to_hex(),
        value: json!("delete me natively"),
        confidence: 0.9,
        source: "user_stated".to_owned(),
        world_ref: None,
        relationship_ref: None,
        scope: None,
        valid_from: None,
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
        confidence_details: None,
    })?;
    drop(memory);
    drop(vault);
    Ok(claim)
}

#[test]
fn the_owners_native_delete_names_their_own_proof() -> TestResult {
    let dir = fresh_dir("own-proof")?;
    let claim = vault_with_owner_claim(&dir)?;
    let client = Oneiron::open(Some(dir.to_string_lossy().into_owned()), None, None)?;
    let receipt = client.vault_delete(claim, SafeDeleteReason::UserDelete, None)?;
    assert!(receipt.existed, "the claim existed: {receipt:?}");
    assert_eq!(receipt.state, DeleteRequestState::Applied);
    assert_eq!(
        receipt.check_in,
        Some(CheckInDecision {
            act_class: "delete".to_owned(),
            role: "owner".to_owned(),
            mode: None,
            basis: "own_proof".to_owned(),
            check_in: None,
            requester: None,
        }),
        "the native receipt names the decision the delete ran on"
    );
    Ok(())
}

#[test]
fn a_native_delete_hands_its_check_in_ref_to_the_engine() -> TestResult {
    let dir = fresh_dir("check-in-ref")?;
    let claim = vault_with_owner_claim(&dir)?;
    let client = Oneiron::open(Some(dir.to_string_lossy().into_owned()), None, None)?;
    // An Owner's delete goes on their own proof and spends no check-in, so
    // the engine refuses one that names a check-in: the ref reached it.
    let named = client.vault_delete(
        claim.clone(),
        SafeDeleteReason::UserDelete,
        Some(EntityId::now().to_hex()),
    );
    assert!(
        named.is_err(),
        "the engine's door refuses an Owner's delete that names a check-in: {named:?}"
    );
    let receipt = client.vault_delete(claim, SafeDeleteReason::UserDelete, None)?;
    assert!(
        receipt.existed,
        "the refused call deleted nothing: {receipt:?}"
    );
    Ok(())
}
