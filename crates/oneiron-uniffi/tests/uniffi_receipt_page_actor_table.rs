//! The native `vault.receipts` page carries the actor table
//! ([UNIFFI-RECEIPT-PAGE-ACTOR-TABLE]): `actors` names every actor the
//! page's rows name, each as the reader's own people list names them.
//! A native client reads who made each receipt's change, as the engine page
//! does.
//!
//! Fixture: an owned vault the embedded owner wrote one claim in, closed,
//! then opened through the native handle, as a native client opens it.
//!
//! `cargo test --locked -p oneiron-uniffi --all-features --test uniffi_receipt_page_actor_table`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use oneiron::memory::ClaimInput;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_uniffi::{FacadeActorAttributionKind, Oneiron};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A fresh vault directory under the system temp dir, unique per call.
fn fresh_dir(tag: &str) -> TestResult<PathBuf> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "oneiron-uniffi-actor-table-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// An owned vault whose embedded owner wrote one claim about itself,
/// closed again; the owner's actor ref, as the receipts name it.
fn vault_with_owner_claim(dir: &Path) -> TestResult<String> {
    let vault = Vault::open_owned(dir, VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    memory.claim_upsert(&ClaimInput {
        id: Some(EntityId::now().to_hex()),
        predicate: "decision.practical".to_owned(),
        subject_ref: owner.to_hex(),
        value: json!("keep the native entry"),
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
    let owner = owner.to_hex();
    drop(memory);
    drop(vault);
    Ok(owner)
}

#[test]
fn native_receipts_page_names_each_actor_as_the_engine_page_does() -> TestResult {
    let dir = fresh_dir("named")?;
    let owner = vault_with_owner_claim(&dir)?;
    let client = Oneiron::open(Some(dir.to_string_lossy().into_owned()), None, None)?;
    let page = client.vault_receipts(100, None, None)?;
    let refs: BTreeSet<String> = page
        .receipts
        .iter()
        .filter_map(|receipt| receipt.actor_ref.clone())
        .collect();
    assert!(
        refs.contains(&owner),
        "precondition: the native page holds the owner's receipt: {refs:?}"
    );
    assert_eq!(
        page.actors.keys().cloned().collect::<BTreeSet<_>>(),
        refs,
        "the native page names every actor its rows name"
    );
    let by_owner = &page.actors[&owner];
    assert_eq!(
        by_owner.kind,
        FacadeActorAttributionKind::Human,
        "the owner's own receipt is by the owner, a human"
    );
    assert_eq!(
        by_owner.person.as_deref(),
        Some(owner.as_str()),
        "the owner's entry names the owner's PERSON"
    );
    drop(client);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn native_receipts_page_of_a_quiet_vault_carries_a_matching_actor_table() -> TestResult {
    let dir = fresh_dir("quiet")?;
    let vault = Vault::open_owned(&dir, VaultConfig::default())?;
    drop(vault);
    let client = Oneiron::open(Some(dir.to_string_lossy().into_owned()), None, None)?;
    let page = client.vault_receipts(100, None, None)?;
    let refs: BTreeSet<String> = page
        .receipts
        .iter()
        .filter_map(|receipt| receipt.actor_ref.clone())
        .collect();
    assert_eq!(
        page.actors.keys().cloned().collect::<BTreeSet<_>>(),
        refs,
        "the native page's actor table matches its rows, even when empty"
    );
    drop(client);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
