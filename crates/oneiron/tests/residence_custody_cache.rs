//! The residence read cache serves no local-only row (ARCH-0069 secret
//! custody v1, "the residence cache, which still trusts its home"; census
//! L6-27b). A diagnostic or a credential never comes from a home, so a touch
//! that brings one is refused, and a copy of one an older build cached reads
//! as not cached: an open then touches the home afresh. An ordinary cached
//! row still reads back byte for byte.
//!
//! Public crate surface only: a device vault, `sync::WindowManager`,
//! `sync::SyncClient::thin_item` and the doc-hidden `Vault::sync_state_put`
//! to leave the cache rows a touch leaves.
//! `cargo test --locked -p oneiron --all-features --test residence_custody_cache`.
#![cfg(feature = "sync")]

use std::sync::Arc;

use oneiron::registry::{ENTITY_TYPE_DIAGNOSTIC, ENTITY_TYPE_PERSON, ENTITY_TYPE_SECRET_CUSTODY};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::{SyncClient, SyncClientConfig, WindowManager};
use oneiron::{EntityId, HnswConfig, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const WINDOW: &str = "2026-09";

/// 2 Sep 2026, inside WINDOW.
const LEARNED_AT: u64 = 1_788_300_000;

/// An entity row from literal parts: type u8, then occurred start and end,
/// learned-at and row version, each a big-endian u64, then the body.
fn entity_blob(entity_type: u8, body: &[u8]) -> Vec<u8> {
    let mut blob = vec![entity_type];
    for field in [LEARNED_AT, LEARNED_AT, LEARNED_AT, 0] {
        blob.extend_from_slice(&field.to_be_bytes());
    }
    blob.extend_from_slice(body);
    blob
}

fn open_vault(dir: &std::path::Path) -> oneiron::Result<Vault> {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    Vault::open(dir, config)
}

/// Leaves `blob` in the read cache as a touch of `item` in WINDOW leaves it:
/// the row, its document, and the window it was opened in.
fn cache(vault: &Vault, item: EntityId, blob: &[u8]) -> oneiron::Result<()> {
    let id = item.to_hex();
    vault.sync_state_put(&format!("ri:b:{id}"), blob)?;
    vault.sync_state_put(&format!("ri:d:{id}"), b"cached document")?;
    vault.sync_state_put(&format!("ro:e:{id}"), WINDOW.as_bytes())
}

#[test]
fn the_read_cache_serves_no_local_only_row() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_vault(dir.path())?);
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "residence-custody-cache",
    ));
    let (client, _events) = SyncClient::new(manager, SyncClientConfig::default())?;

    // Control, the same on main and on the fix: an ordinary cached row reads
    // back whole. A failure here means the fixture is wrong.
    let person = EntityId::now();
    let person_row = entity_blob(ENTITY_TYPE_PERSON, b"an ordinary cached row");
    cache(&vault, person, &person_row)?;
    let cached = client
        .thin_item(person)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("an ordinary cached row reads back")?;
    assert_eq!(cached.raw, person_row);
    assert_eq!(cached.window.as_str(), WINDOW);

    for (entity_type, kind) in [
        (ENTITY_TYPE_SECRET_CUSTODY, "credential"),
        (ENTITY_TYPE_DIAGNOSTIC, "diagnostic"),
    ] {
        let item = EntityId::now();
        cache(
            &vault,
            item,
            &entity_blob(entity_type, b"placeholder local-only body"),
        )?;
        let served = client.thin_item(item).map_err(|e| format!("{e:?}"))?;
        assert!(
            served.is_none(),
            "the read cache served a cached {kind} row a home sent"
        );
    }
    Ok(())
}
