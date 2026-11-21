// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "test-support")]
//! The house voice guide seed (ARCH-0059 #copy-review; lead ruling
//! COPY-REVIEW-JUDGE-BY-DEFAULT = B, 21 Nov): every seeded vault gets one
//! house voice guide NOTE, written by its owner, once. A new vault gets it at
//! creation; a vault from before the seed gets it at its next seeded open.
//!
//! On the base the seed does not exist, so this file does not compile there.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test campaign_house_voice_guide`

use std::path::Path;
use std::sync::Arc;

use oneiron::campaign::house_voice_guide::HOUSE_VOICE_GUIDE_MARKDOWN;
use oneiron::note::NoteReadRequest;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

fn open_seeded(path: &Path) -> Vault {
    let vault = Vault::open(path, VaultConfig::device()).expect("the seeded open");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
}

/// The guide's text as the vault's owner reads it.
fn owner_reads(vault: &Vault, guide: EntityId) -> String {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    vault
        .memory(owner, EdgeActorClass::Human)
        .read_note(&NoteReadRequest {
            note_ref: guide.to_hex(),
            reason: Some("house voice guide seed test".to_owned()),
            version: None,
            spans: Vec::new(),
        })
        .expect("the owner reads the house voice guide")
        .value
        .expect("the house voice guide reads")
        .markdown
}

/// A new vault is created with its house voice guide, which its owner reads.
#[test]
fn a_new_vault_is_seeded_with_its_house_voice_guide() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_seeded(dir.path());
    let guide = vault
        .house_voice_guide()
        .unwrap()
        .expect("the new vault's house voice guide");
    assert_eq!(owner_reads(&vault, guide), HOUSE_VOICE_GUIDE_MARKDOWN);
}

/// A vault from before the seed (here: created unseeded) gets its house voice
/// guide at its next seeded open, and keeps that one guide at every later
/// open.
#[test]
fn a_vault_from_before_the_seed_gets_one_house_voice_guide_at_its_next_open() {
    let dir = tempfile::tempdir().unwrap();
    {
        let vault = Vault::open_unseeded_for_test(dir.path(), VaultConfig::device()).unwrap();
        assert_eq!(
            vault.house_voice_guide().unwrap(),
            None,
            "the unseeded vault has no house voice guide yet"
        );
    }
    let first = {
        let vault = open_seeded(dir.path());
        let guide = vault
            .house_voice_guide()
            .unwrap()
            .expect("the next seeded open seeds the house voice guide");
        assert_eq!(owner_reads(&vault, guide), HOUSE_VOICE_GUIDE_MARKDOWN);
        guide
    };
    let vault = open_seeded(dir.path());
    assert_eq!(
        vault.house_voice_guide().unwrap(),
        Some(first),
        "a later open keeps the one guide"
    );
    assert_eq!(
        vault.ensure_house_voice_guide().unwrap(),
        Some(first),
        "the seed runs once"
    );
}
