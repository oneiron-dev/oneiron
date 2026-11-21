// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "test-support")]
//! The house voice guide seed (ARCH-0059 #copy-review; lead ruling
//! COPY-REVIEW-JUDGE-BY-DEFAULT = B, 21 Nov): a vault's first campaign seeds
//! one house voice guide NOTE, written by the vault's owner, once. A vault
//! from before the seed that already holds a campaign gets it at its next
//! seeded open. A vault that runs no campaign gets none.
//!
//! On the base the seed does not exist, so this file does not compile there.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test campaign_house_voice_guide`

use std::path::Path;
use std::sync::Arc;

use oneiron::campaign::house_voice_guide::HOUSE_VOICE_GUIDE_MARKDOWN;
use oneiron::campaign::register_crm_pack;
use oneiron::campaign::surface::{CAMPAIGN_SCHEMA_VERSION, CreateCampaignRequest, create_campaign};
use oneiron::note::NoteReadRequest;
use oneiron::registry::TypeByteFamily;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

fn install_keystore(vault: &Vault) {
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
}

fn open_seeded(path: &Path) -> Vault {
    let vault = Vault::open(path, VaultConfig::device()).expect("the seeded open");
    install_keystore(&vault);
    vault
}

/// An unseeded vault with the CRM pack, so campaigns can be created, and no
/// owner PERSON yet.
fn open_crm_vault(path: &Path) -> Vault {
    let vault = Vault::open_unseeded_for_test(path, VaultConfig::device()).unwrap();
    install_keystore(&vault);
    register_crm_pack(&vault, 107, 108, TypeByteFamily::Productivity).unwrap();
    vault
}

fn owner(vault: &Vault) -> EntityId {
    vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner")
}

/// A campaign named `name`, created by `principal` through the create door.
fn create(vault: &Vault, principal: EntityId, name: &str) -> EntityId {
    create_campaign(
        vault,
        principal,
        &CreateCampaignRequest {
            schema_version: CAMPAIGN_SCHEMA_VERSION,
            name: name.to_owned(),
            reply_snooze_policy: None,
            voice_guide_ref: None,
            copy_review: None,
            send_mode: None,
        },
        vault.now_recorded_at(),
    )
    .expect("the campaign")
    .campaign_ref
}

/// The guide's text as the vault's owner reads it.
fn owner_reads(vault: &Vault, guide: EntityId) -> String {
    vault
        .memory(owner(vault), EdgeActorClass::Human)
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

/// The vault's first campaign seeds its house voice guide, which its owner
/// reads; a second campaign keeps that one guide.
#[test]
fn a_vaults_first_campaign_seeds_its_house_voice_guide() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_crm_vault(dir.path());
    let owner = owner(&vault);
    assert_eq!(
        vault.house_voice_guide().unwrap(),
        None,
        "no campaign, no house voice guide"
    );
    create(&vault, owner, "first campaign");
    let guide = vault
        .house_voice_guide()
        .unwrap()
        .expect("the first campaign seeds the house voice guide");
    assert_eq!(owner_reads(&vault, guide), HOUSE_VOICE_GUIDE_MARKDOWN);
    create(&vault, owner, "second campaign");
    assert_eq!(
        vault.house_voice_guide().unwrap(),
        Some(guide),
        "the seed runs once"
    );
}

/// A campaign stored while the guide cannot be seeded (here: no owner PERSON
/// yet, as in a vault from before the seed) still lands, and the vault's next
/// seeded open seeds one guide; a later open keeps it.
#[test]
fn a_vault_whose_campaign_predates_the_seed_gets_one_guide_at_its_next_open() {
    let dir = tempfile::tempdir().unwrap();
    {
        let vault = open_crm_vault(dir.path());
        create(&vault, EntityId::now(), "campaign from before the seed");
        assert_eq!(
            vault.house_voice_guide().unwrap(),
            None,
            "no owner PERSON yet, so no guide was seeded"
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
}

/// A guide the owner deletes is not seeded again, neither by a later
/// campaign nor by an open: a campaign with no guide of its own then holds
/// its sends until the owner names a guide or skips its copy review.
#[test]
fn a_deleted_house_voice_guide_is_not_seeded_again() {
    let dir = tempfile::tempdir().unwrap();
    let guide = {
        let vault = open_crm_vault(dir.path());
        let owner = owner(&vault);
        create(&vault, owner, "first campaign");
        let guide = vault
            .house_voice_guide()
            .unwrap()
            .expect("the house voice guide");
        vault
            .delete_entity(&guide)
            .expect("the owner deletes the guide");
        create(&vault, owner, "campaign after the delete");
        assert_eq!(
            vault.house_voice_guide().unwrap(),
            Some(guide),
            "a later campaign seeds no new guide"
        );
        guide
    };
    let vault = open_seeded(dir.path());
    assert_eq!(
        vault.house_voice_guide().unwrap(),
        Some(guide),
        "nor does the next open"
    );
}

/// A vault that runs no campaign gets no house voice guide, at creation or
/// at a later open, so its text never reaches that vault's reads.
#[test]
fn a_vault_with_no_campaign_gets_no_house_voice_guide() {
    let dir = tempfile::tempdir().unwrap();
    drop(open_seeded(dir.path()));
    let vault = open_seeded(dir.path());
    assert_eq!(vault.house_voice_guide().unwrap(), None);
}

/// A deleted campaign keeps its typed shell, which is no live campaign: a
/// vault from before the seed whose only campaign is deleted gets no guide at
/// its next open.
#[test]
fn a_vault_whose_only_campaign_is_deleted_gets_no_guide_at_open() {
    let dir = tempfile::tempdir().unwrap();
    {
        let vault = open_crm_vault(dir.path());
        let campaign = create(&vault, EntityId::now(), "campaign from before the seed");
        vault
            .delete_entity(&campaign)
            .expect("the campaign is deleted");
        assert_eq!(vault.house_voice_guide().unwrap(), None);
    }
    let vault = open_seeded(dir.path());
    assert_eq!(
        vault.house_voice_guide().unwrap(),
        None,
        "a deleted campaign seeds no guide"
    );
}
