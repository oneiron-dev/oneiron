// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "test-support")]
//! The house voice guide seed (ARCH-0059 #copy-review; lead ruling
//! COPY-REVIEW-JUDGE-BY-DEFAULT = B, 21 Nov): a vault's first campaign seeds
//! one house voice guide NOTE, written by the vault's owner, once. A vault
//! from before the seed that already holds a campaign gets it at its next
//! seeded open. A vault that runs no campaign gets none. The owner's
//! whole-vault restore keeps the guide the archive's vault had, or its
//! absence once the owner deleted it.
//!
//! The guide is an instruction for the copy review's judge, so it is
//! explicit-only with extraction off (FIX VOICE-GUIDE-NOTES-REACH-CONTEXT-PACKS):
//! no ordinary retrieval returns it, the owner's own recall included, and its
//! owner still reads it by ref.
//!
//! On the base the seed does not exist, so this file does not compile there.
//! On the seed's head before the archive carried the marker, the two restore
//! tests fail at their first assert: the restored vault holds no marker.
//! On main before the explicit-only kind, the guide is a vault-readable
//! `research` NOTE: the explicit-only test fails at its context assert, and
//! the recall test at its last assert (the recall answers the guide).
//!
//! Run: `cargo test --locked -p oneiron --all-features --test campaign_house_voice_guide`

use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;

use oneiron::campaign::house_voice_guide::HOUSE_VOICE_GUIDE_MARKDOWN;
use oneiron::campaign::register_crm_pack;
use oneiron::campaign::surface::{CAMPAIGN_SCHEMA_VERSION, CreateCampaignRequest, create_campaign};
use oneiron::memory::RecallRequest;
use oneiron::note::{ContextDefault, ExtractionDefault, NoteReadRequest};
use oneiron::registry::TypeByteFamily;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::task_verb::sdk::recall_unembedded;
use oneiron::write_envelope::WriteActor;
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

/// A seeded vault with the CRM pack and its first campaign, so it holds its
/// house voice guide; its owner; and the guide.
fn seeded_vault_with_guide(path: &Path) -> (Vault, EntityId, EntityId) {
    drop(open_crm_vault(path));
    let vault = open_seeded(path);
    let owner = owner(&vault);
    create(&vault, owner, "spring campaign");
    let guide = vault
        .house_voice_guide()
        .unwrap()
        .expect("the first campaign seeds the house voice guide");
    (vault, owner, guide)
}

/// The house voice guide is an instruction for the copy review's judge, as a
/// lens's intent is: explicit-only, and never extracted into claims. Its
/// owner still reads it by ref.
#[test]
fn the_house_voice_guide_is_explicit_only_and_never_extracted() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _, guide) = seeded_vault_with_guide(dir.path());
    let defaults = vault.note_defaults(guide).unwrap().defaults;
    assert_eq!(
        defaults.context,
        ContextDefault::ExplicitOnly,
        "no ordinary retrieval returns the guide: {defaults:?}"
    );
    assert_eq!(
        defaults.extraction,
        ExtractionDefault::Disabled,
        "no claim is extracted from the guide: {defaults:?}"
    );
    assert_eq!(owner_reads(&vault, guide), HOUSE_VOICE_GUIDE_MARKDOWN);
}

/// The owner's recall of a word the house voice guide holds answers the
/// owner's own research NOTE that holds it, and leaves the guide out: the
/// guide's lines reach no unrelated context.
#[test]
fn the_owners_recall_leaves_the_house_voice_guide_out() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, owner, guide) = seeded_vault_with_guide(dir.path());
    let note = vault
        .create_note(
            "research",
            "Write warmly to the quillwort growers.",
            WriteActor::new(owner, EdgeActorClass::Human),
        )
        .expect("the owner's research NOTE");
    vault.set_indexed_idle_delay_ms(0).expect("idle delay row");
    let published = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("idle publication");
    assert!(
        published.failed.is_empty(),
        "every staged text publishes: {published:?}"
    );
    let pack = recall_unembedded(
        &vault.memory(owner, EdgeActorClass::Human),
        RecallRequest {
            query: "warmly".to_owned(),
            ..RecallRequest::default()
        },
    )
    .expect("the owner's recall");
    let ids: Vec<String> = pack
        .items
        .iter()
        .filter_map(|item| item.record.as_ref())
        .map(|record| record.id.clone())
        .collect();
    assert!(
        ids.contains(&note.to_hex()),
        "the recall answers the owner's NOTE that holds the word: {ids:?}"
    );
    assert!(
        !ids.contains(&guide.to_hex()),
        "the recall leaves the house voice guide out: {ids:?}"
    );
}

/// The second the source vault's manual clock reads: long before the
/// host's clock, on which the restored vault opens.
const SOURCE_SECOND: u64 = 90;

/// A source vault opened as its owner's, for a whole-vault archive, on a
/// manual clock at [`SOURCE_SECOND`].
fn open_owned_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = VaultConfig::default();
    config.store_clock = ManualClock::new(SOURCE_SECOND).bundle();
    let vault = Vault::open_owned(dir.path(), config).expect("the source vault");
    (dir, vault)
}

/// Restores `archive` into a fresh vault through its owner's restore door.
/// The vault opens on the host's clock, later than the source's
/// [`SOURCE_SECOND`], so the engine seeds' times differ, as an owner's
/// restore meets them.
fn restored_vault(archive: &[u8]) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("the destination vault");
    let owner = owner(&vault);
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof");
    vault
        .import_whole_vault_archive_from_as_owner(Cursor::new(archive), &proof)
        .expect("the owner's whole-vault restore");
    (dir, vault)
}

/// The owner's whole-vault restore keeps the house voice guide the archive's
/// vault had: the restored vault reviews against that guide, as its owner
/// left it, and seeds no second one beside it.
#[test]
fn a_whole_vault_restore_keeps_the_house_voice_guide() {
    let (_source_dir, source) = open_owned_vault();
    let guide = source
        .ensure_house_voice_guide()
        .unwrap()
        .expect("the house voice guide");
    let archive = source
        .export_whole_vault(true)
        .expect("the whole-vault archive")
        .bytes()
        .to_vec();
    let (_dir, restored) = restored_vault(&archive);
    assert_eq!(
        restored.house_voice_guide().unwrap(),
        Some(guide),
        "the restore keeps the archive's house voice guide"
    );
    assert_eq!(
        restored.ensure_house_voice_guide().unwrap(),
        Some(guide),
        "the restored vault seeds no second guide"
    );
}

/// A house voice guide the owner deleted stays deleted through the owner's
/// whole-vault restore: the marker comes back without its NOTE, so no
/// default guide is seeded in its place, and a campaign with no guide of its
/// own holds its sends there as it did in the archive's vault.
#[test]
fn a_whole_vault_restore_keeps_a_deleted_house_voice_guide_deleted() {
    let (_source_dir, source) = open_owned_vault();
    let guide = source
        .ensure_house_voice_guide()
        .unwrap()
        .expect("the house voice guide");
    source
        .delete_entity(&guide)
        .expect("the owner deletes the guide");
    let archive = source
        .export_whole_vault(true)
        .expect("the whole-vault archive")
        .bytes()
        .to_vec();
    let (_dir, restored) = restored_vault(&archive);
    assert_eq!(
        restored.house_voice_guide().unwrap(),
        Some(guide),
        "the restore keeps the marker of the deleted guide"
    );
    assert_eq!(
        restored.ensure_house_voice_guide().unwrap(),
        Some(guide),
        "no default guide is seeded in the deleted one's place"
    );
}
