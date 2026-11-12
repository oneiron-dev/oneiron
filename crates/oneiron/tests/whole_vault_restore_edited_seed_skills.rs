//! Owner whole-vault restore replaces an owner-edited seeded SKILL.
//!
//! K1 archives a seeded bootstrap SKILL through the owner library door, then
//! restores the archive into a later fresh vault through the owner door: the
//! destination SKILL equals the archived one, header times included, its
//! runtime package still reads, and the receipt counts one replaced seed.
//! K3 and K4 pin the guards: a used destination and the actorless door keep
//! the seed collision. K5 hub-syncs a Candidate setup SKILL to new content
//! through the supplied-package door (no network hub) and restores it the
//! same way. K2 is omitted: no self-contained public-API fixture was found
//! for the required setup qualification (see the row1b build report).
//!
//! Base behaviour (this file on base `93a8907f079`):
//! * `owner_restore_replaces_lifecycle_edited_seed_skill` is red: the
//!   restore fails with "import ID collides with different entity data".
//!   On the head the receipt counts 1 replaced seed.
//! * `owner_restore_replaces_hub_synced_seed_skill` is red: the same
//!   collision on base, 1 replaced seed on the head.
//! * `owner_restore_of_edited_seed_skill_into_used_vault_still_collides` is
//!   green: the same collision, on base and head.
//! * `actorless_restore_of_edited_seed_skill_still_collides` is green: the
//!   actorless door collides on base and head.
//!
//! Public doors only; vaults in tempdirs; neutral fixtures (`owen`, `yuki`).
//! Each destination opens at least one wall-clock second after its source
//! (sleep 1100 ms), copied from `whole_vault_restore_edited_seeds.rs`.

use std::io::Cursor;

use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use oneiron::skill_hub::{
    HubFile, HubPackage, HubPin, HubRef, HubSyncDisposition, HubSyncPolicy, SkillCapabilitySurface,
};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    HubSkillRequest, SkillLibraryLifecycle, skill_archive_as_owner, skill_library_get_as_owner,
};
use oneiron::{ClaimApprovalStatus, EntityId, Result, TimeRange, Vault, VaultConfig};
use rmpv::Value;

/// The owner restore, returning the receipt's Debug text: this file reads the
/// `replaced_seed_entities` count by name from the text, as
/// `whole_vault_restore_edited_seeds.rs` does, so it names no receipt field.
fn restore_as_owner(dest: &Vault, archive: &[u8], owner: &AuthenticatedOwner) -> Result<String> {
    let receipt = dest.import_whole_vault_archive_from_as_owner(Cursor::new(archive), owner)?;
    Ok(format!("{receipt:?}"))
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// A fresh SEEDED destination whose engine-seed seconds differ from the
/// source's: any 1100 ms interval crosses a second boundary.
fn open_later_vault() -> (tempfile::TempDir, Vault) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    open_vault()
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

fn person_body(name: &str) -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from(name))]),
    )
    .expect("encode PERSON");
    body
}

/// One carried SKILL row's exported header times, by id hex, from a
/// whole-vault archive's Skill section.
fn exported_skill_header(vault: &Vault, archive: &[u8], id: &EntityId) -> (u64, u64, u64) {
    let document = vault
        .read_whole_vault_archive(archive)
        .expect("read archive");
    let bundle = document
        .skills
        .iter()
        .find(|bundle| bundle.entity.id == id.to_hex())
        .expect("skill in export");
    (
        bundle.entity.occurred_start,
        bundle.entity.occurred_end,
        bundle.entity.learned_at,
    )
}

/// A seeded bootstrap SKILL that is still Active: bootstrap seeds sit at
/// learned_at zero in both vaults, so the first Active one in id order is
/// deterministic across runs.
fn find_bootstrap_active_skill(vault: &Vault) -> (EntityId, SkillRecord) {
    let export = vault.export_whole_vault(true).expect("export skills");
    let document = vault
        .read_whole_vault_archive(export.bytes())
        .expect("read skills");
    let mut candidates = Vec::new();
    for bundle in &document.skills {
        if bundle.entity.learned_at != 0 {
            continue;
        }
        let id = EntityId::from_hex(&bundle.entity.id).expect("skill id");
        let record = vault
            .get_skill_record(&id)
            .expect("skill read")
            .expect("skill row");
        if record.lifecycle_status == SkillLifecycle::Active {
            candidates.push((id, record));
        }
    }
    candidates.sort_by_key(|(id, _)| id.to_hex());
    candidates
        .into_iter()
        .next()
        .expect("an active bootstrap SKILL seed")
}

/// A Candidate connector setup SKILL seed: pack seeds carry wall-clock
/// learned_at, so the first Candidate one in id order is deterministic.
fn find_candidate_setup_skill(vault: &Vault) -> (EntityId, SkillRecord) {
    let export = vault.export_whole_vault(true).expect("export skills");
    let document = vault
        .read_whole_vault_archive(export.bytes())
        .expect("read skills");
    let mut candidates = Vec::new();
    for bundle in &document.skills {
        if bundle.entity.learned_at == 0 {
            continue;
        }
        let id = EntityId::from_hex(&bundle.entity.id).expect("skill id");
        let record = vault
            .get_skill_record(&id)
            .expect("skill read")
            .expect("skill row");
        if record.lifecycle_status == SkillLifecycle::Candidate {
            candidates.push((id, record));
        }
    }
    candidates.sort_by_key(|(id, _)| id.to_hex());
    candidates
        .into_iter()
        .next()
        .expect("a candidate setup SKILL seed")
}

/// A source vault whose owner archived one seeded bootstrap SKILL through
/// the owner library door (same id, Quarantined plus Approved), plus the
/// whole-vault archive carrying it.
fn seed_source_with_archived_seed_skill()
-> (tempfile::TempDir, Vault, EntityId, SkillRecord, Vec<u8>) {
    let (dir, source) = open_vault();
    let (skill, seed) = find_bootstrap_active_skill(&source);
    assert_eq!(
        seed.lifecycle_status,
        SkillLifecycle::Active,
        "the seed stands Active"
    );
    let proof = owner_proof(&source);
    let view = skill_archive_as_owner(&source, &proof, &HubSkillRequest { entity: skill })
        .expect("owner archives the seeded skill");
    assert_eq!(
        view.lifecycle,
        SkillLibraryLifecycle::Archived,
        "the library view shows the archived skill"
    );
    let archived = source
        .get_skill_record(&skill)
        .expect("archived read")
        .expect("archived row");
    assert_eq!(
        archived.lifecycle_status,
        SkillLifecycle::Quarantined,
        "the archive door quarantines the seed"
    );
    assert_eq!(
        archived.approval_status,
        ClaimApprovalStatus::Approved,
        "the archive door approves the seed"
    );
    assert_eq!(
        archived.skill_id, seed.skill_id,
        "a lifecycle edit keeps the skill id"
    );
    assert_eq!(
        archived.version, seed.version,
        "a lifecycle edit keeps the version"
    );
    assert_eq!(
        archived.content_hash, seed.content_hash,
        "a lifecycle edit keeps the content hash"
    );
    let archive = source
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    (dir, source, skill, archived, archive)
}

/// A source vault whose Candidate setup SKILL seed took a same-id new-hash
/// hub sync through the supplied-package door (no network hub), plus the
/// whole-vault archive carrying it. The new version is the content-named
/// Folder version of the new tree, so the archived record still matches
/// its source frontmatter.
fn seed_source_with_synced_seed_skill() -> (tempfile::TempDir, Vault, EntityId, SkillRecord, Vec<u8>)
{
    let (dir, source) = open_vault();
    let (skill, seed) = find_candidate_setup_skill(&source);
    assert_eq!(
        seed.lifecycle_status,
        SkillLifecycle::Candidate,
        "the setup seed stands Candidate"
    );
    let proof = owner_proof(&source);
    let view = skill_library_get_as_owner(&source, &proof, &HubSkillRequest { entity: skill })
        .expect("source package reads");
    let files = view.files.expect("the seed carries source files");
    assert!(!files.is_empty(), "the seed carries at least one file");
    let mut synced_files = Vec::new();
    let mut saw_skill_md = false;
    for file in &files {
        let mut content = file.content.clone();
        if file.path == "SKILL.md" {
            saw_skill_md = true;
            content.extend_from_slice(b"\n<!-- yuki sync edit -->\n");
        }
        synced_files.push(HubFile::new(file.path.clone(), content));
    }
    assert!(saw_skill_md, "the setup skill carries SKILL.md");
    let new_hash = canonical_skill_tree_hash(
        synced_files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )
    .expect("new tree hash");
    assert_ne!(
        Some(new_hash),
        seed.content_hash,
        "the new files change the content hash"
    );
    let new_version = format!("0.0.0+{}", &new_hash.to_hex()[..12]);
    assert_ne!(
        new_version, seed.version,
        "the content version moves with the tree"
    );
    let mut synced_record = seed.clone();
    synced_record.version = new_version.clone();
    synced_record.content_hash = None;
    let package = HubPackage::new(
        synced_record,
        synced_files,
        SkillCapabilitySurface::default(),
    );
    let sources = source.skill_hub_sources(&skill).expect("hub sources read");
    let hub_ref = if let Some(first) = sources.first() {
        HubRef::new(first.hub_id, first.ref_string.clone(), HubPin::None).expect("sync ref")
    } else {
        HubRef::new(EntityId::now(), "owen-sync", HubPin::None).expect("sync ref")
    };
    let disposition = source
        .sync_skill_from_hub(
            &skill,
            &hub_ref,
            &package,
            HubSyncPolicy::PinnedRef,
            TimeRange {
                start: 500,
                end: 500,
            },
            500,
        )
        .expect("hub sync");
    assert_eq!(
        disposition,
        HubSyncDisposition::Applied,
        "the candidate sync applies, got {disposition:?}"
    );
    let updated = source
        .get_skill_record(&skill)
        .expect("synced read")
        .expect("synced row");
    assert_eq!(
        updated.version, new_version,
        "the sync lands the new version"
    );
    assert_eq!(
        updated.content_hash,
        Some(new_hash),
        "the sync lands the new content hash"
    );
    assert_eq!(
        updated.lifecycle_status,
        SkillLifecycle::Candidate,
        "the sync keeps the Candidate lifecycle"
    );
    assert_eq!(
        updated.skill_id, seed.skill_id,
        "the sync keeps the skill id"
    );
    let archive = source
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    (dir, source, skill, updated, archive)
}

/// Sorted `(path, content)` pairs of a library view's files, for an
/// order-independent comparison of two runtime packages.
fn sorted_files(files: Vec<oneiron::verbs::SkillLibraryFile>) -> Vec<(String, Vec<u8>)> {
    let mut pairs: Vec<(String, Vec<u8>)> = files
        .into_iter()
        .map(|file| (file.path, file.content))
        .collect();
    pairs.sort();
    pairs
}

/// The owner restore into a fresh vault replaces the archived seeded SKILL
/// with the archive's row, header times included, durably; the runtime
/// package still reads.
#[test]
fn owner_restore_replaces_lifecycle_edited_seed_skill() -> Result<()> {
    let (_source_dir, source, skill, archived, archive) = seed_source_with_archived_seed_skill();
    let stored = source.get_skill_record(&skill)?.expect("edited seed row");
    assert_eq!(stored, archived, "the source holds the owner archive");
    let source_header = exported_skill_header(&source, &archive, &skill);
    let source_proof = owner_proof(&source);
    let source_view =
        skill_library_get_as_owner(&source, &source_proof, &HubSkillRequest { entity: skill })
            .expect("source package reads");
    let source_files = sorted_files(source_view.files.expect("source carries files"));
    let (dest_dir, dest) = open_later_vault();
    let dest_seed = dest
        .get_skill_record(&skill)?
        .expect("destination seed row");
    assert_eq!(
        dest_seed.lifecycle_status,
        SkillLifecycle::Active,
        "the destination still holds the fresh Active seed"
    );
    assert_ne!(
        dest_seed.lifecycle_status, archived.lifecycle_status,
        "the archive differs from the fresh seed"
    );
    let proof = owner_proof(&dest);
    let receipt = restore_as_owner(&dest, &archive, &proof)?;
    assert!(
        receipt.contains("replaced_seed_entities: 1,"),
        "the receipt counts the SKILL as a replaced seed: {receipt}"
    );
    let landed = dest.get_skill_record(&skill)?.expect("restored seed row");
    assert_eq!(
        landed, archived,
        "the destination SKILL decodes equal to the source's"
    );
    assert_eq!(
        landed.lifecycle_status,
        SkillLifecycle::Quarantined,
        "the restored SKILL keeps the archived lifecycle"
    );
    assert_eq!(
        landed.approval_status,
        ClaimApprovalStatus::Approved,
        "the restored SKILL keeps the archived approval"
    );
    let dest_export = dest.export_whole_vault(true)?;
    assert_eq!(
        exported_skill_header(&dest, dest_export.bytes(), &skill),
        source_header,
        "the restored SKILL keeps the archive's header times"
    );
    let dest_view = skill_library_get_as_owner(&dest, &proof, &HubSkillRequest { entity: skill })
        .expect("restored runtime package reads");
    assert_eq!(
        dest_view.lifecycle,
        SkillLibraryLifecycle::Archived,
        "the restored library view shows the archived skill"
    );
    assert_eq!(
        dest_view.approval,
        ClaimApprovalStatus::Approved,
        "the restored library view keeps the archived approval"
    );
    assert_eq!(
        sorted_files(dest_view.files.expect("restored carries files")),
        source_files,
        "the restored package keeps the archived files"
    );
    let path = dest_dir.path().to_path_buf();
    drop(dest);
    drop(proof);
    let dest = Vault::open_owned(&path, VaultConfig::default())?;
    let reopened = dest.get_skill_record(&skill)?.expect("reopened row");
    assert_eq!(reopened, archived, "the edited SKILL survives a reopen");
    let proof = owner_proof(&dest);
    let reopened_view =
        skill_library_get_as_owner(&dest, &proof, &HubSkillRequest { entity: skill })
            .expect("reopened package reads");
    assert!(
        reopened_view.files.is_some(),
        "the reopened package still carries files"
    );
    Ok(())
}

/// The owner restore into a fresh vault replaces the hub-synced seeded
/// SKILL with the archive's new-hash row, header times included, durably;
/// the runtime package still reads.
#[test]
fn owner_restore_replaces_hub_synced_seed_skill() -> Result<()> {
    let (_source_dir, source, skill, updated, archive) = seed_source_with_synced_seed_skill();
    let stored = source.get_skill_record(&skill)?.expect("synced seed row");
    assert_eq!(stored, updated, "the source holds the hub sync");
    let source_header = exported_skill_header(&source, &archive, &skill);
    let source_proof = owner_proof(&source);
    let source_view =
        skill_library_get_as_owner(&source, &source_proof, &HubSkillRequest { entity: skill })
            .expect("source package reads");
    let source_files = sorted_files(source_view.files.expect("source carries files"));
    let (dest_dir, dest) = open_later_vault();
    let dest_seed = dest
        .get_skill_record(&skill)?
        .expect("destination seed row");
    assert_eq!(
        dest_seed.lifecycle_status,
        SkillLifecycle::Candidate,
        "the destination still holds the fresh Candidate seed"
    );
    assert_ne!(
        dest_seed.version, updated.version,
        "the archive carries a new version"
    );
    assert_ne!(
        dest_seed.content_hash, updated.content_hash,
        "the archive carries a new content hash"
    );
    let proof = owner_proof(&dest);
    let receipt = restore_as_owner(&dest, &archive, &proof)?;
    assert!(
        receipt.contains("replaced_seed_entities: 1,"),
        "the receipt counts the SKILL as a replaced seed: {receipt}"
    );
    let landed = dest.get_skill_record(&skill)?.expect("restored seed row");
    assert_eq!(
        landed, updated,
        "the destination SKILL decodes equal to the source's"
    );
    let dest_export = dest.export_whole_vault(true)?;
    assert_eq!(
        exported_skill_header(&dest, dest_export.bytes(), &skill),
        source_header,
        "the restored SKILL keeps the archive's header times"
    );
    let dest_view = skill_library_get_as_owner(&dest, &proof, &HubSkillRequest { entity: skill })
        .expect("restored runtime package reads");
    assert_eq!(
        sorted_files(dest_view.files.expect("restored carries files")),
        source_files,
        "the restored package keeps the archived files"
    );
    let path = dest_dir.path().to_path_buf();
    drop(dest);
    drop(proof);
    let dest = Vault::open_owned(&path, VaultConfig::default())?;
    let reopened = dest.get_skill_record(&skill)?.expect("reopened row");
    assert_eq!(reopened, updated, "the synced SKILL survives a reopen");
    Ok(())
}

/// The same archive into a used destination still collides: the owner door
/// replaces edited seeds only in a fresh vault.
#[test]
fn owner_restore_of_edited_seed_skill_into_used_vault_still_collides() -> Result<()> {
    let (_source_dir, _source, skill, _archived, archive) = seed_source_with_archived_seed_skill();
    let (_dest_dir, dest) = open_later_vault();
    let before = dest
        .get_skill_record(&skill)?
        .expect("destination seed row");
    assert_eq!(
        before.lifecycle_status,
        SkillLifecycle::Active,
        "the destination still holds the fresh Active seed"
    );
    let owen = EntityId::now();
    dest.put_entity(
        &owen,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
        &person_body("owen"),
    )?;
    let proof = owner_proof(&dest);
    let error =
        restore_as_owner(&dest, &archive, &proof).expect_err("a used destination still collides");
    assert!(
        error
            .to_string()
            .contains("import ID collides with different entity data"),
        "unexpected refusal: {error}"
    );
    let after = dest
        .get_skill_record(&skill)?
        .expect("destination seed row");
    assert_eq!(
        after, before,
        "the failed import leaves the destination seed unchanged"
    );
    Ok(())
}

/// The same archive through the actorless door still collides: only the
/// owner door replaces edited seeds.
#[test]
fn actorless_restore_of_edited_seed_skill_still_collides() -> Result<()> {
    let (_source_dir, _source, skill, _archived, archive) = seed_source_with_archived_seed_skill();
    let (_dest_dir, dest) = open_later_vault();
    let before = dest
        .get_skill_record(&skill)?
        .expect("destination seed row");
    let error = dest
        .import_whole_vault_archive_from(Cursor::new(archive.as_slice()))
        .expect_err("the actorless door still collides");
    assert!(
        error
            .to_string()
            .contains("import ID collides with different entity data"),
        "unexpected refusal: {error}"
    );
    let after = dest
        .get_skill_record(&skill)?
        .expect("destination seed row");
    assert_eq!(
        after, before,
        "the failed import leaves the destination seed unchanged"
    );
    Ok(())
}
