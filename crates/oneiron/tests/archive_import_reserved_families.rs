//! The whole-vault import's one decision per reserved predicate family, and
//! two families whose omitted rows other restored rows sit beside
//! (ARCHIVE-IMPORT-RESERVED-CLAIM-ABORTS; Engine ruling 12 Nov 19:08).
//!
//! * `every_reserved_family_has_an_import_route_or_omission`: each family the
//!   reserved-predicate check reads (the `edge` namespace, every engine-owned
//!   namespace, every exact engine-owned predicate) has a restore door or an
//!   omission reason. A family added to that check without one fails here,
//!   before any archive holding it can abort an import.
//! * `each_reserved_family_takes_its_ruled_door_or_reason`: the ruled table.
//! * `a_section_install_claim_restores_without_its_fit_receipt`: a fit
//!   install's `plugin.section_install` claim restores (Imported, Proposed)
//!   while its `skill.section_fit` receipt stays archive data
//!   (`EngineAttestationNotRestored`).
//! * `the_receipt_names_the_default_facet_the_destination_kept`: an actorless
//!   import lists the archived `vault.default_facet` in the receipt's
//!   `destination_omissions` as `TargetDefaultFacetKept`.
//!
//! Needs the doors (green only: the doors and the receipt field are new):
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test archive_import_reserved_families`.
#![cfg(oneiron_test_support)]

use std::io::Cursor;

use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use oneiron::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use oneiron::skill_hub::HubFile;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::archive_import::{
    land_section_install_with_fit_receipt, reserved_claim_import, reserved_family_predicates,
};
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
    WriteActor,
};
use rmpv::Value;

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

fn owner_actor(vault: &Vault) -> WriteActor {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    WriteActor::new(owner, EdgeActorClass::Human)
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

fn put_named(vault: &Vault, id: &EntityId, entity_type: u8, name: &str) {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from(name))]),
    )
    .expect("encode named body");
    vault
        .put_entity(
            id,
            entity_type,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            &body,
        )
        .expect("ordinary named row");
}

fn export_whole(vault: &Vault) -> Vec<u8> {
    vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec()
}

#[test]
fn every_reserved_family_has_an_import_route_or_omission() {
    let families = reserved_family_predicates();
    assert!(
        families.len() >= 11,
        "edge, 8 engine-owned namespaces, 2 exact predicates: {families:?}"
    );
    let uncovered: Vec<&String> = families
        .iter()
        .filter(|predicate| reserved_claim_import(predicate).is_none())
        .collect();
    assert!(
        uncovered.is_empty(),
        "a reserved family with neither a restore door nor an omission reason aborts every \
         whole-vault import that holds it: {uncovered:?}"
    );
}

#[test]
fn each_reserved_family_takes_its_ruled_door_or_reason() {
    let ruled = [
        ("edge.provenance", "Restore(EdgeProvenance)"),
        ("person.substrate", "Restore(SubjectModel)"),
        ("actor.subject_ref", "Restore(SubjectModel)"),
        ("actor.lesson", "Restore(ActorProjection)"),
        ("vault.default_facet", "Restore(OwnerDefaultFacet)"),
        (
            "skill.hub_provenance",
            "ArchiveOnly(ForeignSkillSignalNotRestored)",
        ),
        (
            "skill.scan_verdict",
            "ArchiveOnly(ForeignSkillSignalNotRestored)",
        ),
        (
            "actor.peer_binding",
            "ArchiveOnly(LocalActorConfigurationNotRestored)",
        ),
        (
            "learning.reliability",
            "ArchiveOnly(LearningCellsRebuiltFromReceipts)",
        ),
        (
            "world_access.allowed",
            "ArchiveOnly(LocalHistoryNotRestored)",
        ),
        ("activated.pinned", "ArchiveOnly(LocalHistoryNotRestored)"),
        ("machine.birth", "ArchiveOnly(LocalHistoryNotRestored)"),
        ("machine.handoff", "ArchiveOnly(LocalHistoryNotRestored)"),
        ("esign.signed", "ArchiveOnly(EngineAttestationNotRestored)"),
        (
            "skill.section_fit",
            "ArchiveOnly(EngineAttestationNotRestored)",
        ),
        (
            "skill.quarantine_proposal",
            "ArchiveOnly(LocalProjectionNotRestored)",
        ),
        (
            "skill.hub_update_proposal",
            "ArchiveOnly(HubConfigurationNotRestored)",
        ),
        ("repo.import_manifest", "ArchiveOnly(RepoClaimsNotRestored)"),
        ("repo.publication", "ArchiveOnly(RepoClaimsNotRestored)"),
    ];
    for (predicate, decision) in ruled {
        assert_eq!(
            reserved_claim_import(predicate).as_deref(),
            Some(decision),
            "{predicate}"
        );
    }
    assert_eq!(
        reserved_claim_import("profile.name"),
        None,
        "an ordinary predicate takes the generic claim door"
    );
}

#[test]
fn a_section_install_claim_restores_without_its_fit_receipt() {
    let (_source_dir, source) = open_vault();
    let _owner = owner_actor(&source);
    let files = vec![HubFile::new(
        "SKILL.md",
        b"# a skill with a fitted section\n".to_vec(),
    )];
    let tree = canonical_skill_tree_hash(
        files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )
    .expect("tree hash");
    let record = SkillRecord::new(
        "archive-pin.sectioned",
        "A skill a plugin section was fitted onto",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        0.9,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(
            Value::from("source"),
            Value::from("archive-pin-fixture"),
        )]),
    )
    .with_content_hash(tree);
    let skill =
        oneiron::test_doors::skill_package::land_active_skill_with_files(&source, &record, files)
            .expect("an active skill");
    let (install, receipt) =
        land_section_install_with_fit_receipt(&source, skill, source.now_recorded_at())
            .expect("the install claim and its fit receipt");
    let archive = export_whole(&source);
    let (_dest_dir, dest) = open_later_vault();
    let omissions: Vec<(String, String)> = dest
        .read_whole_vault_archive(&archive)
        .expect("read the archive")
        .manifest
        .import_omissions
        .iter()
        .map(|omission| (omission.entity_id.clone(), format!("{:?}", omission.reason)))
        .collect();
    assert!(
        omissions
            .iter()
            .any(|(id, reason)| *id == receipt.to_hex() && reason == "EngineAttestationNotRestored"),
        "the manifest names the fit receipt as EngineAttestationNotRestored: {omissions:?}"
    );
    let owner = owner_proof(&dest);

    if let Err(error) = dest.import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner)
    {
        panic!("the owner's whole archive holding a fit install must restore: {error:?}");
    }

    let restored = dest
        .get_claim(&install)
        .expect("read the install claim")
        .expect("the install claim restores without its receipt");
    assert_eq!(restored.predicate, "plugin.section_install");
    assert_eq!(restored.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(restored.source, Some(ClaimSource::Imported));
    assert_eq!(
        dest.get_entity_type(&receipt).expect("read the receipt"),
        None,
        "the fit receipt stays archive data"
    );
}

#[test]
fn the_receipt_names_the_default_facet_the_destination_kept() {
    let (_source_dir, source) = open_vault();
    let owner = owner_actor(&source);
    let owen = EntityId::now();
    put_named(&source, &owen, ENTITY_TYPE_PERSON, "owen");
    let work = EntityId::now();
    put_named(&source, &work, ENTITY_TYPE_FACET, "work");
    source
        .set_default_facet(work, owner)
        .expect("the owner sets the vault default facet");
    let archive = export_whole(&source);
    let (_dest_dir, dest) = open_later_vault();

    let receipt = dest
        .import_whole_vault_archive_from(Cursor::new(&archive))
        .expect("an actorless import keeps the archived default facet as archive data");

    let [kept] = receipt.destination_omissions.as_slice() else {
        panic!(
            "one kept default facet claim: {:?}",
            receipt.destination_omissions
        );
    };
    assert_eq!(format!("{:?}", kept.reason), "TargetDefaultFacetKept");
    let claim = EntityId::from_hex(&kept.entity_id).expect("a claim id");
    assert_eq!(
        source
            .get_claim(&claim)
            .expect("read the source claim")
            .map(|body| body.predicate),
        Some("vault.default_facet".to_owned())
    );
    assert_eq!(dest.get_entity_type(&claim).expect("read the claim"), None);
}
