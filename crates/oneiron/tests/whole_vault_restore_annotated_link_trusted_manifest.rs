//! Fix list row WHOLE-VAULT-SAME-AS-ANNOTATED-LINK-IMPORT-PENDS, its plain
//! link part: a whole-vault archive of a vault holding an annotated
//! `mentions` link (an owner's edge provenance claim on it) imports into a
//! vault whose policy manifest is trusted, as on every install with a
//! keystore. The import restores each archived provenance claim as an
//! Imported Auto claim of its annotator, and the shipped manifest has no
//! Imported Auto row, so the gate pended the first one
//! (`gate.pending.source_trust`) and the whole import rolled back, through
//! every door. Now (Engine ANSWER PROVENANCE-RESTORE-UNDER-TRUSTED-MANIFEST =
//! A, 20 Nov 09:26) the owner's restore carries its one-restore permit into
//! the provenance writer, so the annotation comes back; every other door
//! keeps the annotation as archive data (`ProvenanceAutoNotPermitted`),
//! brings the link back bare, and completes.
//!
//! * `owner_restore_brings_an_annotated_link_back_with_its_provenance`: the
//!   owner's restore into a fresh vault; the link and its live annotation
//!   come back, and the receipt names no omission for it.
//! * `owner_restore_brings_a_superseded_and_a_retracted_annotation_back`:
//!   the source superseded its first annotation with a second and retracted
//!   the second; the restore closes and retracts them through the writer,
//!   under the same permit.
//! * `an_import_without_the_owner_keeps_the_annotation_out`: the actorless
//!   door.
//! * `an_actor_import_keeps_the_annotation_out`: the actor-taking door, with
//!   the destination's owner as the actor; only the owner's restore door
//!   carries the permit.
//!
//! Red on main 384cf8319e6b: each test fails at its import with
//! `Gate(GateWriteRejected { outcome: "pending", reason_codes:
//! ["gate.pending.source_trust"] })`; the source preconditions pass. The
//! omission reason is read by its debug name, so the file compiles on main,
//! where `ProvenanceAutoNotPermitted` does not exist. The same_as part is in
//! `whole_vault_restore_same_as_links.rs`.
//!
//! Vaults in tempdirs, opened as `whole_vault_restore_same_as_links.rs` opens
//! them (shipped default manifest, an in-memory keystore, this install's
//! signing keys prepared, so the manifest is trusted and the gate enforced),
//! every step through public doors. Each destination opens at least one
//! wall-clock second after its source (sleep 1100 ms), and an annotation
//! that must be newer than another is written at least 1100 ms after it, as
//! in `whole_vault_restore_held_link_provenance.rs`. Run with `cargo test
//! --locked -p oneiron --all-features --test
//! whole_vault_restore_annotated_link_trusted_manifest`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use oneiron::batch::export::WholeVaultImportReceipt;
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeKind;
use oneiron::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimLifecycleStatus, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};

/// A vault opened with the shipped default manifest and this install's
/// signing keys, so its manifest is trusted and its write gate enforced.
fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    (dir, vault)
}

/// Waits until the wall-clock second has changed: any 1100 ms interval
/// crosses a second boundary.
fn next_second() {
    std::thread::sleep(std::time::Duration::from_millis(1100));
}

/// A fresh SEEDED destination whose engine-seed seconds differ from the
/// source's.
fn open_later_vault() -> (tempfile::TempDir, Vault) {
    next_second();
    open_vault()
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

fn put_person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"person fixture",
        )
        .expect("put the person");
    id
}

fn export(vault: &Vault) -> Vec<u8> {
    vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec()
}

/// A source vault holding a `mentions` link between two PERSONs.
struct Linked {
    _dir: tempfile::TempDir,
    vault: Vault,
    source: EntityId,
    target: EntityId,
}

fn linked_source() -> Linked {
    let (dir, vault) = open_vault();
    let source = put_person(&vault);
    let target = put_person(&vault);
    vault
        .put_edge(&source, EdgeKind::Mentions, &target, 1.0)
        .expect("put the link");
    Linked {
        _dir: dir,
        vault,
        source,
        target,
    }
}

/// A provenance claim on the link through the public provenance door,
/// learned at the vault's current second.
fn annotate(linked: &Linked) -> EntityId {
    let id = EntityId::now();
    linked
        .vault
        .put_edge_provenance(
            &id,
            &EdgeRef::new(linked.source, EdgeKind::Mentions, linked.target),
            &EdgeProvenanceClaimBody::new(linked.source, 1.0, SupersessionStatus::Confirmed),
            EdgeActorClass::Human,
            linked.vault.now_recorded_at(),
        )
        .expect("the provenance claim on the link lands");
    id
}

/// The source's link with one live annotation, and its whole-vault archive.
fn annotated_archive() -> (Linked, EntityId, Vec<u8>) {
    let linked = linked_source();
    let annotation = annotate(&linked);
    assert_eq!(
        lifecycle(&linked.vault, &annotation),
        Some(ClaimLifecycleStatus::Active),
        "precondition: the source's annotation is live"
    );
    let archive = export(&linked.vault);
    (linked, annotation, archive)
}

fn lifecycle(vault: &Vault, claim: &EntityId) -> Option<ClaimLifecycleStatus> {
    vault
        .get_claim(claim)
        .expect("read the provenance claim")
        .map(|body| body.lifecycle)
}

fn link_here(vault: &Vault, linked: &Linked) -> bool {
    vault
        .edge_exists(&linked.source, EdgeKind::Mentions, &linked.target)
        .expect("read the link")
}

/// The reason the receipt's `destination_omissions` gives for `id`, by its
/// debug name.
fn omission_reason(receipt: &WholeVaultImportReceipt, id: EntityId) -> Option<String> {
    receipt
        .destination_omissions
        .iter()
        .find(|kept| kept.entity_id == id.to_hex())
        .map(|kept| format!("{:?}", kept.reason))
}

/// The import completed: the link came back bare, and its annotation stayed
/// archive data, named in the receipt.
fn assert_annotation_kept_out(
    dest: &Vault,
    linked: &Linked,
    receipt: &WholeVaultImportReceipt,
    annotation: EntityId,
) {
    assert!(link_here(dest, linked), "the link comes back");
    assert!(
        !dest
            .entity_exists(&annotation)
            .expect("read the annotation"),
        "the annotation stays archive data"
    );
    assert_eq!(
        omission_reason(receipt, annotation).as_deref(),
        Some("ProvenanceAutoNotPermitted"),
        "the receipt names the annotation: {:?}",
        receipt.destination_omissions
    );
}

#[test]
fn owner_restore_brings_an_annotated_link_back_with_its_provenance() {
    let (linked, annotation, archive) = annotated_archive();
    let (_dir, dest) = open_later_vault();
    let owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner)
        .expect("the owner's restore of the annotated link completes");
    assert!(link_here(&dest, &linked), "the link comes back");
    assert_eq!(
        lifecycle(&dest, &annotation),
        Some(ClaimLifecycleStatus::Active),
        "the link's annotation comes back live"
    );
    assert_eq!(
        omission_reason(&receipt, annotation),
        None,
        "the receipt names no omission for the annotation: {:?}",
        receipt.destination_omissions
    );
}

#[test]
fn owner_restore_brings_a_superseded_and_a_retracted_annotation_back() {
    let linked = linked_source();
    let first = annotate(&linked);
    next_second();
    let second = annotate(&linked);
    next_second();
    linked
        .vault
        .retract_edge_provenance(&second, linked.vault.now_recorded_at())
        .expect("the source retracts its second annotation");
    assert_eq!(
        lifecycle(&linked.vault, &first),
        Some(ClaimLifecycleStatus::Superseded),
        "precondition: the second annotation superseded the first"
    );
    assert_eq!(
        lifecycle(&linked.vault, &second),
        Some(ClaimLifecycleStatus::Retracted),
        "precondition: the source retracted the second annotation"
    );
    let archive = export(&linked.vault);
    let (_dir, dest) = open_later_vault();
    let owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&archive), &owner)
        .expect("the owner's restore of the closed annotations completes");
    assert!(link_here(&dest, &linked), "the link comes back");
    assert_eq!(
        lifecycle(&dest, &first),
        Some(ClaimLifecycleStatus::Superseded),
        "the first annotation comes back superseded"
    );
    assert_eq!(
        lifecycle(&dest, &second),
        Some(ClaimLifecycleStatus::Retracted),
        "the second annotation comes back retracted"
    );
    for annotation in [first, second] {
        assert_eq!(
            omission_reason(&receipt, annotation),
            None,
            "the receipt names no omission for {annotation:?}: {:?}",
            receipt.destination_omissions
        );
    }
}

#[test]
fn an_import_without_the_owner_keeps_the_annotation_out() {
    let (linked, annotation, archive) = annotated_archive();
    let (_dir, dest) = open_later_vault();
    let receipt = dest
        .import_whole_vault_archive_from(Cursor::new(&archive))
        .expect("the actorless import of the annotated link completes");
    assert_annotation_kept_out(&dest, &linked, &receipt, annotation);
}

#[test]
fn an_actor_import_keeps_the_annotation_out() {
    let (linked, annotation, archive) = annotated_archive();
    let (_dir, dest) = open_later_vault();
    let owner = dest.ensure_embedded_owner_actor().expect("embedded owner");
    let receipt = dest
        .import_whole_vault_archive_with_actor(
            &archive,
            &WriteActor::new(owner, EdgeActorClass::Human),
        )
        .expect("the actor import of the annotated link completes");
    assert_annotation_kept_out(&dest, &linked, &receipt, annotation);
}
