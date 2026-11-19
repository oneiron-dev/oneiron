//! Fix list row WHOLE-VAULT-IMPORT-HELD-LINK-OLDER-PROVENANCE-ABORTS, the
//! plain-link twin of REVIEW-9581 round 2: the destination took a bare
//! `mentions` link from an earlier whole-vault archive and annotated it
//! itself. A later archive of the source carries the source's own annotation
//! of that link. Its cohort reached the provenance writer, whose precedence
//! check refused an annotation older than the destination's own
//! (`ProvenancePrecedenceViolation`), and the whole import rolled back; an
//! annotation newer than the destination's own closed it. Now a link this
//! vault holds keeps its own provenance history (Engine ruling 19 Nov 13:46):
//! the archived cohort stays archive data, named in the receipt's
//! `destination_omissions` (`ClaimSubjectEdgeNotRestored`), as a held
//! `same_as`'s does, the import goes on, and the two histories never merge by
//! learned-at.
//!
//! * `an_older_archived_annotation_on_a_held_link_stays_archive_data`: the
//!   destination annotated after the source; the import completes, the
//!   destination's annotation stays active, and the archived one stays out.
//! * `a_newer_archived_annotation_never_closes_the_held_links_own`: the
//!   destination annotated before the source; the import completes, and the
//!   destination's annotation stays active and is not superseded.
//! * `a_held_row_its_own_history_closed_stays_closed`: the destination took
//!   the link with the source's annotation, then annotated it itself, which
//!   closed the archived row it holds; the same archive imports again, and
//!   the row stays as this vault holds it (superseded by its own claim).
//! * `a_held_link_with_no_history_of_its_own_takes_the_archived_annotation`:
//!   the destination never annotated the link it took from the earlier
//!   archive, so the later archive's annotation comes back on it, as before.
//! * `a_held_link_keeps_its_own_retracted_stamp` (REVIEW-9652 P1): the
//!   destination annotated the link and retracted its annotation, so the link
//!   carries the retracted stamp while the archived link carries the source's
//!   confirmed one; the import completes and the link keeps its own stamp.
//! * `a_held_claim_with_the_archived_id_and_another_body_is_a_collision`
//!   (REVIEW-9652 P1): the destination holds an active claim on the link with
//!   an archived claim's id but another confidence, and a claim of its own on
//!   the link beside it; the import refuses it as an ID collision and rolls
//!   back.
//!
//! Red on main 584b44473513: the first test fails at the second import,
//! refused with `ProvenancePrecedenceViolation`; the second test finds the
//! destination's annotation superseded by the archived one; the third test
//! fails at the second import, which compares the held row closed by the
//! destination's own claim with the archived active row
//! (`archive provenance ID collision`). The fourth test passes on main and
//! on the fix. The fifth test is red on main, which restores the archived
//! annotation onto the link, and red at the round-1 head 504a12878a78, whose
//! last edge pass compared the stamps and refused the import (`import edge
//! collides with different stored metadata`). The sixth test passes on main
//! and is red at the round-1 head, which took any held claim on the link as
//! unchanged. The omission reason is read by its debug name, as in
//! `whole_vault_restore_same_as_links.rs`.
//!
//! Vaults in tempdirs, every step through public doors. Each destination
//! opens at least one wall-clock second after its source (sleep 1100 ms), as
//! in `whole_vault_restore_seeds.rs`, and each annotation that must be newer
//! than another is written at least 1100 ms after it, so the two learned-at
//! seconds differ. Run with `cargo test --locked -p oneiron --all-features
//! --test whole_vault_restore_held_link_provenance`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use oneiron::batch::export::WholeVaultImportReceipt;
use oneiron::edge::{EdgeConfirmationStatus, EdgeKind};
use oneiron::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{ClaimLifecycleStatus, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
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

/// A source vault still open, holding a plain `mentions` link between two
/// PERSONs, and its whole-vault archive with the bare link.
struct Linked {
    _dir: tempfile::TempDir,
    vault: Vault,
    source: EntityId,
    target: EntityId,
    bare_archive: Vec<u8>,
}

fn linked_source() -> Linked {
    let (dir, vault) = open_vault();
    let source = put_person(&vault);
    let target = put_person(&vault);
    vault
        .put_edge(&source, EdgeKind::Mentions, &target, 1.0)
        .expect("put the link");
    let bare_archive = export(&vault);
    Linked {
        _dir: dir,
        vault,
        source,
        target,
        bare_archive,
    }
}

/// An owner's provenance claim on the link, through the public provenance
/// door, learned at the vault's current second.
fn annotate(vault: &Vault, source: EntityId, target: EntityId) -> EntityId {
    let id = EntityId::now();
    annotate_as(vault, id, source, target, 1.0, vault.now_recorded_at());
    id
}

/// The owner's provenance claim `id` on the link with `confidence`, learned
/// at `learned_at`.
fn annotate_as(
    vault: &Vault,
    id: EntityId,
    source: EntityId,
    target: EntityId,
    confidence: f32,
    learned_at: u64,
) {
    vault
        .put_edge_provenance(
            &id,
            &EdgeRef::new(source, EdgeKind::Mentions, target),
            &EdgeProvenanceClaimBody::new(source, confidence, SupersessionStatus::Confirmed),
            EdgeActorClass::Human,
            learned_at,
        )
        .expect("the provenance claim on the link lands");
}

/// The confirmation flag the link's stored value carries.
fn link_stamp(vault: &Vault, linked: &Linked) -> Option<EdgeConfirmationStatus> {
    vault
        .edges_out(&linked.source)
        .expect("read the source's links")
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::Mentions && edge.target == linked.target)
        .expect("the link is here")
        .provenance
        .map(|flags| flags.confirmation_status)
}

/// A destination that took the bare link from the source's earlier archive.
fn destination_holding_the_link(linked: &Linked) -> (tempfile::TempDir, Vault) {
    let (dir, dest) = open_later_vault();
    dest.import_whole_vault_archive_from(Cursor::new(&linked.bare_archive))
        .expect("the archive with the bare link imports");
    assert!(
        dest.edge_exists(&linked.source, EdgeKind::Mentions, &linked.target)
            .expect("read the link"),
        "precondition: the destination holds the link"
    );
    (dir, dest)
}

fn lifecycle(vault: &Vault, claim: &EntityId) -> Option<ClaimLifecycleStatus> {
    vault
        .get_claim(claim)
        .expect("read the provenance claim")
        .map(|body| body.lifecycle)
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

/// The held link, its own annotation and the archived one after the later
/// archive imported: the link and its own history as they were, the
/// archived annotation archive data.
fn assert_own_history_kept(
    dest: &Vault,
    linked: &Linked,
    receipt: &WholeVaultImportReceipt,
    own: EntityId,
    archived: EntityId,
) {
    assert!(
        dest.edge_exists(&linked.source, EdgeKind::Mentions, &linked.target)
            .expect("read the link"),
        "the held link stays"
    );
    assert_eq!(
        lifecycle(dest, &own),
        Some(ClaimLifecycleStatus::Active),
        "the held link keeps its own provenance claim active"
    );
    assert!(
        !dest
            .entity_exists(&archived)
            .expect("read the archived annotation"),
        "the archived annotation stays archive data"
    );
    assert_eq!(
        omission_reason(receipt, archived).as_deref(),
        Some("ClaimSubjectEdgeNotRestored"),
        "the receipt names the archived annotation: {:?}",
        receipt.destination_omissions
    );
}

#[test]
fn an_older_archived_annotation_on_a_held_link_stays_archive_data() {
    let linked = linked_source();
    let archived = annotate(&linked.vault, linked.source, linked.target);
    let annotated_archive = export(&linked.vault);
    let (_dir, dest) = destination_holding_the_link(&linked);
    let own = annotate(&dest, linked.source, linked.target);
    let receipt = dest
        .import_whole_vault_archive_from(Cursor::new(&annotated_archive))
        .expect("the archive with the older annotation imports");
    assert_own_history_kept(&dest, &linked, &receipt, own, archived);
}

#[test]
fn a_newer_archived_annotation_never_closes_the_held_links_own() {
    let linked = linked_source();
    let (_dir, dest) = destination_holding_the_link(&linked);
    let own = annotate(&dest, linked.source, linked.target);
    next_second();
    let archived = annotate(&linked.vault, linked.source, linked.target);
    let annotated_archive = export(&linked.vault);
    let receipt = dest
        .import_whole_vault_archive_from(Cursor::new(&annotated_archive))
        .expect("the archive with the newer annotation imports");
    assert_own_history_kept(&dest, &linked, &receipt, own, archived);
}

#[test]
fn a_held_row_its_own_history_closed_stays_closed() {
    let linked = linked_source();
    let archived = annotate(&linked.vault, linked.source, linked.target);
    let annotated_archive = export(&linked.vault);
    let (_dir, dest) = open_later_vault();
    dest.import_whole_vault_archive_from(Cursor::new(&annotated_archive))
        .expect("the archive with the annotated link imports");
    assert_eq!(
        lifecycle(&dest, &archived),
        Some(ClaimLifecycleStatus::Active),
        "precondition: the destination holds the archived annotation"
    );
    let own = annotate(&dest, linked.source, linked.target);
    assert_eq!(
        lifecycle(&dest, &archived),
        Some(ClaimLifecycleStatus::Superseded),
        "precondition: the destination's own annotation closed the archived one"
    );
    let receipt = dest
        .import_whole_vault_archive_from(Cursor::new(&annotated_archive))
        .expect("the same archive imports again");
    assert_eq!(
        lifecycle(&dest, &own),
        Some(ClaimLifecycleStatus::Active),
        "the held link keeps its own provenance claim active"
    );
    assert_eq!(
        lifecycle(&dest, &archived),
        Some(ClaimLifecycleStatus::Superseded),
        "the held row stays as this vault closed it"
    );
    assert_eq!(
        omission_reason(&receipt, archived),
        None,
        "the held row is no omission: {:?}",
        receipt.destination_omissions
    );
}

#[test]
fn a_held_link_with_no_history_of_its_own_takes_the_archived_annotation() {
    let linked = linked_source();
    let archived = annotate(&linked.vault, linked.source, linked.target);
    let annotated_archive = export(&linked.vault);
    let (_dir, dest) = destination_holding_the_link(&linked);
    let receipt = dest
        .import_whole_vault_archive_from(Cursor::new(&annotated_archive))
        .expect("the archive with the annotation imports");
    assert!(
        dest.entity_exists(&archived)
            .expect("read the archived annotation"),
        "the archived annotation comes back on the held link"
    );
    assert_eq!(
        lifecycle(&dest, &archived),
        Some(ClaimLifecycleStatus::Active),
        "the archived annotation is the link's live provenance"
    );
    assert_eq!(
        omission_reason(&receipt, archived),
        None,
        "the receipt names no omission for it: {:?}",
        receipt.destination_omissions
    );
}

#[test]
fn a_held_link_keeps_its_own_retracted_stamp() {
    let linked = linked_source();
    let archived = annotate(&linked.vault, linked.source, linked.target);
    let annotated_archive = export(&linked.vault);
    let (_dir, dest) = destination_holding_the_link(&linked);
    let own = annotate(&dest, linked.source, linked.target);
    dest.retract_edge_provenance(&own, dest.now_recorded_at())
        .expect("the destination retracts its own annotation");
    assert_eq!(
        link_stamp(&dest, &linked),
        Some(EdgeConfirmationStatus::Retracted),
        "precondition: the held link carries its own retracted stamp"
    );
    let receipt = dest
        .import_whole_vault_archive_from(Cursor::new(&annotated_archive))
        .expect("the archive with the confirmed link imports");
    assert_eq!(
        lifecycle(&dest, &own),
        Some(ClaimLifecycleStatus::Retracted),
        "the held link's own annotation stays retracted"
    );
    assert_eq!(
        link_stamp(&dest, &linked),
        Some(EdgeConfirmationStatus::Retracted),
        "the held link keeps its own stamp"
    );
    assert!(
        !dest
            .entity_exists(&archived)
            .expect("read the archived annotation"),
        "the archived annotation stays archive data"
    );
    assert_eq!(
        omission_reason(&receipt, archived).as_deref(),
        Some("ClaimSubjectEdgeNotRestored"),
        "the receipt names the archived annotation: {:?}",
        receipt.destination_omissions
    );
}

#[test]
fn a_held_claim_with_the_archived_id_and_another_body_is_a_collision() {
    let linked = linked_source();
    let shared = EntityId::now();
    annotate_as(
        &linked.vault,
        shared,
        linked.source,
        linked.target,
        1.0,
        linked.vault.now_recorded_at(),
    );
    let annotated_archive = export(&linked.vault);
    let (_dir, dest) = destination_holding_the_link(&linked);
    let learned_at = dest.now_recorded_at();
    annotate_as(&dest, shared, linked.source, linked.target, 0.5, learned_at);
    let own = EntityId::now();
    annotate_as(&dest, own, linked.source, linked.target, 1.0, learned_at);
    assert_eq!(
        lifecycle(&dest, &shared),
        Some(ClaimLifecycleStatus::Active),
        "precondition: the destination's claim with the archived id is active"
    );
    let error = dest
        .import_whole_vault_archive_from(Cursor::new(&annotated_archive))
        .expect_err("a held claim with the archived id and another body is no unchanged row");
    assert!(
        error
            .to_string()
            .contains("archive provenance ID collision"),
        "the import refuses the ID collision: {error}"
    );
    assert_eq!(
        lifecycle(&dest, &shared),
        Some(ClaimLifecycleStatus::Active),
        "the import rolled back: the destination's claim is as it was"
    );
    assert_eq!(
        lifecycle(&dest, &own),
        Some(ClaimLifecycleStatus::Active),
        "the import rolled back: the destination's own claim is as it was"
    );
}
