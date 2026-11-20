//! Fix list row WHOLE-VAULT-IMPORT-REFUSES-EDGE-SUBJECT-CLAIMS: a whole-vault
//! archive of a vault holding a claim about a link (a claim whose subject is
//! an EdgeRef) imports. The claim door reads such a subject live, and the
//! import put every claim before any edge, so the claim was refused and the
//! whole import aborted. Now the archived link goes in just before the claim
//! about it, and a claim whose link the archive does not carry stays archive
//! data, named in the receipt.
//!
//! * `owner_restore_brings_the_claim_about_a_link_back`: the owner's restore
//!   into a fresh vault.
//! * `actor_import_brings_the_claim_about_a_link_back`: through the
//!   actor-taking door.
//! * `actorless_import_again_finds_the_claim_about_a_link_unchanged`: the
//!   actorless door, twice; the second import finds the claim as it is.
//! * `a_claim_about_a_deleted_link_stays_archive_data`: the source deleted
//!   the link after the claim, so the archive carries the claim without it;
//!   the import completes, the claim stays out, and the receipt's
//!   `destination_omissions` names it (`ClaimSubjectEdgeNotRestored`).
//!
//! Red on the base (#9324's head 6c10217c1d72): each test fails at its first
//! import, which refuses the claim with `EntityNotFound`; the source
//! preconditions pass. The omission reason is read by its debug name, so the
//! file compiles on the base, where that reason does not exist.
//!
//! Vaults in tempdirs, every step through public doors. Each destination
//! opens at least one wall-clock second after its source (sleep 1100 ms), as
//! in `whole_vault_restore_seeds.rs`. Run with `cargo test --locked -p
//! oneiron --all-features --test whole_vault_restore_edge_subject_claims`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use oneiron::batch::export::WholeVaultImportReceipt;
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeKind;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;

/// The predicate of the claim about the link: an ordinary family, which
/// takes the generic claim door.
const PREDICATE: &str = "relationship.context";

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

/// What the source vault holds: a `mentions` link between two PERSONs, a
/// claim about that link, and its whole-vault archive.
struct Linked {
    archive: Vec<u8>,
    source: EntityId,
    target: EntityId,
    claim: EntityId,
}

/// A source vault with one claim about a plain `mentions` link, put through
/// the public claim door. With `delete_link`, the source deletes the link
/// after the claim, so its archive carries the claim without the link.
fn linked_archive(delete_link: bool) -> Linked {
    let (_dir, vault) = open_vault();
    let source = put_person(&vault);
    let target = put_person(&vault);
    vault
        .put_edge(&source, EdgeKind::Mentions, &target, 1.0)
        .expect("put the link");
    let claim = EntityId::now();
    vault
        .put_claim(
            &claim,
            &ClaimBody::new(
                PREDICATE,
                ClaimSubject::Edge {
                    source,
                    kind: EdgeKind::Mentions,
                    target,
                },
                Value::from("met at the climbing gym"),
                0.9,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            )
            .expect("claim body"),
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        )
        .expect("put the claim about the link");
    if delete_link {
        assert!(
            vault
                .delete_edge(&source, EdgeKind::Mentions, &target)
                .expect("delete the link"),
            "precondition: the link existed"
        );
    }
    assert!(
        vault
            .get_claim(&claim)
            .expect("read the source claim")
            .is_some(),
        "precondition: the source holds the claim about the link"
    );
    let archive = vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    let document = vault
        .read_whole_vault_archive(&archive)
        .expect("read the archive back");
    assert!(
        document.claims.iter().any(|row| row.id == claim.to_hex()),
        "precondition: the archive carries the claim"
    );
    let carries_link = document.evidence_ledger.edges.iter().any(|edge| {
        edge.source == source.to_hex()
            && edge.kind == EdgeKind::Mentions as u8
            && edge.target == target.to_hex()
    });
    assert_eq!(
        carries_link, !delete_link,
        "precondition: the archive carries the link unless the source deleted it"
    );
    Linked {
        archive,
        source,
        target,
        claim,
    }
}

/// `dest` holds the link and the claim about it.
fn assert_claim_back(dest: &Vault, restored: &Linked) {
    assert!(
        dest.edge_exists(&restored.source, EdgeKind::Mentions, &restored.target)
            .expect("read the restored link"),
        "the link is restored"
    );
    let claim = dest
        .get_claim(&restored.claim)
        .expect("read the restored claim")
        .expect("the claim about the link is restored");
    assert_eq!(claim.predicate, PREDICATE, "the restored claim's predicate");
    assert!(
        matches!(
            claim.subject,
            ClaimSubject::Edge {
                source,
                kind: EdgeKind::Mentions,
                target,
            } if source == restored.source && target == restored.target
        ),
        "the restored claim is about the restored link: {:?}",
        claim.subject
    );
}

/// The receipt keeps no row out for this vault's state.
fn assert_nothing_kept_out(receipt: &WholeVaultImportReceipt) {
    assert!(
        receipt.destination_omissions.is_empty(),
        "no row stays archive data: {:?}",
        receipt.destination_omissions
    );
}

#[test]
fn owner_restore_brings_the_claim_about_a_link_back() {
    let restored = linked_archive(false);
    let (_dir, dest) = open_later_vault();
    let owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&restored.archive), &owner)
        .expect("the owner's restore completes");
    assert_claim_back(&dest, &restored);
    assert_nothing_kept_out(&receipt);
}

#[test]
fn actor_import_brings_the_claim_about_a_link_back() {
    let restored = linked_archive(false);
    let (_dir, dest) = open_later_vault();
    let owner = dest.ensure_embedded_owner_actor().expect("embedded owner");
    let receipt = dest
        .import_whole_vault_archive_with_actor(
            &restored.archive,
            &WriteActor::new(owner, EdgeActorClass::Human),
        )
        .expect("the actor import completes");
    assert_claim_back(&dest, &restored);
    assert_nothing_kept_out(&receipt);
}

#[test]
fn actorless_import_again_finds_the_claim_about_a_link_unchanged() {
    let restored = linked_archive(false);
    let (_dir, dest) = open_later_vault();
    let receipt = dest
        .import_whole_vault_archive_from(Cursor::new(&restored.archive))
        .expect("the actorless import completes");
    assert_claim_back(&dest, &restored);
    assert_nothing_kept_out(&receipt);
    let again = dest
        .import_whole_vault_archive_from(Cursor::new(&restored.archive))
        .expect("the same archive again completes");
    assert_claim_back(&dest, &restored);
    assert_nothing_kept_out(&again);
}

#[test]
fn a_claim_about_a_deleted_link_stays_archive_data() {
    let restored = linked_archive(true);
    let (_dir, dest) = open_later_vault();
    let receipt = dest
        .import_whole_vault_archive_from(Cursor::new(&restored.archive))
        .expect("the import completes");
    assert!(
        !dest
            .edge_exists(&restored.source, EdgeKind::Mentions, &restored.target)
            .expect("read the link"),
        "the deleted link stays deleted"
    );
    assert!(
        dest.get_claim(&restored.claim)
            .expect("read the claim")
            .is_none(),
        "the claim about the deleted link stays archive data"
    );
    let [kept] = receipt.destination_omissions.as_slice() else {
        panic!(
            "one row stays archive data: {:?}",
            receipt.destination_omissions
        );
    };
    assert_eq!(
        kept.entity_id,
        restored.claim.to_hex(),
        "the claim is named"
    );
    assert_eq!(
        format!("{:?}", kept.reason),
        "ClaimSubjectEdgeNotRestored",
        "with the reason its link did not come back"
    );
}
