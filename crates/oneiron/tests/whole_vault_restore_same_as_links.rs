//! Fix list row WHOLE-VAULT-IMPORT-REFUSES-RESERVED-OWNER-EDGES, its same_as
//! part: a whole-vault archive of a vault holding a coreference link (a
//! `same_as` link between two PERSONs, written with its status claim by the
//! federation door) imports. The import wrote every archived link through the
//! public edge door, which refuses `same_as` (`ReservedEdgeKind`), so the
//! whole import aborted. Now the link comes back between two PERSONs the
//! import inserted, with its status claim as a proposal, as every imported
//! claim comes back; a share consent stays archive data, since an imported
//! consent never counts (ARCH-0023b H212); and a link to a PERSON the
//! destination already holds stays out, counted in the receipt.
//!
//! * `owner_restore_brings_a_confirmed_link_back_as_a_proposal`: the owner's
//!   restore into a fresh vault; the consent is named in the receipt's
//!   `destination_omissions` (`CoreferenceConsentNotRestored`), and the
//!   restored link is shared into no pact.
//! * `actor_import_brings_a_proposed_link_back`: through the actor-taking
//!   door.
//! * `actorless_import_again_finds_the_link_unchanged`: the actorless door,
//!   twice; the second import finds the link as it is.
//! * `a_link_between_persons_already_here_stays_out`: the destination took
//!   the two PERSONs from an earlier archive, so the later archive's link
//!   would tell it who its own persons are; the import completes, the link
//!   stays out and is counted (`unrestored_same_as_links`), and its status
//!   claim stays archive data (`ClaimSubjectEdgeNotRestored`).
//! * `an_annotated_link_comes_back_with_its_provenance`: the owner annotated
//!   the link through the structural provenance door; the link and its
//!   provenance claim come back.
//! * `an_annotated_link_between_persons_already_here_stays_out`: blind review
//!   round 1 of #9581 (REVIEW-9581 P1): the provenance cohort staged a link
//!   the import leaves out, and its claim write then aborted the whole import
//!   (`EdgeNotFound`). Now the provenance claim stays archive data
//!   (`ClaimSubjectEdgeNotRestored`) and the import completes.
//! * `a_claim_about_the_share_consent_stays_archive_data`: REVIEW-9581 P1: an
//!   ordinary claim about the consent reached the claim door after the
//!   consent was kept out, and the door aborted the whole import
//!   (`EntityNotFound`). Now it stays archive data with the consent
//!   (`ClaimSubjectNotRestored`).
//!
//! Red on main f8ebe0a0d6b3: each test fails at its first import of an
//! archive that carries the link, refused with `ReservedEdgeKind("same_as")`;
//! the source preconditions pass. The receipt's count and the omission reason
//! are read by their debug text, so the file compiles on main, where neither
//! exists. Red on cb06f77e8331 (#9581 before the review fix): the two
//! REVIEW-9581 tests fail at the import, with `EdgeNotFound` and
//! `EntityNotFound`.
//!
//! Vaults in tempdirs, every step through public doors. Each destination
//! opens at least one wall-clock second after its source (sleep 1100 ms), as
//! in `whole_vault_restore_seeds.rs`. Run with `cargo test --locked -p
//! oneiron --all-features --test whole_vault_restore_same_as_links`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use oneiron::batch::export::WholeVaultImportReceipt;
use oneiron::claim::{
    COREFERENCE_PACT_ID_LEN, COREFERENCE_STATUS_PROPOSED, PREDICATE_COREFERENCE_STATUS,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeKind;
use oneiron::federation::CoreferenceStatus;
use oneiron::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    CoreferenceLinkRequest, CoreferenceShareConsentRequest, link_coreference_as_owner,
    share_coreference_as_owner,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;

/// The pact the source's owner consents to share the link into.
const PACT: [u8; COREFERENCE_PACT_ID_LEN] = [0xab; COREFERENCE_PACT_ID_LEN];

/// A vault opened with the shipped default manifest and this install's
/// signing keys, as `coreference_owner_doors_pend_at_floor.rs` opens one.
fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
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

fn export(vault: &Vault) -> Vec<u8> {
    vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec()
}

/// What the source writes beside its link.
#[derive(Clone, Copy, Default)]
struct Beside {
    /// The owner's share consent into [`PACT`].
    consent: bool,
    /// An ordinary claim about that consent.
    claim_about_consent: bool,
    /// The owner's provenance claim on the link, through the structural
    /// provenance door.
    provenance: bool,
}

/// What the source vault holds: two PERSONs, the owner's coreference link
/// between them, its status claim and what [`Beside`] asked for; the
/// whole-vault archive taken before the link and the one taken after.
struct Linked {
    persons_archive: Vec<u8>,
    archive: Vec<u8>,
    local: EntityId,
    other: EntityId,
    status_claim: EntityId,
    consent_claim: Option<EntityId>,
    claim_about_consent: Option<EntityId>,
    provenance_claim: Option<EntityId>,
}

/// A source vault whose owner links two PERSONs through the federation
/// door at `status`, and writes what `beside` asks for.
fn linked_archive(status: CoreferenceStatus, beside: Beside) -> Linked {
    let (_dir, vault) = open_vault();
    let proof = owner_proof(&vault);
    let local = put_person(&vault);
    let other = put_person(&vault);
    let persons_archive = export(&vault);
    let status_claim = link_coreference_as_owner(
        &vault,
        &proof,
        CoreferenceLinkRequest {
            local_person: local,
            other_person: other,
            status,
        },
    )
    .expect("the owner's link lands")
    .status_claim;
    let consent_claim = beside.consent.then(|| {
        share_coreference_as_owner(
            &vault,
            &proof,
            CoreferenceShareConsentRequest {
                local_person: local,
                other_person: other,
                pact: "ab".repeat(COREFERENCE_PACT_ID_LEN),
            },
        )
        .expect("the owner's share consent lands")
        .consent_claim
    });
    let claim_about_consent = consent_claim
        .filter(|_| beside.claim_about_consent)
        .map(|consent| {
            let id = EntityId::now();
            vault
                .put_claim(
                    &id,
                    &ClaimBody::new(
                        "relationship.context",
                        ClaimSubject::Entity(consent),
                        Value::from("shared after the climbing trip"),
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
                .expect("the claim about the consent lands");
            id
        });
    let provenance_claim = beside.provenance.then(|| {
        let id = EntityId::now();
        vault
            .put_structural_edge_provenance(
                &id,
                &EdgeRef::new(local, EdgeKind::SameAs, other),
                &EdgeProvenanceClaimBody::new(local, 1.0, SupersessionStatus::Confirmed),
                EdgeActorClass::Human,
                vault.now_recorded_at(),
            )
            .expect("the provenance claim on the link lands");
        id
    });
    assert!(
        vault
            .edge_exists(&local, EdgeKind::SameAs, &other)
            .expect("read the source link"),
        "precondition: the source holds the link"
    );
    assert_eq!(
        oneiron::federation::coreference_shared_for_pact(&vault, local, other, &PACT)
            .expect("read the source consent"),
        beside.consent,
        "precondition: the source shares the link into the pact exactly when it consented"
    );
    let archive = export(&vault);
    let document = vault
        .read_whole_vault_archive(&archive)
        .expect("read the archive back");
    assert!(
        document.evidence_ledger.edges.iter().any(|edge| {
            edge.source == local.to_hex()
                && edge.kind == EdgeKind::SameAs as u8
                && edge.target == other.to_hex()
        }),
        "precondition: the archive carries the link"
    );
    for claim in std::iter::once(status_claim)
        .chain(consent_claim)
        .chain(claim_about_consent)
        .chain(provenance_claim)
    {
        assert!(
            document.claims.iter().any(|row| row.id == claim.to_hex()),
            "precondition: the archive carries claim {claim:?}"
        );
    }
    Linked {
        persons_archive,
        archive,
        local,
        other,
        status_claim,
        consent_claim,
        claim_about_consent,
        provenance_claim,
    }
}

/// `dest` holds the link, and its status claim as a proposal.
fn assert_link_back(dest: &Vault, linked: &Linked) {
    assert!(
        dest.edge_exists(&linked.local, EdgeKind::SameAs, &linked.other)
            .expect("read the restored link"),
        "the link is restored"
    );
    let status = dest
        .get_claim(&linked.status_claim)
        .expect("read the restored status claim")
        .expect("the link's status claim is restored");
    assert_eq!(status.predicate, PREDICATE_COREFERENCE_STATUS);
    assert_eq!(
        status.subject,
        ClaimSubject::Edge {
            source: linked.local,
            kind: EdgeKind::SameAs,
            target: linked.other,
        },
        "the restored status is about the restored link"
    );
    assert_eq!(
        status.value.as_str(),
        Some(COREFERENCE_STATUS_PROPOSED),
        "the status comes back proposed"
    );
    assert_eq!(
        status.approval,
        ClaimApprovalStatus::Proposed,
        "as every imported claim comes back"
    );
}

/// The receipt's `unrestored_same_as_links`, read from its debug text.
fn unrestored_same_as_links(receipt: &WholeVaultImportReceipt) -> Option<usize> {
    let text = format!("{receipt:?}");
    let rest = text.split("unrestored_same_as_links: ").nth(1)?;
    rest.split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
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

#[test]
fn owner_restore_brings_a_confirmed_link_back_as_a_proposal() {
    let linked = linked_archive(
        CoreferenceStatus::Confirmed,
        Beside {
            consent: true,
            ..Beside::default()
        },
    );
    let (_dir, dest) = open_later_vault();
    let owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&linked.archive), &owner)
        .expect("the owner's restore completes");
    assert_link_back(&dest, &linked);
    let consent = linked.consent_claim.expect("the source consented");
    assert!(
        dest.get_claim(&consent)
            .expect("read the consent")
            .is_none(),
        "the share consent stays archive data"
    );
    assert_eq!(
        omission_reason(&receipt, consent).as_deref(),
        Some("CoreferenceConsentNotRestored"),
        "the receipt names the consent with its reason: {:?}",
        receipt.destination_omissions
    );
    assert!(
        !oneiron::federation::coreference_shared_for_pact(&dest, linked.local, linked.other, &PACT)
            .expect("read the restored consent"),
        "the restored link is shared into no pact"
    );
    assert_eq!(
        unrestored_same_as_links(&receipt),
        Some(0),
        "no link stays out"
    );
}

#[test]
fn actor_import_brings_a_proposed_link_back() {
    let linked = linked_archive(CoreferenceStatus::Proposed, Beside::default());
    let (_dir, dest) = open_later_vault();
    let owner = dest.ensure_embedded_owner_actor().expect("embedded owner");
    let receipt = dest
        .import_whole_vault_archive_with_actor(
            &linked.archive,
            &WriteActor::new(owner, EdgeActorClass::Human),
        )
        .expect("the actor import completes");
    assert_link_back(&dest, &linked);
    assert_eq!(
        unrestored_same_as_links(&receipt),
        Some(0),
        "no link stays out"
    );
}

#[test]
fn actorless_import_again_finds_the_link_unchanged() {
    let linked = linked_archive(CoreferenceStatus::Proposed, Beside::default());
    let (_dir, dest) = open_later_vault();
    let receipt = dest
        .import_whole_vault_archive_from(Cursor::new(&linked.archive))
        .expect("the actorless import completes");
    assert_link_back(&dest, &linked);
    assert_eq!(
        unrestored_same_as_links(&receipt),
        Some(0),
        "no link stays out"
    );
    let again = dest
        .import_whole_vault_archive_from(Cursor::new(&linked.archive))
        .expect("the same archive again completes");
    assert_link_back(&dest, &linked);
    assert_eq!(
        unrestored_same_as_links(&again),
        Some(0),
        "the held link is left as it is"
    );
}

#[test]
fn a_link_between_persons_already_here_stays_out() {
    let linked = linked_archive(CoreferenceStatus::Proposed, Beside::default());
    let (_dir, dest) = open_later_vault();
    dest.import_whole_vault_archive_from(Cursor::new(&linked.persons_archive))
        .expect("the archive taken before the link imports");
    for person in [linked.local, linked.other] {
        assert!(
            dest.entity_exists(&person).expect("read the person"),
            "precondition: the destination holds the person"
        );
    }
    let receipt = dest
        .import_whole_vault_archive_from(Cursor::new(&linked.archive))
        .expect("the archive with the link imports");
    assert!(
        !dest
            .edge_exists(&linked.local, EdgeKind::SameAs, &linked.other)
            .expect("read the link"),
        "the link between persons already here stays out"
    );
    assert!(
        dest.get_claim(&linked.status_claim)
            .expect("read the status claim")
            .is_none(),
        "its status claim stays archive data"
    );
    assert_eq!(
        omission_reason(&receipt, linked.status_claim).as_deref(),
        Some("ClaimSubjectEdgeNotRestored"),
        "the receipt names the status claim: {:?}",
        receipt.destination_omissions
    );
    assert_eq!(
        unrestored_same_as_links(&receipt),
        Some(1),
        "the receipt counts the link that stayed out"
    );
}

#[test]
fn an_annotated_link_comes_back_with_its_provenance() {
    let linked = linked_archive(
        CoreferenceStatus::Proposed,
        Beside {
            provenance: true,
            ..Beside::default()
        },
    );
    let provenance = linked
        .provenance_claim
        .expect("the source annotated the link");
    let (_dir, dest) = open_later_vault();
    let receipt = dest
        .import_whole_vault_archive_from(Cursor::new(&linked.archive))
        .expect("the archive with the annotated link imports");
    assert_link_back(&dest, &linked);
    assert!(
        dest.entity_exists(&provenance)
            .expect("read the provenance claim"),
        "the link's provenance claim is restored"
    );
    assert_eq!(
        unrestored_same_as_links(&receipt),
        Some(0),
        "no link stays out"
    );
}

#[test]
fn an_annotated_link_between_persons_already_here_stays_out() {
    let linked = linked_archive(
        CoreferenceStatus::Proposed,
        Beside {
            provenance: true,
            ..Beside::default()
        },
    );
    let provenance = linked
        .provenance_claim
        .expect("the source annotated the link");
    let (_dir, dest) = open_later_vault();
    dest.import_whole_vault_archive_from(Cursor::new(&linked.persons_archive))
        .expect("the archive taken before the link imports");
    let receipt = dest
        .import_whole_vault_archive_from(Cursor::new(&linked.archive))
        .expect("the archive with the annotated link imports");
    assert!(
        !dest
            .edge_exists(&linked.local, EdgeKind::SameAs, &linked.other)
            .expect("read the link"),
        "the link between persons already here stays out"
    );
    assert!(
        !dest
            .entity_exists(&provenance)
            .expect("read the provenance claim"),
        "its provenance claim stays archive data"
    );
    assert_eq!(
        omission_reason(&receipt, provenance).as_deref(),
        Some("ClaimSubjectEdgeNotRestored"),
        "the receipt names the provenance claim: {:?}",
        receipt.destination_omissions
    );
    assert_eq!(
        omission_reason(&receipt, linked.status_claim).as_deref(),
        Some("ClaimSubjectEdgeNotRestored"),
        "the receipt names the status claim: {:?}",
        receipt.destination_omissions
    );
    assert_eq!(
        unrestored_same_as_links(&receipt),
        Some(1),
        "the receipt counts the link that stayed out"
    );
}

#[test]
fn a_claim_about_the_share_consent_stays_archive_data() {
    let linked = linked_archive(
        CoreferenceStatus::Proposed,
        Beside {
            consent: true,
            claim_about_consent: true,
            ..Beside::default()
        },
    );
    let consent = linked.consent_claim.expect("the source consented");
    let about = linked
        .claim_about_consent
        .expect("the source wrote a claim about the consent");
    let (_dir, dest) = open_later_vault();
    let owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&linked.archive), &owner)
        .expect("the owner's restore completes");
    assert_link_back(&dest, &linked);
    for claim in [consent, about] {
        assert!(
            !dest.entity_exists(&claim).expect("read the claim"),
            "claim {claim:?} stays archive data"
        );
    }
    assert_eq!(
        omission_reason(&receipt, consent).as_deref(),
        Some("CoreferenceConsentNotRestored"),
        "the receipt names the consent: {:?}",
        receipt.destination_omissions
    );
    assert_eq!(
        omission_reason(&receipt, about).as_deref(),
        Some("ClaimSubjectNotRestored"),
        "the receipt names the claim about the consent: {:?}",
        receipt.destination_omissions
    );
}
