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
//!
//! Red on main f8ebe0a0d6b3: each test fails at its first import of an
//! archive that carries the link, refused with `ReservedEdgeKind("same_as")`;
//! the source preconditions pass. The receipt's count and the omission reason
//! are read by their debug text, so the file compiles on main, where neither
//! exists.
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
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    CoreferenceLinkRequest, CoreferenceShareConsentRequest, link_coreference_as_owner,
    share_coreference_as_owner,
};
use oneiron::{
    ClaimApprovalStatus, ClaimSubject, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
    WriteActor,
};

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

/// What the source vault holds: two PERSONs, the owner's coreference link
/// between them, its status claim and, when asked, the owner's share
/// consent; the whole-vault archive taken before the link and the one taken
/// after.
struct Linked {
    persons_archive: Vec<u8>,
    archive: Vec<u8>,
    local: EntityId,
    other: EntityId,
    status_claim: EntityId,
    consent_claim: Option<EntityId>,
}

/// A source vault whose owner links two PERSONs through the federation
/// door at `status`, and with `consent` shares the link into [`PACT`].
fn linked_archive(status: CoreferenceStatus, consent: bool) -> Linked {
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
    let consent_claim = consent.then(|| {
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
    assert!(
        vault
            .edge_exists(&local, EdgeKind::SameAs, &other)
            .expect("read the source link"),
        "precondition: the source holds the link"
    );
    assert_eq!(
        oneiron::federation::coreference_shared_for_pact(&vault, local, other, &PACT)
            .expect("read the source consent"),
        consent,
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
    for claim in std::iter::once(status_claim).chain(consent_claim) {
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
    let linked = linked_archive(CoreferenceStatus::Confirmed, true);
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
    let linked = linked_archive(CoreferenceStatus::Proposed, false);
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
    let linked = linked_archive(CoreferenceStatus::Proposed, false);
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
    let linked = linked_archive(CoreferenceStatus::Proposed, false);
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
