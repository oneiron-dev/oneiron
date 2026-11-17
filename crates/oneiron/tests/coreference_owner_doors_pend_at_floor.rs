//! The owner's own coreference link and share-consent acts land past the
//! criticality floor ([COREFERENCE-OWNER-DOORS-PEND-AT-FLOOR]). Both owner
//! doors write an `Approved` `core.coreference.*` claim, and the shipped
//! default manifest names no `core.coreference.` rule, so on main the claim
//! takes the criticality floor and the owner's own act is refused FORBIDDEN.
//! Each door now carries the owner's proof to the gate, as
//! `federation::bind_member_person` does. A non-owner's `Approved` write keeps
//! the floor exactly as before.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test coreference_owner_doors_pend_at_floor`.

use oneiron::claim::{
    COREFERENCE_PACT_ID_LEN, COREFERENCE_STATUS_CONFIRMED, COREFERENCE_STATUS_PROPOSED,
    PREDICATE_COREFERENCE_SHARE_CONSENT, PREDICATE_COREFERENCE_STATUS,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::CoreferenceStatus;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    CoreferenceLinkRequest, CoreferenceShareConsentRequest, link_coreference_as_owner,
    share_coreference_as_owner,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EdgeKind,
    EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};

/// The gate's reason for a write parked on the criticality floor.
const CRITICALITY_FLOOR: &str = "gate.pending.criticality_floor";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    /// A vault opened with the shipped default manifest, and its owner's proof.
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            owner,
            owner_proof,
            _directory: directory,
        }
    }

    fn person(&self) -> EntityId {
        let id = EntityId::now();
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"person",
            )
            .expect("fixture person");
        id
    }

    fn body(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("read claim")
            .expect("claim exists")
    }
}

/// `vault.federation.coreference.link` with status confirmed: the owner's own
/// act lands. On main it is refused FORBIDDEN on the criticality floor.
#[test]
fn owner_confirmed_link_lands_on_a_seeded_vault() {
    let f = Fixture::new();
    let other = f.person();

    let receipt = link_coreference_as_owner(
        &f.vault,
        &f.owner_proof,
        CoreferenceLinkRequest {
            local_person: f.owner,
            other_person: other,
            status: CoreferenceStatus::Confirmed,
        },
    )
    .expect("the owner's confirmed link lands");

    assert_eq!(receipt.status, CoreferenceStatus::Confirmed);
    assert!(
        f.vault
            .edge_exists(&f.owner, EdgeKind::SameAs, &other)
            .expect("read edge"),
        "the link lands with its status"
    );
    let body = f.body(receipt.status_claim);
    assert_eq!(body.predicate, PREDICATE_COREFERENCE_STATUS);
    assert_eq!(body.approval, ClaimApprovalStatus::Approved);
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(
        body.subject,
        ClaimSubject::Edge {
            source: f.owner,
            kind: EdgeKind::SameAs,
            target: other,
        }
    );
    assert_eq!(body.value.as_str(), Some(COREFERENCE_STATUS_CONFIRMED));
}

/// `vault.federation.coreference.link` with status proposed: lands held, on
/// main and with the fix alike.
#[test]
fn owner_proposed_link_still_lands() {
    let f = Fixture::new();
    let (local, other) = (f.person(), f.person());

    let receipt = link_coreference_as_owner(
        &f.vault,
        &f.owner_proof,
        CoreferenceLinkRequest {
            local_person: local,
            other_person: other,
            status: CoreferenceStatus::Proposed,
        },
    )
    .expect("the owner's proposed link lands");

    assert!(
        f.vault
            .edge_exists(&local, EdgeKind::SameAs, &other)
            .expect("read edge"),
        "the link lands with its status"
    );
    let body = f.body(receipt.status_claim);
    assert_eq!(body.predicate, PREDICATE_COREFERENCE_STATUS);
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(body.value.as_str(), Some(COREFERENCE_STATUS_PROPOSED));
}

/// `vault.federation.coreference.share_consent`: the owner's consent lands. On
/// main it is refused FORBIDDEN on the floor; the proposed link it hangs on
/// lands on main too, so this test is red on main at the consent step.
#[test]
fn owner_share_consent_lands_on_a_seeded_vault() {
    let f = Fixture::new();
    let (local, other) = (f.person(), f.person());
    link_coreference_as_owner(
        &f.vault,
        &f.owner_proof,
        CoreferenceLinkRequest {
            local_person: local,
            other_person: other,
            status: CoreferenceStatus::Proposed,
        },
    )
    .expect("the proposed link lands");
    let pact_bytes = [0xab; COREFERENCE_PACT_ID_LEN];
    let pact_hex = "ab".repeat(COREFERENCE_PACT_ID_LEN);

    let receipt = share_coreference_as_owner(
        &f.vault,
        &f.owner_proof,
        CoreferenceShareConsentRequest {
            local_person: local,
            other_person: other,
            pact: pact_hex.clone(),
        },
    )
    .expect("the owner's share consent lands");

    assert_eq!(receipt.pact, pact_hex);
    let body = f.body(receipt.consent_claim);
    assert_eq!(body.predicate, PREDICATE_COREFERENCE_SHARE_CONSENT);
    assert_eq!(body.approval, ClaimApprovalStatus::Approved);
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(
        body.subject,
        ClaimSubject::Edge {
            source: local,
            kind: EdgeKind::SameAs,
            target: other,
        }
    );
    assert!(
        oneiron::federation::coreference_shared_for_pact(&f.vault, local, other, &pact_bytes)
            .expect("read consent"),
        "the consent names exactly this pact"
    );
}

/// Refusal: a non-owner's confirmed link keeps the floor exactly as on main.
/// The raw-put door is untouched, so nothing is written.
#[test]
fn non_owner_confirmed_link_still_pends_on_the_floor() {
    let f = Fixture::new();
    let (local, other, stranger) = (f.person(), f.person(), f.person());
    let actor = WriteActor::new(stranger, EdgeActorClass::Human);
    let now = f.vault.now_recorded_at();

    let refused = oneiron::federation::put_coreference_link(
        &f.vault,
        &actor,
        local,
        other,
        CoreferenceStatus::Confirmed,
        TimeRange {
            start: now,
            end: u64::MAX,
        },
        now,
    )
    .expect_err("a non-owner's confirmed link pends, not lands");

    let refused = refused.to_string();
    assert!(refused.contains("pending"), "the floor pends it: {refused}");
    assert!(
        refused.contains(CRITICALITY_FLOOR),
        "on the criticality floor: {refused}"
    );
    assert!(
        !f.vault
            .edge_exists(&local, EdgeKind::SameAs, &other)
            .expect("read edge"),
        "a refused link writes nothing"
    );
}
