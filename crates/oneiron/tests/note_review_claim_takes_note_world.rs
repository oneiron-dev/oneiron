//! NOTE-REVIEW-CLAIM-DROPS-NOTE-WORLD: a CLAIM learnt from a NOTE is born in
//! the NOTE's one world; a NOTE in two worlds without base teaches nothing.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test note_review_claim_takes_note_world`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::note_review_pass::{
    claim_reads_in_worlds, note_review_seen, review_notes_once,
};
use oneiron::{EdgeActorClass, EdgeKind, EntityId, Vault, VaultConfig, WriteActor};

const MARKDOWN: &str = "Mira Vale keeps a lantern list.";

struct Fixture {
    vault: Vault,
    owner: WriteActor,
    proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open the vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("install signing keys");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("the embedded owner");
        let issuer = HostSlipIssuer::from_secret(b"note-review-claim-takes-note-world")
            .expect("fixture host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("bind the owner to the host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine signers");
        let proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof");

        // Give the review one known subject to list as P1.
        let mut named = Vec::new();
        rmpv::encode::write_value(
            &mut named,
            &rmpv::Value::Map(vec![("name".into(), "Mira Vale".into())]),
        )
        .expect("encode the named PERSON");
        vault
            .put_entity(
                &EntityId::now(),
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                &named,
            )
            .expect("write the named PERSON");
        Self {
            vault,
            owner: WriteActor::new(owner, EdgeActorClass::Human),
            proof,
            _dir: dir,
        }
    }

    fn create_world(&self, name: &str) -> EntityId {
        self.vault
            .create_world(&self.proof, name, 1)
            .expect("the owner creates a world")
    }

    fn create_note(&self, worlds: &[EntityId]) -> EntityId {
        let note = self
            .vault
            .create_note("observation", MARKDOWN, self.owner)
            .expect("the owner creates an observation NOTE");
        for world in worlds {
            self.vault
                .put_edge(&note, EdgeKind::InWorld, world, 1.0)
                .expect("place the NOTE in the world");
        }
        note
    }

    fn review(&self) -> Vec<EntityId> {
        review_notes_once(
            &self.vault,
            serde_json::json!({
                "candidates": [{
                    "subject": "P1",
                    "predicate": "profile.preference",
                    "value": "keeps a lantern list",
                    "confidence": 0.9,
                    "evidence_refs": [{"source": "N1", "quote": MARKDOWN}],
                }],
                "importance": 0.2,
            }),
        )
        .expect("run the NOTE review")
    }

    fn review_one_claim(&self) -> EntityId {
        let landed = self.review();
        assert_eq!(
            landed.len(),
            1,
            "the NOTE review did not land exactly one CLAIM"
        );
        landed[0]
    }

    fn claim_world(&self, claim: EntityId) -> Option<EntityId> {
        self.vault
            .get_claim(&claim)
            .expect("read the CLAIM")
            .expect("the landed CLAIM exists")
            .world
    }
}

#[test]
fn a_note_in_one_world_teaches_a_claim_in_that_world() {
    let f = Fixture::new();
    let world = f.create_world("Harbor");
    let note = f.create_note(&[world]);
    let claim = f.review_one_claim();
    assert_eq!(
        f.claim_world(claim),
        Some(world),
        "the CLAIM learnt from a NOTE in W alone is not in W"
    );
    assert!(
        !claim_reads_in_worlds(&f.vault, claim, true, &[]).expect("read on the base lane"),
        "a lane on base reality alone reads the CLAIM learnt from a NOTE in W alone"
    );
    assert!(
        claim_reads_in_worlds(&f.vault, claim, false, &[world]).expect("read on the W lane"),
        "a lane in W does not read the CLAIM learnt from its NOTE"
    );
    assert!(note_review_seen(&f.vault, note).expect("read the NOTE's review row"));
}

#[test]
fn a_note_in_two_worlds_teaches_nothing() {
    let f = Fixture::new();
    let world_one = f.create_world("Harbor");
    let world_two = f.create_world("Inland");
    let note = f.create_note(&[world_one, world_two]);
    let landed = f.review();
    assert!(landed.is_empty(), "a NOTE in two worlds taught a CLAIM");
    assert!(
        !note_review_seen(&f.vault, note).expect("read the NOTE's review row"),
        "a skipped NOTE has a review row"
    );
}

#[test]
fn a_note_in_base_and_one_world_teaches_a_base_claim() {
    let f = Fixture::new();
    let world = f.create_world("Harbor");
    f.create_note(&[base_world_id(), world]);
    let claim = f.review_one_claim();
    assert_eq!(
        f.claim_world(claim),
        None,
        "a NOTE in base among other worlds taught a CLAIM outside base"
    );
    assert!(
        claim_reads_in_worlds(&f.vault, claim, true, &[]).expect("read on the base lane"),
        "the base lane does not read the CLAIM learnt from a NOTE in base among other worlds"
    );
}

#[test]
fn a_base_note_teaches_a_base_claim() {
    let f = Fixture::new();
    f.create_note(&[]);
    let claim = f.review_one_claim();
    assert_eq!(
        f.claim_world(claim),
        None,
        "a base NOTE taught a CLAIM outside base"
    );
    assert!(
        claim_reads_in_worlds(&f.vault, claim, true, &[]).expect("read on the base lane"),
        "the base lane does not read the CLAIM learnt from a base NOTE"
    );
}
