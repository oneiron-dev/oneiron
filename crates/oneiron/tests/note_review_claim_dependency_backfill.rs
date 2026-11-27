//! N1-OLD-CLAIMS: a CLAIM the NOTE review learnt before N1 gets its NOTE
//! dependency, or is withdrawn, by a one-time pass at open.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test note_review_claim_dependency_backfill`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::DeleteReason;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::note_claim_dependency_backfill::{
    forget_note_claim_dependencies, note_claim_dependency_backfill_counts,
    plant_bare_hard_delete_marker, reset_note_claim_dependency_backfill, write_claim_citing_refs,
};
use oneiron::test_doors::note_review_pass::{note_review_seen, review_notes_once};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};

const MARKDOWN: &str = "Mira Vale keeps a lantern list.";

struct Fixture {
    vault: Vault,
    owner: WriteActor,
    proof: AuthenticatedOwner,
    dir: tempfile::TempDir,
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
        let issuer = HostSlipIssuer::from_secret(b"note-review-claim-dependency-backfill")
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
            dir,
        }
    }

    /// Drops the vault and opens the same directory again, reinstalling the
    /// keystore and the owner credentials the next step needs.
    fn reopen(self) -> Self {
        let Fixture {
            vault,
            owner: _,
            proof: _,
            dir,
        } = self;
        drop(vault);
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("reopen the vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault
            .prepare_install_signing()
            .expect("install signing keys");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("the embedded owner");
        let issuer = HostSlipIssuer::from_secret(b"note-review-claim-dependency-backfill")
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
        Self {
            vault,
            owner: WriteActor::new(owner, EdgeActorClass::Human),
            proof,
            dir,
        }
    }

    fn review_new_note(&self) -> (EntityId, EntityId) {
        let note = self
            .vault
            .create_note("observation", MARKDOWN, self.owner)
            .expect("the owner creates an observation NOTE");
        let landed = review_notes_once(
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
        .expect("run the NOTE review");
        assert_eq!(
            landed.len(),
            1,
            "the NOTE review did not land exactly one CLAIM"
        );
        let claim = landed[0];
        assert!(
            self.vault
                .get_claim(&claim)
                .expect("read the CLAIM")
                .is_some(),
            "the CLAIM learnt from the NOTE does not read"
        );
        assert!(note_review_seen(&self.vault, note).expect("read the NOTE's review row"));
        (note, claim)
    }
}

/// A named PERSON for a synthetic CLAIM's subject.
fn put_person(vault: &Vault) -> EntityId {
    let mut named = Vec::new();
    rmpv::encode::write_value(
        &mut named,
        &rmpv::Value::Map(vec![("name".into(), "Mira Vale".into())]),
    )
    .expect("encode the named PERSON");
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &named,
        )
        .expect("write the named PERSON");
    id
}

#[test]
fn an_old_claim_gets_its_note_dependency() {
    let f = Fixture::new();
    let (note, claim) = f.review_new_note();
    forget_note_claim_dependencies(&f.vault, claim).expect("strip the CLAIM's dependency");
    reset_note_claim_dependency_backfill(&f.vault).expect("reset the backfill marker");
    let f = f.reopen();
    assert!(
        f.vault.get_claim(&claim).expect("read the CLAIM").is_some(),
        "the old CLAIM does not read after the backfill"
    );
    assert!(f.vault.delete_entity(&note).expect("soft delete the NOTE"));
    assert!(
        f.vault.get_claim(&claim).expect("read the CLAIM").is_none(),
        "the old CLAIM learnt from a deleted NOTE still reads after the backfill"
    );
}

#[test]
fn an_old_claim_whose_note_was_soft_deleted_is_withdrawn() {
    let f = Fixture::new();
    let (note, claim) = f.review_new_note();
    forget_note_claim_dependencies(&f.vault, claim).expect("strip the CLAIM's dependency");
    assert!(f.vault.delete_entity(&note).expect("soft delete the NOTE"));
    assert!(
        f.vault.get_claim(&claim).expect("read the CLAIM").is_some(),
        "the CLAIM does not read before the backfill"
    );
    reset_note_claim_dependency_backfill(&f.vault).expect("reset the backfill marker");
    let f = f.reopen();
    assert!(
        f.vault.get_claim(&claim).expect("read the CLAIM").is_none(),
        "the backfill left an old CLAIM whose NOTE was deleted"
    );
}

#[test]
fn an_old_claim_whose_note_was_hard_deleted_is_withdrawn() {
    let f = Fixture::new();
    let (note, claim) = f.review_new_note();
    forget_note_claim_dependencies(&f.vault, claim).expect("strip the CLAIM's dependency");
    let deleted = f
        .vault
        .delete_entity_with_reason_as_owner(&f.proof, &note, DeleteReason::UserHardDelete)
        .expect("the owner hard deletes the NOTE");
    assert!(deleted.existed);
    assert!(
        f.vault.get_claim(&claim).expect("read the CLAIM").is_some(),
        "the CLAIM does not read before the backfill"
    );
    reset_note_claim_dependency_backfill(&f.vault).expect("reset the backfill marker");
    let f = f.reopen();
    assert!(
        f.vault.get_claim(&claim).expect("read the CLAIM").is_none(),
        "the backfill left an old CLAIM whose NOTE was deleted"
    );
}

#[test]
fn a_claim_whose_note_is_absent_without_a_marker_stays() {
    let f = Fixture::new();
    let subject = put_person(&f.vault);
    let missing = EntityId::now();
    let claim = write_claim_citing_refs(&f.vault, subject, &[missing])
        .expect("write the CLAIM citing an absent id");
    assert!(
        f.vault
            .get(&missing)
            .expect("read the missing id")
            .is_none(),
        "the cited id is stored"
    );
    assert!(
        f.vault.get_claim(&claim).expect("read the CLAIM").is_some(),
        "the CLAIM does not read before the backfill"
    );
    reset_note_claim_dependency_backfill(&f.vault).expect("reset the backfill marker");
    let f = f.reopen();
    assert!(
        f.vault.get_claim(&claim).expect("read the CLAIM").is_some(),
        "a CLAIM whose NOTE is absent without a marker was withdrawn"
    );
    let counts = note_claim_dependency_backfill_counts(&f.vault)
        .expect("read the backfill counts")
        .expect("the backfill is complete");
    assert_eq!(counts[4], 1, "missing_without_marker counts the absent ref");
}

#[test]
fn a_claim_whose_removed_ref_has_no_witness_stays() {
    let f = Fixture::new();
    let subject = put_person(&f.vault);
    let removed = EntityId::now();
    let claim = write_claim_citing_refs(&f.vault, subject, &[removed])
        .expect("write the CLAIM citing an absent id");
    plant_bare_hard_delete_marker(&f.vault, removed).expect("plant the bare marker");
    assert!(
        f.vault
            .get(&removed)
            .expect("read the removed id")
            .is_none(),
        "the cited id is stored"
    );
    assert!(
        f.vault.get_claim(&claim).expect("read the CLAIM").is_some(),
        "the CLAIM does not read before the backfill"
    );
    reset_note_claim_dependency_backfill(&f.vault).expect("reset the backfill marker");
    let f = f.reopen();
    assert!(
        f.vault.get_claim(&claim).expect("read the CLAIM").is_some(),
        "a CLAIM whose removed ref has no NOTE witness was withdrawn"
    );
    let counts = note_claim_dependency_backfill_counts(&f.vault)
        .expect("read the backfill counts")
        .expect("the backfill is complete");
    assert_eq!(
        counts[5], 1,
        "deleted_ref_type_unknown counts the unwitnessed removed ref"
    );
}

#[test]
fn the_backfill_runs_once() {
    let f = Fixture::new();
    let (_note, claim) = f.review_new_note();
    forget_note_claim_dependencies(&f.vault, claim).expect("strip the CLAIM's dependency");
    reset_note_claim_dependency_backfill(&f.vault).expect("reset the backfill marker");
    let f = f.reopen();
    let first = note_claim_dependency_backfill_counts(&f.vault)
        .expect("read the backfill counts")
        .expect("the backfill is complete");
    let f = f.reopen();
    let second = note_claim_dependency_backfill_counts(&f.vault)
        .expect("read the backfill counts")
        .expect("the backfill is still complete");
    assert_eq!(
        first, second,
        "a second open leaves the backfill counts unchanged"
    );
}
