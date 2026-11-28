//! PROMOTED-CLAIM-SOURCE-DEPENDENCY-GAPS, NOTE review path: the CLAIM learnt
//! from a NOTE depends on it, and the NOTE's erase clears its review row.
//! Erasing the NOTE also withdraws the CLAIM's signed birth copy.
//! Editing the NOTE keeps the CLAIM; a new NOTE with the same text is reviewed.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test note_review_claim_depends_on_note`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::DeleteReason;
use oneiron::note::{NoteProgramEdit, NoteProgramEditOutcome};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::note_review_pass::{
    note_dependency_exists, note_review_seen, record_note_dependencies_for_test, review_notes_once,
    review_notes_once_after_reply,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};

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
        let issuer = HostSlipIssuer::from_secret(b"note-review-claim-depends-on-note")
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

    fn create_note(&self) -> EntityId {
        self.vault
            .create_note("observation", MARKDOWN, self.owner)
            .expect("the owner creates an observation NOTE")
    }

    fn review_new_note(&self) -> (EntityId, EntityId) {
        let note = self.create_note();
        let landed = review_notes_once(&self.vault, keep_reply()).expect("run the NOTE review");
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

    fn signed_birth(&self, claim: EntityId) -> EntityId {
        let mut births =
            oneiron::test_doors::gate_receipt_unclear::machine_history_controls(&self.vault, claim)
                .expect("read the CLAIM's machine history controls")
                .into_iter()
                .filter(|id| {
                    self.vault
                        .get_claim(id)
                        .expect("read a machine history control")
                        .is_some_and(|body| body.predicate == "machine.birth")
                });
        let birth = births
            .next()
            .expect("the NOTE review's promotion has no signed birth: it is not a MACHINE claim");
        assert!(
            births.next().is_none(),
            "the NOTE review's promotion has more than one signed birth"
        );
        birth
    }

    fn assert_withdrawn(&self, note: EntityId, claim: EntityId) {
        assert!(
            self.vault
                .get_claim(&claim)
                .expect("read the CLAIM")
                .is_none(),
            "the CLAIM learnt from a deleted NOTE still reads"
        );
        assert!(
            !note_review_seen(&self.vault, note).expect("read the NOTE's review row"),
            "the deleted NOTE's review row is still stored"
        );
    }
}

fn keep_reply() -> serde_json::Value {
    serde_json::json!({
        "candidates": [{
            "subject": "P1",
            "predicate": "profile.preference",
            "value": "keeps a lantern list",
            "confidence": 0.9,
            "evidence_refs": [{"source": "N1", "quote": MARKDOWN}],
        }],
        "importance": 0.2,
    })
}

#[test]
fn a_note_review_claim_reads_and_the_note_is_seen() {
    Fixture::new().review_new_note();
}

#[test]
fn a_soft_deleted_note_withdraws_its_claim() {
    let f = Fixture::new();
    let (note, claim) = f.review_new_note();
    assert!(f.vault.delete_entity(&note).expect("soft delete the NOTE"));
    f.assert_withdrawn(note, claim);
    // The dependency is a row of the walk's index, not an edge: the withdrawn
    // CLAIM's edge read names the NOTE to no reader.
    assert!(
        !f.vault
            .edges_out(&claim)
            .expect("read the withdrawn CLAIM's edges")
            .iter()
            .any(|edge| edge.target == note),
        "the withdrawn CLAIM's edges name the deleted NOTE"
    );
}

#[test]
fn a_hard_deleted_note_withdraws_its_claim() {
    let f = Fixture::new();
    let (note, claim) = f.review_new_note();
    let deleted = f
        .vault
        .delete_entity_with_reason_as_owner(&f.proof, &note, DeleteReason::UserHardDelete)
        .expect("the owner hard deletes the NOTE");
    assert!(deleted.existed);
    f.assert_withdrawn(note, claim);
}

#[test]
fn a_soft_deleted_note_withdraws_its_claims_signed_birth() {
    let f = Fixture::new();
    let (note, claim) = f.review_new_note();
    let birth = f.signed_birth(claim);
    assert!(
        f.vault
            .get_claim(&birth)
            .expect("read the signed birth")
            .is_some(),
        "the signed birth does not read before the delete"
    );
    assert!(f.vault.delete_entity(&note).expect("soft delete the NOTE"));
    f.assert_withdrawn(note, claim);
    assert!(
        f.vault
            .get_claim(&birth)
            .expect("read the signed birth")
            .is_none(),
        "the signed birth of a deleted NOTE's CLAIM still reads"
    );
}

#[test]
fn a_hard_deleted_note_withdraws_its_claims_signed_birth() {
    let f = Fixture::new();
    let (note, claim) = f.review_new_note();
    let birth = f.signed_birth(claim);
    assert!(
        f.vault
            .get_claim(&birth)
            .expect("read the signed birth")
            .is_some(),
        "the signed birth does not read before the delete"
    );
    let deleted = f
        .vault
        .delete_entity_with_reason_as_owner(&f.proof, &note, DeleteReason::UserHardDelete)
        .expect("the owner hard deletes the NOTE");
    assert!(deleted.existed);
    f.assert_withdrawn(note, claim);
    assert!(
        f.vault
            .get_claim(&birth)
            .expect("read the signed birth")
            .is_none(),
        "the signed birth of a deleted NOTE's CLAIM still reads"
    );
}

#[test]
fn an_edited_note_keeps_its_claim() {
    let f = Fixture::new();
    let (note, claim) = f.review_new_note();
    let doc = f
        .vault
        .note_program_document(note)
        .expect("read the NOTE document")
        .expect("the NOTE has a document");
    let edit = NoteProgramEdit::ReplaceSpan {
        start: doc.anchor(0).expect("start anchor"),
        end: doc.anchor(MARKDOWN.chars().count()).expect("end anchor"),
        text: "Mira Vale keeps a tide chart.".into(),
    };
    let outcome = f
        .vault
        .edit_note(note, &edit, f.owner)
        .expect("edit the NOTE");
    assert!(matches!(outcome, NoteProgramEditOutcome::Edited { .. }));
    assert!(
        f.vault.get_claim(&claim).expect("read the CLAIM").is_some(),
        "an edit withdrew the CLAIM learnt from the NOTE"
    );
}

#[test]
fn a_new_note_after_the_delete_is_learnt_under_a_new_id() {
    let f = Fixture::new();
    let (note, claim) = f.review_new_note();
    assert!(f.vault.delete_entity(&note).expect("soft delete the NOTE"));
    f.assert_withdrawn(note, claim);

    let (new_note, new_claim) = f.review_new_note();
    assert_ne!(new_note, note);
    assert_ne!(new_claim, claim);
}

#[test]
fn a_note_deleted_while_its_review_waits_on_the_model_leaves_no_row_or_claim() {
    let f = Fixture::new();
    let note = f.create_note();
    let landed = review_notes_once_after_reply(&f.vault, keep_reply(), move |vault| {
        assert!(vault.delete_entity(&note).expect("soft delete the NOTE"));
    })
    .expect("run the NOTE review");
    assert!(
        !note_review_seen(&f.vault, note).expect("read the NOTE's review row"),
        "the deleted NOTE's review row is still stored"
    );
    assert!(
        landed.is_empty(),
        "a CLAIM learnt from a deleted NOTE still reads"
    );
}

#[test]
fn a_note_hard_deleted_while_its_review_waits_on_the_model_leaves_no_row_or_claim() {
    let f = Fixture::new();
    let note = f.create_note();
    let proof = f.proof.clone();
    let landed = review_notes_once_after_reply(&f.vault, keep_reply(), move |vault| {
        let deleted = vault
            .delete_entity_with_reason_as_owner(&proof, &note, DeleteReason::UserHardDelete)
            .expect("the owner hard deletes the NOTE");
        assert!(deleted.existed);
    })
    .expect("run the NOTE review");
    assert!(
        !note_review_seen(&f.vault, note).expect("read the NOTE's review row"),
        "the deleted NOTE's review row is still stored"
    );
    assert!(
        landed.is_empty(),
        "a CLAIM learnt from a deleted NOTE still reads"
    );
}

#[test]
fn a_promotion_whose_cited_note_is_gone_at_the_write_is_refused() {
    let f = Fixture::new();
    let claim = EntityId::now();
    let live = f.create_note();
    let soft = f.create_note();
    let hard = f.create_note();
    assert!(f.vault.delete_entity(&soft).expect("soft delete the NOTE"));
    let deleted = f
        .vault
        .delete_entity_with_reason_as_owner(&f.proof, &hard, DeleteReason::UserHardDelete)
        .expect("the owner hard deletes the NOTE");
    assert!(deleted.existed);

    record_note_dependencies_for_test(&f.vault, claim, &[live])
        .expect("register the live NOTE dependency");
    assert!(note_dependency_exists(&f.vault, claim, live).expect("read the live NOTE dependency"));
    assert!(
        matches!(
            record_note_dependencies_for_test(&f.vault, claim, &[live, hard]),
            Err(oneiron::Error::InvalidClaimBody(_))
        ),
        "a purged NOTE was accepted at the write"
    );
    assert!(
        !note_dependency_exists(&f.vault, claim, hard).expect("read the purged NOTE dependency")
    );
    assert!(
        matches!(
            record_note_dependencies_for_test(&f.vault, claim, &[live, soft]),
            Err(oneiron::Error::InvalidClaimBody(_))
        ),
        "a soft-deleted NOTE was accepted at the write"
    );
    assert!(
        !note_dependency_exists(&f.vault, claim, soft)
            .expect("read the soft-deleted NOTE dependency")
    );
}
