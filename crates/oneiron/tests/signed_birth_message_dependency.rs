//! SIGNED-BIRTH-MESSAGE-SOURCES-UNREGISTERED: a signed (MACHINE) CLAIM's
//! `machine.birth` copy carries its whole first body, so it depends on the
//! MESSAGE the CLAIM was learnt from. Erasing that MESSAGE, soft or hard,
//! withdraws the birth with the CLAIM; erasing another MESSAGE leaves both
//! reading. The CLAIM lands through the promotion writer's verified arm
//! (`record_message_dependencies_in_txn`, which the settlement Keep, the
//! imported Keep and the open-conflict proposal share). The signed-history
//! reader (`Vault::resolved_machine_claim`) returns the birth's body only
//! while the birth reads.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test signed_birth_message_dependency`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::deletion::DeleteReason;
use oneiron::test_doors::consolidation::{consolidate_witnessed_turn, open_dreamer_vault};
use oneiron::test_doors::gate_receipt_unclear::machine_history_controls;
use oneiron::test_doors::nightly::witness_turn;
use oneiron::{EntityId, Vault};

const SAID: &str = "my name is owen";

/// One extracted name, cited by its words in the witnessed MESSAGE.
fn reply() -> String {
    serde_json::json!({
        "persons": [{"id": "new:P1", "name": "owen", "evidence_turn_refs": ["T1"]}],
        "candidates": [{
            "subject": "new:P1", "predicate": "profile.name", "value": "owen",
            "confidence": 0.8, "evidence_refs": [{"source": "T1", "quote": "owen"}],
        }],
    })
    .to_string()
}

/// A CLAIM learnt from one witnessed MESSAGE, and its signed birth.
struct Learnt {
    _dir: tempfile::TempDir,
    vault: Vault,
    message: EntityId,
    claim: EntityId,
    birth: EntityId,
}

impl Learnt {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = open_dreamer_vault(dir.path(), "reader").expect("vault");
        let (turn, message) = witness_turn(&vault, EntityId::now(), SAID, 10).expect("witness");
        let pass = consolidate_witnessed_turn(&vault, turn, &reply()).expect("one pass");
        assert_eq!(pass.landed.len(), 1, "one CLAIM lands: {:?}", pass.landed);
        let claim = pass.landed[0];
        let birth = signed_birth(&vault, claim);
        let learnt = Self {
            _dir: dir,
            vault,
            message,
            claim,
            birth,
        };
        assert!(learnt.reads(claim), "the CLAIM does not read");
        assert!(
            learnt.reads(birth),
            "the signed birth does not read before the erase"
        );
        learnt
    }

    fn reads(&self, claim: EntityId) -> bool {
        self.vault
            .get_claim(&claim)
            .expect("read a CLAIM")
            .is_some()
    }

    fn erase(&self, message: EntityId, reason: DeleteReason) {
        let erased = self
            .vault
            .delete_room_record_unchecked_for_test(&message, reason)
            .expect("erase the MESSAGE");
        assert!(erased.existed, "the MESSAGE existed");
    }
}

/// The one `machine.birth` control the CLAIM's trusted pin names.
fn signed_birth(vault: &Vault, claim: EntityId) -> EntityId {
    let mut births = machine_history_controls(vault, claim)
        .expect("read the CLAIM's machine history controls")
        .into_iter()
        .filter(|id| {
            vault
                .get_claim(id)
                .expect("read a machine history control")
                .is_some_and(|body| body.predicate == "machine.birth")
        });
    let birth = births
        .next()
        .expect("the promotion has no signed birth: it is not a MACHINE claim");
    assert!(
        births.next().is_none(),
        "the promotion has more than one signed birth"
    );
    birth
}

/// T1.
#[test]
fn a_soft_erased_message_withdraws_the_signed_birth() {
    let learnt = Learnt::new();
    learnt.erase(learnt.message, DeleteReason::UserDelete);
    assert!(
        !learnt.reads(learnt.claim),
        "the CLAIM of an erased MESSAGE still reads"
    );
    assert!(
        !learnt.reads(learnt.birth),
        "the signed birth of an erased MESSAGE's CLAIM still reads"
    );
}

/// T2.
#[test]
fn a_hard_erased_message_withdraws_the_signed_birth() {
    let learnt = Learnt::new();
    learnt.erase(learnt.message, DeleteReason::UserHardDelete);
    assert!(
        !learnt.reads(learnt.claim),
        "the CLAIM of a hard-erased MESSAGE still reads"
    );
    assert!(
        !learnt.reads(learnt.birth),
        "the signed birth of a hard-erased MESSAGE's CLAIM still reads"
    );
}

/// T5 (review round 1): the signed-history reader withholds the birth of an
/// erased MESSAGE's CLAIM, which it loads through the raw port.
#[test]
fn the_signed_history_reader_withholds_an_erased_messages_birth() {
    let learnt = Learnt::new();
    let before = learnt.vault.resolved_machine_claim(learnt.claim);
    assert!(
        before.is_ok(),
        "the signed history does not resolve before the erase: {:?}",
        before.err()
    );
    learnt.erase(learnt.message, DeleteReason::UserDelete);
    assert!(
        learnt.vault.resolved_machine_claim(learnt.claim).is_err(),
        "the signed-history reader still returns an erased MESSAGE's birth"
    );
}

/// T3 (control).
#[test]
fn erasing_another_message_keeps_the_signed_birth() {
    let learnt = Learnt::new();
    let (_, other) = witness_turn(&learnt.vault, EntityId::now(), "the weather turned", 20)
        .expect("witness another MESSAGE");
    learnt.erase(other, DeleteReason::UserDelete);
    assert!(
        learnt.reads(learnt.claim),
        "an unrelated erase withdrew the CLAIM"
    );
    assert!(
        learnt.reads(learnt.birth),
        "an unrelated erase withdrew the signed birth"
    );
}
