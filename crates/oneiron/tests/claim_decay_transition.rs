//! One decay rule for the live demotion door and the signed-history fold
//! (FIX 22387, brief 15 B).
//!
//! Main's live door let a decayed claim decay again at a lower or an EQUAL
//! weight, while the fold rolled back any decay once a rung existed. So a
//! demotion's outcome depended on which path it took. Both now rule with one
//! helper: a claim with no rung or the `decayed` rung decays to a strictly
//! lower ClaimOf weight. The documented lower-weight re-decay stays, and an
//! equal weight, which changes nothing, is refused in both paths.
//!
//! The fold is crate-private, so it is reached through
//! `oneiron::test_doors::claim_transition` under `--cfg oneiron_test_support`;
//! the live door is the public `Vault::apply_claim_demotion`.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::claim_transition::{FoldedDecay, fold_decay_chain};
use oneiron::write_envelope::claim_body::{ClaimDemotionAction, ClaimDemotionRung};
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    Error, TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

/// A vault holding one active, UserStated claim on a normal predicate, born
/// at the default ClaimOf weight 1.0.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    claim: EntityId,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
        let subject = EntityId::now();
        for id in [actor.entity_ref(), subject] {
            vault
                .put_entity(
                    &id,
                    oneiron::registry::ENTITY_TYPE_PERSON,
                    TimeRange { start: 1, end: 1 },
                    1,
                    b"",
                )
                .expect("put person");
        }
        // A normal predicate avoids the critical-confirm hold.
        let envelope = WriteEnvelope::new(
            actor,
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from("fix 22387 fixture")).expect("provenance"),
            ClaimApprovalStatus::Auto,
        );
        let claim = EntityId::now();
        vault
            .batch()
            .claim_candidate(
                &claim,
                ClaimCandidate::new(
                    "profile.decay_fixture",
                    ClaimSubject::Entity(subject),
                    Value::from("fact"),
                    1.0,
                ),
                &envelope,
                TimeRange { start: 10, end: 99 },
                10,
            )
            .commit()
            .expect("write the claim");
        Self {
            _dir: dir,
            vault,
            claim,
        }
    }

    fn decay(&self, weight: f32, now: u64) -> oneiron::Result<ClaimDemotionRung> {
        self.vault
            .apply_claim_demotion(
                &self.claim,
                ClaimDemotionAction::Decay {
                    new_claim_of_weight: weight,
                },
                now,
            )
            .map(|demotion| demotion.rung)
    }
}

#[test]
fn demotion_fold_accepts_a_second_decay_like_the_live_door() {
    assert_eq!(
        fold_decay_chain(0.8, &[0.4, 0.2]),
        Ok(FoldedDecay {
            claim_of_weight: Some(0.2),
            demotion_rung: Some(ClaimDemotionRung::Decayed),
        }),
        "a decayed claim's history decays again to a lower weight, as the live door lets it"
    );
}

#[test]
fn the_live_door_refuses_an_equal_weight_decay_like_the_fold() {
    let fixture = Fixture::open();
    assert_eq!(
        fixture.decay(0.5, 20).expect("the first decay lands"),
        ClaimDemotionRung::Decayed
    );
    match fixture.decay(0.5, 21) {
        Err(Error::InvalidEdgeWeight { value }) => assert_eq!(value, 0.5),
        other => panic!("an equal-weight decay changes nothing and is refused; got {other:?}"),
    }
    assert!(
        fold_decay_chain(0.8, &[0.4, 0.4]).is_err(),
        "the fold refuses the same equal-weight decay"
    );
}

#[test]
fn the_live_door_still_takes_a_lower_weight_redecay() {
    let fixture = Fixture::open();
    assert_eq!(
        fixture.decay(0.5, 20).expect("the first decay lands"),
        ClaimDemotionRung::Decayed
    );
    assert_eq!(
        fixture
            .decay(0.25, 21)
            .expect("the documented re-decay lands"),
        ClaimDemotionRung::Decayed
    );
    match fixture.decay(0.75, 22) {
        Err(Error::InvalidEdgeWeight { value }) => assert_eq!(value, 0.75),
        other => panic!("a higher weight is no decay; got {other:?}"),
    }
}
