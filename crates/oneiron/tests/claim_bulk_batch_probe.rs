//! Diagnostic probe for FIX-LIST row [CLAIM-PUT-HINT-PROOF-GREEN-BAD-TXN]
//! (scratch only, never merged): which bulk claim batch first fails with
//! `Storage(Mdb(BadTxn))`, by batch size, by subject spread, and by how
//! the same count is split into commits. It prints every outcome and then
//! fails naming the shapes that did not land.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test claim_bulk_batch_probe -- --nocapture`
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

const fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, b"person")
        .expect("a live PERSON");
    id
}

fn actor_and_subject(vault: &Vault) -> (WriteEnvelope, EntityId) {
    let actor = person(vault);
    let subject = person(vault);
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("hint lookup fixture")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    );
    (envelope, subject)
}

fn candidate(subject: EntityId) -> ClaimCandidate {
    ClaimCandidate::new(
        "profile.preference",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    )
}

/// Commits `count` claim candidates in commits of `per_commit`, each on a
/// fresh subject when `spread`, else all on one subject. Returns the first
/// commit error with the claim index it ended at.
fn land(count: usize, per_commit: usize, spread: bool) -> Result<(), String> {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let (envelope, subject) = actor_and_subject(&vault);
    let mut batch = vault.batch();
    let mut pending = 0;
    for index in 0..count {
        let target = if spread { person(&vault) } else { subject };
        batch = batch.claim_candidate(
            &EntityId::now(),
            candidate(target),
            &envelope,
            range(10),
            1000 + index as u64,
        );
        pending += 1;
        if pending == per_commit || index + 1 == count {
            batch
                .commit()
                .map_err(|error| format!("commit ending at claim {index}: {error:?}"))?;
            batch = vault.batch();
            pending = 0;
        }
    }
    Ok(())
}

#[test]
fn bulk_claim_batches_by_size_spread_and_split() {
    let mut shapes = Vec::new();
    for size in [20, 63, 64, 65, 66, 100, 128, 129, 200, 256, 257, 500] {
        shapes.push((size, size, false));
    }
    shapes.push((500, 500, true));
    shapes.push((500, 50, false));
    shapes.push((2000, 50, false));
    let mut failed = Vec::new();
    for (count, per_commit, spread) in shapes {
        let outcome = land(count, per_commit, spread);
        println!(
            "PROBE count={count} per_commit={per_commit} spread={spread} -> {}",
            match &outcome {
                Ok(()) => "ok".to_owned(),
                Err(error) => error.clone(),
            }
        );
        if outcome.is_err() {
            failed.push((count, per_commit, spread));
        }
    }
    assert!(failed.is_empty(), "shapes that did not land: {failed:?}");
}
