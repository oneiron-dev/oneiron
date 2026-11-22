//! FIX-LIST row 24676 [CLAIM-PUT-HINT-LOOKUP-WALKS-EVERY-CLAIM]: each
//! claim Put looked up the lexical query hints of the claim it wrote by
//! walking every CLAIM id in the vault, so one Put cost O(the vault's claim
//! count). The lookup now reads only that target's hints from a derived
//! index and walks only while the index cannot answer. One claim Put in a
//! vault of thousands of claims raises no `LexicalHintRows` check and costs
//! what one Put costs in a vault of twenty; hint replace and delete still
//! find every hint.
//!
//! Public API only, so this stem runs on main (red) and with the fix
//! (green):
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test claim_put_hint_lookup_walks_every_claim -- --nocapture`
//! (the timing line prints with `--nocapture`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Instant;

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::scan_check::EngineScan;
use oneiron::temporal::TimeRange;
use oneiron::write_envelope::claim_body::lexical_query_hint::{
    PREDICATE_LEXICAL_QUERY_HINT, decode_lexical_query_hint_value,
};
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

fn hint_checks(vault: &Vault, scan: EngineScan) -> usize {
    vault
        .scan_checks()
        .expect("checks")
        .iter()
        .filter(|check| check.scan == scan.code())
        .count()
}

#[test]
fn one_claim_put_reads_only_its_own_hints() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let (envelope, subject) = actor_and_subject(&vault);
    // Three claims with two hints each: six derived hint rows, every one of
    // which the old walk read on each later Put.
    let mut hinted = Vec::new();
    for (index, queries) in [
        ["alpha one", "beta one"],
        ["alpha two", "beta two"],
        ["alpha three", "beta three"],
    ]
    .iter()
    .enumerate()
    {
        let claim = EntityId::now();
        vault
            .batch()
            .claim_candidate_with_lexical_hints(
                &claim,
                candidate(subject),
                &envelope,
                range(10),
                11 + index as u64,
                queries.as_slice(),
            )
            .commit()
            .expect("a hinted claim lands");
        hinted.push(claim);
    }
    for claim in &hinted {
        assert_eq!(
            vault.claims_for_subject(claim).expect("hints").len(),
            2,
            "each seeded claim holds its two hints"
        );
    }

    // The measured write: one claim with no hints of its own.
    let scan = EngineScan::LexicalHintRows;
    vault.set_scan_threshold(scan, 2).expect("threshold");
    vault
        .batch()
        .claim_candidate(
            &EntityId::now(),
            candidate(subject),
            &envelope,
            range(10),
            20,
        )
        .commit()
        .expect("one claim Put");
    assert_eq!(
        hint_checks(&vault, scan),
        0,
        "one claim Put reads only its own hints"
    );

    // A rewrite still finds every hint: the dropped query's hint is gone,
    // the kept one stays, and the rewrite reads only its own hints too.
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &hinted[0],
            candidate(subject),
            &envelope,
            range(12),
            21,
            &["alpha one"],
        )
        .commit()
        .expect("a rewrite with one hint lands");
    let kept = vault.claims_for_subject(&hinted[0]).expect("hints");
    assert_eq!(kept.len(), 1, "the rewrite keeps one hint");
    let stored = vault.get_claim(&kept[0]).expect("hint").expect("hint row");
    assert_eq!(stored.predicate, PREDICATE_LEXICAL_QUERY_HINT);
    let value = decode_lexical_query_hint_value(&stored.value).expect("hint value");
    assert_eq!(value.query, "alpha one");
    assert_eq!(value.target, hinted[0]);
    assert_eq!(
        hint_checks(&vault, scan),
        0,
        "the rewrite reads only its own hints"
    );
}

#[test]
fn claim_put_cost_does_not_grow_with_vault_claim_count() {
    const SMALL_CLAIMS: usize = 20;
    const BIG_CLAIMS: usize = 2000;
    const BATCH: usize = 500;

    fn seed(vault: &Vault, plains: usize) {
        let (envelope, subject) = actor_and_subject(vault);
        let mut batch = vault.batch();
        let mut pending = 0;
        for index in 0..plains {
            batch = batch.claim_candidate(
                &EntityId::now(),
                candidate(subject),
                &envelope,
                range(10),
                1000 + index as u64,
            );
            pending += 1;
            if pending == BATCH {
                batch.commit().expect("bulk claims land");
                batch = vault.batch();
                pending = 0;
            }
        }
        if pending > 0 {
            batch.commit().expect("bulk claims land");
        }
        // Two hinted claims: four derived hint rows the old walk always read.
        for (index, queries) in [["fig one", "fig two"], ["fig three", "fig four"]]
            .iter()
            .enumerate()
        {
            vault
                .batch()
                .claim_candidate_with_lexical_hints(
                    &EntityId::now(),
                    candidate(subject),
                    &envelope,
                    range(10),
                    9000 + index as u64,
                    queries.as_slice(),
                )
                .commit()
                .expect("a hinted claim lands");
        }
    }

    let small_dir = tempfile::tempdir().expect("tempdir");
    let small = Vault::open(small_dir.path(), VaultConfig::default()).expect("vault");
    seed(&small, SMALL_CLAIMS);
    let big_dir = tempfile::tempdir().expect("tempdir");
    let big = Vault::open(big_dir.path(), VaultConfig::default()).expect("vault");
    seed(&big, BIG_CLAIMS);

    let scan = EngineScan::LexicalHintRows;
    small.set_scan_threshold(scan, 2).expect("threshold");
    big.set_scan_threshold(scan, 2).expect("threshold");

    // One claim Put in each vault, timed.
    let time_one_put = |vault: &Vault| {
        let (envelope, subject) = actor_and_subject(vault);
        let start = Instant::now();
        vault
            .batch()
            .claim_candidate(
                &EntityId::now(),
                candidate(subject),
                &envelope,
                range(10),
                50_000,
            )
            .commit()
            .expect("one claim Put");
        start.elapsed().as_micros()
    };
    let small_us = time_one_put(&small);
    let big_us = time_one_put(&big);
    println!(
        "DIAG claim_put_hint_lookup: small_claims={} small_us={small_us} big_claims={} big_us={big_us}",
        SMALL_CLAIMS + 2,
        BIG_CLAIMS + 2,
    );
    for (name, vault) in [("small", &small), ("big", &big)] {
        assert_eq!(
            hint_checks(vault, scan),
            0,
            "one claim Put in the {name} vault reads only its own hints"
        );
    }
}
