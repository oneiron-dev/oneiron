//! FIX [CLEANUP-ARCHIVES-MINTED-PERSON-BETWEEN-TRIES]: an attempt mints a
//! PERSON before the claims about it land, in a separate write, and a try
//! that stops in between is tried again. The vault cleanup archives an
//! extraction-minted PERSON with no live claim. It spares one while a try of
//! the retry lineage that minted it is pending, so a claim that lands later,
//! from the same try or from a retry, still finds its subject. Once no try of
//! that lineage is pending, the empty PERSON is the cleanup's to archive. A
//! mint that recorded no lineage (the public mint door) is judged on its
//! evidence and its claims alone.
//!
//! The mint here is the person item of a derivation batch on an agent's
//! leased run. The Dreamer's own extraction records its lineage through the
//! same mint door.
//!
//! Red without the fix: the cleanup lists and archives the PERSON while the
//! run that minted it is live.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test cleanup_spares_minted_person_between_tries`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
    CompleteAttempt, RetryAttempt,
};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{row_live, source_version};
use oneiron::test_doors::derive_person::cleanup_lists;
use oneiron::test_doors::derive_verbs::{LiveRun, define_agent, grant_derive_rows, lease_run};
use oneiron::vault_cleanup::run_vault_cleanup;
use oneiron::{ClaimSource, EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};

const READER: &str = "reader";

/// The lease owner `lease_run` leases the agent's run to.
const LEASE_OWNER: &str = "test-door";

/// A TURN holding its own `words`, spoken by the user.
fn turn(vault: &Vault, words: &str) -> EntityId {
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([
        ("speaker", "user"),
        ("text", words),
    ]))
    .expect("a TURN body");
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange { start: at, end: at },
            at,
            &body,
        )
        .expect("a TURN");
    id
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    agent: EntityId,
    run: LiveRun,
}

/// A vault with one agent the owner's policy lets derive, on a leased run.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let agent =
        define_agent(&vault, "oneiron.agent.cleanup-spares-minted-person").expect("an agent");
    grant_derive_rows(&vault, &[agent]).expect("the agent's policy rows");
    let run = lease_run(&vault, agent).expect("the agent's live run");
    Fixture {
        _dir: dir,
        vault,
        agent,
        run,
    }
}

/// Commits `items` on the fixture's run, citing `source` at the version the
/// agent's own read serves; the wire answer.
fn commit(fixture: &Fixture, items: Vec<Value>, source: EntityId) -> Value {
    let version = source_version(&fixture.vault, fixture.agent, EdgeActorClass::Agent, source)
        .expect("read")
        .expect("the agent reads the source");
    let version = serde_json::to_value(version).expect("a version");
    fixture
        .run
        .commit(
            &fixture.vault,
            json!({ "items": items, "sources": [version] }),
        )
        .expect("the batch commits")
}

/// Mints the PERSON "Ann" named in the TURN `said`, through a batch that
/// holds the person item alone, with no claim about her; her id.
fn mint_ann(fixture: &Fixture, said: EntityId) -> EntityId {
    let answer = commit(
        fixture,
        vec![json!({
            "kind": "person",
            "spec": { "local": "ann", "name": "Ann", "evidence": [{ "stored": said }] },
        })],
        said,
    );
    assert_eq!(answer["items"][0]["landed"], true, "{answer}");
    EntityId::from_hex(answer["items"][0]["rows"][0].as_str().expect("an id"))
        .expect("a 32-character hex id")
}

/// Ends the leased try `leased`: its run completed.
fn complete(vault: &Vault, leased: &AttemptRecord) {
    AttemptQueue::new(vault)
        .complete(CompleteAttempt {
            id: leased.id,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: leased.attempt_count,
            now: leased.updated_at,
        })
        .expect("the leased try completes");
}

#[test]
fn a_person_is_spared_while_the_run_that_minted_it_is_live() {
    let fixture = fixture();
    let said = turn(
        &fixture.vault,
        "Coffee with Ann: an oat milk flat white, as every Tuesday.",
    );
    let ann = mint_ann(&fixture, said);
    assert!(
        !cleanup_lists(&fixture.vault, ann).expect("read"),
        "the run that minted her is live: the cleanup does not list her"
    );
    let report = run_vault_cleanup(&fixture.vault, &AttemptId::now()).expect("a cleanup run");
    assert!(
        !report.archived.contains(&Some(ann)),
        "the run archives no PERSON whose minting run is live: {report:?}"
    );
    assert!(row_live(&fixture.vault, ann).expect("read"));
    assert!(fixture.vault.archived_entity(&ann).expect("read").is_none());

    // The claim about her lands in a later write of the same run.
    let claimed = commit(
        &fixture,
        vec![json!({
            "kind": "claim",
            "spec": {
                "local": "drink",
                "predicate": "profile.drink",
                "subject": { "stored": ann },
                "value": "an oat milk flat white",
                "confidence": 0.9,
                "evidence": [{ "stored": said }],
            },
        })],
        said,
    );
    assert_eq!(claimed["items"][0]["landed"], true, "{claimed}");
    complete(&fixture.vault, fixture.run.leased());
    assert!(
        !cleanup_lists(&fixture.vault, ann).expect("read"),
        "a PERSON with a live claim is not listed, whatever her run's state"
    );
}

#[test]
fn a_person_is_listed_once_no_try_of_its_lineage_is_pending() {
    let fixture = fixture();
    let said = turn(&fixture.vault, "I had lunch with Ann today.");
    let ann = mint_ann(&fixture, said);
    let queue = AttemptQueue::new(&fixture.vault);
    let first = fixture.run.leased();

    // The first try fails and its retry waits scheduled.
    queue
        .retry(RetryAttempt {
            id: first.id,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: first.attempt_count,
            backoff_until: first.updated_at,
            last_error: None,
            now: first.updated_at,
        })
        .expect("the run is retried");
    assert_eq!(
        queue.get(first.id).expect("read").map(|row| row.state),
        Some(AttemptState::Failed),
        "the try that minted her has failed"
    );
    assert!(
        !cleanup_lists(&fixture.vault, ann).expect("read"),
        "a retry of the try that minted her waits: the cleanup does not list her"
    );

    // The retry is leased, and ends with no claim about her.
    let ClaimOutcome::Claimed(retry) = queue
        .claim_kind(
            &first.kind,
            ClaimAttempt {
                lease_owner: LEASE_OWNER.to_owned(),
                now: fixture.vault.now_recorded_at(),
            },
        )
        .expect("claim")
    else {
        panic!("the retry is ready to lease");
    };
    assert_eq!(
        retry.retry_of,
        Some(first.id),
        "the leased row is the retry"
    );
    assert!(
        !cleanup_lists(&fixture.vault, ann).expect("read"),
        "the retry runs: the cleanup does not list her"
    );
    complete(&fixture.vault, &retry);

    assert!(
        cleanup_lists(&fixture.vault, ann).expect("read"),
        "no try of her lineage is pending: the empty mint is listed"
    );
    let report = run_vault_cleanup(&fixture.vault, &AttemptId::now()).expect("a cleanup run");
    assert!(
        report.archived.contains(&Some(ann)),
        "the run archives her: {report:?}"
    );
    assert!(
        fixture.vault.archived_entity(&ann).expect("read").is_some(),
        "she is archived, for the owner's restore"
    );
}

#[test]
fn a_mint_that_recorded_no_lineage_is_listed_at_once() {
    let fixture = fixture();
    let husk = EntityId::now();
    assert!(
        fixture
            .vault
            .put_extraction_minted_person(
                &husk,
                ClaimSource::Generated,
                TimeRange { start: 1, end: 1 },
                1,
                b"a person nobody mentions again",
            )
            .expect("mint")
    );
    assert!(
        cleanup_lists(&fixture.vault, husk).expect("read"),
        "the public mint door records no lineage: an agent's live run does not spare the row"
    );
}
