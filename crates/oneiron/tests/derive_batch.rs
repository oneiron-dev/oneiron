//! The derivation batch (untangle 6.7a, primitive C): one commit lands every
//! claim the gate admits, each in its own savepoint with its own verdict; a
//! refused item lands nothing and keeps a refusal receipt; an item that names
//! a refused item is refused in turn; the batch record lists every outcome.
//! The derive verdict, which settlement, artifacts and archives ask, reads
//! the actor's live Steward grant at each ask.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_batch`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derivation_floor::define_agent;
use oneiron::test_doors::derive::{
    Claim, Named, batch_items, batches_of, commit_claims, derive_verdict, refusal_receipt,
    refusal_tokens,
};
use oneiron::test_doors::steward::{
    STEWARD_ARCHIVE_VERB, STEWARD_READ_VERB, STEWARD_VERBS, dreamer, mark_steward_opt_out,
    stand_steward_grant,
};
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::json;

const READER: &str = "reader";
const NO_EVIDENCE: &str = "gate.deny.dreamer_precommit.no_evidence";
const DEPENDENCY_REFUSED: &str = "gate.deny.derive.dependency_refused";

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("a row");
    id
}

fn turn(vault: &Vault) -> EntityId {
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    put(vault, ENTITY_TYPE_TURN, &body)
}

/// Three claims about `person`: one citing `turn`, one citing nothing, and
/// one citing the second.
fn three_claims(person: EntityId, turn: EntityId) -> Vec<Claim> {
    vec![
        Claim {
            local: "kept",
            predicate: "preference.coffee",
            subject: Named::Stored(person),
            value: json!("an oat milk flat white"),
            evidence: vec![Named::Stored(turn)],
        },
        Claim {
            local: "unfounded",
            predicate: "preference.tea",
            subject: Named::Stored(person),
            value: json!("a green tea"),
            evidence: Vec::new(),
        },
        Claim {
            local: "built_on_unfounded",
            predicate: "preference.snack",
            subject: Named::Stored(person),
            value: json!("a rice cracker"),
            evidence: vec![Named::Local("unfounded")],
        },
    ]
}

fn assert_kept_refused_dependent(vault: &Vault, actor: EntityId, class: EdgeActorClass) {
    let person = put(vault, ENTITY_TYPE_PERSON, b"someone");
    let turn = turn(vault);
    let committed = commit_claims(vault, actor, class, "run-1", &three_claims(person, turn))
        .expect("the batch commits");
    let [kept, unfounded, dependent] = committed.items.as_slice() else {
        panic!("three items: {:?}", committed.items);
    };

    assert!(kept.landed, "the founded claim lands: {kept:?}");
    let [claim] = kept.rows.as_slice() else {
        panic!("one row: {kept:?}");
    };
    assert!(
        vault.get(claim).expect("read").is_some(),
        "the claim is stored"
    );

    assert!(!unfounded.landed, "the unfounded claim is refused");
    assert!(unfounded.rows.is_empty());
    assert!(
        unfounded.reasons.iter().any(|code| code == NO_EVIDENCE),
        "it is refused by the evidence floor: {unfounded:?}"
    );
    let receipt = refusal_receipt(vault, committed.batch, "unfounded")
        .expect("read")
        .expect("its refusal is receipted");
    assert!(
        receipt.iter().any(|code| code == NO_EVIDENCE),
        "{receipt:?}"
    );

    assert!(
        !dependent.landed,
        "a claim citing a refused item is refused"
    );
    assert_eq!(dependent.reasons, vec![DEPENDENCY_REFUSED.to_owned()]);
    assert_eq!(
        refusal_receipt(vault, committed.batch, "built_on_unfounded").expect("read"),
        Some(vec![DEPENDENCY_REFUSED.to_owned()])
    );

    assert_eq!(
        batch_items(vault, committed.batch).expect("read"),
        Some(committed.items.clone()),
        "the batch record keeps every outcome"
    );
    assert_eq!(
        batches_of(vault, actor).expect("read"),
        vec![committed.batch]
    );
}

#[test]
fn the_dreamers_batch_lands_what_the_gate_admits_and_receipts_each_refusal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    assert_kept_refused_dependent(&vault, dreamer, EdgeActorClass::System);
}

#[test]
fn an_ordinary_agents_batch_meets_the_same_floors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let agent = define_agent(&vault).expect("an agent");
    assert_kept_refused_dependent(&vault, agent, EdgeActorClass::Agent);
}

#[test]
fn a_malformed_batch_lands_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    let turn = turn(&vault);
    let mut claims = three_claims(person, turn);
    // A later item named before it lands.
    claims[0].evidence.push(Named::Local("built_on_unfounded"));
    commit_claims(&vault, dreamer, EdgeActorClass::System, "run-2", &claims)
        .expect_err("a forward reference is a malformed batch");
    assert!(
        batches_of(&vault, dreamer).expect("read").is_empty(),
        "no batch is recorded"
    );
}

#[test]
fn the_derive_verdict_reads_the_live_steward_grant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let verdict = |archive| {
        derive_verdict(&vault, dreamer, EdgeActorClass::System, archive, None).expect("verdict")
    };

    // Before a host mints the grant the policy rows decide.
    assert!(verdict(false).is_ok(), "the Dreamer's rows let it derive");

    let full = stand_steward_grant(&vault, dreamer, &STEWARD_VERBS).expect("full grant");
    assert_eq!(verdict(false), Ok(full.to_hex()));
    assert_eq!(verdict(true), Ok(full.to_hex()));

    let narrowed =
        stand_steward_grant(&vault, dreamer, &[STEWARD_READ_VERB, "derive"]).expect("narrowed");
    assert_eq!(verdict(false), Ok(narrowed.to_hex()));
    assert_eq!(verdict(true), Err("gate.deny.derive.grant_lacks_archive"));

    stand_steward_grant(&vault, dreamer, &[STEWARD_READ_VERB, STEWARD_ARCHIVE_VERB])
        .expect("archive only");
    assert_eq!(verdict(false), Err("gate.deny.derive.grant_lacks_derive"));

    mark_steward_opt_out(&vault, dreamer).expect("opt out");
    assert_eq!(verdict(false), Err("gate.deny.derive.opted_out"));
    assert_eq!(verdict(true), Err("gate.deny.derive.opted_out"));
}

#[test]
fn an_agent_with_no_landing_rows_may_not_derive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let agent = define_agent(&vault).expect("an agent");
    assert_eq!(
        derive_verdict(&vault, agent, EdgeActorClass::Agent, false, None).expect("verdict"),
        Err("gate.deny.derive.no_landing_rows")
    );
}

#[test]
fn the_refusal_tokens_are_stable() {
    assert_eq!(
        refusal_tokens(),
        vec![
            "gate.deny.derive.no_landing_rows",
            "gate.deny.derive.opted_out",
            "gate.deny.derive.grant_gone",
            "gate.deny.derive.grant_lacks_derive",
            "gate.deny.derive.grant_lacks_archive",
            "gate.deny.derive.outside_grant",
        ]
    );
}
