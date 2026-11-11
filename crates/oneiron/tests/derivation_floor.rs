//! The derivation floor (untangle 6.7a, decision C-3): GATE-12 holds every
//! derivation-class claim, not only a Dreamer run's. A claim an ordinary
//! agent stamps `surface = vault.derive` must cite live evidence, as the
//! Dreamer's must; on the base an agent's claim with no evidence lands as a
//! proposal.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derivation_floor`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derivation_floor::{define_agent, write_derived_claim};
use oneiron::{EntityId, Vault};

const READER: &str = "reader";
const NO_EVIDENCE: &str = "gate.deny.dreamer_precommit.no_evidence";

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

#[test]
fn an_agents_derived_claim_with_no_evidence_is_refused_by_the_derivation_floor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let agent = define_agent(&vault).expect("an agent");
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");

    let refused = write_derived_claim(&vault, agent, person, &[])
        .expect("the write door answers")
        .expect_err("a derived claim citing nothing meets GATE-12");
    assert!(
        refused.iter().any(|code| code == NO_EVIDENCE),
        "the refusal names the evidence floor: {refused:?}"
    );
}

#[test]
fn an_agents_derived_claim_citing_a_live_turn_passes_the_derivation_floor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let agent = define_agent(&vault).expect("an agent");
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    let turn = turn(&vault);

    let landed = write_derived_claim(&vault, agent, person, &[turn])
        .expect("the write door answers")
        .unwrap_or_else(|codes| panic!("a derived claim citing a live TURN lands: {codes:?}"));
    assert!(
        vault.get(&landed).expect("read").is_some(),
        "the claim is stored"
    );
}
