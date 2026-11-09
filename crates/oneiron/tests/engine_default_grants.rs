//! The receipt of each engine default grant (lead 10 Nov 06:5x; Engine
//! S6C-PLACE-1 = A): when a host first opens the vault, the engine stands
//! the Dreamer's and the Coach's Steward grants with an `EngineDefaultGrant`
//! receipt, origin "engine default at vault creation", which the owner reads
//! on first open (`vault.engine.defaults`). A second open stands nothing
//! more.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test engine_default_grants`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use oneiron::federation::EngineDefaultOrigin;
use oneiron::task_verb::sdk::{EngineDefaultGrantEntry, invoke};
use oneiron::test_doors::coach::{coach, read_and_engine_controls};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, open_owner_carrier_vault, owner};
use oneiron::{EdgeActorClass, EntityId};
use serde_json::json;

fn verbs(verbs: &[&str]) -> BTreeSet<String> {
    verbs.iter().map(|verb| (*verb).to_owned()).collect()
}

#[test]
fn the_owner_reads_each_engine_default_and_its_origin() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
    let owner_proof = owner(&vault).expect("owner proof");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let coach = coach(&vault).expect("the Coach");
    assert!(
        vault
            .engine_default_grants(&owner_proof)
            .expect("defaults")
            .is_empty(),
        "no default before a host opens the vault"
    );

    vault
        .provision_system_agent_grants()
        .expect("the engine's defaults");
    let defaults = vault.engine_default_grants(&owner_proof).expect("defaults");
    assert_eq!(defaults.len(), 2, "{defaults:?}");
    let of = |agent: EntityId| {
        defaults
            .iter()
            .find(|(_, receipt)| receipt.agent == agent)
            .map(|(_, receipt)| receipt.clone())
            .expect("a receipt for each base agent")
    };
    let dreamers = of(dreamer);
    let coachs = of(coach);
    assert_eq!(dreamers.verbs, verbs(&STEWARD_VERBS));
    assert_eq!(coachs.verbs, verbs(&read_and_engine_controls()));
    for receipt in [&dreamers, &coachs] {
        assert_eq!(
            receipt.origin,
            EngineDefaultOrigin::EngineDefaultAtVaultCreation
        );
    }

    // The verb answers the owner with the same receipts.
    let owner_id = vault.ensure_embedded_owner_actor().expect("owner");
    let answer = invoke(
        &vault.memory(owner_id, EdgeActorClass::Human),
        "vault.engine.defaults",
        json!({}),
    )
    .expect("the owner's read");
    let entries: Vec<EngineDefaultGrantEntry> =
        serde_json::from_value(answer).expect("receipt entries");
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.grant)
            .collect::<BTreeSet<_>>(),
        defaults
            .iter()
            .map(|(grant, _)| *grant)
            .collect::<BTreeSet<_>>()
    );

    // A second open stands nothing more.
    vault
        .provision_system_agent_grants()
        .expect("a second open");
    assert_eq!(
        vault
            .engine_default_grants(&owner_proof)
            .expect("defaults")
            .len(),
        2
    );
}
