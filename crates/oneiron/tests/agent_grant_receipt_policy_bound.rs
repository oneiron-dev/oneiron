//! A read an agent's own live Grant admits keeps the receipt's static grant
//! boundary hint while a policy row still caps a read under that Grant
//! (review round 1 of #9775, FIX-LIST GRANT-READ-NARROWING-SAYS-DENY-ALL).
//! The owner's read Grant reaches every world, but the agent's own
//! `core:read` policy row reaches the base world only, and the row gate
//! applies a matching non-house row to a read carrying the Grant's Scope
//! too. So the read is bounded, and its receipt says `grant_scope`.

use std::collections::BTreeSet;

use oneiron::claim::base_world_id;
use oneiron::federation::{ScopeAxis, ScopeId};
use oneiron::memory::Memory;
use oneiron::registry::ENTITY_TYPE_POLICY_MANIFEST;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_authority::federation::scope_codec::read_preset;
use oneiron_testkit::door;
use serde_json::{Value, json};

/// Runs `verb` as `caller`, panicking with its refusal.
fn call(caller: &Memory<'_>, verb: &str, input: Value) -> Value {
    door::invoke(caller, verb, input).unwrap_or_else(|error| panic!("{verb}: {error}"))
}

/// Adds to the shipped policy manifest one `core:read` row for `agent` whose
/// Scope reaches the base world only; every shipped row stays.
fn cap_agent_reads_to_base_world(vault: &Vault, agent: EntityId) {
    let (id, mut manifest) = vault
        .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
        .expect("policy manifests")
        .into_iter()
        .find_map(|id| {
            let bytes = vault.get(&id).expect("policy read")?;
            let body: Value = rmp_serde::from_slice(&bytes).expect("policy body");
            (body["pack_id"] == "oneiron-default-policy").then_some((id, body))
        })
        .expect("the shipped policy manifest");
    let mut scope = read_preset();
    scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    manifest["scoped_grants"]
        .as_array_mut()
        .expect("scoped grants")
        .push(json!({
            "actor_ref": agent.to_hex(),
            "effector": "core:read",
            "scope": scope,
            "receipt_required": false,
        }));
    oneiron::test_support::put_policy_manifest_bytes(
        vault,
        id,
        &rmp_serde::to_vec_named(&manifest).expect("policy encoding"),
    )
    .expect("the agent's base-world read row");
}

#[test]
fn a_full_grant_under_a_base_world_policy_row_reports_the_grant_scope_hint() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("fresh vault");
    oneiron_testkit::dreamer::attach_test_host(&vault).expect("the test host");
    let owner = door::owner(&vault).expect("the embedded owner");

    let agent = vault.new_entity_id().expect("an agent id");
    call(
        &owner,
        "vault.agents.create",
        json!({
            "agent_def_ref": agent.to_hex(),
            "definition": {
                "agent_id": "policy-bound-reader",
                "desc": "an agent whose policy row caps its Grant's reads",
                "version": "1",
            },
        }),
    );
    let minted = call(
        &owner,
        "vault.agents.grants.mint",
        json!({
            "agent": agent.to_hex(),
            "authority_scope": {
                "worlds": {"kind": "all"},
                "facets": {"kind": "all"},
                "bands": {"kind": "all"},
                "audience": {"kind": "all"},
                "verbs": {"kind": "some", "values": ["read"]},
                "sensitivity": {"kind": "all"},
            },
        }),
    );
    assert_eq!(
        minted.pointer("/grant/confers"),
        Some(&Value::Bool(true)),
        "the owner's read Grant is live: {minted:#}"
    );
    cap_agent_reads_to_base_world(&vault, agent);

    let reader = vault.memory(agent, EdgeActorClass::Agent);
    let answer = call(
        &reader,
        "vault.claims.list",
        json!({"predicate": "project.deadline", "limit": 100}),
    );
    let narrowing = &answer["narrowing"];
    let hints = narrowing["replan_hint"]
        .as_array()
        .unwrap_or_else(|| panic!("a receipt with a replan_hint list: {answer:#}"));
    assert!(
        hints.iter().any(|hint| hint == "grant_scope"),
        "the base-world policy row bounds the Grant's read, yet the receipt names no grant \
         boundary: {narrowing:#}"
    );
}
