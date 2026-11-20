//! A hydrate an agent's own live Grant admits reports that Grant's reach in
//! its receipt, as vault.get does, not the agent key's own floor, which reads
//! nothing (FIX-LIST GRANT-RECEIPT-OTHER-READ-LANES, after
//! GRANT-READ-NARROWING-SAYS-DENY-ALL). The receipt only reports: after the
//! owner revokes the Grant the same hydrate reads nothing.
//!
//! The claim takes the vault's own time (no `occurred_at` or `learned_at`),
//! so the test reads no wall clock.

use oneiron::memory::Memory;
use oneiron::{EdgeActorClass, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

/// Runs `verb` as `caller`, panicking with its refusal.
fn call(caller: &Memory<'_>, verb: &str, input: Value) -> Value {
    door::invoke(caller, verb, input).unwrap_or_else(|error| panic!("{verb}: {error}"))
}

/// Whether the receipt list `list` names `entry`.
fn lists(list: &Value, entry: &str) -> bool {
    list.as_array()
        .is_some_and(|entries| entries.iter().any(|named| named == entry))
}

#[test]
fn an_agents_hydrate_under_a_live_read_grant_reports_the_grant_not_deny_all() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("fresh vault");
    oneiron_testkit::dreamer::attach_test_host(&vault).expect("the test host");
    let owner_id = vault.ensure_embedded_owner_actor().expect("the owner");
    let owner = door::owner(&vault).expect("the embedded owner");

    let remembered = call(
        &owner,
        "vault.remember",
        json!({
            "predicate": "project.deadline",
            "subject_ref": owner_id.to_hex(),
            "value": "The harbour survey is due on Friday.",
            "confidence": 0.9,
            "source": "user_stated",
        }),
    );
    let claim = remembered
        .pointer("/claim/id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("the remembered claim's id: {remembered:#}"))
        .to_owned();

    let agent = vault.new_entity_id().expect("an agent id");
    call(
        &owner,
        "vault.agents.create",
        json!({
            "agent_def_ref": agent.to_hex(),
            "definition": {
                "agent_id": "hydrate-reader",
                "desc": "an agent that hydrates through the owner's read Grant",
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
    let grant = minted
        .pointer("/grant/grant_ref")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("the minted Grant's ref: {minted:#}"))
        .to_owned();

    let reader = vault.memory(agent, EdgeActorClass::Agent);
    let answer = call(&reader, "vault.hydrate", json!({"refs": [claim]}));
    let views = answer["value"]
        .as_array()
        .unwrap_or_else(|| panic!("a hydrate answer with a view list: {answer:#}"));
    assert_eq!(views.len(), 1, "one view for one ref: {answer:#}");
    assert_eq!(
        views[0]["id_hex"], claim,
        "the Grant admits the owner's claim: {answer:#}"
    );
    let narrowing = &answer["narrowing"];
    for scope in ["requested", "actor_ceiling", "applied"] {
        assert_eq!(
            narrowing[scope]["deny_all"], false,
            "the {scope} scope denies all under the live Grant: {narrowing:#}"
        );
        assert_eq!(
            narrowing[scope]["max_sensitivity_band"], 3,
            "the {scope} scope is not the Grant's band: {narrowing:#}"
        );
    }
    for list in ["narrowed_axes", "replan_hint"] {
        for entry in ["deny_all", "grant_scope"] {
            assert!(
                !lists(&narrowing[list], entry),
                "{list} names {entry} under the live Grant: {narrowing:#}"
            );
        }
    }

    call(
        &owner,
        "vault.agents.grants.revoke",
        json!({"grant_ref": grant}),
    );
    let after = door::invoke(&reader, "vault.hydrate", json!({"refs": [claim]}));
    assert!(
        after.is_err(),
        "the agent still hydrates the owner's claim after the revoke: {after:?}"
    );
}
