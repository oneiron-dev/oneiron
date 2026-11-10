//! An agent's generic row writers follow ARCH-0053:20 for AGENT_DEF rows.
//!
//! Canon ARCH-0053:20 (owner, 22 Sep 2026): "An agent may author an
//! AGENT_DEF for later use under the same rule as a skill: a definition that
//! widens nothing lands Active at the author's ceiling; anything beyond the
//! author's slice is a proposal."
//!
//! `vault.agents.put` applies that rule. An agent's code-mode run also reaches
//! the generic `vault.structural.put` and `vault.batch` rows: a pumped run's
//! `RunHostDoor` answers them on the agent's own Agent-class `Memory`
//! (crates/oneiron-server/src/server/run_host_door.rs:830-876). These tests
//! call those same generated rows on that Memory for a fresh AGENT_DEF of a
//! Base, ceiling-Proposed author. A definition wider than the author lands as
//! a proposal no dispatch runs; one inside the author's slice lands active.
//! Neither is refused.

use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope, encode_agent_definition};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};

const NOW: u64 = 1_700_000_000;

// Fixture ids are `[seed; 16]`, off the pinned bytes a fresh vault holds
// (`0x00 0x11 0x42 0x47 0xA1..=0xA6 0xD7 0xE1 0xFF`).
const AUTHOR: u8 = 0x70;

fn definition(
    name: &str,
    scope: AgentScope,
    ceiling: AgentCeiling,
    source: ClaimSource,
    generated: bool,
    human_authored: bool,
) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "generic writer conformance fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        scope,
        ceiling,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        source,
        1.0,
        generated,
        human_authored,
        RmpValue::Map(vec![(
            RmpValue::from("definedVia"),
            RmpValue::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

fn json_of(value: &RmpValue) -> Value {
    match value {
        RmpValue::Nil => Value::Null,
        RmpValue::Boolean(flag) => Value::Bool(*flag),
        RmpValue::Integer(int) => int
            .as_u64()
            .map(Value::from)
            .or_else(|| int.as_i64().map(Value::from))
            .expect("an integer fits i64 or u64"),
        RmpValue::F32(float) => json!(f64::from(*float)),
        RmpValue::F64(float) => json!(*float),
        RmpValue::String(text) => Value::String(text.as_str().expect("UTF-8").to_owned()),
        RmpValue::Array(items) => Value::Array(items.iter().map(json_of).collect()),
        RmpValue::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| (key.as_str().expect("string key").to_owned(), json_of(value)))
                .collect(),
        ),
        other => panic!("an AGENT_DEF body holds no {other:?}"),
    }
}

/// How the candidate stands against its Base, ceiling-Proposed author.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slice {
    /// Scope All, ceiling Auto.
    Wider,
    /// Scope Base, ceiling Proposed: the author's own.
    Within,
}

/// The candidate's body as JSON, made by the engine's own codec: Approved,
/// Active, enabled, at the scope and ceiling `slice` names.
fn candidate_body(slice: Slice) -> Value {
    let (scope, ceiling) = match slice {
        Slice::Wider => (AgentScope::All, AgentCeiling::Auto),
        Slice::Within => (AgentScope::Base, AgentCeiling::Proposed),
    };
    let bytes = encode_agent_definition(&definition(
        "conformance.candidate",
        scope,
        ceiling,
        ClaimSource::Generated,
        true,
        false,
    ))
    .expect("valid candidate");
    json_of(&rmpv::decode::read_value(&mut bytes.as_slice()).expect("candidate MessagePack"))
}

fn run_case(verb: &str, candidate_seed: u8, slice: Slice) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("personal vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let author = EntityId::from_bytes([AUTHOR; 16]).expect("author id");
    vault
        .create_agent_definition_as(
            &owner,
            &author,
            &definition(
                "conformance.author",
                AgentScope::Base,
                AgentCeiling::Proposed,
                ClaimSource::UserStated,
                false,
                true,
            ),
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
        )
        .expect("owner creates the Base, ceiling-Proposed author");
    let candidate = EntityId::from_bytes([candidate_seed; 16]).expect("candidate id");
    assert!(
        vault
            .get_agent_definition(&candidate)
            .expect("fresh id")
            .is_none()
    );

    let input = match verb {
        "vault.structural.put" => json!({
            "id": candidate.to_hex(),
            "kind": "AGENT_DEF",
            "body": candidate_body(slice),
            "occurred_at": NOW + 1,
            "learned_at": NOW + 1,
        }),
        "vault.batch" => json!({"entities": [{
            "id": candidate.to_hex(),
            "entity_type": ENTITY_TYPE_AGENT_DEF,
            "occurred_start": NOW + 1,
            "occurred_end": NOW + 1,
            "learned_at": NOW + 1,
            "body": candidate_body(slice),
        }]}),
        other => panic!("no fixture for {other}"),
    };
    assert!(
        oneiron::task_verb::sdk::code_mode_verb_names().any(|name| name == verb),
        "{verb} is a code-mode row"
    );
    // The author's own Memory, as the run host door binds it.
    let memory = vault.memory(author, EdgeActorClass::Agent);
    let write = oneiron::task_verb::sdk::invoke(&memory, verb, input);
    let stored = vault
        .get_agent_definition(&candidate)
        .expect("read candidate");
    let dispatch = match AgentDispatcher::new(&vault).dispatch(DispatchAgent {
        target: AgentDispatchTarget::Custom(candidate),
        parent_attempt: None,
        dedupe_key: None,
        run_id: None,
        now: NOW + 2,
    }) {
        Ok(AgentDispatchOutcome::Dispatched(_)) => "dispatched".to_owned(),
        Ok(AgentDispatchOutcome::Existing(_)) => "existing".to_owned(),
        Ok(AgentDispatchOutcome::ProposedWiden(_)) => "proposed-widen".to_owned(),
        Ok(_) => "workflow".to_owned(),
        Err(error) => format!("refused: {error}"),
    };
    let write_label = match &write {
        Ok(_) => "landed".to_owned(),
        Err(error) => format!("refused: {error:?}"),
    };
    let standing = stored.as_ref().map_or_else(
        || "absent".to_owned(),
        |def| {
            format!(
                "approval={:?} lifecycle={:?} enabled={} scope={:?} ceiling={:?} source={:?}",
                def.approval_status,
                def.lifecycle_status,
                def.enabled,
                def.scope,
                def.ceiling,
                def.source
            )
        },
    );
    let slice_label = match slice {
        Slice::Wider => "wider",
        Slice::Within => "within",
    };
    println!(
        "CONFORMANCE path=agent-memory/{verb} slice={slice_label} write={write_label} stored=[{standing}] dispatch={dispatch}"
    );
    assert!(
        write.is_ok(),
        "ARCH-0053:20: {verb} refused a {slice_label} definition: {write_label}"
    );
    let def = stored.expect("the put landed a definition");
    assert_eq!(
        def.lifecycle_status,
        ClaimLifecycleStatus::Active,
        "{verb} {slice_label}: a saved definition is live at rest"
    );
    match slice {
        Slice::Wider => {
            assert_eq!(
                def.approval_status,
                ClaimApprovalStatus::Proposed,
                "ARCH-0053:20: {verb} stored a definition wider than its author's slice as other than a proposal"
            );
            assert_ne!(
                dispatch, "dispatched",
                "ARCH-0053:20: {verb} left a definition wider than its author's slice dispatchable"
            );
        }
        Slice::Within => {
            assert_eq!(
                def.approval_status,
                ClaimApprovalStatus::Approved,
                "ARCH-0053:20: {verb} did not land a definition inside its author's slice at the author's approval"
            );
            assert!(def.enabled, "{verb} within: the definition stays enabled");
            assert_eq!(
                dispatch, "dispatched",
                "ARCH-0053:20: {verb} left a definition inside its author's slice undispatchable"
            );
        }
    }
}

#[test]
fn agent_structural_put_stores_no_active_definition_wider_than_its_slice() {
    run_case("vault.structural.put", 0x72, Slice::Wider);
}

#[test]
fn agent_batch_stores_no_active_definition_wider_than_its_slice() {
    run_case("vault.batch", 0x73, Slice::Wider);
}

#[test]
fn agent_structural_put_stores_a_definition_inside_its_slice_active() {
    run_case("vault.structural.put", 0x74, Slice::Within);
}

#[test]
fn agent_batch_stores_a_definition_inside_its_slice_active() {
    run_case("vault.batch", 0x75, Slice::Within);
}
