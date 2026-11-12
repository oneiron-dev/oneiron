//! The write receipt of an agent's AGENT_DEF put names what the author
//! writer made of it (ARCH-0053:20; FIX AGENTDEF-PROPOSED-CHANGE-RECEIPT-ID).
//!
//! An agent's `vault.batch` and `vault.structural.put` hold each definition
//! they put to the agent's own slice: inside it the definition is active,
//! wider it is a proposal, and a put that grants a stored definition more
//! than the slice holds is stored as a proposed change at its own id. Each
//! receipt row keeps the id the put was staged at and adds
//! `agent_definition: {disposition, proposal_id?}`, so the caller learns the
//! outcome and the proposal's id without deriving it. Any other put, and
//! every put of a writer that is no agent, carries no such field.

use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope, encode_agent_definition};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};

const NOW: u64 = 1_700_000_000;

/// The author agent's fixture id, `[seed; 16]`, off the pinned bytes a fresh
/// vault holds.
const AUTHOR: u8 = 0x70;

/// The key the engine derives the id of a proposed change under
/// (`agent_def/doors.rs`, `PROPOSED_CHANGE_ID_CONTEXT`).
const PROPOSED_CHANGE_ID_CONTEXT: &str = "oneiron agent_def proposed change id v1";

fn proposed_change_id(stored: &EntityId, version: &str) -> EntityId {
    let mut hasher = blake3::Hasher::new_derive_key(PROPOSED_CHANGE_ID_CONTEXT);
    hasher.update(stored.as_bytes());
    hasher.update(version.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    EntityId::from_bytes(bytes).expect("derived proposal id")
}

fn definition(name: &str, scope: AgentScope, ceiling: AgentCeiling) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "write receipt fixture",
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
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        RmpValue::Map(vec![(
            RmpValue::from("definedVia"),
            RmpValue::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

/// A definition an agent puts: generated, at `scope` and `ceiling`, as the
/// generic-writer fixture's candidates are.
fn candidate(name: &str, scope: AgentScope, ceiling: AgentCeiling) -> AgentDefinition {
    let mut def = definition(name, scope, ceiling);
    def.source = ClaimSource::Generated;
    def.generated = true;
    def.human_authored = false;
    def
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

fn body_of(def: &AgentDefinition) -> Value {
    let bytes = encode_agent_definition(def).expect("valid definition");
    json_of(&rmpv::decode::read_value(&mut bytes.as_slice()).expect("MessagePack"))
}

/// A personal vault whose owner created one Base, ceiling-Proposed agent,
/// which reads the rows it updates.
struct Fixture {
    vault: Vault,
    owner_person: EntityId,
    author: EntityId,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("personal vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner_person = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(
            owner_person,
            &owner_person.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let author = EntityId::from_bytes([AUTHOR; 16]).expect("author id");
    vault
        .create_agent_definition_as(
            &owner,
            &author,
            &definition(
                "write_receipt.author",
                AgentScope::Base,
                AgentCeiling::Proposed,
            ),
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
        )
        .expect("owner creates the Base, ceiling-Proposed author");
    vault
        .install_read_permits_for_test(&[oneiron::WriteActor::new(author, EdgeActorClass::Agent)])
        .expect("the author reads its own row");
    Fixture {
        vault,
        owner_person,
        author,
        _dir: dir,
    }
}

/// `vault.batch` of one AGENT_DEF put at `id` by `writer` as `class`; its
/// receipt.
fn batch(
    fixture: &Fixture,
    writer: EntityId,
    class: EdgeActorClass,
    id: EntityId,
    def: &AgentDefinition,
) -> Value {
    oneiron::task_verb::sdk::invoke(
        &fixture.vault.memory(writer, class),
        "vault.batch",
        json!({"entities": [{
            "id": id.to_hex(),
            "entity_type": ENTITY_TYPE_AGENT_DEF,
            "occurred_start": NOW + 5,
            "occurred_end": NOW + 5,
            "learned_at": NOW + 5,
            "body": body_of(def),
        }]}),
    )
    .expect("the batch lands")
}

/// The one receipt row of a one-put batch: its staged id and its
/// `agent_definition` field.
fn row(receipt: &Value) -> (&str, Option<&Value>) {
    let entity = &receipt["entities"][0];
    (
        entity["id"]
            .as_str()
            .unwrap_or_else(|| panic!("a receipt row id in {receipt}")),
        entity.get("agent_definition"),
    )
}

#[test]
fn an_agents_batch_receipt_names_an_active_definition() {
    let fixture = fixture();
    let id = EntityId::from_bytes([0x81; 16]).expect("candidate id");
    let within = candidate(
        "write_receipt.within",
        AgentScope::Base,
        AgentCeiling::Proposed,
    );
    let receipt = batch(&fixture, fixture.author, EdgeActorClass::Agent, id, &within);
    println!("CONFORMANCE case=batch-within receipt={receipt}");
    let (staged, written) = row(&receipt);
    assert_eq!(staged, id.to_hex(), "the row keeps the staged id");
    assert_eq!(
        written,
        Some(&json!({"disposition": "active"})),
        "a definition inside the author's slice is named active"
    );
}

#[test]
fn an_agents_batch_receipt_names_a_proposal() {
    let fixture = fixture();
    let id = EntityId::from_bytes([0x82; 16]).expect("candidate id");
    let wider = candidate("write_receipt.wider", AgentScope::All, AgentCeiling::Auto);
    let receipt = batch(&fixture, fixture.author, EdgeActorClass::Agent, id, &wider);
    println!("CONFORMANCE case=batch-wider receipt={receipt}");
    let (staged, written) = row(&receipt);
    assert_eq!(staged, id.to_hex());
    assert_eq!(
        written,
        Some(&json!({"disposition": "proposed"})),
        "a definition wider than the author's slice is named a proposal"
    );
}

#[test]
fn an_agents_batch_receipt_names_a_proposed_change_and_its_id() {
    let fixture = fixture();
    let mut wider = fixture
        .vault
        .get_agent_definition(&fixture.author)
        .expect("read the author")
        .expect("the author row");
    wider.scope = AgentScope::All;
    wider.version = "2".to_owned();
    let receipt = batch(
        &fixture,
        fixture.author,
        EdgeActorClass::Agent,
        fixture.author,
        &wider,
    );
    println!("CONFORMANCE case=batch-proposed-change receipt={receipt}");
    let proposal = proposed_change_id(&fixture.author, "2");
    let (staged, written) = row(&receipt);
    assert_eq!(
        staged,
        fixture.author.to_hex(),
        "the row keeps the id the put was staged at"
    );
    assert_eq!(
        written,
        Some(&json!({"disposition": "proposed_change", "proposal_id": proposal.to_hex()})),
        "a widening put over a stored definition names the proposal it was stored as"
    );
    assert!(
        fixture
            .vault
            .get_agent_definition(&proposal)
            .expect("read the proposal id")
            .is_some(),
        "the named proposal is stored"
    );
}

#[test]
fn an_agents_structural_put_receipt_names_its_disposition() {
    let fixture = fixture();
    let memory = fixture.vault.memory(fixture.author, EdgeActorClass::Agent);
    for (seed, def, disposition) in [
        (
            0x83,
            candidate(
                "write_receipt.structural_within",
                AgentScope::Base,
                AgentCeiling::Proposed,
            ),
            "active",
        ),
        (
            0x84,
            candidate(
                "write_receipt.structural_wider",
                AgentScope::All,
                AgentCeiling::Auto,
            ),
            "proposed",
        ),
    ] {
        let id = EntityId::from_bytes([seed; 16]).expect("candidate id");
        let receipt = oneiron::task_verb::sdk::invoke(
            &memory,
            "vault.structural.put",
            json!({
                "id": id.to_hex(),
                "kind": "AGENT_DEF",
                "body": body_of(&def),
                "occurred_at": NOW + 5,
                "learned_at": NOW + 5,
            }),
        )
        .expect("the structural put lands");
        println!("CONFORMANCE case=structural-{disposition} receipt={receipt}");
        assert_eq!(receipt["id_hex"], json!(id.to_hex()));
        assert_eq!(
            receipt.get("agent_definition"),
            Some(&json!({"disposition": disposition})),
            "the structural put's receipt names how the definition landed"
        );
    }
}

#[test]
fn a_put_that_is_no_agents_definition_carries_no_agent_definition_field() {
    let fixture = fixture();
    let id = EntityId::from_bytes([0x85; 16]).expect("candidate id");
    let within = definition(
        "write_receipt.owner",
        AgentScope::Base,
        AgentCeiling::Proposed,
    );
    let receipt = batch(
        &fixture,
        fixture.owner_person,
        EdgeActorClass::Human,
        id,
        &within,
    );
    println!("CONFORMANCE case=owner-batch receipt={receipt}");
    let (staged, written) = row(&receipt);
    assert_eq!(staged, id.to_hex());
    assert_eq!(
        written, None,
        "a writer that is no agent gets the receipt it had"
    );
}

#[test]
fn two_puts_at_one_definition_each_name_their_own_proposal() {
    let fixture = fixture();
    let stored = fixture
        .vault
        .get_agent_definition(&fixture.author)
        .expect("read the author")
        .expect("the author row");
    let entities: Vec<Value> = ["2", "3"]
        .into_iter()
        .map(|version| {
            let mut wider = stored.clone();
            wider.scope = AgentScope::All;
            wider.version = version.to_owned();
            json!({
                "id": fixture.author.to_hex(),
                "entity_type": ENTITY_TYPE_AGENT_DEF,
                "occurred_start": NOW + 5,
                "occurred_end": NOW + 5,
                "learned_at": NOW + 5,
                "body": body_of(&wider),
            })
        })
        .collect();
    let receipt = oneiron::task_verb::sdk::invoke(
        &fixture.vault.memory(fixture.author, EdgeActorClass::Agent),
        "vault.batch",
        json!({ "entities": entities }),
    )
    .expect("the batch lands");
    println!("CONFORMANCE case=batch-two-proposed-changes receipt={receipt}");
    for (row, version) in [(0, "2"), (1, "3")] {
        let proposal = proposed_change_id(&fixture.author, version);
        assert_eq!(
            receipt["entities"][row]["agent_definition"],
            json!({"disposition": "proposed_change", "proposal_id": proposal.to_hex()}),
            "row {row} names the proposal its own put became"
        );
    }
}
