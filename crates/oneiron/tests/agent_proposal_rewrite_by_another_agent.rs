//! Can another agent rewrite who proposed a change to a stored agent
//! definition? (FIX-LIST 24125 [AGENT-DEF-PROPOSAL-PROPOSER-FORGEABLE];
//! Engine RULING NEXT-ROW-8, Fri 13 Nov 19:21 JST.) Evidence run on the
//! stack head with no engine change: these tests pin what the engine does
//! today, and print what they see.
//!
//! Agent A proposes a wider version "2" of its own definition, stored at the
//! proposal id the engine derives from (target, version). Agent B, which
//! holds a read permit, then puts the proposal row again with itself as the
//! provenance author:
//! - at the same version, the shared AGENT_DEF update check refuses the put
//!   ("version must change when updating agent definition body"), so the
//!   owner's list still names A;
//! - at a new version, the put lands, and the row no longer sits at the id
//!   its version derives, so it leaves the owner's list of waiting changes.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron
//! --all-features --test agent_proposal_rewrite_by_another_agent`.

use std::sync::Arc;

use oneiron::agent_def::{
    AgentCeiling, AgentDefinition, AgentScope, AgentWakeCadence, encode_agent_definition,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};

const NOW: u64 = 1_700_000_000;
const AUTHOR: u8 = 0x70;
const REWRITER: u8 = 0x71;
const LIST: &str = "vault.agents.proposed_changes.list";

/// The key the engine derives a proposal id under (`agent_def/doors.rs`,
/// `PROPOSED_CHANGE_ID_CONTEXT`).
const PROPOSED_CHANGE_ID_CONTEXT: &str = "oneiron agent_def proposed change id v1";

fn proposed_change_id(stored: &EntityId, version: &str) -> EntityId {
    let mut hasher = blake3::Hasher::new_derive_key(PROPOSED_CHANGE_ID_CONTEXT);
    hasher.update(stored.as_bytes());
    hasher.update(version.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    EntityId::from_bytes(bytes).expect("derived proposal id")
}

/// An owner-created definition: scope Base, ceiling Proposed, version "1".
fn definition(agent_id: &str) -> AgentDefinition {
    AgentDefinition::new(
        agent_id,
        "proposal rewrite fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
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
    .with_wake_cadence(AgentWakeCadence::Companion {
        every_turns: Some(1),
    })
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

/// Puts `def` at `id` through `vault.batch` on `writer`'s Agent-class handle.
fn batch_put(
    vault: &Vault,
    writer: EntityId,
    id: EntityId,
    def: &AgentDefinition,
    at: u64,
) -> Result<Value, String> {
    let bytes = encode_agent_definition(def).expect("valid definition");
    let body = json_of(&rmpv::decode::read_value(&mut bytes.as_slice()).expect("MessagePack"));
    oneiron::task_verb::sdk::invoke(
        &vault.memory(writer, EdgeActorClass::Agent),
        "vault.batch",
        json!({"entities": [{
            "id": id.to_hex(),
            "entity_type": ENTITY_TYPE_AGENT_DEF,
            "occurred_start": at,
            "occurred_end": at,
            "learned_at": at,
            "body": body,
        }]}),
    )
    .map_err(|error| format!("{error:?}"))
}

struct Fixture {
    vault: Vault,
    owner_person: EntityId,
    author: EntityId,
    rewriter: EntityId,
    proposal: EntityId,
    _dir: tempfile::TempDir,
}

/// A process-owned device vault: the owner creates agents A and B, both
/// read, and A proposes scope All at version "2" of its own definition.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("owned vault");
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
    let rewriter = EntityId::from_bytes([REWRITER; 16]).expect("rewriter id");
    for (id, agent_id) in [
        (author, "proposal_rewrite.author"),
        (rewriter, "proposal_rewrite.rewriter"),
    ] {
        vault
            .create_agent_definition_as(
                &owner,
                &id,
                &definition(agent_id),
                TimeRange {
                    start: NOW,
                    end: NOW,
                },
                NOW,
            )
            .expect("the owner creates the agent");
    }
    vault
        .install_read_permits_for_test(&[
            WriteActor::new(author, EdgeActorClass::Agent),
            WriteActor::new(rewriter, EdgeActorClass::Agent),
        ])
        .expect("both agents read");
    let mut wider = vault
        .get_agent_definition(&author)
        .expect("read the author")
        .expect("the author row");
    wider.scope = AgentScope::All;
    wider.version = "2".to_owned();
    batch_put(&vault, author, author, &wider, NOW + 5).expect("A's widening batch lands");
    let proposal = proposed_change_id(&author, "2");
    let stored = vault
        .get_agent_definition(&proposal)
        .expect("read the proposal id")
        .expect("the widening put is stored as a proposal");
    assert_eq!(stored.approval_status, ClaimApprovalStatus::Proposed);
    Fixture {
        vault,
        owner_person,
        author,
        rewriter,
        proposal,
        _dir: dir,
    }
}

fn waiting_changes(f: &Fixture) -> Vec<Value> {
    let listed = oneiron::task_verb::sdk::invoke(
        &f.vault.memory(f.owner_person, EdgeActorClass::Human),
        LIST,
        json!({}),
    )
    .expect("the owner lists proposed changes");
    listed
        .get("changes")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("changes is a list in {listed}"))
        .clone()
}

fn proposers(f: &Fixture) -> Vec<String> {
    waiting_changes(f)
        .iter()
        .map(|change| {
            change
                .get("proposed_by")
                .map(Value::to_string)
                .unwrap_or_default()
        })
        .collect()
}

/// The proposal row with B as its provenance author, at `version`.
fn rewritten(f: &Fixture, version: &str) -> AgentDefinition {
    let mut def = f
        .vault
        .get_agent_definition(&f.proposal)
        .expect("read the proposal")
        .expect("the proposal row");
    let RmpValue::Map(entries) = &mut def.provenance else {
        panic!("the proposal's provenance is a map");
    };
    for (key, value) in entries.iter_mut() {
        if key.as_str() == Some("author") {
            *value = RmpValue::from(f.rewriter.to_hex());
        }
    }
    def.version = version.to_owned();
    def
}

#[test]
fn another_agents_same_version_rewrite_of_a_proposal_is_refused() {
    let f = fixture();
    assert_eq!(proposers(&f), vec![format!("\"{}\"", f.author.to_hex())]);
    let put = batch_put(
        &f.vault,
        f.rewriter,
        f.proposal,
        &rewritten(&f, "2"),
        NOW + 6,
    );
    println!("EVIDENCE same-version rewrite by B: {put:?}");
    println!("EVIDENCE proposers after: {:?}", proposers(&f));
    let error = put.expect_err("a same-version body change is refused");
    assert!(
        error.contains("version must change when updating agent definition body"),
        "refused by the update check: {error}"
    );
    assert_eq!(
        proposers(&f),
        vec![format!("\"{}\"", f.author.to_hex())],
        "the owner's list still names A"
    );
}

#[test]
fn another_agents_new_version_of_a_proposal_takes_it_off_the_owners_list() {
    let f = fixture();
    let put = batch_put(
        &f.vault,
        f.rewriter,
        f.proposal,
        &rewritten(&f, "2.rewritten"),
        NOW + 6,
    );
    println!("EVIDENCE new-version rewrite by B: {put:?}");
    let listed = proposers(&f);
    println!("EVIDENCE proposers after: {listed:?}");
    let stored = f
        .vault
        .get_agent_definition(&f.proposal)
        .expect("read the proposal id");
    println!(
        "EVIDENCE row at the proposal id: version={:?} approval={:?}",
        stored.as_ref().map(|def| def.version.clone()),
        stored
            .as_ref()
            .map(|def| format!("{:?}", def.approval_status))
    );
    put.expect("B's new-version put lands");
    assert!(
        listed.is_empty(),
        "the row no longer sits at the id its version derives, so no change waits: {listed:?}"
    );
}
