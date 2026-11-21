//! What an agent made is read from the engine's creation stamp, not from a
//! definition's provenance (AGENT-DEF-PROVENANCE-AUTHOR-FORGEABLE; Engine
//! RULING 18:25, 13 Nov 2026).
//!
//! An AGENT_DEF's `provenance.author` is caller-supplied. Any agent with
//! `save_agent` that reads a stored definition can put it again with another
//! author in its provenance. Such a put lands as staged when it grants the
//! row nothing new. The owner's blast radius (`vault.agents.made_by.get`,
//! owner ruling AUTHOR-OFF = A, ARCH-0053 #author-off-no-cascade) and
//! `vault.agents.pause_tree` used to file the definition under whatever that
//! provenance named. Now the engine stamps the author in the write that
//! creates a definition on each agent-authored create road, and both verbs
//! read that stamp.
//!
//! The tests: agent A creates definitions on three roads: `vault.agents.put`
//! (the leased host dispatcher), `memory.raw_put_entity` and
//! `vault.structural.put` (an Agent-class `Memory`). Agent B, which may read
//! them, rewrites their provenance author to itself, and the rewrite lands.
//! A's made-by still lists each one, and B's lists none. B's tree pause
//! switches nothing off, and A's switches off what A made.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::agent_def::{
    AgentCeiling, AgentDefinition, AgentDefinitionPutDisposition, AgentScope,
    encode_agent_definition,
};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::code_run::{
    HostSelfDispatcher, SelfCall, SelfDispatchOutcome, SelfDispatcher, parse_agent_put_request,
};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, RawEntityPut, TimeRange, Vault, VaultConfig, WriteActor};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

// Fixture ids are `[seed; 16]`; every seed here avoids the pinned bytes a
// fresh vault already holds (`0x00 0x11 0x42 0x47 0xA1..=0xA6 0xD7 0xE1
// 0xFF`, the seeded system agents among them).
const AUTHOR: u8 = 0x63;
const REWRITER: u8 = 0x64;
const SAVED: u8 = 0x65;
const RAW_PUT: u8 = 0x66;
const STRUCTURAL_PUT: u8 = 0x67;

const MADE_BY: &str = "vault.agents.made_by.get";
const PAUSE_TREE: &str = "vault.agents.pause_tree";

/// The lease owner this test claims rows as.
const WORKER: &str = "agent-made-by-creating-stamp";

fn definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "creating stamp fixture",
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
        // The codec requires a non-empty provenance map.
        RmpValue::Map(vec![(
            RmpValue::from("definedVia"),
            RmpValue::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

struct Fixture {
    vault: Vault,
    owner: EntityId,
    /// Agent A: an owner-made Base agent at ceiling Proposed.
    author: EntityId,
    /// Agent B: a second owner-made agent, which may read every row.
    rewriter: EntityId,
    /// A's root attempt, leased.
    leased: AttemptRecord,
    // Dropped after the vault.
    _dir: TempDir,
}

/// A process-owned device vault (the owner verbs answer the embedded owner
/// on the handle that holds the writer lease), its owner, agents A and B,
/// B's read permit, and A's root attempt, leased.
fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let now = vault.now_recorded_at();
    let author = EntityId::from_bytes([AUTHOR; 16])?;
    let rewriter = EntityId::from_bytes([REWRITER; 16])?;
    for (id, name) in [
        (author, "fixture.stamp.author"),
        (rewriter, "fixture.stamp.rewriter"),
    ] {
        vault.create_agent_definition_as(
            &proof,
            &id,
            &definition(name),
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
    }
    // A put over a stored row is admitted only on a lane that reads the row:
    // B reads the definitions it rewrites. The permit grants a read alone.
    vault.install_read_permit_for_test(WriteActor::new(rewriter, EdgeActorClass::Agent))?;
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(&vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(author),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now,
        })?
    else {
        return Err("FIXTURE: the author dispatches without running a model".into());
    };
    let leased = claim(&vault, &status.attempt.id)?;
    Ok(Fixture {
        vault,
        owner,
        author,
        rewriter,
        leased,
        _dir: dir,
    })
}

/// Leases `id` to this test's worker. Rows are claimed oldest first, so a
/// row queued before it is claimed past.
fn claim(vault: &Vault, id: &oneiron::attempt_queue::AttemptId) -> TestResult<AttemptRecord> {
    let queue = AttemptQueue::new(vault);
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now: vault.now_recorded_at(),
            },
        )?
        else {
            break;
        };
        if row.id == *id {
            return Ok(row);
        }
    }
    Err("FIXTURE: the attempt is ready to claim".into())
}

/// A's `vault.agents.put` of an in-slice definition at `id`, through the
/// leased host dispatcher of its root attempt.
fn save_agent(f: &Fixture, id: EntityId, name: &str) -> TestResult {
    let draft = json!({
        "agentId": name,
        "desc": "creating stamp saved agent",
        "version": "1",
        "scope": {"kind": "base"},
        "ceiling": "proposed",
    });
    let call = parse_agent_put_request(&id.to_hex(), draft, f.vault.now_recorded_at())?;
    let host = HostSelfDispatcher::for_leased_agent_attempt(
        &f.vault,
        WriteActor::new(f.author, EdgeActorClass::Agent),
        &f.leased,
    )?;
    match host.dispatch(SelfCall::AgentsPut(Box::new(call)))? {
        SelfDispatchOutcome::AgentDefinitionPut(result) => {
            assert_eq!(
                result.disposition,
                AgentDefinitionPutDisposition::Active,
                "FIXTURE: an in-slice definition lands Active"
            );
            Ok(())
        }
        other => Err(format!("FIXTURE: expected the put to land, got {other:?}").into()),
    }
}

/// An in-slice definition for A to create on a generic row door: Base,
/// ceiling Proposed, as an agent writes it.
fn candidate(name: &str) -> AgentDefinition {
    let mut candidate = definition(name);
    candidate.source = ClaimSource::Generated;
    candidate.generated = true;
    candidate.human_authored = false;
    candidate
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

/// `writer`'s `memory.raw_put_entity` of `def` at `id`, on its Agent-class
/// `Memory`.
fn raw_put(f: &Fixture, writer: EntityId, id: EntityId, def: &AgentDefinition) -> TestResult {
    let at = f.vault.now_recorded_at();
    let bytes = encode_agent_definition(def)?;
    f.vault
        .memory(writer, EdgeActorClass::Agent)
        .raw_put_entity(RawEntityPut {
            id,
            entity_type: ENTITY_TYPE_AGENT_DEF,
            occurred: TimeRange { start: at, end: at },
            learned_at: at,
            data: &bytes,
        })
        .map_err(|error| format!("{error:?}").into())
}

/// `writer`'s `vault.structural.put` of `def` at `id`, on its Agent-class
/// `Memory`.
fn structural_put(
    f: &Fixture,
    writer: EntityId,
    id: EntityId,
    def: &AgentDefinition,
) -> TestResult {
    let at = f.vault.now_recorded_at();
    let bytes = encode_agent_definition(def)?;
    let body = json_of(&rmpv::decode::read_value(&mut bytes.as_slice())?);
    oneiron::task_verb::sdk::invoke(
        &f.vault.memory(writer, EdgeActorClass::Agent),
        "vault.structural.put",
        json!({
            "id": id.to_hex(),
            "kind": "AGENT_DEF",
            "body": body,
            "occurred_at": at,
            "learned_at": at,
        }),
    )
    .map(|_| ())
    .map_err(|error| format!("{error:?}").into())
}

/// The provenance author the stored definition at `id` names.
fn provenance_author(f: &Fixture, id: EntityId) -> TestResult<Option<String>> {
    let stored = f
        .vault
        .get_agent_definition(&id)?
        .ok_or("FIXTURE: the definition stands")?;
    let RmpValue::Map(entries) = &stored.provenance else {
        return Ok(None);
    };
    Ok(entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("author"))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_owned))
}

/// B puts the stored definition at `id` again through `memory.raw_put_entity`,
/// one version on, with itself as the provenance author: a put that grants
/// the row nothing new. The rewrite lands.
fn rewrite_author(f: &Fixture, id: EntityId) -> TestResult {
    let mut rewritten = f
        .vault
        .get_agent_definition(&id)?
        .ok_or("FIXTURE: the definition stands")?;
    assert_eq!(
        provenance_author(f, id)?,
        Some(f.author.to_hex()),
        "FIXTURE: the created definition's provenance names its author"
    );
    rewritten.version = format!("{}.rewritten", rewritten.version);
    rewritten.provenance = RmpValue::Map(vec![
        (
            RmpValue::from("author"),
            RmpValue::from(f.rewriter.to_hex()),
        ),
        (
            RmpValue::from("definedVia"),
            RmpValue::from("vault.agents.put"),
        ),
    ]);
    raw_put(f, f.rewriter, id, &rewritten)?;
    let author = provenance_author(f, id)?;
    println!(
        "STAMP rewrite id={} provenance_author={author:?}",
        id.to_hex()
    );
    assert_eq!(
        author,
        Some(f.rewriter.to_hex()),
        "FIXTURE: B's rewrite of the provenance author lands (FIX 24089)"
    );
    Ok(())
}

fn as_owner(f: &Fixture, verb: &str, input: Value) -> Result<Value, String> {
    oneiron::task_verb::sdk::invoke(&f.vault.memory(f.owner, EdgeActorClass::Human), verb, input)
        .map_err(|error| format!("{error:?}"))
}

/// The definitions `vault.agents.made_by.get` lists as `agent`'s.
fn made_agents(f: &Fixture, agent: EntityId) -> TestResult<BTreeSet<String>> {
    let made = as_owner(f, MADE_BY, json!({"agent_def_ref": agent}))?;
    println!("STAMP made_by agent={} answer={made}", agent.to_hex());
    Ok(made
        .get("agents")
        .and_then(Value::as_array)
        .ok_or("the answer lists agents")?
        .iter()
        .filter_map(|row| row.get("agent_def_ref").and_then(Value::as_str))
        .map(str::to_owned)
        .collect())
}

fn enabled(f: &Fixture, id: EntityId) -> TestResult<bool> {
    Ok(f.vault
        .get_agent_definition(&id)?
        .ok_or("FIXTURE: the definition stands")?
        .enabled)
}

fn hexes(ids: &[EntityId]) -> BTreeSet<String> {
    ids.iter().map(EntityId::to_hex).collect()
}

/// A definition A saved through `vault.agents.put` stays A's after B
/// rewrites its provenance author to B.
#[test]
fn an_agents_put_definition_stays_its_creators_after_another_agent_rewrites_its_author()
-> TestResult {
    let f = fixture()?;
    let saved = EntityId::from_bytes([SAVED; 16])?;
    save_agent(&f, saved, "fixture.stamp.saved")?;
    rewrite_author(&f, saved)?;

    assert_eq!(
        made_agents(&f, f.author)?,
        hexes(&[saved]),
        "A's made-by lists the definition A saved"
    );
    assert_eq!(
        made_agents(&f, f.rewriter)?,
        BTreeSet::new(),
        "B's made-by lists nothing: B made no definition"
    );
    Ok(())
}

/// Definitions A created on the generic row doors (`memory.raw_put_entity`
/// and `vault.structural.put`) stay A's after B rewrites their provenance
/// author to B.
#[test]
fn a_generic_door_definition_stays_its_creators_after_another_agent_rewrites_its_author()
-> TestResult {
    let f = fixture()?;
    let raw = EntityId::from_bytes([RAW_PUT; 16])?;
    let structural = EntityId::from_bytes([STRUCTURAL_PUT; 16])?;
    raw_put(&f, f.author, raw, &candidate("fixture.stamp.raw"))?;
    structural_put(
        &f,
        f.author,
        structural,
        &candidate("fixture.stamp.structural"),
    )?;
    for id in [raw, structural] {
        rewrite_author(&f, id)?;
    }

    assert_eq!(
        made_agents(&f, f.author)?,
        hexes(&[raw, structural]),
        "A's made-by lists the definitions A created on both generic doors"
    );
    assert_eq!(
        made_agents(&f, f.rewriter)?,
        BTreeSet::new(),
        "B's made-by lists nothing: B made no definition"
    );
    Ok(())
}

/// B's tree pause switches off nothing B did not make; A's switches off the
/// definition A saved.
#[test]
fn pause_tree_of_the_rewriting_agent_switches_off_nothing_it_did_not_make() -> TestResult {
    let f = fixture()?;
    let saved = EntityId::from_bytes([SAVED; 16])?;
    save_agent(&f, saved, "fixture.stamp.saved")?;
    rewrite_author(&f, saved)?;

    let by_rewriter = as_owner(&f, PAUSE_TREE, json!({"agent_def_ref": f.rewriter}))?;
    println!("STAMP pause_tree agent=rewriter answer={by_rewriter}");
    assert_eq!(
        by_rewriter["paused"]["agents"],
        json!([]),
        "B's tree pause switches off no definition: {by_rewriter}"
    );
    assert!(
        enabled(&f, saved)?,
        "A's saved definition stays on after B's tree pause"
    );

    let by_author = as_owner(&f, PAUSE_TREE, json!({"agent_def_ref": f.author}))?;
    println!("STAMP pause_tree agent=author answer={by_author}");
    assert_eq!(
        by_author["paused"]["agents"],
        json!([saved.to_hex()]),
        "A's tree pause switches off the definition A saved: {by_author}"
    );
    assert!(
        !enabled(&f, saved)?,
        "A's tree pause switched the saved definition off"
    );
    Ok(())
}
