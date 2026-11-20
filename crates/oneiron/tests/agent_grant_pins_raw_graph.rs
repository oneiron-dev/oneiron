//! An agent that reads through its own live read Grant sees what that Grant
//! admits, as it reads each row on vault.get, on two reads that judged their
//! rows under the agent key's own floor alone, which reads nothing:
//! - the manifest's pinned critical claims (`ScopedRead::manifest_pinned_refs`,
//!   the pin source of the context board and the server's context pack);
//! - the native raw graph reads on its own credential lane
//!   (`Memory::with_credential_raw_read`): `edges` both ways, `peers`,
//!   `ancestors` and `would_create_cycle`.
//!
//! Each answered nothing for such an agent (FIX-LIST
//! SCOPED-READ-UNKNOWN-AUTHORITY-CALLERS, part 2e). After the owner revokes
//! the Grant none of them reads the rows.
//!
//! Public paths only: the embedded owner's door, `Vault::put_edge`, the
//! agent's own `Vault::memory` handle and `Vault::scoped_read` of a reader's
//! key. The claims take a fixed time, so the test reads no wall clock.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test agent_grant_pins_raw_graph`

use oneiron::memory::Memory;
use oneiron::{EdgeActorClass, EdgeKind, EntityId, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

/// The time the owner's claims say they were learned: fixed, so the test
/// reads no wall clock.
const RECORDED_AT: u64 = 1_700_000_000;

/// A predicate in a class the shipped manifest declares critical (`health.`),
/// which the manifest's pins list.
const CRITICAL_PREDICATE: &str = "health.allergy";

/// A predicate no shipped rule names: the manifest never pins it.
const NOTE_PREDICATE: &str = "project.note";

/// Runs `verb` as `caller`, panicking with its refusal.
fn call(caller: &Memory<'_>, verb: &str, input: Value) -> Value {
    door::invoke(caller, verb, input).unwrap_or_else(|error| panic!("{verb}: {error}"))
}

/// The id of a written record in `answer` at `pointer`.
fn id_at(answer: &Value, pointer: &str) -> EntityId {
    let id = answer
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no id at {pointer}: {answer:#}"));
    EntityId::from_hex(id).expect("a record id in hex")
}

/// A vault this process owns with an identity agent holding a live read
/// Grant over every world, facet, band, audience and sensitivity. The vault
/// closes before its directory goes.
struct Fixture {
    vault: Vault,
    owner_id: EntityId,
    agent: EntityId,
    grant: String,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("fresh vault");
        oneiron_testkit::dreamer::attach_test_host(&vault).expect("the test host");
        let owner_id = vault.ensure_embedded_owner_actor().expect("the owner");
        let owner = door::owner(&vault).expect("the embedded owner");

        let agent = vault.new_entity_id().expect("an agent id");
        call(
            &owner,
            "vault.agents.create",
            json!({
                "agent_def_ref": agent.to_hex(),
                "definition": {
                    "agent_id": "pin-and-graph-reader",
                    "desc": "an agent that reads pins and the raw graph through the owner's read Grant",
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
            .unwrap_or_else(|| panic!("no grant_ref: {minted:#}"))
            .to_owned();
        Self {
            vault,
            owner_id,
            agent,
            grant,
            _dir: dir,
        }
    }

    fn owner(&self) -> Memory<'_> {
        door::owner(&self.vault).expect("the embedded owner")
    }

    fn reader(&self) -> Memory<'_> {
        self.vault.memory(self.agent, EdgeActorClass::Agent)
    }

    /// The owner remembers `value` under `predicate` about itself.
    fn remember(&self, predicate: &str, value: &str) -> EntityId {
        let remembered = call(
            &self.owner(),
            "vault.remember",
            json!({
                "predicate": predicate,
                "subject_ref": self.owner_id.to_hex(),
                "value": value,
                "confidence": 0.9,
                "source": "user_stated",
                "occurred_at": RECORDED_AT,
                "learned_at": RECORDED_AT,
            }),
        );
        id_at(&remembered, "/claim/id")
    }

    /// The agent reads `id` on vault.get under its live Grant.
    fn assert_agent_reads(&self, id: &EntityId) {
        let read = call(
            &self.reader(),
            "vault.get",
            json!({"entity_ref": id.to_hex()}),
        );
        assert!(
            read.get("value").is_some_and(|value| !value.is_null()),
            "FIXTURE: the live Grant admits {} on vault.get: {read:#}",
            id.to_hex()
        );
    }

    fn revoke(&self) {
        call(
            &self.owner(),
            "vault.agents.grants.revoke",
            json!({"grant_ref": self.grant}),
        );
    }
}

/// The manifest's pins `caller`'s key reads.
fn pinned_refs(vault: &Vault, caller: &Memory<'_>) -> Vec<String> {
    let key = caller.read_key().expect("the caller's read key");
    vault
        .scoped_read(key)
        .manifest_pinned_refs()
        .expect("the manifest's pins")
        .value
}

#[test]
fn an_agents_pins_under_a_live_read_grant_list_the_owners_critical_claim() {
    let fixture = Fixture::open();
    let owner = fixture.owner();
    let before = pinned_refs(&fixture.vault, &owner);
    let claim = fixture.remember(
        CRITICAL_PREDICATE,
        "The harbour pilot is allergic to peanuts.",
    );
    let owners = pinned_refs(&fixture.vault, &owner);
    let added: Vec<&String> = owners.iter().filter(|pin| !before.contains(pin)).collect();
    let [pin] = added.as_slice() else {
        panic!(
            "FIXTURE: the shipped manifest pins the owner's {CRITICAL_PREDICATE} claim once: before {before:?}, after {owners:?}"
        );
    };
    fixture.assert_agent_reads(&claim);

    let agents = pinned_refs(&fixture.vault, &fixture.reader());
    assert!(
        agents.contains(pin),
        "the live Grant admits the owner's critical claim, yet the agent's pins leave it out: {agents:?}"
    );

    fixture.revoke();
    let after = pinned_refs(&fixture.vault, &fixture.reader());
    assert!(
        !after.contains(pin),
        "the agent's pins still list the claim after the revoke: {after:?}"
    );
}

#[test]
fn an_agents_raw_graph_reads_under_a_live_read_grant_read_the_edge() {
    let fixture = Fixture::open();
    let source = fixture.remember(NOTE_PREDICATE, "The harbour survey needs the tide tables.");
    let target = fixture.remember(NOTE_PREDICATE, "The tide tables arrive on Thursday.");
    fixture
        .vault
        .put_edge(&source, EdgeKind::Supports, &target, 0.5)
        .expect("the owner's edge between the two claims");
    for id in [&source, &target] {
        fixture.assert_agent_reads(id);
    }
    // Whether `caller` reads the edge raw: out of the source, into the
    // target (an inbound edge names its source as its target), and the
    // target as the source's peer.
    let edge_read = |caller: &Memory<'_>| {
        caller.with_credential_raw_read(|raw| {
            let out = raw
                .edges(&source, true)?
                .iter()
                .any(|edge| edge.kind == EdgeKind::Supports && edge.target == target);
            let into = raw
                .edges(&target, false)?
                .iter()
                .any(|edge| edge.kind == EdgeKind::Supports && edge.target == source);
            let peer = raw
                .peers(&source, EdgeKind::Supports, None, true)?
                .contains(&target);
            Ok((out, into, peer))
        })
    };
    assert_eq!(
        edge_read(&fixture.owner()).expect("the owner's raw read"),
        (true, true, true),
        "FIXTURE: the owner reads its own edge raw"
    );

    let (out, into, peer) = edge_read(&fixture.reader()).expect("the agent's raw read");
    assert!(
        out,
        "the live Grant admits both claims, yet the agent's raw edges out of the source miss the edge"
    );
    assert!(
        into,
        "the live Grant admits both claims, yet the agent's raw edges into the target miss the edge"
    );
    assert!(
        peer,
        "the live Grant admits both claims, yet the agent's raw peers of the source miss the target"
    );

    fixture.revoke();
    if let Ok(after) = edge_read(&fixture.reader()) {
        assert_eq!(
            after,
            (false, false, false),
            "the agent still reads the edge raw after the revoke"
        );
    }
}

#[test]
fn an_agents_raw_ancestors_under_a_live_read_grant_walk_to_the_goal() {
    let fixture = Fixture::open();
    let owner = fixture.owner();
    let goal = id_at(
        &call(
            &owner,
            "vault.productivity.create",
            json!({"role": "goal", "label": "Survey the harbour"}),
        ),
        "/id_hex",
    );
    let milestone = id_at(
        &call(
            &owner,
            "vault.productivity.create",
            json!({"role": "milestone", "label": "Tide tables in", "parent_ref": goal.to_hex()}),
        ),
        "/id_hex",
    );
    for id in [&goal, &milestone] {
        fixture.assert_agent_reads(id);
    }
    // The milestone's ancestors as `caller` reads them, and whether filing
    // the goal under its own milestone would close a cycle.
    let walk = |caller: &Memory<'_>| {
        caller.with_credential_raw_read(|raw| {
            Ok((
                raw.ancestors(&milestone)?,
                raw.would_create_cycle(&goal, &milestone)?,
            ))
        })
    };
    assert_eq!(
        walk(&owner).expect("the owner's raw walk"),
        (vec![goal], true),
        "FIXTURE: the owner walks its own milestone to its goal"
    );

    let (ancestors, cyclic) = walk(&fixture.reader()).expect("the agent's raw walk");
    assert_eq!(
        ancestors,
        [goal],
        "the live Grant admits the milestone and its goal, yet the agent's raw ancestors of the milestone miss the goal"
    );
    assert!(
        cyclic,
        "the live Grant admits the milestone and its goal, yet the agent's raw walk finds no cycle in filing the goal under its milestone"
    );

    fixture.revoke();
    if let Ok((ancestors, cyclic)) = walk(&fixture.reader()) {
        assert!(
            ancestors.is_empty() && !cyclic,
            "the agent still walks the milestone raw after the revoke: {ancestors:?} {cyclic}"
        );
    }
}
