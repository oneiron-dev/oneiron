//! An agent that reads through its own live read Grant sees an edge whose two
//! endpoints that Grant admits on the graph reads, as it reads each endpoint
//! on vault.get: vault.neighbors in both directions, `ScopedRead::edges_out`
//! and vault.productivity.tree. Their anchor and peer checks took the agent
//! key's own floor alone, which reads nothing, so each answered no edge
//! (FIX-LIST SCOPED-READ-UNKNOWN-AUTHORITY-CALLERS, part 2a). vault.neighbors
//! also reports that Grant's reach in its receipt, not deny_all. After the
//! owner revokes the Grant none of them reads the edge.
//!
//! Public paths only: the embedded owner's door, `Vault::put_edge`, the
//! agent's own `Vault::memory` handle and `Vault::scoped_read` of its key.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test agent_grant_graph_reads`

use oneiron::memory::Memory;
use oneiron::{EdgeActorClass, EdgeKind, EntityId, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

/// The time the owner's claims say they were learned: fixed, so the test
/// reads no wall clock.
const RECORDED_AT: u64 = 1_700_000_000;

/// Runs `verb` as `caller`, panicking with its refusal.
fn call(caller: &Memory<'_>, verb: &str, input: Value) -> Value {
    door::invoke(caller, verb, input).unwrap_or_else(|error| panic!("{verb}: {error}"))
}

/// Whether the receipt list `list` names `entry`.
fn lists(list: &Value, entry: &str) -> bool {
    list.as_array()
        .is_some_and(|entries| entries.iter().any(|named| named == entry))
}

/// The id of a written record in `answer` at `pointer`.
fn id_at(answer: &Value, pointer: &str) -> String {
    answer
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no id at {pointer}: {answer:#}"))
        .to_owned()
}

/// A vault this process owns with two of the owner's claims, `source`
/// supporting `target`, and an identity agent holding a live read Grant
/// over every world, facet, band, audience and sensitivity. The vault closes
/// before its directory goes.
struct Fixture {
    vault: Vault,
    source: EntityId,
    target: EntityId,
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
        let remember = |value: &str| {
            let remembered = call(
                &owner,
                "vault.remember",
                json!({
                    "predicate": "project.note",
                    "subject_ref": owner_id.to_hex(),
                    "value": value,
                    "confidence": 0.9,
                    "source": "user_stated",
                    "occurred_at": RECORDED_AT,
                    "learned_at": RECORDED_AT,
                }),
            );
            EntityId::from_hex(&id_at(&remembered, "/claim/id")).expect("a claim id in hex")
        };
        let source = remember("The harbour survey needs the tide tables.");
        let target = remember("The tide tables arrive on Thursday.");
        vault
            .put_edge(&source, EdgeKind::Supports, &target, 0.5)
            .expect("the owner's edge between the two claims");

        let agent = vault.new_entity_id().expect("an agent id");
        call(
            &owner,
            "vault.agents.create",
            json!({
                "agent_def_ref": agent.to_hex(),
                "definition": {
                    "agent_id": "graph-reader",
                    "desc": "an agent that reads the graph through the owner's read Grant",
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
        let grant = id_at(&minted, "/grant/grant_ref");
        Self {
            vault,
            source,
            target,
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

    fn revoke(&self) {
        call(
            &self.owner(),
            "vault.agents.grants.revoke",
            json!({"grant_ref": self.grant}),
        );
    }
}

/// The hit in a vault.neighbors `answer` whose peer is `peer`, if any.
fn neighbor<'a>(answer: &'a Value, peer: &EntityId) -> Option<&'a Value> {
    let peer = peer.to_hex();
    answer
        .pointer("/value")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("vault.neighbors answered no hit list: {answer:#}"))
        .iter()
        .find(|hit| {
            [hit.get("short_id"), hit.pointer("/record/id")]
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .any(|id| id.eq_ignore_ascii_case(&peer))
        })
}

fn neighbors_of(caller: &Memory<'_>, anchor: &EntityId) -> Result<Value, String> {
    door::invoke(
        caller,
        "vault.neighbors",
        json!({
            "entity_ref": anchor.to_hex(),
            "opts": {"edge_kind": "supports", "limit": 8},
        }),
    )
    .map_err(|error| error.to_string())
}

#[test]
fn an_agents_neighbors_under_a_live_read_grant_list_the_edge_both_ways() {
    let fixture = Fixture::open();
    let owners = neighbors_of(&fixture.owner(), &fixture.source).expect("the owner's neighbors");
    assert!(
        neighbor(&owners, &fixture.target).is_some(),
        "the owner reads its own edge: {owners:#}"
    );
    let reader = fixture.reader();
    for end in [fixture.source, fixture.target] {
        let read = call(&reader, "vault.get", json!({"entity_ref": end.to_hex()}));
        assert!(
            read.get("value").is_some_and(|value| !value.is_null()),
            "the live Grant admits the endpoint {end:?} on vault.get: {read:#}"
        );
    }

    let out = neighbors_of(&reader, &fixture.source).expect("the agent's neighbors");
    let hit = neighbor(&out, &fixture.target).unwrap_or_else(|| {
        panic!("the live Grant admits both endpoints, yet the edge is not a neighbor: {out:#}")
    });
    assert_eq!(hit["edge_kind"], "supports", "the edge's kind: {hit:#}");
    assert_eq!(
        hit["direction"], "out",
        "the edge leaves the anchor: {hit:#}"
    );
    let narrowing = &out["narrowing"];
    for scope in ["requested", "actor_ceiling", "applied"] {
        assert_eq!(
            narrowing[scope]["deny_all"], false,
            "the {scope} scope denies all under the live Grant: {narrowing:#}"
        );
    }
    for list in ["narrowed_axes", "replan_hint"] {
        assert!(
            !lists(&narrowing[list], "deny_all"),
            "{list} names deny_all under the live Grant: {narrowing:#}"
        );
    }
    let into = neighbors_of(&reader, &fixture.target).expect("the agent's inbound neighbors");
    let hit = neighbor(&into, &fixture.source)
        .unwrap_or_else(|| panic!("the inbound edge is not a neighbor of its target: {into:#}"));
    assert_eq!(
        hit["direction"], "in",
        "the edge reaches the anchor: {hit:#}"
    );

    fixture.revoke();
    for (anchor, peer) in [
        (fixture.source, fixture.target),
        (fixture.target, fixture.source),
    ] {
        if let Ok(after) = neighbors_of(&reader, &anchor) {
            assert!(
                neighbor(&after, &peer).is_none(),
                "the agent still reads the edge after the revoke: {after:#}"
            );
        }
    }
}

#[test]
fn an_agents_edges_out_under_a_live_read_grant_list_the_edge() {
    let fixture = Fixture::open();
    let reader = fixture.reader();
    let edges_to_target = || {
        let key = reader.read_key().expect("the agent's read key");
        let read = fixture
            .vault
            .scoped_read(key)
            .edges_out(&fixture.source)
            .expect("the agent's edges_out");
        read.value.map(|edges| {
            edges
                .iter()
                .filter(|edge| edge.kind == EdgeKind::Supports && edge.target == fixture.target)
                .count()
        })
    };
    assert_eq!(
        edges_to_target(),
        Some(1),
        "the live Grant admits the centre and its peer, yet edges_out lists no edge to it"
    );
    fixture.revoke();
    assert!(
        edges_to_target().is_none_or(|count| count == 0),
        "edges_out still lists the edge after the revoke"
    );
}

#[test]
fn an_agents_productivity_tree_under_a_live_read_grant_reads_the_child() {
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
            json!({"role": "milestone", "label": "Tide tables in", "parent_ref": goal}),
        ),
        "/id_hex",
    );
    let reader = fixture.reader();
    for task in [&goal, &milestone] {
        let read = call(&reader, "vault.get", json!({"entity_ref": task}));
        assert!(
            read.get("value").is_some_and(|value| !value.is_null()),
            "the live Grant admits the TASK {task} on vault.get: {read:#}"
        );
    }
    let tree = |caller: &Memory<'_>| {
        door::invoke(
            caller,
            "vault.productivity.tree",
            json!({"root_ref": goal, "max_depth": 1}),
        )
        .map_err(|error| error.to_string())
    };
    let nodes = |answer: &Value| -> Vec<String> {
        answer
            .pointer("/value/nodes")
            .and_then(Value::as_array)
            .map(|nodes| {
                nodes
                    .iter()
                    .filter_map(|node| node["id_hex"].as_str().map(str::to_ascii_lowercase))
                    .collect()
            })
            .unwrap_or_default()
    };
    let owners = tree(&owner).expect("the owner's tree");
    assert_eq!(
        nodes(&owners),
        [goal.to_ascii_lowercase(), milestone.to_ascii_lowercase()],
        "the owner reads its own tree: {owners:#}"
    );
    let read = tree(&reader).expect("the agent's tree");
    assert_eq!(
        nodes(&read),
        [goal.to_ascii_lowercase(), milestone.to_ascii_lowercase()],
        "the live Grant admits the root and its child, yet the tree misses them: {read:#}"
    );

    fixture.revoke();
    if let Ok(after) = tree(&reader) {
        assert!(
            nodes(&after).is_empty(),
            "the agent still reads the tree after the revoke: {after:#}"
        );
    }
}
