//! An agent that reads through its own live read Grant keeps, in a context
//! pack filtered for it, the edge between two claims that Grant admits and
//! the neighbor that edge reaches, as it keeps each claim as a row. The
//! pack filter (`ScopedRead::filter_context_pack`) judged its rows under the
//! reader's held authority, but each row's edges and the reachability of
//! its neighbors under the agent key's own floor alone, which reads nothing:
//! the anchor stayed while its edge and its neighbor went (FIX-LIST
//! SCOPED-READ-UNKNOWN-AUTHORITY-CALLERS, part 2c). After the owner revokes
//! the Grant the filter keeps none of them.
//!
//! Public paths only: the embedded owner's door, `Vault::put_edge`,
//! `Vault::context_pack`, the agent's own `Vault::memory` handle and
//! `Vault::scoped_read` of its key.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test agent_grant_context_pack_edges`

use oneiron::memory::Memory;
use oneiron::registry::ENTITY_TYPE_CLAIM;
use oneiron::{ContextEntity, ContextPack, EdgeActorClass, EdgeKind, EntityId, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

/// The time the owner's claims say they were learned: fixed, so the test
/// reads no wall clock.
const RECORDED_AT: u64 = 1_700_000_000;

/// The anchor's words, which the neighbor's value does not share.
const ANCHOR_QUERY: &str = "harbour survey lantern";

/// Runs `verb` as `caller`, panicking with its refusal.
fn call(caller: &Memory<'_>, verb: &str, input: Value) -> Value {
    door::invoke(caller, verb, input).unwrap_or_else(|error| panic!("{verb}: {error}"))
}

/// The id of a written record in `answer` at `pointer`.
fn id_at(answer: &Value, pointer: &str) -> String {
    answer
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no id at {pointer}: {answer:#}"))
        .to_owned()
}

/// A vault this process owns with two of the owner's claims, `anchor`
/// supporting `peer`, and an identity agent holding a live read Grant over
/// every world, facet, band, audience and sensitivity. The vault closes
/// before its directory goes.
struct Fixture {
    vault: Vault,
    anchor: EntityId,
    peer: EntityId,
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
        let anchor = remember("The harbour survey needs a brass lantern.");
        let peer = remember("Thursday brings the tide tables.");
        vault
            .put_edge(&anchor, EdgeKind::Supports, &peer, 0.9)
            .expect("the owner's edge between the two claims");

        let agent = vault.new_entity_id().expect("an agent id");
        call(
            &owner,
            "vault.agents.create",
            json!({
                "agent_def_ref": agent.to_hex(),
                "definition": {
                    "agent_id": "pack-reader",
                    "desc": "an agent that reads context packs through the owner's read Grant",
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
            anchor,
            peer,
            agent,
            grant,
            _dir: dir,
        }
    }

    fn reader(&self) -> Memory<'_> {
        self.vault.memory(self.agent, EdgeActorClass::Agent)
    }

    fn revoke(&self) {
        let owner = door::owner(&self.vault).expect("the embedded owner");
        call(
            &owner,
            "vault.agents.grants.revoke",
            json!({"grant_ref": self.grant}),
        );
    }

    /// The anchor's pack as the vault assembles it before any reader's
    /// filter: claims only, one hop out, with or without each row's edges.
    fn assembled_pack(&self, include_edges: bool) -> ContextPack {
        let pack = self
            .vault
            .context_pack()
            .search_text(ANCHOR_QUERY, 10)
            .filter_types(&[ENTITY_TYPE_CLAIM])
            .include_edges(include_edges)
            .edge_hop(1)
            .max_neighbors(10)
            .run()
            .expect("the assembled pack");
        assert!(
            row(&pack.results, &self.anchor).is_some()
                && row(&pack.neighbors, &self.peer).is_some(),
            "FIXTURE: the walk finds the anchor and hydrates its peer before any filter: \
             results {:?}, neighbors {:?}",
            ids(&pack.results),
            ids(&pack.neighbors),
        );
        if include_edges {
            assert!(
                supports_peer(&pack, self),
                "FIXTURE: the assembled anchor carries its edge to the peer"
            );
        }
        pack
    }

    /// `pack` as the agent's own key filters it, on `Vault::scoped_read`.
    fn filtered_for_agent(&self, mut pack: ContextPack) -> ContextPack {
        let key = self.reader().read_key().expect("the agent's read key");
        self.vault
            .scoped_read(key)
            .filter_context_pack(&mut pack)
            .expect("the agent's pack filter");
        pack
    }

    /// The agent reads each claim on vault.get under its live Grant.
    fn assert_agent_reads_both_claims(&self) {
        let reader = self.reader();
        for claim in [self.anchor, self.peer] {
            let read = call(&reader, "vault.get", json!({"entity_ref": claim.to_hex()}));
            assert!(
                read.get("value").is_some_and(|value| !value.is_null()),
                "the live Grant admits the claim {claim:?} on vault.get: {read:#}"
            );
        }
    }
}

fn row<'a>(rows: &'a [ContextEntity], id: &EntityId) -> Option<&'a ContextEntity> {
    rows.iter().find(|row| row.id == *id)
}

fn ids(rows: &[ContextEntity]) -> Vec<EntityId> {
    rows.iter().map(|row| row.id).collect()
}

/// Whether `pack`'s anchor row carries its `Supports` edge to the peer.
fn supports_peer(pack: &ContextPack, fixture: &Fixture) -> bool {
    row(&pack.results, &fixture.anchor)
        .and_then(|anchor| anchor.edges.as_ref())
        .is_some_and(|edges| {
            edges
                .iter()
                .any(|edge| edge.kind == EdgeKind::Supports && edge.target == fixture.peer)
        })
}

#[test]
fn an_agents_pack_under_a_live_read_grant_keeps_the_anchors_edge_and_its_neighbor() {
    let fixture = Fixture::open();
    fixture.assert_agent_reads_both_claims();
    let assembled = fixture.assembled_pack(true);

    let pack = fixture.filtered_for_agent(assembled.clone());
    assert!(
        row(&pack.results, &fixture.anchor).is_some(),
        "the agent's filter keeps the anchor row under the live Grant: results {:?}",
        ids(&pack.results),
    );
    assert!(
        supports_peer(&pack, &fixture),
        "the live Grant admits both claims, yet the agent's pack drops the anchor's edge to \
         the peer: edges {:?}",
        row(&pack.results, &fixture.anchor).and_then(|anchor| anchor.edges.as_ref()),
    );
    assert!(
        row(&pack.neighbors, &fixture.peer).is_some(),
        "the live Grant admits both claims, yet the agent's pack drops the neighbor the \
         anchor's edge reaches: neighbors {:?}",
        ids(&pack.neighbors),
    );

    fixture.revoke();
    let revoked = fixture.filtered_for_agent(assembled);
    assert!(
        row(&revoked.results, &fixture.anchor).is_none()
            && row(&revoked.neighbors, &fixture.peer).is_none(),
        "the agent's pack still holds the claims after the revoke: results {:?}, neighbors {:?}",
        ids(&revoked.results),
        ids(&revoked.neighbors),
    );
}

#[test]
fn an_agents_pack_without_edges_under_a_live_read_grant_keeps_the_reachable_neighbor() {
    let fixture = Fixture::open();
    fixture.assert_agent_reads_both_claims();
    let assembled = fixture.assembled_pack(false);

    let pack = fixture.filtered_for_agent(assembled);
    assert!(
        row(&pack.results, &fixture.anchor).is_some(),
        "the agent's filter keeps the anchor row under the live Grant: results {:?}",
        ids(&pack.results),
    );
    assert!(
        row(&pack.neighbors, &fixture.peer).is_some(),
        "the live Grant admits both claims, yet the agent's pack finds the neighbor \
         unreachable from the anchor: neighbors {:?}",
        ids(&pack.neighbors),
    );
}
