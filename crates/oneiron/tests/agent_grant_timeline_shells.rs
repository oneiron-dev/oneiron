//! An agent that reads through its own live read Grant sees the shell a
//! deleted record leaves on its memory timeline (its deleted state and
//! deletion metadata, never a body) when ONE of its live Grants alone holds
//! the shell's proved world, its facet and its record type (Engine ANSWER
//! GRANT-AGENT-DELETED-SHELLS = A). The timeline judged a shell under the
//! agent key's own floor alone, which reads nothing, so the agent saw no
//! shell of a record the same Grant let it read while it lived (FIX-LIST
//! GRANT-RECEIPT-OTHER-READ-LANES, part 5).
//!
//! Two Grants never combine: Grants that hold the shell only together show
//! nothing. A shell that proves no single world reads as if it sat anywhere,
//! so it shows only under a Grant holding every world and every facet. A
//! revoked Grant shows no shell.
//!
//! The record is an ASSET: it carries a birth facet, and its world edges and
//! its `facet_of` edge outlive its body, so its shell still proves where it
//! sat. Public paths only: the embedded owner's door, `Vault::put_entity`
//! and `Vault::batch` for the owner's ASSETs, `Vault::delete_entity` for a
//! soft delete that keeps the shell, `Vault::create_world` and
//! `Vault::create_facet` under the owner's proof (the cfg test door
//! `oneiron::test_doors::steward::owner`), the agent's own `Vault::memory`
//! handle and `ScopedRead::memory_timeline` on its read key. Fixed times, so
//! the test reads no wall clock.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test agent_grant_timeline_shells`
#![cfg(oneiron_test_support)]

use oneiron::memory::Memory;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM};
use oneiron::test_doors::steward::owner as owner_proof;
use oneiron::{
    EdgeActorClass, EdgeKind, EntityId, MemoryTimelineRecordState, TimeRange, Vault, VaultConfig,
};
use oneiron_testkit::door;
use serde_json::{Value, json};

/// The time each fixture row says it was written.
const WRITTEN_AT: u64 = 1_700_000_000;

/// What a timeline that shows no record lists.
const NOTHING: [(EntityId, MemoryTimelineRecordState); 0] = [];

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

/// A Grant axis that holds everything.
fn all() -> Value {
    json!({"kind": "all"})
}

/// A Grant axis that holds `values` alone.
fn some(values: &[Value]) -> Value {
    json!({"kind": "some", "values": values})
}

/// `id` as a Grant axis value.
fn named(id: EntityId) -> Value {
    Value::String(id.to_hex())
}

/// A read Grant's Scope over `worlds`, `facets` and `bands`, every audience
/// and sensitivity.
fn read_scope(worlds: Value, facets: Value, bands: Value) -> Value {
    json!({
        "worlds": worlds,
        "facets": facets,
        "bands": bands,
        "audience": {"kind": "all"},
        "verbs": {"kind": "some", "values": ["read"]},
        "sensitivity": {"kind": "all"},
    })
}

/// A vault this process owns with an identity agent that holds no Grant
/// yet, and two worlds of the owner's. The vault closes before its
/// directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    harbor: EntityId,
    orchard: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("fresh vault");
        oneiron_testkit::dreamer::attach_test_host(&vault).expect("the test host");
        let owner = vault.ensure_embedded_owner_actor().expect("the owner");
        let agent = vault.new_entity_id().expect("an agent id");
        call(
            &door::owner(&vault).expect("the embedded owner"),
            "vault.agents.create",
            json!({
                "agent_def_ref": agent.to_hex(),
                "definition": {
                    "agent_id": "shell-reader",
                    "desc": "an agent that reads deleted records' shells through the owner's Grant",
                    "version": "1",
                },
            }),
        );
        let proof = owner_proof(&vault).expect("the owner's proof");
        let harbor = vault
            .create_world(&proof, "Harbor", WRITTEN_AT)
            .expect("FIXTURE: the owner creates the Harbor world");
        let orchard = vault
            .create_world(&proof, "Orchard", WRITTEN_AT)
            .expect("FIXTURE: the owner creates the Orchard world");
        Self {
            vault,
            owner,
            agent,
            harbor,
            orchard,
            _dir: dir,
        }
    }

    fn owner(&self) -> Memory<'_> {
        door::owner(&self.vault).expect("the embedded owner")
    }

    fn reader(&self) -> Memory<'_> {
        self.vault.memory(self.agent, EdgeActorClass::Agent)
    }

    /// The owner mints the agent a read Grant of `scope`; its id.
    fn mint(&self, scope: Value) -> String {
        let minted = call(
            &self.owner(),
            "vault.agents.grants.mint",
            json!({"agent": self.agent.to_hex(), "authority_scope": scope}),
        );
        assert_eq!(
            minted.pointer("/grant/confers"),
            Some(&Value::Bool(true)),
            "FIXTURE: the owner's read Grant is live: {minted:#}"
        );
        id_at(&minted, "/grant/grant_ref")
    }

    fn revoke(&self, grant: &str) {
        call(
            &self.owner(),
            "vault.agents.grants.revoke",
            json!({"grant_ref": grant}),
        );
    }

    /// A facet of the owner's that no fixture row sits in.
    fn other_facet(&self) -> EntityId {
        let proof = owner_proof(&self.vault).expect("the owner's proof");
        self.vault
            .create_facet(&proof, self.owner, "Elsewhere", WRITTEN_AT)
            .expect("FIXTURE: the owner creates a second facet")
    }

    /// The owner's ASSET, placed in each of `worlds` by its own `in_world`
    /// edge (none: base reality), and the one facet it was born in.
    fn asset_in(&self, worlds: &[EntityId]) -> (EntityId, EntityId) {
        let asset = self.vault.new_entity_id().expect("an ASSET id");
        let mut batch = self.vault.batch().put(
            &asset,
            ENTITY_TYPE_ASSET,
            TimeRange {
                start: WRITTEN_AT,
                end: WRITTEN_AT,
            },
            WRITTEN_AT,
            b"harbor tide tables, kept as an asset",
        );
        for world in worlds {
            batch = batch.edge(&asset, EdgeKind::InWorld, world, 1.0);
        }
        batch.commit().expect("FIXTURE: the owner stores an ASSET");
        let facets: Vec<EntityId> = self
            .vault
            .edges_out(&asset)
            .expect("the ASSET's edges")
            .iter()
            .filter(|edge| edge.kind == EdgeKind::FacetOf)
            .map(|edge| edge.target)
            .collect();
        let [facet] = facets.as_slice() else {
            panic!("FIXTURE: the owner's ASSET carries one facet_of edge: {facets:?}");
        };
        (asset, *facet)
    }

    /// The owner soft-deletes `id`, which keeps its shell, and the owner's
    /// own timeline shows that shell.
    fn delete(&self, id: EntityId) {
        assert!(
            self.vault
                .delete_entity(&id)
                .expect("FIXTURE: the owner deletes the record"),
            "FIXTURE: the record existed before its delete"
        );
        assert_eq!(
            self.timeline(&self.owner(), id),
            [(id, MemoryTimelineRecordState::Deleted)],
            "FIXTURE: the owner's own timeline shows the deleted record's shell"
        );
    }

    /// Each record `reader`'s memory timeline of `anchor` shows, with its
    /// state.
    fn timeline(
        &self,
        reader: &Memory<'_>,
        anchor: EntityId,
    ) -> Vec<(EntityId, MemoryTimelineRecordState)> {
        let key = reader.read_key().expect("the reader's read key");
        self.vault
            .scoped_read(key)
            .memory_timeline(&anchor)
            .expect("the reader's memory timeline")
            .value
            .records
            .iter()
            .map(|record| (record.id, record.state))
            .collect()
    }
}

#[test]
fn one_live_grant_over_a_deleted_assets_world_facet_and_type_shows_its_shell() {
    let fixture = Fixture::open();
    let (asset, facet) = fixture.asset_in(&[fixture.harbor]);
    let grant = fixture.mint(read_scope(
        some(&[named(fixture.harbor)]),
        some(&[named(facet)]),
        some(&[json!(ENTITY_TYPE_ASSET)]),
    ));
    let reader = fixture.reader();
    assert_eq!(
        fixture.timeline(&reader, asset),
        [(asset, MemoryTimelineRecordState::Live)],
        "FIXTURE: the live Grant reads the owner's live ASSET on the agent's timeline"
    );

    fixture.delete(asset);
    assert_eq!(
        fixture.timeline(&reader, asset),
        [(asset, MemoryTimelineRecordState::Deleted)],
        "one live Grant holds the deleted ASSET's world, facet and type, yet the agent's \
         timeline shows no shell of it"
    );

    fixture.revoke(&grant);
    assert_eq!(
        fixture.timeline(&reader, asset),
        NOTHING,
        "the agent still sees the shell after the owner revoked its only Grant"
    );
}

#[test]
fn grants_that_hold_a_shell_only_together_show_nothing() {
    let fixture = Fixture::open();
    let (asset, facet) = fixture.asset_in(&[fixture.harbor]);
    let other_facet = fixture.other_facet();
    let asset_band = some(&[json!(ENTITY_TYPE_ASSET)]);
    // Each misses one axis the other two hold: the world, the type, the
    // facet. Joined, they hold all three.
    fixture.mint(read_scope(some(&[named(fixture.orchard)]), all(), all()));
    fixture.mint(read_scope(
        some(&[named(fixture.harbor)]),
        all(),
        some(&[json!(ENTITY_TYPE_CLAIM)]),
    ));
    fixture.mint(read_scope(
        some(&[named(fixture.harbor)]),
        some(&[named(other_facet)]),
        asset_band.clone(),
    ));
    fixture.delete(asset);
    let reader = fixture.reader();
    assert_eq!(
        fixture.timeline(&reader, asset),
        NOTHING,
        "three Grants that each miss the shell's world, type or facet show it together"
    );

    fixture.mint(read_scope(
        some(&[named(fixture.harbor)]),
        some(&[named(facet)]),
        asset_band,
    ));
    assert_eq!(
        fixture.timeline(&reader, asset),
        [(asset, MemoryTimelineRecordState::Deleted)],
        "a fourth Grant alone holds the deleted ASSET's world, facet and type, yet the \
         agent's timeline shows no shell of it"
    );
}

#[test]
fn a_shell_that_proves_no_world_shows_only_under_a_grant_over_every_world_and_facet() {
    let fixture = Fixture::open();
    // In two worlds and not in base reality: no single world to prove.
    let (asset, facet) = fixture.asset_in(&[fixture.harbor, fixture.orchard]);
    let asset_band = some(&[json!(ENTITY_TYPE_ASSET)]);
    fixture.mint(read_scope(
        some(&[named(fixture.harbor), named(fixture.orchard)]),
        all(),
        asset_band.clone(),
    ));
    fixture.mint(read_scope(all(), some(&[named(facet)]), asset_band.clone()));
    fixture.delete(asset);
    let reader = fixture.reader();
    assert_eq!(
        fixture.timeline(&reader, asset),
        NOTHING,
        "a shell in no single world shows under Grants that miss a world or a facet"
    );

    let grant = fixture.mint(read_scope(all(), all(), asset_band));
    assert_eq!(
        fixture.timeline(&reader, asset),
        [(asset, MemoryTimelineRecordState::Deleted)],
        "a Grant over every world and facet holds the shell in no single world, yet the \
         agent's timeline shows no shell of it"
    );
    fixture.revoke(&grant);
    assert_eq!(
        fixture.timeline(&reader, asset),
        NOTHING,
        "the agent still sees the shell after the owner revoked the Grant that showed it"
    );
}
