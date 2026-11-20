#![cfg(oneiron_test_support)]
//! [TIMELINE-SHELL-TWO-SNAPSHOT-CAP]: the core memory timeline route
//! (`GET /v1/core/memory/{id}/timeline`) shows a deleted record's shell only
//! while the snapshot it projects in still admits that shell.
//!
//! The route reads the timeline in one snapshot (`ScopedRead::memory_timeline`)
//! and projects it in a second. An identity agent holds two live read Grants
//! of the ASSET band: one over the Harbor world, where the deleted ASSET sat,
//! and one over the Orchard world. Only the Harbor Grant holds the shell, so
//! the timeline lists it. The owner revokes the Harbor Grant between the two
//! snapshots. The Orchard Grant keeps the ASSET band in the read's applied
//! scope, but it alone never held the shell's world (Engine ANSWER
//! GRANT-AGENT-DELETED-SHELLS = A: one Grant alone must hold it), so the
//! projection must show no shell: neither the deleted anchor nor a deleted
//! record behind a live anchor. The owner's own projection keeps the shell.
//!
//! Red on main: the projection skips a deleted record before any per-row
//! check, and the route shows its shell on the receipt's applied record types
//! alone, so the shell still shows its deletion metadata once.
//!
//! Public paths, plus two test doors: the owner's proof
//! (`oneiron::test_doors::steward::owner`) for the owner's worlds, and the
//! route's projection (`oneiron_server::test_doors::memory_timeline_projection`),
//! called on a timeline read before the revoke. The owner's acts are public
//! verbs (`oneiron::verbs::invoke`); the ASSETs go in through `Vault::batch`
//! and out through `Vault::delete_entity`, a soft delete that keeps the shell.
//! Fixed times, so the test reads no wall clock.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! timeline_shell_projection_recheck`.

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::memory::Memory;
use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::test_doors::steward::owner as owner_proof;
use oneiron::{EdgeActorClass, EdgeKind, EntityId, MemoryTimelineRecordState, TimeRange, Vault};
use oneiron::{MemoryTimeline, VaultConfig};
use oneiron_server::test_doors::memory_timeline_projection::project_timeline;
use serde_json::{Value, json};

/// The time the older fixture rows say they were written.
const WRITTEN_AT: u64 = 1_700_000_000;

/// The time the newer ASSET, which supersedes the older one, was written.
const REWRITTEN_AT: u64 = WRITTEN_AT + 60;

/// What a timeline read that lists no record lists.
const NOTHING_READ: [(EntityId, MemoryTimelineRecordState); 0] = [];

/// What a projected timeline answer that shows no record lists.
const NOTHING_SHOWN: [(String, String); 0] = [];

/// Runs `verb` as `caller`, panicking with its refusal.
fn call(caller: &Memory<'_>, verb: &str, input: Value) -> Value {
    oneiron::verbs::invoke(caller, verb, input).unwrap_or_else(|error| panic!("{verb}: {error}"))
}

/// The id at `pointer` in `answer`.
fn id_at(answer: &Value, pointer: &str) -> String {
    answer
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no id at {pointer}: {answer:#}"))
        .to_owned()
}

/// A read Grant's Scope over the one world `world`, every facet, audience
/// and sensitivity, for ASSET rows alone.
fn asset_read_scope(world: EntityId) -> Value {
    json!({
        "worlds": {"kind": "some", "values": [world.to_hex()]},
        "facets": {"kind": "all"},
        "bands": {"kind": "some", "values": [ENTITY_TYPE_ASSET]},
        "audience": {"kind": "all"},
        "verbs": {"kind": "some", "values": ["read"]},
        "sensitivity": {"kind": "all"},
    })
}

/// Each record a projected timeline answer lists, with its state.
fn listed(answer: &Value) -> Vec<(String, String)> {
    answer["records"]
        .as_array()
        .unwrap_or_else(|| panic!("a timeline answer lists its records: {answer:#}"))
        .iter()
        .map(|record| {
            (
                record["id"].as_str().unwrap_or_default().to_owned(),
                record["state"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

/// `id` as a projected answer lists it, in `state`.
fn row(id: EntityId, state: &str) -> (String, String) {
    (id.to_hex(), state.to_owned())
}

/// A vault this process owns with an identity agent holding two live read
/// Grants of the ASSET band, one over each of the owner's two worlds. The
/// vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    harbor: EntityId,
    orchard: EntityId,
    harbor_grant: String,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("fresh vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("FIXTURE: the install profile");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("FIXTURE: the host root slip");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("FIXTURE: the owner");
        let agent = vault.new_entity_id().expect("an agent id");
        call(
            &vault.memory(owner, EdgeActorClass::Human),
            "vault.agents.create",
            json!({
                "agent_def_ref": agent.to_hex(),
                "definition": {
                    "agent_id": "timeline-reader",
                    "desc": "an agent that reads timelines through the owner's read Grants",
                    "version": "1",
                },
            }),
        );
        let proof = owner_proof(&vault).expect("FIXTURE: the owner's proof");
        let harbor = vault
            .create_world(&proof, "Harbor", WRITTEN_AT)
            .expect("FIXTURE: the owner creates the Harbor world");
        let orchard = vault
            .create_world(&proof, "Orchard", WRITTEN_AT)
            .expect("FIXTURE: the owner creates the Orchard world");
        let mut fixture = Self {
            vault,
            owner,
            agent,
            harbor,
            orchard,
            harbor_grant: String::new(),
            _dir: dir,
        };
        fixture.harbor_grant = fixture.mint(harbor);
        fixture.mint(orchard);
        fixture
    }

    fn owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// The owner mints the agent a read Grant over ASSET rows in `world`;
    /// its id.
    fn mint(&self, world: EntityId) -> String {
        let minted = call(
            &self.owner(),
            "vault.agents.grants.mint",
            json!({"agent": self.agent.to_hex(), "authority_scope": asset_read_scope(world)}),
        );
        assert_eq!(
            minted.pointer("/grant/confers"),
            Some(&Value::Bool(true)),
            "FIXTURE: the owner's read Grant is live: {minted:#}"
        );
        id_at(&minted, "/grant/grant_ref")
    }

    /// The owner revokes the agent's Grant over the Harbor world, the only one
    /// that holds a Harbor shell.
    fn revoke_the_harbor_grant(&self) {
        call(
            &self.owner(),
            "vault.agents.grants.revoke",
            json!({"grant_ref": self.harbor_grant}),
        );
    }

    /// The owner's ASSET in `world`, written at `at`, superseding each of
    /// `older`.
    fn asset_in(&self, world: EntityId, at: u64, older: &[EntityId]) -> EntityId {
        let asset = self.vault.new_entity_id().expect("an ASSET id");
        let mut batch = self
            .vault
            .batch()
            .put(
                &asset,
                ENTITY_TYPE_ASSET,
                TimeRange { start: at, end: at },
                at,
                b"harbor tide tables, kept as an asset",
            )
            .edge(&asset, EdgeKind::InWorld, &world, 1.0);
        for older in older {
            batch = batch.edge(&asset, EdgeKind::Supersedes, older, 1.0);
        }
        batch.commit().expect("FIXTURE: the owner stores an ASSET");
        asset
    }

    /// The owner soft-deletes `id`, which keeps its shell.
    fn delete(&self, id: EntityId) {
        assert!(
            self.vault
                .delete_entity(&id)
                .expect("FIXTURE: the owner deletes the record"),
            "FIXTURE: the record existed before its delete"
        );
    }

    fn agent(&self) -> Memory<'_> {
        self.vault.memory(self.agent, EdgeActorClass::Agent)
    }

    /// `reader`'s memory timeline of `anchor`, as the route reads it before
    /// it projects it.
    fn read(
        &self,
        reader: &Memory<'_>,
        anchor: EntityId,
    ) -> oneiron::claim::ScopedReadResult<MemoryTimeline> {
        let key = reader.read_key().expect("the reader's read key");
        self.vault
            .scoped_read(key)
            .memory_timeline(&anchor)
            .expect("the reader's memory timeline")
    }

    /// The route's projection, now, of `timeline`, which `reader` read
    /// before.
    fn project(
        &self,
        reader: &Memory<'_>,
        timeline: oneiron::claim::ScopedReadResult<MemoryTimeline>,
    ) -> Value {
        let key = reader.read_key().expect("the reader's read key");
        project_timeline(&self.vault.scoped_read(key), timeline)
            .unwrap_or_else(|error| panic!("the timeline projection: {error}"))
    }
}

/// The states a timeline read lists, by record.
fn states(
    timeline: &oneiron::claim::ScopedReadResult<MemoryTimeline>,
) -> Vec<(EntityId, MemoryTimelineRecordState)> {
    let mut states: Vec<_> = timeline
        .value
        .records
        .iter()
        .map(|record| (record.id, record.state))
        .collect();
    states.sort_by_key(|(id, _)| *id);
    states
}

#[test]
fn a_deleted_anchors_shell_goes_once_its_only_grant_is_revoked_before_the_projection() {
    let fixture = Fixture::open();
    let agent = fixture.agent();
    let asset = fixture.asset_in(fixture.harbor, WRITTEN_AT, &[]);
    fixture.delete(asset);
    assert_eq!(
        states(&fixture.read(&agent, asset)),
        [(asset, MemoryTimelineRecordState::Deleted)],
        "FIXTURE: the agent's Harbor Grant alone holds the deleted ASSET, so its timeline \
         lists the shell"
    );
    assert_eq!(
        listed(&fixture.project(&agent, fixture.read(&agent, asset))),
        [row(asset, "deleted")],
        "FIXTURE: the route's projection shows the shell while the Harbor Grant is live"
    );

    let timeline = fixture.read(&agent, asset);
    fixture.revoke_the_harbor_grant();
    assert_eq!(
        states(&fixture.read(&agent, asset)),
        NOTHING_READ,
        "FIXTURE: once the owner revoked the Harbor Grant, the Orchard Grant alone shows no \
         Harbor shell on a fresh read"
    );
    let answer = fixture.project(&agent, timeline);
    assert_eq!(
        listed(&answer),
        NOTHING_SHOWN,
        "the owner revoked the only Grant that held the deleted ASSET between the timeline's \
         read and its projection, yet the route still shows the shell: {answer:#}"
    );
}

#[test]
fn a_linked_shell_goes_once_its_only_grant_is_revoked_before_the_projection() {
    let fixture = Fixture::open();
    let agent = fixture.agent();
    let older = fixture.asset_in(fixture.harbor, WRITTEN_AT, &[]);
    let newer = fixture.asset_in(fixture.orchard, REWRITTEN_AT, &[older]);
    fixture.delete(older);
    let mut both = vec![
        (older, MemoryTimelineRecordState::Deleted),
        (newer, MemoryTimelineRecordState::Live),
    ];
    both.sort_by_key(|(id, _)| *id);
    assert_eq!(
        states(&fixture.read(&agent, newer)),
        both,
        "FIXTURE: the Orchard Grant reads the live ASSET and the Harbor Grant alone holds the \
         deleted one it supersedes, so the agent's timeline lists both"
    );
    let mut shown = listed(&fixture.project(&agent, fixture.read(&agent, newer)));
    shown.sort();
    let mut expected = vec![row(older, "deleted"), row(newer, "live")];
    expected.sort();
    assert_eq!(
        shown, expected,
        "FIXTURE: the route's projection shows the live ASSET and the shell while the Harbor \
         Grant is live"
    );

    let timeline = fixture.read(&agent, newer);
    fixture.revoke_the_harbor_grant();
    assert_eq!(
        states(&fixture.read(&agent, newer)),
        [(newer, MemoryTimelineRecordState::Live)],
        "FIXTURE: once the owner revoked the Harbor Grant, a fresh read lists the live Orchard \
         ASSET alone"
    );
    let answer = fixture.project(&agent, timeline);
    assert_eq!(
        listed(&answer),
        [row(newer, "live")],
        "the owner revoked the only Grant that held the deleted ASSET behind a live anchor \
         between the timeline's read and its projection, yet the route still shows its shell: \
         {answer:#}"
    );
}

#[test]
fn the_owners_projection_keeps_the_shell_after_the_agents_grant_goes() {
    let fixture = Fixture::open();
    let owner = fixture.owner();
    let asset = fixture.asset_in(fixture.harbor, WRITTEN_AT, &[]);
    fixture.delete(asset);
    let timeline = fixture.read(&owner, asset);
    assert_eq!(
        states(&timeline),
        [(asset, MemoryTimelineRecordState::Deleted)],
        "FIXTURE: the owner's own timeline lists the deleted ASSET's shell"
    );
    fixture.revoke_the_harbor_grant();
    let answer = fixture.project(&owner, timeline);
    assert_eq!(
        listed(&answer),
        [row(asset, "deleted")],
        "the owner's own timeline projection no longer shows the deleted ASSET's shell once \
         the owner revoked a Grant of the agent's: {answer:#}"
    );
}

/// Review round 1 of #10031, P1 1: an anchor the projection refuses ends the
/// read with its own count alone, so the 404 receipt cannot size its chain.
/// Two live Orchard ASSETs supersede the deleted Harbor one; once the Harbor
/// Grant goes, the agent can read neither the shell nor its count, and the
/// two linked bodies it still reads count nothing either.
#[test]
fn a_refused_deleted_anchor_counts_none_of_its_linked_records() {
    let fixture = Fixture::open();
    let agent = fixture.agent();
    let older = fixture.asset_in(fixture.harbor, WRITTEN_AT, &[]);
    let first = fixture.asset_in(fixture.orchard, REWRITTEN_AT, &[older]);
    let second = fixture.asset_in(fixture.orchard, REWRITTEN_AT + 60, &[older]);
    fixture.delete(older);
    let mut chain = vec![
        (older, MemoryTimelineRecordState::Deleted),
        (first, MemoryTimelineRecordState::Live),
        (second, MemoryTimelineRecordState::Live),
    ];
    chain.sort_by_key(|(id, _)| *id);
    let timeline = fixture.read(&agent, older);
    assert_eq!(
        states(&timeline),
        chain,
        "FIXTURE: the Harbor Grant alone holds the deleted anchor and the Orchard Grant reads \
         both live ASSETs that supersede it, so the agent's timeline lists all three"
    );

    fixture.revoke_the_harbor_grant();
    let answer = fixture.project(&agent, timeline);
    assert_eq!(
        listed(&answer),
        NOTHING_SHOWN,
        "the owner revoked the only Grant that held the deleted anchor between the timeline's \
         read and its projection, yet the route still shows its timeline: {answer:#}"
    );
    assert_eq!(
        answer["narrowing"]["suppressed_count"],
        json!(0),
        "the projection refused the anchor, which the agent can no longer read at all, yet the \
         receipt counts withheld rows of its chain: {answer:#}"
    );
}
