// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The world-access tiers are local authority (ARCH-0067 #phasing; RULING
//! L2-53-CEILING, 14 Nov 2026).
//!
//! An owner's ALLOWED-SET grant and an agent's DEFAULT-SUBSET stand only on
//! the node that wrote them. A replicated put skips source trust, so a grant
//! that arrived by sync used to set the worlds of an agent that no owner on
//! the receiving node had granted (census L2-53). No sync door ships either
//! tier now, and every door that replays a peer's rows drops them, so a
//! node's fold reads only the rows it wrote.
//!
//! Rows cross the real Loro delta path between two `Vault`s
//! (`reverse_rematerialize`, the window export door, Observer B), or the
//! explicit-tier replay door. The whole-vault import's routing (a cfg door)
//! keeps both tiers as archive data. Each row lands on its node through a cfg
//! door: the shipped manifest parks an owner's Approved grant with no owner
//! proof at the criticality floor, and no production door writes one yet
//! (census L2-56). A same-vault peer's MACHINE claim history comes from a
//! real write on a second vault, through a cfg door that lists its control
//! rows (`test_doors::machine_history`).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test world_access_local_authority`.
#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]

#[path = "it_sync/sync_harness/mod.rs"]
mod sync_harness;

use loro::LoroDoc;
use oneiron::edge::EdgeActorClass;
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, WindowExport};
use oneiron::test_doors::machine_history::{
    PEER_MACHINE_CLAIM_PREDICATE, PeerMachineHistory, peer_machine_history,
};
use oneiron::test_doors::world_access::put_world_access_row;
use oneiron::write_envelope::claim_body::encode_claim_body;
use oneiron::write_envelope::{
    WriteActor, WriteEnvelope, WriteProvenance, write_envelope_evidence,
};
use oneiron::{
    ClaimApprovalStatus, ClaimSource, EntityId, PREDICATE_WORLD_ACCESS_ALLOWED_SET,
    PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET, ResolvedWorldAuthority, TimeRange, Vault,
    WorldAuthoritySet, world_access_claim_body,
};
use oneiron_contracts::record_layout::EntityMetadataHeader;

use crate::sync_harness::{
    ENTITY_METADATA_HEADER_LEN, T0, TestNode, WINDOW, exchange, make_entity_blob, map_insert_bytes,
    sync_through_doors, test_config, time_range, vault_pair,
};

/// One agent, the world its owner grants beside base reality, and the ids of
/// the grant and of the agent's own default.
struct Grant {
    agent: EntityId,
    world: EntityId,
    grant: EntityId,
    default: EntityId,
}

impl Grant {
    fn new() -> Self {
        Self {
            agent: EntityId::now(),
            world: EntityId::now(),
            grant: EntityId::now(),
            default: EntityId::now(),
        }
    }

    /// The agent's PERSON row, written on `vault`.
    fn put_agent(&self, vault: &Vault) {
        vault
            .put_entity(
                &self.agent,
                ENTITY_TYPE_PERSON,
                time_range(T0),
                T0,
                b"agent",
            )
            .unwrap();
    }

    /// The owner's grant of base reality plus `world`, written on `vault`.
    fn put_grant(&self, vault: &Vault) {
        let body = world_access_claim_body(
            PREDICATE_WORLD_ACCESS_ALLOWED_SET,
            self.agent,
            &WorldAuthoritySet::new(true, [self.world]).unwrap(),
            ClaimSource::UserStated,
            ClaimApprovalStatus::Approved,
            None,
            None,
        )
        .unwrap();
        put_world_access_row(vault, &self.grant, &body, time_range(T0), T0).unwrap();
    }

    /// The agent's own default of `world` alone, written on `vault` under the
    /// agent's envelope.
    fn put_default(&self, vault: &Vault) {
        let mut body = world_access_claim_body(
            PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
            self.agent,
            &WorldAuthoritySet::new(false, [self.world]).unwrap(),
            ClaimSource::Inferred,
            ClaimApprovalStatus::Auto,
            None,
            None,
        )
        .unwrap();
        let envelope = WriteEnvelope::new(
            WriteActor::new(self.agent, EdgeActorClass::Agent),
            ClaimSource::Inferred,
            WriteProvenance::new(rmpv::Value::from("world-default-test")).unwrap(),
            ClaimApprovalStatus::Auto,
        );
        body.evidence = Some(write_envelope_evidence(&envelope, None));
        put_world_access_row(vault, &self.default, &body, time_range(T0), T0).unwrap();
    }

    /// The tiers the agent reads on `vault` with no selection.
    fn authority(&self, vault: &Vault) -> ResolvedWorldAuthority {
        vault.board_world_authority(Some(self.agent), None).unwrap()
    }

    /// An ordinary claim body about the agent, approved and user-stated: what
    /// a peer's row under the grant's id would carry.
    fn ordinary_claim(&self) -> Vec<u8> {
        let mut body = world_access_claim_body(
            PREDICATE_WORLD_ACCESS_ALLOWED_SET,
            self.agent,
            &WorldAuthoritySet::new(true, []).unwrap(),
            ClaimSource::UserStated,
            ClaimApprovalStatus::Approved,
            None,
            None,
        )
        .unwrap();
        body.predicate = "preference.food".to_owned();
        encode_claim_body(&body).unwrap()
    }

    /// The agent is governed on `vault` by the grant written there, and
    /// reads base reality plus the granted world.
    fn assert_governed_by_grant(&self, vault: &Vault) {
        let here = self.authority(vault);
        assert_eq!(here.allowed_claim_ids, vec![self.grant]);
        assert_eq!(
            here.allowed_set,
            WorldAuthoritySet::new(true, [self.world]).unwrap()
        );
    }
}

/// The tiers of an actor no grant on the node governs: base reality only.
fn ungoverned() -> ResolvedWorldAuthority {
    let base = WorldAuthoritySet::new(true, []).unwrap();
    ResolvedWorldAuthority {
        allowed_set: base.clone(),
        default_subset: base.clone(),
        active_set: base,
        allowed_claim_ids: Vec::new(),
        default_claim_id: None,
    }
}

/// The entity keys `node`'s window export door ships to a peer that holds
/// nothing of the window yet.
fn exported_entity_keys(node: &TestNode) -> Vec<String> {
    let key = WindowKey::new(WINDOW);
    let empty = LoroDoc::new().oplog_vv().encode();
    let received = LoroDoc::new();
    match window::export_window_updates_since(&node.vault, &key, node.doc(WINDOW), &empty).unwrap()
    {
        WindowExport::Update(bytes) | WindowExport::Replacement(bytes) => {
            received.import(&bytes).unwrap();
        }
    }
    let mut keys = Vec::new();
    received
        .get_map("entities")
        .for_each(|key, _value| keys.push(key.to_owned()));
    keys
}

/// A grant and a default written on node A stay on A: the window export door
/// ships neither, so node B never holds them and B's agent reads base reality
/// only, while A still folds both. Red on main: A's export ships the grant.
#[test]
fn a_grant_written_on_one_node_never_leaves_it() {
    let (a, mut b) = vault_pair();
    let g = Grant::new();
    g.put_agent(&a.vault);
    g.put_agent(&b.vault);
    g.put_grant(&a.vault);
    g.put_default(&a.vault);
    let beside = EntityId::now();
    a.vault
        .put_entity(&beside, ENTITY_TYPE_PERSON, time_range(T0), T0, b"beside")
        .unwrap();

    window::reverse_rematerialize(&a.vault, a.doc(WINDOW), &WindowKey::new(WINDOW)).unwrap();
    let shipped = exported_entity_keys(&a);
    assert!(
        shipped.contains(&beside.to_hex()),
        "the window export door ships A's ordinary rows"
    );
    for (row, id) in [("grant", g.grant), ("default", g.default)] {
        assert!(
            !shipped.contains(&id.to_hex()),
            "the window export door shipped A's world-access {row}"
        );
    }

    sync_through_doors(&a, &mut b);
    assert!(
        b.vault.get_raw(&beside).unwrap().is_some(),
        "B holds the ordinary row A's window carried"
    );
    for id in [g.grant, g.default] {
        assert!(b.vault.get_raw(&id).unwrap().is_none());
    }
    assert_eq!(g.authority(&b.vault), ungoverned());

    let on_a = g.authority(&a.vault);
    assert_eq!(on_a.allowed_claim_ids, vec![g.grant]);
    assert_eq!(on_a.default_claim_id, Some(g.default));
    assert_eq!(
        on_a.allowed_set,
        WorldAuthoritySet::new(true, [g.world]).unwrap()
    );
}

/// A grant an older peer still ships is dropped where it arrives, not
/// refused: the rest of the peer's window lands, nothing goes to quarantine,
/// and the agent stays ungoverned. Red on main: the grant lands and sets the
/// agent's worlds.
#[test]
fn an_older_peers_grant_is_dropped_on_arrival() {
    let (a, b) = vault_pair();
    let g = Grant::new();
    g.put_agent(&a.vault);
    g.put_agent(&b.vault);
    g.put_grant(&a.vault);
    let grant_blob = a.vault.get_raw(&g.grant).unwrap().expect("grant on A");
    let beside = EntityId::now();
    a.put_entity_in_window(
        WINDOW,
        &beside,
        &make_entity_blob(ENTITY_TYPE_PERSON, T0, b"beside"),
    );
    // The peer's window carries the grant, as a node built before the
    // world-access tiers became local mirrored it.
    map_insert_bytes(
        &a.doc(WINDOW).get_map("entities"),
        &g.grant.to_hex(),
        &grant_blob,
    );
    a.doc(WINDOW).commit();
    let quarantined = b.quarantine_rows();

    exchange(&a, &b, WINDOW);

    assert!(
        b.vault.get_raw(&beside).unwrap().is_some(),
        "the rest of the peer's window lands"
    );
    assert!(
        b.vault.get_raw(&g.grant).unwrap().is_none(),
        "the peer's grant is dropped"
    );
    assert_eq!(
        b.quarantine_rows(),
        quarantined,
        "the grant is dropped, not refused into quarantine"
    );
    assert_eq!(g.authority(&b.vault), ungoverned());
}

/// The explicit-tier replay door drops a peer's grant too. Red on main: the
/// replayed grant governs the agent.
#[test]
fn a_replayed_grant_is_dropped() {
    let (a, b) = vault_pair();
    let g = Grant::new();
    g.put_agent(&a.vault);
    g.put_agent(&b.vault);
    g.put_grant(&a.vault);
    let raw = a.vault.get_raw(&g.grant).unwrap().expect("grant on A");
    let header = EntityMetadataHeader::parse(&raw).expect("grant header");

    replay_entity(
        &b.vault,
        ReplicatedEntity {
            id: g.grant,
            entity_type: header.entity_type,
            occurred: TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            learned_at: header.learned_at,
            row_version: header.row_version,
            body: &raw[ENTITY_METADATA_HEADER_LEN..],
        },
        ImportTier::OwnDevice,
    )
    .unwrap();

    assert!(b.vault.get_raw(&g.grant).unwrap().is_none());
    assert_eq!(g.authority(&b.vault), ungoverned());
}

/// Control: a grant written on this node governs here. Passes on main too.
#[test]
fn a_grant_written_here_governs_here() {
    let (_a, b) = vault_pair();
    let g = Grant::new();
    g.put_agent(&b.vault);
    g.put_grant(&b.vault);

    let here = g.authority(&b.vault);
    assert_eq!(here.allowed_claim_ids, vec![g.grant]);
    assert_eq!(
        here.allowed_set,
        WorldAuthoritySet::new(true, [g.world]).unwrap()
    );
}

/// The whole-vault import keeps both tiers as archive data, as it keeps an
/// ACCESS_GRANT row: the importing node's owner grants its own agents their
/// worlds. On main both took the generic claim door and landed Imported +
/// Proposed.
#[test]
fn the_archive_import_keeps_both_tiers_as_archive_data() {
    for predicate in [
        PREDICATE_WORLD_ACCESS_ALLOWED_SET,
        PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
    ] {
        assert_eq!(
            oneiron::test_doors::archive_import::reserved_claim_import(predicate).as_deref(),
            Some("ArchiveOnly(LocalAuthorityNotRestored)"),
            "{predicate}"
        );
    }
}

/// A peer's row under the id of a grant stored here never replaces it,
/// whatever its own predicate: the replay door reads the stored row too.
/// Red on #7793's first head: the replayed ordinary claim overwrote the
/// grant, so the agent was no longer governed by it.
#[test]
fn a_replayed_row_never_replaces_a_local_grant() {
    let (_a, b) = vault_pair();
    let g = Grant::new();
    g.put_agent(&b.vault);
    g.put_grant(&b.vault);
    let stored = b.vault.get_raw(&g.grant).unwrap().expect("grant on B");
    let header = EntityMetadataHeader::parse(&stored).expect("grant header");
    let ordinary = g.ordinary_claim();

    let replayed = replay_entity(
        &b.vault,
        ReplicatedEntity {
            id: g.grant,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            learned_at: header.learned_at + 1,
            row_version: header.row_version + 1,
            body: &ordinary,
        },
        ImportTier::OwnDevice,
    );

    assert_eq!(
        b.vault.get_raw(&g.grant).unwrap().as_deref(),
        Some(stored.as_slice()),
        "the grant stored here stands"
    );
    g.assert_governed_by_grant(&b.vault);
    assert!(replayed.is_ok(), "dropped, not refused: {replayed:?}");
}

/// A peer's window row under the id of a grant stored here is dropped, and
/// the rest of the window lands. Red on #7793's first head: the ordinary
/// claim landed over the grant.
#[test]
fn a_peers_row_under_a_local_grants_id_never_lands() {
    let (a, b) = vault_pair();
    let g = Grant::new();
    g.put_agent(&a.vault);
    g.put_agent(&b.vault);
    g.put_grant(&b.vault);
    let stored = b.vault.get_raw(&g.grant).unwrap().expect("grant on B");
    let beside = EntityId::now();
    a.put_entity_in_window(
        WINDOW,
        &beside,
        &make_entity_blob(ENTITY_TYPE_PERSON, T0, b"beside"),
    );
    map_insert_bytes(
        &a.doc(WINDOW).get_map("entities"),
        &g.grant.to_hex(),
        &make_entity_blob(ENTITY_TYPE_CLAIM, T0 + 1, &g.ordinary_claim()),
    );
    a.doc(WINDOW).commit();
    let quarantined = b.quarantine_rows();

    exchange(&a, &b, WINDOW);

    assert!(
        b.vault.get_raw(&beside).unwrap().is_some(),
        "the rest of the peer's window lands"
    );
    assert_eq!(
        b.vault.get_raw(&g.grant).unwrap().as_deref(),
        Some(stored.as_slice()),
        "the grant stored here stands"
    );
    assert_eq!(
        b.quarantine_rows(),
        quarantined,
        "the row is dropped, not refused into quarantine"
    );
    g.assert_governed_by_grant(&b.vault);
}

/// A peer's tombstone naming a grant stored here deletes nothing: the grant
/// is local authority, and a narrower grant erased would widen the meet.
/// The same window's tombstone of an ordinary row still deletes it. Red on
/// #7793's first head: the tombstone erased the grant.
#[test]
fn a_peers_tombstone_never_deletes_a_local_grant() {
    let (a, b) = vault_pair();
    let g = Grant::new();
    g.put_agent(&a.vault);
    g.put_agent(&b.vault);
    g.put_grant(&b.vault);
    let stored = b.vault.get_raw(&g.grant).unwrap().expect("grant on B");
    let beside = EntityId::now();
    a.put_entity_in_window(
        WINDOW,
        &beside,
        &make_entity_blob(ENTITY_TYPE_PERSON, T0, b"beside"),
    );
    exchange(&a, &b, WINDOW);
    assert!(
        b.vault.get_raw(&beside).unwrap().is_some(),
        "B holds the peer's ordinary row"
    );
    let tombstones = a.doc(WINDOW).get_map("tombstones");
    for id in [beside, g.grant] {
        map_insert_bytes(&tombstones, &id.to_hex(), &(T0 + 5).to_le_bytes());
    }
    a.doc(WINDOW).commit();
    let quarantined = b.quarantine_rows();

    exchange(&a, &b, WINDOW);

    assert!(
        b.vault.get_raw(&beside).unwrap().is_none(),
        "the peer's tombstone deletes its ordinary row"
    );
    assert_eq!(
        b.vault.get_raw(&g.grant).unwrap().as_deref(),
        Some(stored.as_slice()),
        "the grant stored here stands"
    );
    assert_eq!(
        b.quarantine_rows(),
        quarantined,
        "the tombstone is skipped, not refused into quarantine"
    );
    g.assert_governed_by_grant(&b.vault);
}

/// Base reality alone.
fn base_only() -> WorldAuthoritySet {
    WorldAuthoritySet::new(true, []).unwrap()
}

/// The owner's grant of base reality alone to `agent`, under `id` on `vault`:
/// narrower than [`Grant::put_grant`]'s, so the two meet at base reality.
fn put_base_only_grant(vault: &Vault, agent: EntityId, id: &EntityId) {
    let body = world_access_claim_body(
        PREDICATE_WORLD_ACCESS_ALLOWED_SET,
        agent,
        &base_only(),
        ClaimSource::UserStated,
        ClaimApprovalStatus::Approved,
        None,
        None,
    )
    .unwrap();
    put_world_access_row(vault, id, &body, time_range(T0), T0).unwrap();
}

/// A MACHINE claim at `target`, written on a second vault whose own host
/// root signs its history.
fn peer_history_at(target: EntityId) -> (tempfile::TempDir, PeerMachineHistory) {
    let dir = tempfile::tempdir().unwrap();
    let origin = Vault::open(dir.path(), test_config()).unwrap();
    let history = peer_machine_history(&origin, target).unwrap();
    assert!(
        history.controls.len() >= 2,
        "the write minted a birth and a handoff: {} control rows",
        history.controls.len()
    );
    (dir, history)
}

/// Makes `vault` a node of the peer's vault: it imports the peer's signed
/// authority history and holds the peer's MACHINE entity.
fn join_peer_vault(vault: &Vault, history: &PeerMachineHistory) {
    vault
        .import_signed_authority_history(
            &history.authority_history,
            &std::collections::BTreeMap::new(),
        )
        .unwrap();
    vault
        .put_entity(
            &history.machine,
            ENTITY_TYPE_MACHINE,
            time_range(T0),
            T0,
            b"machine",
        )
        .unwrap();
}

/// Replays the history's control rows on `vault` through the explicit-tier
/// replay door, the birth first, as an own device's rows land.
fn replay_peer_controls(vault: &Vault, history: &PeerMachineHistory) {
    for (id, raw) in &history.controls {
        let header = EntityMetadataHeader::parse(raw).expect("control header");
        replay_entity(
            vault,
            ReplicatedEntity {
                id: *id,
                entity_type: header.entity_type,
                occurred: TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                learned_at: header.learned_at,
                row_version: header.row_version,
                body: &raw[ENTITY_METADATA_HEADER_LEN..],
            },
            ImportTier::OwnDevice,
        )
        .unwrap();
    }
}

/// The agent is governed on `vault` by both of its grants, which meet at
/// base reality.
fn assert_governed_by_both(g: &Grant, narrow: EntityId, vault: &Vault, when: &str) {
    let here = g.authority(vault);
    let mut ids = here.allowed_claim_ids.clone();
    ids.sort();
    let mut both = vec![g.grant, narrow];
    both.sort();
    assert_eq!(ids, both, "{when}: both grants govern the agent");
    assert_eq!(
        here.allowed_set,
        base_only(),
        "{when}: the grants meet at base reality"
    );
}

/// Control: the fixture's history reaches adoption. Replayed on a node of
/// the same vault that holds nothing at its target, the peer's birth and
/// owner-signed handoff build the target's row from the verified history
/// (FIX 11926). Passes on main too.
#[test]
fn a_peers_machine_history_builds_its_row_here() {
    let here = TestNode::new("here", 3);
    let target = EntityId::now();
    let (_origin, history) = peer_history_at(target);
    join_peer_vault(&here.vault, &history);

    replay_peer_controls(&here.vault, &history);

    let built = here
        .vault
        .get_claim(&target)
        .unwrap()
        .expect("the adopted history built its row");
    assert_eq!(built.predicate, PEER_MACHINE_CLAIM_PREDICATE);
}

/// A same-vault peer's MACHINE claim history whose target is a grant stored
/// here never replaces the grant (REVIEW-7793 round 2). Its control rows
/// carry ids of their own, so the replay door's stored-row check passes
/// them; the pin exchange they reach adopts nothing over a world-access
/// tier, so the narrower grant still meets the wider one. Window ingest
/// reaches the same exchange. Red on #7793's second head 52dc436eda93: the
/// adopted history put the peer's ordinary claim over the narrower grant,
/// and the agent read the wider grant's world.
#[test]
fn a_peers_machine_history_never_replaces_a_local_grant() {
    let here = TestNode::new("here", 4);
    let g = Grant::new();
    let narrow = EntityId::now();
    g.put_agent(&here.vault);
    g.put_grant(&here.vault);
    put_base_only_grant(&here.vault, g.agent, &narrow);
    let stored = here
        .vault
        .get_raw(&narrow)
        .unwrap()
        .expect("narrower grant here");
    let (_origin, history) = peer_history_at(narrow);
    join_peer_vault(&here.vault, &history);
    assert_governed_by_both(&g, narrow, &here.vault, "joined");

    replay_peer_controls(&here.vault, &history);

    assert_eq!(
        here.vault.get_raw(&narrow).unwrap().as_deref(),
        Some(stored.as_slice()),
        "the narrower grant stored here stands"
    );
    assert_governed_by_both(&g, narrow, &here.vault, "replayed");
}
