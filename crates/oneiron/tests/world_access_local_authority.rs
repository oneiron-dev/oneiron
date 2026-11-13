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
//! explicit-tier replay door.
//!
//! Run: `cargo test --locked -p oneiron --all-features --no-fail-fast --test
//! world_access_local_authority`.
#![cfg(all(feature = "sync", feature = "test-support"))]

#[path = "it_sync/sync_harness/mod.rs"]
mod sync_harness;

use loro::LoroDoc;
use oneiron::edge::EdgeActorClass;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, WindowExport};
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
    sync_through_doors, time_range, vault_pair,
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
        vault
            .put_claim(&self.grant, &body, time_range(T0), T0)
            .unwrap();
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
        vault
            .put_claim(&self.default, &body, time_range(T0), T0)
            .unwrap();
    }

    /// The tiers the agent reads on `vault` with no selection.
    fn authority(&self, vault: &Vault) -> ResolvedWorldAuthority {
        vault.board_world_authority(Some(self.agent), None).unwrap()
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
    g.put_agent(&a);
    g.put_agent(&b);
    g.put_grant(&a);
    g.put_default(&a);
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
    g.put_agent(&a);
    g.put_agent(&b);
    g.put_grant(&a);
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
    g.put_agent(&a);
    g.put_agent(&b);
    g.put_grant(&a);
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
    g.put_agent(&b);
    g.put_grant(&b);

    let here = g.authority(&b.vault);
    assert_eq!(here.allowed_claim_ids, vec![g.grant]);
    assert_eq!(
        here.allowed_set,
        WorldAuthoritySet::new(true, [g.world]).unwrap()
    );
}
