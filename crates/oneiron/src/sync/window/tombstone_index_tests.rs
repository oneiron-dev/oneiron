//! H15: a sync pass reads a peer-sized tombstones map once, not once per carrier it checks.

use std::sync::Arc;

use loro::LoroDoc;

use super::{WindowKey, forward_rematerialize, reverse_rematerialize};
use crate::Vault;
use crate::config::VaultConfig;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_TURN;
use crate::sync::bridge::{Materializer, encode_edge_value_for_crdt, format_edge_key};
use crate::sync::loro_support::{
    TOMBSTONE_KEY_PARSES, export_snapshot, import_doc, map_insert_bytes,
};

const LEARNED_AT: u64 = 1_771_027_200;
const WINDOW: &str = "2026-02";
const CARRIERS: usize = 40;
/// Tombstone keys that name nothing here: case-shifted aliases of absent ids and non-id junk.
const PLANTED: usize = 160;

fn parses() -> u64 {
    TOMBSTONE_KEY_PARSES.with(std::cell::Cell::get)
}

fn carrier_blob(n: usize) -> Vec<u8> {
    let mut blob = vec![ENTITY_TYPE_TURN];
    for _ in 0..3 {
        blob.extend_from_slice(&LEARNED_AT.to_be_bytes());
    }
    blob.extend_from_slice(format!("carrier {n}").as_bytes());
    blob
}

/// A v2 hard tombstone value: `[reason:1][deleted_at:8 LE][request_id:16]`.
fn hard_tombstone() -> Vec<u8> {
    let mut value = vec![2u8];
    value.extend_from_slice(&(LEARNED_AT + 60).to_le_bytes());
    value.extend_from_slice(&[0xAE; 16]);
    value
}

/// A peer window holding `CARRIERS` turns chained by mention edges, one of them tombstoned only
/// under an UPPERCASE alias of its id, beside `PLANTED` tombstone keys that name no carrier.
fn planted_peer_window() -> Result<(LoroDoc, Vec<EntityId>, EntityId)> {
    let peer = LoroDoc::new();
    let entities = peer.get_map("entities");
    let edges = peer.get_map("edges");
    let tombstones = peer.get_map("tombstones");
    let carriers: Vec<EntityId> = (0..CARRIERS)
        .map(|n| EntityId::from_hex(&format!("cafe{n:028x}")))
        .collect::<Result<_>>()?;
    for (n, id) in carriers.iter().enumerate() {
        map_insert_bytes(&entities, &id.to_hex(), &carrier_blob(n))?;
    }
    for pair in carriers.windows(2) {
        map_insert_bytes(
            &edges,
            &format_edge_key(&pair[0], EdgeKind::Mentions, &pair[1]),
            &encode_edge_value_for_crdt(EdgeKind::Mentions, 1.0, LEARNED_AT, None, None)?,
        )?;
    }
    let gated = carriers[CARRIERS / 2];
    let alias = gated.to_hex().to_uppercase();
    assert_ne!(alias, gated.to_hex());
    map_insert_bytes(&tombstones, &alias, &hard_tombstone())?;
    for n in 0..PLANTED {
        let key = if n % 2 == 0 {
            format!("BEEF{n:028X}")
        } else {
            format!("not-an-entity-{n}")
        };
        map_insert_bytes(&tombstones, &key, &hard_tombstone())?;
    }
    peer.commit();
    Ok((peer, carriers, gated))
}

/// H15 bug repro: a peer plants tombstone keys that name nothing here beside many carriers.
/// Every rematerialization pass used to rescan the whole tombstones map for each entity and edge
/// endpoint it checked, so its key parses grew as carriers × tombstones; a pass now parses each
/// key a bounded number of times. The decisions are the oracle and do not move: the carrier
/// under an uppercase alias tombstone stays gated with both its edges, and every other carrier
/// and edge lands.
#[test]
fn a_forward_pass_parses_each_tombstone_key_a_bounded_number_of_times() -> Result<()> {
    let (peer, carriers, gated) = planted_peer_window()?;
    let doc = LoroDoc::new();
    import_doc(&doc, &export_snapshot(&peer)?)?;
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);

    let before = parses();
    forward_rematerialize(&vault, &doc, &Materializer::new(), &WindowKey::new(WINDOW))?;
    let forward = parses() - before;

    assert!(
        vault.get_raw(&gated)?.is_none(),
        "an uppercase alias tombstone still gates its carrier"
    );
    for id in carriers.iter().filter(|id| **id != gated) {
        assert!(
            vault.get_raw(id)?.is_some(),
            "an untombstoned carrier lands"
        );
    }
    for pair in carriers.windows(2) {
        let touches_gated = pair.contains(&gated);
        assert_eq!(
            vault.edge_exists(&pair[0], EdgeKind::Mentions, &pair[1])?,
            !touches_gated,
            "an edge lands exactly when neither endpoint is tombstoned"
        );
    }

    // The way back out reads the same map against every local carrier and edge.
    let before = parses();
    reverse_rematerialize(&vault, &doc, &WindowKey::new(WINDOW))?;
    let reverse = parses() - before;

    let keys = (PLANTED + 1) as u64;
    for (pass, spent) in [("forward", forward), ("reverse", reverse)] {
        assert!(
            spent <= 4 * keys,
            "the {pass} pass parsed {spent} tombstone keys for a {keys}-key map and \
             {CARRIERS} carriers: it must read the map a bounded number of times, not once per \
             carrier"
        );
    }
    Ok(())
}
