//! Reverse rematerialization plus skip/policy predicates and carrier removal.

use std::collections::HashSet;

use super::bridge::{self, BRIDGE_ORIGIN, encode_edge_value_for_crdt, format_edge_key};
use super::loro_support::{
    map_contains_binary, map_delete, map_for_each_tombstone_value, map_for_each_value_bytes,
    map_get_bytes, map_insert_bytes, tombstone_map_contains_id, tombstone_values_for_id,
};
use super::quarantine::{self, QuarantineContainer};
use super::types::WindowKey;
use super::window_packing_excludes_entity;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::companion::{
    CompanionExportClassification, ENTITY_TYPE_COMPANION_REGISTER, decode_companion_record_body,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_SECRET_CUSTODY,
};
use loro::{CommitOptions, LoroDoc, LoroMap};

/// Reverse re-materialization: LMDB→CRDT (insert-missing only).
///
/// ARCH-0023b crash-recovery step 4: scan LMDB entities + `edges_out` in the
/// window's `learned_at` range and mirror every syncable entity missing from
/// CRDT, minus what the packing egress door excludes. Differing edge values
/// are left alone: this pass inserts missing records only.
///
/// Returns the number of entities newly mirrored into the CRDT.
pub fn reverse_rematerialize(vault: &Vault, doc: &LoroDoc, window_key: &WindowKey) -> Result<u32> {
    let start_ts = window_key
        .start_timestamp()
        .ok_or_else(|| Error::InvalidConfig("invalid window key".to_string()))?;
    let end_ts = window_key
        .end_timestamp()
        .ok_or_else(|| Error::InvalidConfig("invalid window key".to_string()))?;

    let entities_in_range = vault.entities_in_learned_range(start_ts, end_ts)?;

    let entities_map = doc.get_map("entities");
    let edges_map = doc.get_map("edges");
    let tombstones_map = doc.get_map("tombstones");

    let mut count = 0u32;
    let mut wrote_any = false;
    let entities_in_range_set: HashSet<EntityId> = entities_in_range.iter().copied().collect();
    let mut protected_tombstones = HashSet::new();
    let mut entity_tombstones = Vec::new();

    // Type-classify entity-keyed tombstones BEFORE any CRDT edge-key scan.
    // A hostile tombstone naming a locally available protected engine row
    // cannot be sent through the edge-key parser (its grammar is just the
    // entity hex), and cannot suppress the carrier before reverse recovery
    // sees its type. Ordinary and out-of-window rows are untouched here and
    // retain the existing delete-wins handling in the main loop below.
    map_for_each_tombstone_value(&tombstones_map, |key, tombstone| {
        if let Ok(id) = EntityId::from_hex(key)
            && entities_in_range_set.contains(&id)
        {
            entity_tombstones.push((id, key.to_owned(), tombstone.to_vec()));
        }
    });
    for (id, key, tombstone) in entity_tombstones {
        let Some(raw) = vault.get_raw_unsealed(&id)? else {
            continue;
        };
        if reverse_remat_skip_policy_manifest_mirror(&raw) {
            continue;
        }
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if !crate::registry::is_delete_protected_engine_record(header.entity_type) {
            continue;
        }

        let rejection = Error::MaintenanceKindNotWritable(header.entity_type);
        quarantine::quarantine_rejected_op(
            vault,
            window_key.as_str(),
            QuarantineContainer::Tombstones,
            &key,
            &rejection,
            &tombstone,
        )?;
        protected_tombstones.insert(id);
        let hex_id = id.to_hex();
        if !map_contains_binary(&entities_map, &hex_id) {
            map_insert_bytes(&entities_map, &hex_id, &raw)?;
            wrote_any = true;
            count += 1;
        }
    }

    // PHASE 1 — entity carriers only: mirror missing rows, replace dominated
    // carriers, and sweep the CRDT edges incident to a carrier this pass
    // evicts.
    //
    // The `edges_out` backfill is deliberately NOT interleaved here; it runs
    // as phase 2 below. Both passes walk `entities_in_range` in `learned_at`
    // order, and an eviction sweep removes EVERY CRDT edge incident to the
    // evicted id — it cannot tell the dominated carrier's residue apart from
    // a locally-backed inbound edge. Interleaved, a legitimate local source
    // `S` ordered BEFORE an attacker-parked authority id `A` would backfill
    // its valid `S→A` edge, then `A`'s dominance sweep would delete it and
    // only `edges_out(A)` would be replayed — so the locally-backed inbound
    // edge stayed deleted, and the committed CRDT update propagated that
    // attacker-triggered deletion to every peer. Running every sweep before
    // any backfill makes each locally-backed edge (re)written after the last
    // sweep that could remove it; only residue with no local backing stays
    // deleted.
    let mut backfill_sources = Vec::with_capacity(entities_in_range.len());
    for id in &entities_in_range {
        let hex_id = id.to_hex();

        // Defer-sync egress door, before reading or packing the payload.
        if window_packing_excludes_entity(vault, id)? {
            continue;
        }

        let Some(raw) = vault.get_raw_unsealed(id)? else {
            continue;
        };

        if reverse_remat_skip_policy_manifest_mirror(&raw) {
            continue;
        }

        // ONE-1865 arm-pending seal: never mirror a SECRET_CUSTODY row into the
        // canonical window doc, and scrub any custody carrier that landed
        // before this pass ran (fail-closed — a resident body is a disclosure,
        // not a presence). Mirror the companion-local-only branch below: drop
        // the entity carrier and every incident edge, never the tombstones.
        if is_secret_custody_record(&raw) {
            let mut removed = false;
            if map_contains_binary(&entities_map, &hex_id) {
                map_delete(&entities_map, &hex_id)?;
                removed = true;
            }
            if delete_edges_touching_entities(&edges_map, &HashSet::from([*id]))? {
                removed = true;
            }
            wrote_any |= removed;
            continue;
        }

        // Read and type-classify the local row BEFORE granting the CRDT
        // tombstone delete authority. A hostile tombstone cannot suppress a
        // protected engine record from outbound recovery; quarantine it and
        // restore the carrier. Ordinary rows retain delete-wins semantics,
        // including non-binary values and case-shifted aliases.
        let protected_tombstone = protected_tombstones.contains(id);
        if !protected_tombstone && tombstone_map_contains_id(&tombstones_map, id) {
            continue;
        }

        if skip_companion_register_sync_mirror(&raw)? {
            let mut removed = false;
            if map_contains_binary(&entities_map, &hex_id) {
                map_delete(&entities_map, &hex_id)?;
                removed = true;
            }
            if delete_edges_touching_entities(&edges_map, &HashSet::from([*id]))? {
                removed = true;
            }
            wrote_any |= removed;
            continue;
        }

        // Presence alone decides for ordinary rows (delete-wins and remote
        // history are not rewritten here). ONE-1604-D1 adds one exception:
        // a validated local AUTHORITY_LOG row DOMINATES any occupant of its
        // content-derived key that no peer's replay door would admit. The
        // local vault already refused that occupant, so leaving it as the
        // CRDT carrier would re-export the very row the authority substrate
        // rejected — and starve peers that have not yet seen the entry.
        if !reverse_remat_skip_redaction_receipt_mirror(&raw) {
            // Evaluated before the insert branch rather than inside it: the
            // verdict also drives the edge sweep below, and it is `false` by
            // construction when the key carries nothing (`map_get_bytes` →
            // `None`), so hoisting it past the short circuit is semantics-
            // preserving.
            let dominates = authority_row_dominates_map_carrier(&entities_map, id, &hex_id, &raw);
            if !map_contains_binary(&entities_map, &hex_id) || dominates {
                map_insert_bytes(&entities_map, hex_id.as_str(), raw.as_slice())?;
                wrote_any = true;
                count += 1;
            }
            // ONE-1604-D1 (fix-leg 4): overwriting the dominated carrier's
            // ENTITY row is only half an eviction. Edge entries are keyed
            // independently of the entity (`src:kind:tgt`), so the squatter's
            // incident edges survive the entity overwrite and keep it
            // traversable on every peer that imports this window — graph
            // residue for a row the authority substrate refused. The local
            // write door already drops both edge directions along with the
            // entity (`deindex_entity` → `delete_related_edges`); this is
            // the outbound mirror of that completeness.
            //
            // Scoped to the DOMINANCE verdict, so it cannot touch a key
            // whose carrier every peer would admit: presence-only rows keep
            // their edges untouched.
            //
            // The swept edges have no local backing to lose. Reaching this
            // branch means the local vault holds a VALIDATED AUTHORITY_LOG row at
            // `id`, which it could only have admitted by evicting whatever
            // squatted the key — and that eviction already deleted both
            // directions of every incident edge. Anything still naming `id`
            // in the CRDT is therefore the dominated carrier's residue. The
            // sweep still runs BEFORE the `edges_out` backfill below, so any
            // edge the local row does own is re-inserted in this same pass.
            //
            // Self-limiting: once the carrier is replaced by the validated
            // local row it becomes admissible, so the next pass takes the
            // presence-only branch and never re-runs this sweep.
            if dominates && delete_edges_touching_entities(&edges_map, &HashSet::from([*id]))? {
                wrote_any = true;
            }
        }

        backfill_sources.push(*id);
    }

    // PHASE 2 — edge backfill for every source that cleared phase 1's gates
    // (egress door, tombstone, unsyncable-companion, missing local row). Ordered
    // after ALL dominance sweeps, so an edge with local backing is always
    // re-inserted, whatever the `learned_at` order of its endpoints.
    for id in &backfill_sources {
        let edges_out = vault.edges_out(id)?;
        for edge in &edges_out {
            // readiness edges are local-only in v1; federated Blocks is banked
            // (ONE-1608 / ARCH-0050 R6 L2). Inbound quarantine and admission
            // aborts stay untouched, so a non-compliant peer that ships one
            // still fails closed on the receive side.
            if edge.kind == EdgeKind::Blocks {
                continue;
            }
            let edge_key = format_edge_key(id, edge.kind, &edge.target);
            // Never backfill an edge whose TARGET is tombstoned — matching
            // forward remat's both-endpoint filter (the source is gated
            // above). A surviving local S→E row from the tombstone-commit/
            // purge-txn crash window must not re-enter the replicated edges
            // map. Plain containment = skip on this branch; reason-aware
            // (skip iff HARD) once tombstone v2 lands in M4-06.
            if tombstone_map_contains_id(&tombstones_map, &edge.target) {
                continue;
            }
            if local_entity_is_unsyncable_companion(vault, &edge.target)? {
                continue;
            }
            if map_contains_binary(&edges_map, &edge_key) {
                continue;
            }
            let edge_val = encode_edge_value_for_crdt(
                edge.kind,
                edge.weight,
                edge.created_at,
                edge.vad,
                edge.provenance,
            )?;
            map_insert_bytes(&edges_map, edge_key.as_str(), &edge_val)?;
            wrote_any = true;
        }
    }

    // Commit all bridge writes with origin tag
    if wrote_any {
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    Ok(count)
}

pub(super) fn skip_companion_register_sync_mirror(raw: &[u8]) -> Result<bool> {
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Ok(false);
    };
    if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
        return Ok(false);
    }
    decode_companion_record_body(&raw[ENTITY_METADATA_HEADER_LEN..])
        .map(|record| record.export_classification == CompanionExportClassification::LocalOnly)
}

/// ONE-1865 arms the SECRET_CUSTODY replication dial; until then the type byte
/// is sealed from every CRDT carrier. This is the canonical-doc mirror twin of
/// the selector decision (`sync::selector::entity_selector_decision`): any path
/// that copies a local row's bytes INTO the canonical window doc (reverse
/// rematerialization) or OUT of it (the export scrub) screens the byte here so
/// a custody body's `value_bytes` never lands in a doc payload. The custody
/// module owns the rejection constructor; this is a pure type-byte read, so a
/// malformed row simply does not skip (it is handled by the ordinary paths).
pub(super) fn is_secret_custody_record(raw: &[u8]) -> bool {
    EntityMetadataHeader::parse(raw)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_SECRET_CUSTODY)
}

/// Quarantines every CRDT tombstone aliasing a locally available,
/// delete-protected engine record. Returns `true` only when tombstone
/// authority was denied, allowing the caller to preserve or restore the
/// entity carrier through the ordinary outbound mirror path.
pub(super) fn quarantine_outbound_protected_tombstones(
    vault: &Vault,
    window_key: &WindowKey,
    tombstones_map: &LoroMap,
    id: &EntityId,
    raw: &[u8],
) -> Result<bool> {
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Ok(false);
    };
    if !crate::registry::is_delete_protected_engine_record(header.entity_type) {
        return Ok(false);
    }

    let tombstones = tombstone_values_for_id(tombstones_map, id);
    if tombstones.is_empty() {
        return Ok(false);
    }

    let rejection = Error::MaintenanceKindNotWritable(header.entity_type);
    for tombstone in &tombstones {
        quarantine::quarantine_rejected_op(
            vault,
            window_key.as_str(),
            QuarantineContainer::Tombstones,
            &id.to_hex(),
            &rejection,
            tombstone,
        )?;
    }
    Ok(true)
}

fn local_entity_is_unsyncable_companion(vault: &Vault, id: &EntityId) -> Result<bool> {
    let Some(raw) = vault.get_raw_unsealed(id)? else {
        return Ok(false);
    };
    skip_companion_register_sync_mirror(&raw)
}

/// Removes an entity's already-present CRDT body and every incident edge.
/// A seal must hold even when the carrier arrived before the local check;
/// merely skipping a later mirror would leave the old carrier sync-visible
/// indefinitely.
pub(super) fn remove_entity_crdt_carriers(
    entities_map: &LoroMap,
    edges_map: &LoroMap,
    id: &EntityId,
) -> Result<bool> {
    let mut removed = false;
    let mut entity_keys = Vec::new();
    map_for_each_value_bytes(entities_map, |key, _| {
        if EntityId::from_hex(key).ok().as_ref() == Some(id) {
            entity_keys.push(key.to_owned());
        }
    });
    for key in &entity_keys {
        map_delete(entities_map, key)?;
        removed = true;
    }
    if delete_edges_touching_entities(edges_map, &HashSet::from([*id]))? {
        removed = true;
    }
    Ok(removed)
}

pub(super) fn delete_edges_touching_entities(
    edges_map: &LoroMap,
    ids: &HashSet<EntityId>,
) -> Result<bool> {
    if ids.is_empty() {
        return Ok(false);
    }

    let mut edge_keys = Vec::new();
    map_for_each_value_bytes(edges_map, |key, _| {
        if let Some((src, _, tgt)) = bridge::parse_edge_key(key)
            && (ids.contains(&src) || ids.contains(&tgt))
        {
            edge_keys.push(key.to_owned());
        }
    });
    for key in &edge_keys {
        map_delete(edges_map, key)?;
    }
    Ok(!edge_keys.is_empty())
}

fn reverse_remat_skip_policy_manifest_mirror(raw: &[u8]) -> bool {
    EntityMetadataHeader::parse(raw)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_POLICY_MANIFEST)
}

/// ONE-1604-D1 dominance on the outbound door: `true` when the LOCAL row is a
/// fully validated AUTHORITY_LOG authority row and the CRDT map carries a row that
/// would NOT survive the authority replay door at that key. Overwriting it is
/// the outbound half of the write-door rule; without it a carrier that
/// pre-occupied a revocation's derived id keeps circulating and keeps that
/// revocation out of peers' folds.
///
/// Dominance is ADMISSIBILITY-based, not type-byte-based (fix-leg 3). The
/// earlier type-byte test rested on "two authority rows at one key are
/// byte-identical by construction", which holds only for rows through the
/// validated write path. A raw CRDT carrier bypasses `apply_put` entirely, so
/// a hostile peer can park a poisoned AUTHORITY_LOG row at a revocation's derived
/// key — an inverted occurred range, or a divergent/malformed body. Every
/// peer rejects such a carrier locally, so preserving it exports the
/// rejection instead of the revocation.
///
/// Presence-only semantics stay intact for an ADMISSIBLE carrier: byte
/// difference alone never triggers dominance, so the legacy-genesis
/// dual-encoding is preserved rather than normalized — see
/// [`crdt_carrier_is_admissible_authority_row`].
fn authority_row_dominates_map_carrier(
    entities_map: &LoroMap,
    id: &EntityId,
    hex_id: &str,
    local: &[u8],
) -> bool {
    let local_is_authority = EntityMetadataHeader::parse(local)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_AUTHORITY_LOG);
    if !local_is_authority {
        return false;
    }
    map_get_bytes(entities_map, hex_id)
        .is_some_and(|carrier| !crdt_carrier_is_admissible_authority_row(id, &carrier))
}

/// The full envelope/body/key admissibility triple a CRDT carrier must clear
/// to be replayable as the AUTHORITY_LOG row at `id` — the outbound mirror of
/// what every receiving peer's replay door computes:
///
/// * ENVELOPE — parses, reads the AUTHORITY_LOG byte, and carries a non-inverted occurred
///   range (`put_replicated` rejects an inverted range with `InvalidTimeRange`
///   before the authority validator ever runs);
/// * BODY — decodes through [`crate::authority::decode_authority_log_entry_body`],
///   which is the same canonical-encoding + origin-signature validation the
///   write door runs;
/// * KEY — the entry's content-derived store key equals `id`, the bind
///   `check_authority_log_store_key` enforces at the write door.
///
/// LEGACY-GENESIS: both checks delegate to the shared helpers, so the decode
/// layer's dual-encoding posture is inherited unchanged. It admits the exact
/// canonical AND the exact legacy-genesis encoding, and
/// `authority_log_entity_id` hashes whichever of the two actually verifies —
/// so a legacy-encoded carrier at its own derived key is ADMISSIBLE and is
/// preserved as-is (no re-encode; the codebase never normalizes legacy bytes,
/// it keys off them). The current re-encoding of a legacy-signed entry
/// carries no verifying signature, so it fails the BODY check — dominated for
/// inadmissibility, not for differing from the local bytes.
pub(super) fn crdt_carrier_is_admissible_authority_row(id: &EntityId, carrier: &[u8]) -> bool {
    let Some(header) = EntityMetadataHeader::parse(carrier) else {
        return false;
    };
    if header.entity_type != ENTITY_TYPE_AUTHORITY_LOG
        || header.occurred_start > header.occurred_end
    {
        return false;
    }
    let Ok(entry) =
        crate::authority::decode_authority_log_entry_body(&carrier[ENTITY_METADATA_HEADER_LEN..])
    else {
        return false;
    };
    crate::authority::authority_log_entity_id(&entry).is_ok_and(|derived| derived == *id)
}

/// REDACTION_AUDIT finalization is local-LMDB-only. Reverse remat is the
/// outgoing replay door, so it must not copy finalized receipt bytes into the
/// CRDT mirror. Undecodable REDACTION_AUDIT bodies also stay local: fail closed
/// rather than replicate raw accountability bytes whose shape is unknown.
pub(super) fn reverse_remat_skip_redaction_receipt_mirror(raw: &[u8]) -> bool {
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return raw.first().copied() == Some(crate::registry::ENTITY_TYPE_REDACTION_AUDIT);
    };
    if header.entity_type != crate::registry::ENTITY_TYPE_REDACTION_AUDIT {
        return false;
    }
    let body = if raw.len() > ENTITY_METADATA_HEADER_LEN {
        &raw[ENTITY_METADATA_HEADER_LEN..]
    } else {
        &[]
    };
    match crate::deletion::decode_redaction_audit_receipt(body) {
        Ok(receipt) => receipt.sweep_complete_at.is_some(),
        Err(_) => true,
    }
}
