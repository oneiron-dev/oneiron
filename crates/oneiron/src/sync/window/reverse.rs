//! Reverse rematerialization plus skip/policy predicates and carrier removal.

use std::collections::{BTreeMap, HashSet};

use super::bridge::{self, encode_edge_value_for_crdt, format_edge_key};
use super::loro_support::{
    TombstoneIndex, map_contains_binary, map_delete, map_for_each_tombstone_value,
    map_for_each_value_bytes, map_get_bytes, map_insert_bytes,
};
use super::pack_sync;
use super::quarantine::{self, QuarantineContainer};
use super::types::WindowKey;
use super::window_packing_excludes_entity;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, RegistryError, Result};
use crate::registry::{ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_SECRET_CUSTODY, ENTITY_TYPE_TURN};
use crate::sync::local_claims::{claim_sync_allowed, local_claim_sync_allowed};
use loro::{CommitOptions, LoroDoc, LoroMap};

/// Reverse re-materialization: LMDB→CRDT (insert-missing only).
///
/// ARCH-0023b crash-recovery step 4: scan LMDB entities + `edges_out` in the
/// window's `learned_at` range and mirror every syncable entity missing from
/// CRDT, minus what the packing egress door excludes. Differing edge values
/// are left alone: this pass inserts missing records only.
///
/// Returns the number of entities newly mirrored into the CRDT.
pub(in crate::sync) fn is_delegated_channel_identity_carrier(raw: &[u8]) -> bool {
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return false;
    };
    if header.entity_type != crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY {
        return false;
    }
    // A ChannelIdentity carrier is portable only after the strict body decoder
    // positively establishes a valid self-held identity. Damage to a delegated
    // map (including truncated MessagePack) must never open the export seal.
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    !matches!(
        crate::channel_identity::decode_channel_identity_body(body),
        Ok(identity) if !identity.is_delegated()
    )
}

/// LMDB → CRDT for a canonical window doc: every row the window holds except
/// those of a world withheld from an unknown destination, a world window's
/// own world excepted (`canonical_withheld_worlds`).
pub fn reverse_rematerialize(vault: &Vault, doc: &LoroDoc, window_key: &WindowKey) -> Result<u32> {
    let withheld = super::device_only::canonical_withheld_worlds(vault, window_key)?;
    reverse_rematerialize_with(vault, doc, window_key, super::Withhold::Worlds(&withheld))
}

/// [`reverse_rematerialize`] into a sealed window's own mirror document
/// (OF-570): it packs the rows a device-only world keeps here too. Only the
/// sealed-content door calls it, and what it packs leaves this machine only
/// sealed under the world's key.
pub(crate) fn reverse_rematerialize_for_sealing(
    vault: &Vault,
    doc: &LoroDoc,
    window_key: &WindowKey,
) -> Result<u32> {
    reverse_rematerialize_with(vault, doc, window_key, super::Withhold::Nothing)
}

/// [`reverse_rematerialize`] for only the `rows` a commit just wrote, not the
/// window's whole learned range: each one this window holds (by its learned
/// month and world) is mirrored as a cold open would mirror it, so a live
/// window gets a write made after it loaded (the live mirror). An `edited`
/// row, one a local write changed, also replaces the carrier the doc holds,
/// and so do its outgoing edges.
pub(crate) fn reverse_rematerialize_rows(
    vault: &Vault,
    doc: &LoroDoc,
    window_key: &WindowKey,
    rows: &std::collections::BTreeSet<EntityId>,
    edited: &std::collections::BTreeSet<EntityId>,
) -> Result<u32> {
    let withheld = super::device_only::canonical_withheld_worlds(vault, window_key)?;
    reverse_rematerialize_scan(
        vault,
        doc,
        window_key,
        super::Withhold::Worlds(&withheld),
        Some((rows, edited)),
    )
}

/// [`reverse_rematerialize`], packing every row except those of a world
/// `withhold` names. Promotion authority packs them all: it asks what a grant
/// covers and exports nothing. A residence read for a proved machine packs
/// the private rows that machine may read.
pub(in crate::sync) fn reverse_rematerialize_with(
    vault: &Vault,
    doc: &LoroDoc,
    window_key: &WindowKey,
    withhold: super::Withhold<'_>,
) -> Result<u32> {
    reverse_rematerialize_scan(vault, doc, window_key, withhold, None)
}

/// The reverse pass over the window's learned range, or over the rows of
/// `committed` (each kept when its learned time falls in the window's month),
/// whose edited rows replace the carriers they differ from.
fn reverse_rematerialize_scan(
    vault: &Vault,
    doc: &LoroDoc,
    window_key: &WindowKey,
    withhold: super::Withhold<'_>,
    committed: Option<(
        &std::collections::BTreeSet<EntityId>,
        &std::collections::BTreeSet<EntityId>,
    )>,
) -> Result<u32> {
    let only = committed.map(|(rows, _)| rows);
    let is_edited = |id: &EntityId| committed.is_some_and(|(_, edited)| edited.contains(id));
    let start_ts = window_key
        .start_timestamp()
        .ok_or_else(|| Error::InvalidConfig("invalid window key".to_string()))?;
    let end_ts = window_key
        .end_timestamp()
        .ok_or_else(|| Error::InvalidConfig("invalid window key".to_string()))?;

    super::egress::scrub_local_claim_carriers(vault, window_key, doc)?;
    super::egress::scrub_local_only_carriers(vault, window_key, doc)?;
    super::egress::scrub_redacted_attribution_carriers(vault, window_key, doc)?;
    let tombstones = TombstoneIndex::build(&doc.get_map("tombstones"));
    let redacted_authors = {
        let rtxn = vault.store.env.read_txn()?;
        crate::identity_topology::redacted_keys_in_txn(&vault.store, &rtxn)?
    };
    // Partition before either carrier or edge backfill. A month-only scan in a
    // world window would duplicate every other project's payload into it.
    let mut entities_in_range = Vec::new();
    let mut base_edge_sources = Vec::new();
    let scanned = match only {
        None => vault.entities_in_learned_range(start_ts, end_ts)?,
        Some(rows) => rows.iter().copied().collect(),
    };
    for id in scanned {
        if let Some(raw) = vault.get_raw_unsealed(&id)? {
            if only.is_some()
                && !EntityMetadataHeader::parse(&raw)
                    .is_some_and(|header| (start_ts..end_ts).contains(&header.learned_at))
            {
                continue;
            }
            let belongs = super::types::entity_belongs_to_window(&raw, window_key);
            let retained = if belongs {
                false
            } else {
                let txn = vault.store.env.read_txn()?;
                super::types::retained_world_shell_belongs_to_window(
                    vault,
                    &txn,
                    doc,
                    &tombstones,
                    &id,
                    &raw,
                    window_key,
                    false,
                )?
            };
            if belongs || retained {
                entities_in_range.push(id);
            } else if window_key.world().is_some()
                && super::types::entity_world(&raw).ok() == Some(None)
            {
                // Base rows do not duplicate into this world document, but an
                // outgoing base→world edge belongs beside its world target.
                // Unassignable local rows cannot enter a world partition.
                base_edge_sources.push(id);
            }
        }
    }
    // Closure (decision 9): every held revision of a PROJECT row in this
    // window travels with it, whatever month it was learned in, so a late
    // joiner that materializes only this window still folds the whole
    // signed history. Forged rows never travel, by either road.
    {
        let rtxn = vault.store.env.read_txn()?;
        let mut seen: HashSet<EntityId> = entities_in_range.iter().copied().collect();
        let mut kept = Vec::with_capacity(entities_in_range.len());
        let mut closure = Vec::new();
        for id in &entities_in_range {
            if crate::workspace_roster::forged_revision_in_txn(&vault.store, &rtxn, *id)? {
                continue;
            }
            kept.push(*id);
            for companion in
                crate::workspace_roster::exportable_revisions_in_txn(&vault.store, &rtxn, *id)?
            {
                if seen.insert(companion) {
                    closure.push(companion);
                }
            }
        }
        kept.extend(closure);
        entities_in_range = kept;
    }
    let device_only = withhold.worlds(vault)?;

    let entities_map = doc.get_map("entities");
    let edges_map = doc.get_map("edges");

    let mut count = 0u32;
    let mut wrote_any = false;
    let mut mirror_sources = BTreeMap::new();
    let entities_in_range_set: HashSet<EntityId> = entities_in_range.iter().copied().collect();
    let mut protected_tombstones = HashSet::new();
    let mut entity_tombstones = Vec::new();
    wrote_any |= remove_inadmissible_revision_carriers(vault, &entities_map, &edges_map)?;

    // Type-classify entity-keyed tombstones BEFORE any CRDT edge-key scan.
    // A hostile tombstone naming a locally available protected engine row
    // cannot be sent through the edge-key parser (its grammar is just the
    // entity hex), and cannot suppress the carrier before reverse recovery
    // sees its type. Ordinary and out-of-window rows are untouched here and
    // retain the existing delete-wins handling in the main loop below.
    map_for_each_tombstone_value(tombstones.map(), |key, tombstone| {
        if let Ok(id) = EntityId::from_hex(key)
            && entities_in_range_set.contains(&id)
        {
            entity_tombstones.push((id, key.to_owned(), tombstone.to_vec()));
        }
    });
    for (id, key, tombstone) in entity_tombstones {
        let Some((raw, source_revision)) = vault.get_raw_and_revision_unsealed(&id)? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if !crate::dreamer_runner::authority::is_base_agent_actor(&id)?
            && !crate::registry::is_delete_protected_engine_record(header.entity_type)
            && !crate::workspace_roster::is_project_revision_type(&vault.store, header.entity_type)
        {
            continue;
        }

        let rejection = if crate::dreamer_runner::authority::is_base_agent_actor(&id)? {
            Error::Registry(RegistryError::DreamerActorImmutable)
        } else {
            Error::Registry(RegistryError::MaintenanceKindNotWritable(
                header.entity_type,
            ))
        };
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
        if !map_contains_binary(&entities_map, &hex_id)
            || (crate::dreamer_runner::authority::is_base_agent_actor(&id)?
                && map_get_bytes(&entities_map, &hex_id).as_deref() != Some(raw.as_slice()))
        {
            // A rejected peer overwrite is not a valid protected carrier.
            // Restore the fixed base-agent bytes, not merely a missing key.
            map_insert_bytes(&entities_map, &hex_id, &raw)?;
            if let Some(revision) = source_revision {
                mirror_sources.insert(id, revision);
            }
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
        if window_packing_excludes_entity(vault, &device_only, id)? {
            continue;
        }

        let Some((raw, source_revision)) = vault.get_raw_and_revision_unsealed(id)? else {
            continue;
        };

        if crate::identity_topology::attribution_carrier_key(&raw)
            .is_some_and(|key| redacted_authors.contains(&key))
        {
            let removed = remove_entity_crdt_carriers(&entities_map, &edges_map, id)?;
            if removed {
                super::egress::require_history_free_window(vault, window_key)?;
            }
            wrote_any |= removed;
            continue;
        }

        let retained_shell = {
            let txn = vault.store.env.read_txn()?;
            super::types::retained_world_shell_belongs_to_window(
                vault,
                &txn,
                doc,
                &tombstones,
                id,
                &raw,
                window_key,
                false,
            )?
        };
        // Excluded credentials and the local default manifest have no live
        // carrier or incident edge. Scrub history as well as the live map when
        // a carrier landed before the custody seal.
        if (!claim_sync_allowed(&raw) && !retained_shell)
            || is_unsyncable_secret_custody(&raw)
            || is_delegated_channel_identity_carrier(&raw)
            || *id == crate::gate::default_policy_manifest_id()?
        {
            let removed = remove_entity_crdt_carriers(&entities_map, &edges_map, id)?;
            if removed {
                super::egress::require_history_free_window(vault, window_key)?;
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
        if !protected_tombstone && tombstones.contains(id) && !retained_shell {
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
            let dominates = authority_row_dominates_map_carrier(&entities_map, id, &hex_id, &raw)
                || held_revision_dominates_map_carrier(vault, &entities_map, &hex_id, &raw)
                || crate::sync::receipt_ingest::local_receipt_dominates(
                    vault,
                    window_key,
                    &entities_map,
                    id,
                    &raw,
                )?;
            let fixed_actor_mismatch = crate::dreamer_runner::authority::is_base_agent_actor(id)?
                && map_get_bytes(&entities_map, &hex_id).as_deref() != Some(raw.as_slice());
            // A local edit to a row the doc already carries replaces it.
            let edited = if is_edited(id) {
                let outbound = pack_sync::canonical_outbound_blob(&raw)?;
                map_get_bytes(&entities_map, &hex_id).as_deref()
                    != Some(outbound.as_deref().unwrap_or(raw.as_slice()))
            } else {
                false
            };
            if !map_contains_binary(&entities_map, &hex_id)
                || dominates
                || fixed_actor_mismatch
                || edited
            {
                // Pack rows mirror the canonical wire header/body (origin
                // handle/generation, exact identity/payload), not the
                // receiver-local materialization. A corrupt local pack row
                // fails closed here; it is never quarantined as remote.
                if let Some(canonical) = pack_sync::canonical_outbound_blob(&raw)? {
                    map_insert_bytes(&entities_map, hex_id.as_str(), &canonical)?;
                } else {
                    map_insert_bytes(&entities_map, hex_id.as_str(), raw.as_slice())?;
                }
                if let Some(revision) = source_revision {
                    mirror_sources.insert(*id, revision);
                }
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
            // Rule A: the row's birth rides beside its carrier, in the same
            // bridge commit, whether the carrier was just written or was
            // already present.
            if map_contains_binary(&entities_map, &hex_id)
                && crate::sync::row_birth::mirror_local_birth(vault, doc, id)?
            {
                wrote_any = true;
            }
            // OF-522: a TURN's room row rides beside its carrier the same
            // way, and is refreshed when only the row changed.
            if window_key.world().is_none()
                && EntityMetadataHeader::parse(&raw)
                    .is_some_and(|header| header.entity_type == ENTITY_TYPE_TURN)
                && map_contains_binary(&entities_map, &hex_id)
                && crate::sync::room_turns::mirror_room_turn(vault, doc, id)?
            {
                wrote_any = true;
            }
            // FIX 1794: a room's side rows ride beside its carrier, and a
            // turn's claim, response and thread facts beside the turn's.
            if window_key.world().is_none()
                && let Some(header) = EntityMetadataHeader::parse(&raw)
                && matches!(
                    header.entity_type,
                    ENTITY_TYPE_TURN | crate::registry::ENTITY_TYPE_CONVERSATION
                )
                && map_contains_binary(&entities_map, &hex_id)
                && crate::sync::room_facts::mirror_room_facts(
                    vault,
                    doc,
                    id,
                    header.entity_type,
                    None,
                )?
            {
                wrote_any = true;
            }
        }

        backfill_sources.push(*id);
    }

    // A base source is resident in the shared monthly document, not here.
    // Only its edges reaching this world are packed below. Apply the same
    // locality and egress gates before adding it to the edge-only pass.
    for id in base_edge_sources {
        if window_packing_excludes_entity(vault, &device_only, &id)?
            || !local_claim_sync_allowed(vault, &id)?
            || local_entity_is_unsyncable(vault, &id)?
        {
            continue;
        }
        backfill_sources.push(id);
    }

    // PHASE 2 — edge backfill for every source that cleared phase 1's gates
    // (egress door, tombstone, unsyncable, missing local row). Ordered
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
            if tombstones.contains(&edge.target)
                || window_packing_excludes_entity(vault, &device_only, &edge.target)?
            {
                continue;
            }
            if !super::types::edge_belongs_to_window(vault, id, &edge.target, window_key)? {
                continue;
            }
            if !local_claim_sync_allowed(vault, &edge.target)?
                || local_entity_is_unsyncable(vault, &edge.target)?
            {
                continue;
            }
            if map_contains_binary(&edges_map, &edge_key) && !is_edited(id) {
                continue;
            }
            let edge_val = encode_edge_value_for_crdt(
                edge.kind,
                edge.weight,
                edge.created_at,
                edge.vad,
                edge.provenance,
            )?;
            // An edited source's edge replaces only a carrier it differs from.
            if map_get_bytes(&edges_map, &edge_key).as_deref() == Some(edge_val.as_slice()) {
                continue;
            }
            map_insert_bytes(&edges_map, edge_key.as_str(), &edge_val)?;
            wrote_any = true;
        }
    }

    // Base→world edges live in the world TARGET's birth month, not the
    // older base source's month. The target index finds those sources without
    // scanning every historic base row or inventing edge-only world windows.
    if window_key.world().is_some() {
        for target in &entities_in_range {
            if tombstones.contains(target) {
                continue;
            }
            for edge in vault.edges_in(target)? {
                let source = edge.target; // edges_in names the source as its neighbor.
                let Some(source_raw) = vault.get_raw_unsealed(&source)? else {
                    continue;
                };
                if super::types::entity_world(&source_raw)?.is_some()
                    || is_unsyncable_secret_custody(&source_raw)
                    || edge.kind == EdgeKind::Blocks
                    || window_packing_excludes_entity(vault, &device_only, &source)?
                    || window_packing_excludes_entity(vault, &device_only, target)?
                    || !local_claim_sync_allowed(vault, &source)?
                    || !local_claim_sync_allowed(vault, target)?
                    || local_entity_is_unsyncable(vault, &source)?
                    || local_entity_is_unsyncable(vault, target)?
                    || !super::types::edge_belongs_to_window(vault, &source, target, window_key)?
                {
                    continue;
                }
                let key = format_edge_key(&source, edge.kind, target);
                if map_contains_binary(&edges_map, &key) {
                    continue;
                }
                let value = encode_edge_value_for_crdt(
                    edge.kind,
                    edge.weight,
                    edge.created_at,
                    edge.vad,
                    edge.provenance,
                )?;
                map_insert_bytes(&edges_map, &key, &value)?;
                wrote_any = true;
            }
        }
    }

    // NOTE text, mutable workflows and head moves change even when the
    // entity carrier already exists. Refresh through the same export gates.
    if window_key.world().is_none() {
        wrote_any |= crate::sync::note::refresh_for(vault, doc, window_key, withhold)?;
    }

    // A carrier the window kept past its row's learned month still takes
    // every revision learned since (Astra #1434 F2).
    wrote_any |= super::project_history::carry_project_history(vault, doc)?;

    // OF-422: the owner-signed custody transitions this vault wrote that ride
    // this window, never a custody row.
    wrote_any |= crate::sync::custody::mirror_custody_transitions(vault, doc, window_key)?;

    // Commit all bridge writes with origin tag
    if wrote_any {
        let origin = bridge::origin_for_mirrors(&mirror_sources)?;
        doc.commit_with(CommitOptions::new().origin(&origin));
    }
    Ok(count)
}

/// Local-only rows: diagnostics, and every credential (custody is sealed from
/// sync whatever its class or dial).
pub(super) fn is_unsyncable_secret_custody(raw: &[u8]) -> bool {
    EntityMetadataHeader::parse(raw).is_some_and(|header| {
        header.entity_type == crate::registry::ENTITY_TYPE_DIAGNOSTIC
            || header.entity_type == ENTITY_TYPE_SECRET_CUSTODY
    })
}

/// Quarantines every CRDT tombstone aliasing a locally available,
/// delete-protected engine record. Returns `true` only when tombstone
/// authority was denied, allowing the caller to preserve or restore the
/// entity carrier through the ordinary outbound mirror path.
pub(super) fn quarantine_outbound_protected_tombstones(
    vault: &Vault,
    window_key: &WindowKey,
    tombstones: &TombstoneIndex,
    id: &EntityId,
    raw: &[u8],
) -> Result<bool> {
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Ok(false);
    };
    if !crate::dreamer_runner::authority::is_base_agent_actor(id)?
        && !crate::registry::is_delete_protected_engine_record(header.entity_type)
        && !crate::workspace_roster::is_project_revision_type(&vault.store, header.entity_type)
    {
        return Ok(false);
    }

    let tombstones = tombstones.values_for(id);
    if tombstones.is_empty() {
        return Ok(false);
    }

    let rejection = if crate::dreamer_runner::authority::is_base_agent_actor(id)? {
        Error::Registry(RegistryError::DreamerActorImmutable)
    } else {
        Error::Registry(RegistryError::MaintenanceKindNotWritable(
            header.entity_type,
        ))
    };
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

fn local_entity_is_unsyncable(vault: &Vault, id: &EntityId) -> Result<bool> {
    let Some(raw) = vault.get_raw_unsealed(id)? else {
        return Ok(false);
    };
    Ok(is_unsyncable_secret_custody(&raw))
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
    // The row's birth leaves with its carrier.
    if let Some(doc) = loro::ContainerTrait::doc(entities_map)
        && crate::sync::row_birth::remove_birth_carrier(&doc, id)?
    {
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

/// A held project revision replaces any carrier at its id that is not
/// byte-identical to it (R2-F10): the id fixes the bytes, so another carrier
/// there is a poisoned one no peer should replay.
fn held_revision_dominates_map_carrier(
    vault: &Vault,
    entities_map: &LoroMap,
    hex_id: &str,
    local: &[u8],
) -> bool {
    EntityMetadataHeader::parse(local).is_some_and(|header| {
        crate::workspace_roster::is_project_revision_type(&vault.store, header.entity_type)
    }) && map_get_bytes(entities_map, hex_id).is_some_and(|carrier| carrier != local)
}

/// Removes, with their incident edges, the carriers that claim the revision
/// kind at an id this vault marked forged, or at an id it does not hold when
/// no peer's admission arm would take them: a body that is not canonical,
/// does not derive its id, or names another vault.
fn remove_inadmissible_revision_carriers(
    vault: &Vault,
    entities_map: &LoroMap,
    edges_map: &LoroMap,
) -> Result<bool> {
    let Some(kind) = crate::workspace_roster::project_revision_type(&vault.store) else {
        return Ok(false);
    };
    let mut carriers = Vec::new();
    crate::sync::loro_support::map_for_each_bytes(entities_map, |key, blob| {
        if EntityMetadataHeader::parse(blob).is_some_and(|header| header.entity_type == kind) {
            carriers.push((key.to_owned(), blob.to_vec()));
        }
    });
    if carriers.is_empty() {
        return Ok(false);
    }
    let rtxn = vault.store.env.read_txn()?;
    let fold = crate::authority::authority_fold_readonly_for_store_in_txn(
        &vault.store,
        vault.privacy_posture(),
        &rtxn,
    )?;
    let mut inadmissible = Vec::new();
    let mut unheld = Vec::new();
    for (key, blob) in carriers {
        let Ok(id) = EntityId::from_hex(&key) else {
            continue;
        };
        if vault.get_raw_in(&rtxn, &id)?.is_none() {
            unheld.push((id, blob));
        } else if crate::workspace_roster::forged_revision_in_txn(&vault.store, &rtxn, id)? {
            inadmissible.push(id);
        }
    }
    inadmissible.extend(crate::workspace_roster::inadmissible_revision_carriers(
        &vault.store,
        &rtxn,
        &fold,
        &unheld,
    )?);
    let mut removed = false;
    for id in inadmissible {
        removed |= remove_entity_crdt_carriers(entities_map, edges_map, &id)?;
    }
    Ok(removed)
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
