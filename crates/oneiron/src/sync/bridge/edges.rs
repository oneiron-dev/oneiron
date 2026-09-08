//! Edge-delta materialization and per-op quarantine bookkeeping.

use std::collections::HashSet;

use loro::LoroDoc;

use super::childof::{apply_materialized_edge_ops, replayed_child_of_candidates};
use super::companion_identity::{
    CompanionCrdtScrub, EndpointHydration, ensure_entity_materialized_from_crdt, parse_edge_key,
    scrub_local_only_companions_from_crdt,
};
#[cfg(test)]
use super::entities::take_injected_batch_commit_failure;
use super::entities::{committed_entity_state_matches, set_remat_marker_logged};

use crate::affect::Vad;
use crate::batch::BatchOp;
use crate::edge::{EdgeKind, decode_edge_value_for_kind};
use crate::entity_id::EntityId;
use crate::store::Store;
use crate::sync::quarantine::{
    self, QuarantineContainer, quarantine_rejected_op_in_txn, remote_rejection_reason,
};
use crate::{Error, Result, Vault};

/// Materialize edge changes from a Loro MapDelta to LMDB.
///
/// Accumulates all edge ops from the delta into a single LMDB write
/// transaction instead of committing per-edge.
///
/// Write-gate rejections of REMOTE ops persist a quarantine record (`x:`
/// family, ONE-1124) and never abort the batch; LOCAL failures (the
/// engine's own LMDB errors) propagate fail-closed and abort the txn.
///
/// A whole-txn failure flags the durable `rm:w:{window}:{entity_hex}`
/// needs-remat marker for each batched edge upsert's SOURCE entity
/// (ONE-1147): the drain is window-scoped — any marker makes forward remat
/// re-walk the whole window's entities/edges maps, so the source id is
/// sufficient to get the edge re-processed, and the marker discharges when
/// the healing edge write lands.
pub(super) fn materialize_edges_from_delta(
    doc: &LoroDoc,
    delta: &loro::event::MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    lease_vault_id: u64,
) -> bool {
    // ONE-1147: source id + LMDB edge key + op bytes for every UPSERT
    // pushed into the batch, retained outside the txn for the swallow site
    // below (no surviving per-op failure point on whole-txn failure).
    let mut applied_edges: Vec<(EntityId, [u8; 33], Vec<u8>)> = Vec::new();
    // ONE-1147 fix-wave: id + written blob for every endpoint whose body this
    // batch HYDRATED-AND-WROTE into LMDB (the `Hydrated` outcome below),
    // retained outside the txn alongside `applied_edges`. A whole-txn
    // rollback erases those hydration writes too; the swallow site flags each
    // for durable remat. Without this, an endpoint hydrated inside the edge
    // batch and rolled back is silently lost — no edge need even have been
    // tracked (e.g. the partner endpoint failed LOCALLY and aborted the batch
    // BEFORE `applied_edges.push`).
    let mut hydrated_endpoints: Vec<(EntityId, Vec<u8>)> = Vec::new();
    let mut pending_companion_scrubs = Vec::new();
    let result = vault.with_write_txn(|wtxn| {
        let entities_map = doc.get_map("entities");
        let tombstones_map = doc.get_map("tombstones");
        let edges_map = doc.get_map("edges");
        // HOLE-1871-F2: the stale rows and stranded live candidates this delta
        // leaves behind, replayed through the very same gauntlet as its own
        // ops.
        let replay = replayed_child_of_candidates(vault, &*wtxn, &edges_map, delta)?;
        let mut ops = Vec::<BatchOp>::new();
        let mut metas = Vec::<EdgeOpMeta>::new();
        for (key, new_val) in delta
            .updated
            .iter()
            .map(|(key, value)| (key.as_ref(), value))
            .chain(replay.iter().map(|(key, value)| (key.as_str(), value)))
        {
            match new_val {
                Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(buf))) => {
                    let Some((src, kind, tgt)) = parse_edge_key(key) else {
                        quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key,
                            QuarantineContainer::Edges,
                            key,
                            &Error::InvalidKey,
                            buf,
                        )?;
                        continue;
                    };

                    // Decode BEFORE endpoint hydration: a malformed value is
                    // a remote rejection regardless of endpoint state, and
                    // decode has no side effects.
                    let decoded = match decode_edge_value_for_kind(kind, buf) {
                        Ok(v) => v,
                        Err(e) => {
                            quarantine_rejected_op_in_txn(
                                vault,
                                wtxn,
                                window_key,
                                QuarantineContainer::Edges,
                                key,
                                &e,
                                buf,
                            )?;
                            continue;
                        }
                    };

                    let reserved_rejection = crate::edge::validate_public_edge_kind(kind).err();
                    let src_ready = ensure_entity_materialized_from_crdt(
                        vault,
                        wtxn,
                        &entities_map,
                        &tombstones_map,
                        window_key,
                        &src,
                        lease_vault_id,
                    );
                    let tgt_ready = ensure_entity_materialized_from_crdt(
                        vault,
                        wtxn,
                        &entities_map,
                        &tombstones_map,
                        window_key,
                        &tgt,
                        lease_vault_id,
                    );
                    // ONE-1147 fix-wave: record every endpoint this batch
                    // ACTUALLY wrote (Hydrated) BEFORE the match may
                    // abort/defer/quarantine the edge — the hydration write
                    // has already landed in the txn and a rollback erases it
                    // regardless of the edge's fate. Already-present (Ready)
                    // endpoints wrote nothing and are never recorded. `src`
                    // and `tgt` are `Copy`, so the moves into the match below
                    // are unaffected.
                    if let Ok(EndpointHydration::Hydrated(blob)) = &src_ready {
                        hydrated_endpoints.push((src, blob.clone()));
                    }
                    if let Ok(EndpointHydration::Hydrated(blob)) = &tgt_ready {
                        hydrated_endpoints.push((tgt, blob.clone()));
                    }
                    if matches!(&src_ready, Ok(EndpointHydration::LocalOnly)) {
                        pending_companion_scrubs.push(CompanionCrdtScrub::new(src.to_hex(), src));
                    }
                    if matches!(&tgt_ready, Ok(EndpointHydration::LocalOnly)) {
                        pending_companion_scrubs.push(CompanionCrdtScrub::new(tgt.to_hex(), tgt));
                    }

                    // ARCH-0055 reserved-kind gate: `merged_into` /
                    // `split_into` carry redirect-shell lifecycle meaning,
                    // and the raw edges CRDT map is peer-controlled input
                    // with no write authority over them. Hydrate BOTH
                    // endpoints first: a successful endpoint put retriggers
                    // the shared deferred-topology reconciliation, so this
                    // mandate read sees the participant types the edge delta
                    // just revealed. The edge is then admitted ONLY as the
                    // BYTE-EXACT echo of a door side-effect: the local
                    // validated type-76 ledger must mandate exactly this
                    // pair AND the value must carry the door-written bytes
                    // (default weight, the event's `at` as `created_at`). A
                    // missing mandate or peer-chosen bytes remain a
                    // quarantine-and-continue rejection; no reserved edge
                    // lands merely because hydration ran first.
                    if let Some(reserved) = &reserved_rejection {
                        let mandated_at = vault.identity_topology_mandated_shell_edge_in_txn(
                            &*wtxn, &src, kind, &tgt,
                        )?;
                        let door_echo = mandated_at.is_some_and(|at| {
                            decoded.created_at == at
                                && kind.default_weight() == Some(decoded.weight)
                        });
                        if !door_echo {
                            quarantine_rejected_op_in_txn(
                                vault,
                                wtxn,
                                window_key,
                                QuarantineContainer::Edges,
                                key,
                                reserved,
                                buf,
                            )?;
                            continue;
                        }
                    }

                    match (src_ready, tgt_ready) {
                        // Both endpoints present — already there (`Ready`) or
                        // just hydrated this batch (`Hydrated`): the edge may
                        // proceed in either case.
                        (
                            Ok(EndpointHydration::Ready | EndpointHydration::Hydrated(_)),
                            Ok(EndpointHydration::Ready | EndpointHydration::Hydrated(_)),
                        ) => {}
                        (Ok(EndpointHydration::LocalOnly), Ok(_))
                        | (Ok(_), Ok(EndpointHydration::LocalOnly)) => {
                            tracing::warn!(
                                edge = %key,
                                "observer-b: edge scrubbed because it touches a local-only companion register row"
                            );
                            continue;
                        }
                        (Ok(EndpointHydration::RejectedBlob), Ok(_))
                        | (Ok(_), Ok(EndpointHydration::RejectedBlob)) => {
                            // The endpoint's CRDT blob is undecodable REMOTE
                            // garbage — the edge op is rejected with it:
                            // quarantine and continue, never abort the batch
                            // (the blob came from the remote doc, not the
                            // engine's own rows).
                            quarantine_rejected_op_in_txn(
                                vault,
                                wtxn,
                                window_key,
                                QuarantineContainer::Edges,
                                key,
                                &Error::CorruptedIndex("entity metadata"),
                                buf,
                            )?;
                            continue;
                        }
                        (Ok(_), Ok(_)) => {
                            // Endpoint absent or tombstoned in the CRDT — a
                            // deferral (cross-window endpoints arrive later;
                            // tombstoned endpoints never resurrect), not a
                            // write-gate rejection. The edge stays in the
                            // CRDT and re-materializes when its endpoints do.
                            tracing::debug!(
                                edge = %key,
                                "observer-b: edge deferred — endpoint absent or tombstoned"
                            );
                            continue;
                        }
                        // Fail-closed split (ONE-1124 fix wave 2): a LOCAL
                        // (non-remote-classifiable) error on EITHER endpoint
                        // aborts the batch FIRST. Matching
                        // `(Err(e), _) | (_, Err(e))` unconditionally would
                        // bind a remote-rejectable src error and silently
                        // swallow a local tgt failure behind an x: row that
                        // pretends the edge was handled.
                        (Err(e), _) if remote_rejection_reason(&e).is_none() => {
                            return Err(e);
                        }
                        (_, Err(e)) if remote_rejection_reason(&e).is_none() => {
                            return Err(e);
                        }
                        (Err(e), _) | (_, Err(e)) => {
                            // Every endpoint error left here is
                            // remote-rejectable: the endpoint's CRDT blob
                            // failed the entity write gate, so this edge op
                            // is rejected with it — quarantine and continue.
                            quarantine_rejected_op_in_txn(
                                vault,
                                wtxn,
                                window_key,
                                QuarantineContainer::Edges,
                                key,
                                &e,
                                buf,
                            )?;
                            continue;
                        }
                    }

                    // ONE-1645 `FacetOf` type table, Observer-B door.
                    //
                    // This is the SYNCHRONOUS path a member/guest import takes
                    // into a LOADED window: `import_federated_window_update`
                    // imports the admitted bytes into the live doc, Observer B
                    // fires inline, and the edge lands through the
                    // deliberately UNGATED `BatchOp::EdgeWithCreatedAt` arm —
                    // never crossing forward rematerialization, where the
                    // replay gate lives. Without this call the whole table is
                    // absent from production's hottest federation path.
                    //
                    // Ordered AFTER endpoint hydration/readiness for the same
                    // reason as the remat gate: the table reads endpoint types
                    // from entity ROWS, and the match above has just proved
                    // both endpoints present (hydrating them from the CRDT
                    // when needed). Running it earlier would read `None` for a
                    // legitimate same-frame endpoint and reject it.
                    //
                    // Guarded (ONE-1124): only a remote-classifiable rejection
                    // quarantines; a LOCAL fault (corrupted stored header,
                    // heed read error) aborts the batch. An `x:` row for our
                    // own defect would be permanent false evidence against the
                    // peer.
                    match crate::batch::validate_facet_of_edge(
                        &vault.store,
                        &*wtxn,
                        src,
                        kind,
                        tgt,
                    ) {
                        Ok(()) => {}
                        Err(off_table)
                            if remote_rejection_reason(&off_table).is_some() =>
                        {
                            quarantine_rejected_op_in_txn(
                                vault,
                                wtxn,
                                window_key,
                                QuarantineContainer::Edges,
                                key,
                                &off_table,
                                buf,
                            )?;
                            continue;
                        }
                        Err(local) => return Err(local),
                    }

                    applied_edges.push((
                        src,
                        Store::encode_edge_key(&src, kind, &tgt),
                        buf.to_vec(),
                    ));
                    ops.push(BatchOp::EdgeWithCreatedAt {
                        src,
                        kind,
                        tgt,
                        weight: decoded.weight,
                        created_at: decoded.created_at,
                        vad: decoded.vad.unwrap_or(Vad::NEUTRAL),
                        provenance: decoded.provenance,
                    });
                    metas.push(EdgeOpMeta::for_key(key, buf));
                }
                None => {
                    // Deleted.
                    //
                    // ONE-1147: bare edge-map removals are deliberately NOT
                    // flagged with rm: markers on batch failure — forward
                    // remat (the drain's only heal step) iterates the
                    // CURRENT edges map and has no delete leg, so such a
                    // marker could never discharge; recovery's reverse pass
                    // re-mirrors the surviving in-range LMDB edge back into
                    // the CRDT (LMDB wins for absent-from-CRDT records), so
                    // a lost removal converges edge-alive rather than
                    // staying silently divergent. Entity deletions ride the
                    // tombstone path, which has its own hardened rm:
                    // producer.
                    let Some((src, kind, tgt)) = parse_edge_key(key) else {
                        quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key,
                            QuarantineContainer::Edges,
                            key,
                            &Error::InvalidKey,
                            &[],
                        )?;
                        continue;
                    };
                    // ARCH-0055 reserved-kind gate, removal side: a raw
                    // edges-map removal must not tear a shell edge the
                    // validated ledger still mandates (an unledgered
                    // merge/split teardown → EntityNotFound-shaped wedge).
                    // The honest undo path deletes the edge as the
                    // ingested counter-event's door side-effect; after
                    // that the fold no longer mandates it and the removal
                    // echo passes through as a no-op delete.
                    //
                    // ONE-1608 blocks door, removal side: `blocks` is
                    // UNCONDITIONALLY quarantined here, with no mandate
                    // predicate to soften it. Its shape differs from the
                    // shell kinds on exactly the axis that matters — no
                    // ledger ever mandates a `blocks` row, so the
                    // mandate check above would be permanently false and
                    // every forged `{src}:24:{tgt}` removal would drain
                    // into a `BatchOp::DeleteEdge` that retires the
                    // victim's locally inserted row with no actor or
                    // source gate. Retirement is reserved to
                    // `code_memory::remove_blocks_edge`; a replicated
                    // removal is never evidence that the door ran, so it
                    // is quarantined rather than applied.
                    if let Err(reserved) = crate::edge::validate_public_edge_kind(kind)
                        && (kind == EdgeKind::Blocks
                            || vault
                                .identity_topology_mandated_shell_edge_in_txn(
                                    &*wtxn, &src, kind, &tgt,
                                )?
                                .is_some())
                    {
                        quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key,
                            QuarantineContainer::Edges,
                            key,
                            &reserved,
                            &[],
                        )?;
                        continue;
                    }
                    ops.push(BatchOp::DeleteEdge { src, kind, tgt });
                    metas.push(EdgeOpMeta::for_key(key, &[]));
                }
                _ => {
                    // Non-binary value where an edge value belongs —
                    // undecodable remote op, quarantined (never a bare log).
                    quarantine_rejected_op_in_txn(
                        vault,
                        wtxn,
                        window_key,
                        QuarantineContainer::Edges,
                        key,
                        &Error::InvalidKey,
                        &[],
                    )?;
                }
            }
        }
        apply_materialized_edge_ops(vault, wtxn, ops, &metas, window_key)?;
        #[cfg(test)]
        if take_injected_batch_commit_failure() {
            return Err(Error::Io(std::io::Error::other(
                "injected batch commit failure (test hook)",
            )));
        }
        Ok(())
    });

    if result.is_ok()
        && let Err(e) = scrub_local_only_companions_from_crdt(doc, &pending_companion_scrubs)
    {
        tracing::error!(
            error = %e,
            window = %window_key,
            "observer-b: local-only companion CRDT scrub failed after edge batch commit"
        );
    }

    let committed = result.is_ok();
    if let Err(e) = result {
        // ONE-1147: whole-txn failure — same marker semantics and
        // best-effort layering as the entity swallow site above. Two classes
        // of write the dead txn rolled back get a durable entity-scoped rm:
        // marker, de-duped through ONE shared `seen` set so an id that is
        // both is marked exactly once:
        //   (1) ONE-1147 fix-wave — every endpoint this batch HYDRATED-AND-
        //       WROTE (`hydrated_endpoints`): the rolled-back hydration write
        //       is otherwise silently lost, even when no edge was tracked
        //       (a partner endpoint may have aborted the batch before the
        //       edge reached `applied_edges`); and
        //   (2) the SOURCE entity of every lost edge upsert (`applied_edges`).
        // The committed_*_state_matches guards skip any id whose COMMITTED
        // bytes already equal the op's bytes (nothing lost; an at-parity
        // marker could never discharge — forward remat heals on the actual
        // healing write only, never on parity).
        let mut seen = HashSet::new();
        let mut marked = 0usize;
        for (id, blob) in &hydrated_endpoints {
            if committed_entity_state_matches(vault, id, blob) || !seen.insert(*id) {
                continue;
            }
            if set_remat_marker_logged(vault, window_key, id) {
                marked += 1;
            }
        }
        for (src, edge_key, buf) in &applied_edges {
            if committed_edge_state_matches(vault, edge_key, buf) || !seen.insert(*src) {
                continue;
            }
            if set_remat_marker_logged(vault, window_key, src) {
                marked += 1;
            }
        }
        tracing::error!(
            error = %e,
            window = %window_key,
            applied_ops = applied_edges.len(),
            hydrated_endpoints = hydrated_endpoints.len(),
            marked,
            "observer-b: edge batch commit failed — flagged entity-scoped rm: markers for durable retry"
        );
    }
    committed
}

/// ONE-1147 (best-effort, post-abort): `true` ONLY when the committed
/// `edges_out` bytes provably equal the op's bytes. Read errors report
/// `false` (mark — conservative direction).
pub(super) fn committed_edge_state_matches(vault: &Vault, edge_key: &[u8; 33], buf: &[u8]) -> bool {
    let Ok(rtxn) = vault.store.env.read_txn() else {
        return false;
    };
    matches!(
        vault.store.edges_out.get(&rtxn, edge_key),
        Ok(Some(existing)) if *existing == *buf
    )
}

/// Quarantine bookkeeping for one edge op, index-aligned with the ops vec.
/// Carries bounded non-content metadata only: the CRDT map key is
/// attacker-controlled, so it is hashed up front and never retained
/// (ONE-1124 — `x:` rows are hash+metadata, never content).
#[derive(Clone)]
pub(super) struct EdgeOpMeta {
    crdt_key_hash: u64,
    crdt_key_len: u32,
    payload_hash: u64,
    remat_marker_entity: Option<EntityId>,
}

impl EdgeOpMeta {
    pub(super) fn for_key(crdt_key: &str, payload: &[u8]) -> Self {
        let (crdt_key_hash, crdt_key_len) = quarantine::crdt_key_metadata(crdt_key);
        Self {
            crdt_key_hash,
            crdt_key_len,
            payload_hash: quarantine::payload_hash(payload),
            remat_marker_entity: quarantine::remat_marker_entity_for_quarantine(
                QuarantineContainer::Edges,
                crdt_key,
            ),
        }
    }
}

pub(super) fn quarantine_edge_apply_failure(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    meta: &EdgeOpMeta,
    error: &Error,
) -> Result<()> {
    quarantine::record_in_txn(
        vault,
        wtxn,
        &quarantine::QuarantineRecord {
            window_key: window_key.to_string(),
            container: QuarantineContainer::Edges,
            crdt_key_hash: meta.crdt_key_hash,
            crdt_key_len: meta.crdt_key_len,
            reason_code: quarantine::reason_code_for(error),
            payload_hash: meta.payload_hash,
            quarantined_at: crate::unix_seconds_now(),
        },
    )?;
    if let Some(id) = meta.remat_marker_entity {
        quarantine::set_replay_remat_marker_in_txn(vault, wtxn, window_key, &id)?;
    }
    Ok(())
}
