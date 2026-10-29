//! Edge pass of forward rematerialization: materialize window edge rows into LMDB.

mod apply;

use self::apply::{EdgeRematOutcome, apply_edge_in_txn};
use super::super::bridge;
use super::super::loro_support::{map_for_each_value_bytes, map_get_bytes};
use super::super::quarantine::{self, QuarantineContainer};
use super::{RematCtx, RematLedger};

use crate::Vault;
use crate::edge::decode_edge_value_for_kind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Edges queued under one door transaction. A batching size, not a cap:
/// every edge of the window still replays, one chunk after another.
const FORWARD_EDGE_CHUNK: usize = 128;

/// Run the edge pass: iterate the window `edges` map, filter tombstoned
/// endpoints, byte-compare against LMDB, and write what differs.
///
/// Queued edges replay FORWARD_EDGE_CHUNK at a time under one door
/// transaction, each in a savepoint child of its own, so the door's checks
/// run once per chunk. Nothing of a chunk is recorded before its door
/// commits. A chunk whose door fails, or that runs out of room, replays
/// one by one, each in its own transaction as the pass always has. Parent
/// edges keep their own door transaction each.
pub(super) fn run(ctx: &RematCtx<'_>, ledger: &mut RematLedger) -> Result<()> {
    // Edges (endpoint + tombstone filtering, stored-value byte-compare).
    // ARCH-0023b step 5 byte-compares edges too ("write any that differ"):
    // an exists-skip would let a CRDT edge carrying confirmation_status =
    // retracted (value[24] == 3) lose to a stale local Active stamp, and the
    // PPR retracted gate would keep propagating withdrawn provenance.
    // FIX 5972: a `regenerates` link is proven on its MESSAGEs' axes, so
    // it lands after every ordinary edge, whatever the map's key order.
    let mut keys = Vec::new();
    let mut regenerates = Vec::new();
    map_for_each_value_bytes(&ctx.edges_map, |key, buf| {
        match (buf, bridge::parse_edge_key(key)) {
            (Some(_), Some((_, crate::edge::EdgeKind::Regenerates, _))) => {
                regenerates.push(key.to_owned());
            }
            _ => keys.push(key.to_owned()),
        }
    });
    keys.extend(regenerates);
    let count = ledger.count;
    let mut pass = Pass { ctx, ledger, count };
    let mut pending: Vec<PendingEdge<'_>> = Vec::new();
    for key in &keys {
        let buf = map_get_bytes(&ctx.edges_map, key);
        match gate(ctx, key.as_str(), buf.as_deref()) {
            Err(err) => {
                // A gate that failed queued nothing it must keep: land what
                // queued before it, as the pass always had, then stop.
                pass.flush(&mut pending)?;
                return Err(err);
            }
            Ok(Gate::Skip) => {}
            Ok(Gate::Parent {
                src,
                tgt,
                tombstoned,
            }) => {
                pass.flush(&mut pending)?;
                // The gate quarantines a missing value before Parent
                // dispatch, so the value is present here.
                pass.replay_parent(src, tgt, buf.as_deref().unwrap_or_default(), tombstoned)?;
            }
            Ok(Gate::Queued(queued)) => {
                pending.push(PendingEdge {
                    key: key.as_str(),
                    buf: buf.unwrap_or_default(),
                    queued,
                });
                if pending.len() >= FORWARD_EDGE_CHUNK {
                    pass.flush(&mut pending)?;
                }
            }
        }
    }
    pass.flush(&mut pending)?;
    pass.ledger.count = pass.count;
    Ok(())
}

/// The pass's running state: the window, its ledger and the rows it has
/// written so far.
struct Pass<'a> {
    ctx: &'a RematCtx<'a>,
    ledger: &'a mut RematLedger,
    count: u32,
}

/// What the pre-gate decided for one edge, before any write.
enum Gate {
    /// A tombstoned endpoint (or an untrusted soft shell) skips the edge.
    Skip,
    /// A Parent edge, for its own door transaction.
    Parent {
        src: EntityId,
        tgt: EntityId,
        tombstoned: bool,
    },
    /// Queued for the chunk's door transaction.
    Queued(Queued),
}

/// One edge held until the chunk's door transaction commits.
struct PendingEdge<'k> {
    key: &'k str,
    /// The map's Binary value, empty when the map held none (which the
    /// chunk quarantines with an empty payload, as its own transaction
    /// did).
    buf: Vec<u8>,
    queued: Queued,
}

/// The chunked work one edge owes.
enum Queued {
    /// A refused carrier: its `x:` row, and the terminal ledger entry the
    /// pass records once the chunk commits (`None` when the key names no
    /// entity).
    Quarantine {
        terminal: Option<EntityId>,
        err: Error,
    },
    /// The mandate-checked write.
    Main(EdgeWork),
}

/// The mandate-checked write one edge owes its chunk.
struct EdgeWork {
    src: EntityId,
    kind: crate::edge::EdgeKind,
    tgt: EntityId,
    decoded: crate::edge::DecodedEdgeValue,
    soft_addressing: bool,
}

/// One edge of a chunk, held until the chunk's door transaction commits.
enum Staged {
    /// Quarantined in the chunk, or owed its wait in the ledger.
    Terminal(Option<EntityId>),
    /// A healing write: the ledger count and the source's marker, once
    /// the chunk commits.
    Written(EntityId),
    /// A deferral: the pending index, for the after-commit debug log.
    Deferred(usize),
}

/// Why a chunk's door transaction did not commit its staged edges: an
/// edge's own failure, or the door's.
enum ChunkError {
    /// A local edge failure: the chunk is dropped uncommitted, nothing was
    /// recorded, and the pass stops with this error.
    Edge(Error),
    /// The door itself failed around the chunk: the chunk replays one by
    /// one, as a room-short chunk does.
    Door(Error),
}

impl From<Error> for ChunkError {
    fn from(error: Error) -> Self {
        Self::Door(error)
    }
}

impl Pass<'_> {
    /// Drains `pending` through one chunk's door transaction, replaying
    /// one by one what the chunk did not take.
    fn flush(&mut self, pending: &mut Vec<PendingEdge<'_>>) -> Result<()> {
        if pending.is_empty() {
            return Ok(());
        }
        let done = self.replay_chunk(pending)?;
        for edge in &pending[done..] {
            self.replay_one(edge)?;
        }
        pending.clear();
        Ok(())
    }

    /// Replays queued edges under ONE door transaction, the raw topology
    /// of the one-by-one replay. Each edge applies in a savepoint child of
    /// its own, so a failure rolls back only that edge. Once the door
    /// commits, the staged ledger entries land. Returns how many edges the
    /// chunk took: an edge out of room ends it early, so that edge and the
    /// rest get a transaction each. An `Err` is a local edge failure: the
    /// chunk is dropped uncommitted, nothing was recorded, and the pass
    /// stops.
    fn replay_chunk(&mut self, pending: &[PendingEdge<'_>]) -> Result<usize> {
        let ctx = self.ctx;
        let vault = ctx.vault;
        let committed = vault.try_with_write_txn_grouped(
            |wtxn| -> std::result::Result<(Vec<Staged>, usize), ChunkError> {
                let mut staged = Vec::new();
                for (index, edge) in pending.iter().enumerate() {
                    match stage(ctx, wtxn, edge, index, &mut staged) {
                        Ok(()) => {}
                        Err(err) if out_of_room(&err) => {
                            return Ok((staged, index));
                        }
                        Err(err) => return Err(ChunkError::Edge(err)),
                    }
                }
                Ok((staged, pending.len()))
            },
        );
        let (staged, done) = match committed {
            Err(ChunkError::Edge(err)) => return Err(err),
            Err(ChunkError::Door(err)) => {
                tracing::warn!(
                    window = %ctx.window_key,
                    edges = pending.len(),
                    kind = ?err.kind(),
                    "forward remat: edge chunk transaction failed; replaying its edges one by one"
                );
                return Ok(0);
            }
            Ok(committed) => committed,
        };
        if done < pending.len() {
            tracing::warn!(
                window = %ctx.window_key,
                edges = pending.len() - done,
                "forward remat: edge chunk ran out of transaction room; replaying the rest one by one"
            );
        }
        for step in staged {
            match step {
                Staged::Terminal(id) => self.ledger.terminal_quarantines.extend(id),
                Staged::Written(src) => {
                    self.count += 1;
                    // ONE-1147: a healing edge write discharges the SOURCE
                    // entity's needs-remat marker (Observer B's edge batch
                    // swallow site marks lost upserts by source id).
                    if self.ledger.marked.contains(&src.to_hex()) {
                        self.ledger.healed.push(src);
                    }
                }
                Staged::Deferred(index) => {
                    // Deferral, not a rejection: cross-window endpoints
                    // arrive later; the edge stays in the CRDT and
                    // re-materializes when its endpoints do.
                    tracing::debug!(
                        edge = %pending[index].key,
                        "forward remat: edge deferred — endpoint absent"
                    );
                }
            }
        }
        Ok(done)
    }

    /// Replays one queued edge in its own transactions, as the pass always
    /// has: the path a chunk takes when its door fails or runs out of
    /// room.
    fn replay_one(&mut self, edge: &PendingEdge<'_>) -> Result<()> {
        let ctx = self.ctx;
        let vault = ctx.vault;
        let window_key = ctx.window_key.as_str();
        match &edge.queued {
            Queued::Quarantine { terminal, err } => {
                quarantine::quarantine_rejected_op(
                    vault,
                    window_key,
                    QuarantineContainer::Edges,
                    edge.key,
                    err,
                    &edge.buf,
                )?;
                self.ledger.terminal_quarantines.extend(*terminal);
                Ok(())
            }
            Queued::Main(work) => {
                let result = vault.with_write_txn_grouped(|wtxn| {
                    apply_edge_in_txn(ctx, wtxn, edge.key, &edge.buf, work)
                });
                match result {
                    Ok(EdgeRematOutcome::Written) => {
                        self.count += 1;
                        // ONE-1147: a healing edge write discharges the SOURCE
                        // entity's needs-remat marker (Observer B's edge batch
                        // swallow site marks lost upserts by source id).
                        if self.ledger.marked.contains(&work.src.to_hex()) {
                            self.ledger.healed.push(work.src);
                        }
                    }
                    Ok(EdgeRematOutcome::Unchanged) => {}
                    Ok(EdgeRematOutcome::Deferred) => {
                        // Deferral, not a rejection: cross-window endpoints
                        // arrive later; the edge stays in the CRDT and
                        // re-materializes when its endpoints do.
                        tracing::debug!(
                            edge = %edge.key,
                            "forward remat: edge deferred — endpoint absent"
                        );
                    }
                    // Its wait moved into the ledger, so a replay-origin marker
                    // its source holds clears as a terminal quarantine's does:
                    // only with no other work of the source pending (FIX 6204).
                    Ok(EdgeRematOutcome::Waiting) => {
                        self.ledger.terminal_quarantines.push(work.src);
                    }
                    Ok(EdgeRematOutcome::Quarantined) => {
                        // The reserved-kind rejection and its durable evidence
                        // committed in the edge txn above. Keep iterating: one
                        // forged row must not starve the other N-1 edge heals.
                        self.ledger.terminal_quarantines.push(work.src);
                    }
                    Err(err) if quarantine::remote_rejection_reason(&err).is_some() => {
                        quarantine::quarantine_rejected_op(
                            vault,
                            window_key,
                            QuarantineContainer::Edges,
                            edge.key,
                            &err,
                            &edge.buf,
                        )?;
                        self.ledger.terminal_quarantines.push(work.src);
                    }
                    Err(err) => {
                        // LOCAL failure — fail closed.
                        return Err(err);
                    }
                }
                Ok(())
            }
        }
    }

    /// Replays one Parent edge through its own door transaction, as the
    /// pass always has: the Parent coordinator owns envelope, deletion
    /// policy, admission, pending work and terminal evidence for the key,
    /// and stays per edge.
    fn replay_parent(
        &mut self,
        src: EntityId,
        tgt: EntityId,
        buf: &[u8],
        tombstoned: bool,
    ) -> Result<()> {
        let vault = self.ctx.vault;
        let window_key = self.ctx.window_key.as_str();
        match vault.with_write_txn_grouped(|wtxn| {
            bridge::submit_parent_in_txn(vault, wtxn, window_key, src, tgt, buf, tombstoned)
        }) {
            Ok(bridge::ParentOutcome::Written) => {
                self.count += 1;
                if self.ledger.marked.contains(&src.to_hex()) {
                    self.ledger.healed.push(src);
                }
            }
            Ok(bridge::ParentOutcome::Waiting) => {
                self.ledger.pending_dag_parent_sources.insert(src);
            }
            Ok(bridge::ParentOutcome::Rejected) => self.ledger.terminal_quarantines.push(src),
            Ok(bridge::ParentOutcome::Unchanged | bridge::ParentOutcome::Ignored) => {}
            Err(local) => return Err(local),
        }
        Ok(())
    }
}

/// Classifies one edge before any write: malformed carriers queue their
/// quarantine row, Parent edges go to their own door, tombstoned
/// endpoints skip, and the rest queue their mandate-checked write. The
/// residence read stays a fresh read transaction per edge, as it was;
/// only the writes share the chunk's door transaction. An `Err` is a
/// local failure that stops the pass.
fn gate(ctx: &RematCtx<'_>, key: &str, buf: Option<&[u8]>) -> Result<Gate> {
    let vault = ctx.vault;
    let window_key = ctx.window_key;
    let tombstones = &ctx.tombstones;
    // ONE-1157 (edge-pass parity, same gap as the entity pass):
    // non-Binary value where an edge value belongs — quarantined
    // like Observer B's non-Binary edge arm, never an invisible
    // skip.
    let Some(buf) = buf else {
        return Ok(Gate::Queued(Queued::Quarantine {
            terminal: quarantine::remat_marker_entity_for_quarantine(
                QuarantineContainer::Edges,
                key,
            ),
            err: Error::InvalidKey,
        }));
    };
    let Some((src, kind, tgt)) = bridge::parse_edge_key(key) else {
        return Ok(Gate::Queued(Queued::Quarantine {
            terminal: None,
            err: Error::InvalidKey,
        }));
    };

    // The Parent coordinator owns envelope, deletion policy,
    // admission, pending work and terminal evidence for this key.
    // Do not let a generic early exit strand an older obligation.
    if kind == crate::edge::EdgeKind::Parent {
        let tombstoned = tombstones.contains(&src) || tombstones.contains(&tgt);
        return Ok(Gate::Parent {
            src,
            tgt,
            tombstoned,
        });
    }

    // Decode BEFORE the tombstone/endpoint gates (mirrors Observer
    // B's ordering in bridge.rs): a malformed value is a remote
    // rejection regardless of endpoint state, and decode has no side
    // effects. Checking endpoints first would silently defer a
    // valid-key malformed edge whose endpoint is absent — no x: row.
    let decoded = match decode_edge_value_for_kind(kind, buf) {
        Ok(decoded) => decoded,
        Err(err) => {
            return Ok(Gate::Queued(Queued::Quarantine {
                terminal: Some(src),
                err,
            }));
        }
    };

    let soft_addressing = kind == crate::edge::EdgeKind::AddressedTo
        && crate::recovery::retained_soft_shell(ctx.doc, tombstones, &src).is_some();
    if soft_addressing {
        // Ordinary peer replay has no body proof after a soft erase.
        // Only canonical recovery's validated BaseEdge may retain it.
        let Some(snapshot) = ctx.trusted else {
            return Ok(Gate::Skip);
        };
        match crate::recovery::trusted_soft_addressing_edge(snapshot, &src, &tgt, buf) {
            Ok(true) => {}
            Ok(false) => {
                return Err(
                    crate::error::RegistryError::ReservedEdgeKind("conversation_dag").into(),
                );
            }
            Err(error) => {
                return Err(error);
            }
        }
    }

    let residence = (|| {
        let txn = vault.store.env.read_txn()?;
        crate::sync::types::edge_belongs_to_window_in(
            vault, &txn, ctx.doc, tombstones, &src, &tgt, window_key,
        )
    })();
    match residence {
        Ok(true) => {}
        Ok(false) => {
            return Ok(Gate::Queued(Queued::Quarantine {
                terminal: Some(src),
                err: Error::InvalidConfig("edge outside window residence".into()),
            }));
        }
        Err(err) => {
            return Err(err);
        }
    }

    // Never re-add an edge whose endpoint is tombstoned in the CRDT.
    // ANY-value, entity-canonical presence — a non-binary tombstone
    // gates too, and a case-shifted hex alias still names the id.
    if (tombstones.contains(&src)
        && crate::recovery::retained_soft_shell(ctx.doc, tombstones, &src).is_none())
        || (tombstones.contains(&tgt)
            && crate::recovery::retained_soft_shell(ctx.doc, tombstones, &tgt).is_none())
    {
        return Ok(Gate::Skip);
    }

    Ok(Gate::Queued(Queued::Main(EdgeWork {
        src,
        kind,
        tgt,
        decoded,
        soft_addressing,
    })))
}

/// Applies one queued edge of a chunk in `parent`: a refused carrier
/// lands its `x:` row, and a mandate-checked write runs in a savepoint
/// child of its own, so its failure rolls back that edge alone. Stages
/// what the pass records once `parent` commits. An `Err` stops the chunk
/// there: a child out of room hands this edge on to the one-by-one path,
/// and any other error (a quarantine write or a local edge failure)
/// stops the pass.
fn stage(
    ctx: &RematCtx<'_>,
    parent: &mut heed::RwTxn<'_>,
    edge: &PendingEdge<'_>,
    index: usize,
    staged: &mut Vec<Staged>,
) -> Result<()> {
    let vault = ctx.vault;
    let window_key = ctx.window_key.as_str();
    match &edge.queued {
        Queued::Quarantine { terminal, err } => {
            quarantine_in(vault, window_key, parent, edge.key, &edge.buf, err)?;
            staged.push(Staged::Terminal(*terminal));
            Ok(())
        }
        Queued::Main(work) => {
            match savepoint(vault, parent, |child| {
                apply_edge_in_txn(ctx, child, edge.key, &edge.buf, work)
            }) {
                Err(err) if out_of_room(&err) => Err(err),
                Err(err) if quarantine::remote_rejection_reason(&err).is_some() => {
                    quarantine_in(vault, window_key, parent, edge.key, &edge.buf, &err)?;
                    staged.push(Staged::Terminal(Some(work.src)));
                    Ok(())
                }
                Err(err) => Err(err),
                Ok(EdgeRematOutcome::Written) => {
                    staged.push(Staged::Written(work.src));
                    Ok(())
                }
                Ok(EdgeRematOutcome::Unchanged) => Ok(()),
                Ok(EdgeRematOutcome::Deferred) => {
                    staged.push(Staged::Deferred(index));
                    Ok(())
                }
                // Its wait moved into the ledger, so a replay-origin marker
                // its source holds clears as a terminal quarantine's does:
                // only with no other work of the source pending (FIX 6204).
                Ok(EdgeRematOutcome::Waiting) => {
                    staged.push(Staged::Terminal(Some(work.src)));
                    Ok(())
                }
                Ok(EdgeRematOutcome::Quarantined) => {
                    // The reserved-kind rejection and its durable evidence
                    // landed in the edge's savepoint above. Keep iterating:
                    // one forged row must not starve the other N-1 edge
                    // heals.
                    staged.push(Staged::Terminal(Some(work.src)));
                    Ok(())
                }
            }
        }
    }
}

/// Writes a refused edge's `x:` row in a child of `parent`: a failed
/// write leaves nothing behind, as its own transaction did.
fn quarantine_in(
    vault: &Vault,
    window_key: &str,
    parent: &mut heed::RwTxn<'_>,
    key: &str,
    buf: &[u8],
    err: &Error,
) -> Result<()> {
    savepoint(vault, parent, |child| {
        quarantine::quarantine_rejected_op_in_txn(
            vault,
            child,
            window_key,
            QuarantineContainer::Edges,
            key,
            err,
            buf,
        )
    })
    .map(|_| ())
}

/// Whether a child failed for want of room in its parent. An edge that
/// fits no transaction fails this way on every pass; in one of its own it
/// fails alone, so it cannot starve the edges after it.
fn out_of_room(error: &Error) -> bool {
    matches!(
        error,
        Error::MapFull | Error::Storage(heed::Error::Mdb(heed::MdbError::TxnFull))
    )
}

/// Runs `apply` in a child of `parent`, committed into it only on success: a
/// failure rolls back that child's writes alone.
fn savepoint<T>(
    vault: &Vault,
    parent: &mut heed::RwTxn<'_>,
    apply: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<T>,
) -> Result<T> {
    let mut child = vault.store.env.nested_write_txn(parent)?;
    let applied = apply(&mut child)?;
    child.commit()?;
    Ok(applied)
}
