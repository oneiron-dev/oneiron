//! OF-540/OF-397: the write envelope of a leased agent run.
//!
//! While a leased run's verb call writes, the DerivedFrom edges its batches
//! create are the run's own derivations. Base apply appends them to the run's
//! live attribution row in the same transaction, so the run's close can
//! witness what its output derived from ([`super::witness_agent_run_close`]).
//! Edges carry no attempt, so this envelope is the only place the run is
//! known.

use std::cell::RefCell;

use crate::agent_def::AgentAuthorLease;
use crate::attempt_queue::AttemptQueue;
use crate::batch::BatchOp;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::receipt::UsedProvenanceEdge;
use crate::store::Store;

use super::host::WITNESS_MAX_EDGES;

thread_local! {
    static RUN_WRITES: RefCell<Option<AgentAuthorLease>> = const { RefCell::new(None) };
}

/// The leased run one verb call writes for. Dropping it restores the
/// envelope it replaced.
pub(crate) struct RunWriteScope(Option<AgentAuthorLease>);

impl Drop for RunWriteScope {
    fn drop(&mut self) {
        let previous = self.0.take();
        RUN_WRITES.with(|slot| *slot.borrow_mut() = previous);
    }
}

/// Opens `lease`'s write envelope on this thread for one verb call. A
/// grouped write runs its closure on the caller's thread, so every batch the
/// call applies sees it.
pub(crate) fn enter_run_writes(lease: &AgentAuthorLease) -> RunWriteScope {
    RunWriteScope(RUN_WRITES.with(|slot| slot.borrow_mut().replace(lease.clone())))
}

/// The DerivedFrom edges one batch creates under a leased run's envelope.
pub(crate) struct RunDerivations {
    lease: AgentAuthorLease,
    pairs: Vec<(EntityId, EntityId)>,
}

/// The DerivedFrom edges `ops` create, as (derived, source), when a leased
/// run's envelope is open; none outside one or for a replayed promotion.
pub(crate) fn run_derivations(ops: &[BatchOp], replay: bool) -> Option<RunDerivations> {
    if replay {
        return None;
    }
    let lease = RUN_WRITES.with(|slot| slot.borrow().clone())?;
    let pairs: Vec<_> = ops
        .iter()
        .filter_map(|op| match op {
            BatchOp::Edge {
                src,
                kind: EdgeKind::DerivedFrom,
                tgt,
                ..
            }
            | BatchOp::PublicEdgeWithCreatedAt {
                src,
                kind: EdgeKind::DerivedFrom,
                tgt,
                ..
            }
            | BatchOp::EdgeWithCreatedAt {
                src,
                kind: EdgeKind::DerivedFrom,
                tgt,
                ..
            } => Some((*src, *tgt)),
            _ => None,
        })
        .collect();
    (!pairs.is_empty()).then_some(RunDerivations { lease, pairs })
}

/// Appends `derivations` to their run's live attribution row once the batch
/// has applied them in `wtxn`: only edges the batch left stored, only while
/// the run's lease holds and its row is bound, never past the receipt's cap.
pub(crate) fn note_run_derivations_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    derivations: Option<&RunDerivations>,
) -> Result<()> {
    let Some(RunDerivations { lease, pairs }) = derivations else {
        return Ok(());
    };
    if AttemptQueue::from_store(store)
        .require_skill_load_lease_in_txn(wtxn, lease.attempt, &lease.owner, lease.generation)
        .is_err()
    {
        return Ok(());
    }
    let Some(mut fields) =
        crate::receipt::attempt_pack_attribution_in_txn(store, wtxn, lease.attempt)?
    else {
        return Ok(());
    };
    let before = fields.used_edges.len();
    for (derived, source) in pairs {
        if fields.used_edges.len() >= WITNESS_MAX_EDGES {
            break;
        }
        if derived == source
            || fields
                .used_edges
                .iter()
                .any(|edge| edge.derived == *derived && edge.source == *source)
            || !store.port_edge_present(
                wtxn,
                derived,
                EdgeDirection::Out,
                EdgeKind::DerivedFrom,
                source,
            )?
        {
            continue;
        }
        fields.used_edges.push(UsedProvenanceEdge {
            derived: *derived,
            source: *source,
            check: None,
        });
    }
    if fields.used_edges.len() == before {
        return Ok(());
    }
    crate::receipt::put_attempt_pack_attribution_in_txn(store, wtxn, lease.attempt, &fields)
}
