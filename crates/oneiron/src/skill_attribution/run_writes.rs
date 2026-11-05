//! OF-540/OF-397: the write envelope of a leased agent run.
//!
//! While a leased run writes, the DerivedFrom edges its writes leave stored
//! are the run's own derivations. Each is recorded as the run's derivation
//! witness in the writing transaction ([`super::derivation_witness`]), so the
//! run's bind and close can witness what its output derived from
//! ([`super::witness_agent_run_close`]). Edges carry no attempt, so the run is
//! known only from its [`RunWriteToken`]: captured from the host's lease
//! before a write leaves the thread that holds it, and carried explicitly
//! (FIX 3103). The thread-local envelope is the synchronous adapter: a verb
//! call opens it on its own thread, and a write carried across a thread hop
//! opens it again from its token ([`with_run_write_token`]).

use std::cell::RefCell;

use crate::agent_def::AgentAuthorLease;
use crate::attempt_queue::AttemptQueue;
use crate::batch::BatchOp;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::memory::HostWriteOrigin;
use crate::store::Store;

use super::derivation_witness::{self, WitnessProducer};

thread_local! {
    static RUN_WRITES: RefCell<Option<RunWriteToken>> = const { RefCell::new(None) };
}

pub use oneiron_store::run_write_token::RunWriteToken;

/// The token of the run `lease` is the host lease of.
pub(crate) fn run_write_token_from_lease(lease: &AgentAuthorLease) -> RunWriteToken {
    RunWriteToken::of(lease.attempt, lease.owner.clone(), lease.generation)
}

/// The token of the leased run a host-bound write's `origin` carries:
/// the sealed lease binding the host read live as it built the origin.
/// `None` for an origin no leased run binds.
#[must_use]
pub fn run_write_token_of_origin(origin: &HostWriteOrigin) -> Option<RunWriteToken> {
    origin.task_host().map(|binding| {
        RunWriteToken::of(
            binding.parent(),
            binding.lease_owner().to_owned(),
            binding.attempt_count(),
        )
    })
}

/// Whether `token`'s run lease holds in `txn`, read only through it.
pub(super) fn run_write_lease_holds_in_txn(
    token: &RunWriteToken,
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> bool {
    AttemptQueue::from_store(store)
        .require_skill_load_lease_in_txn(txn, token.attempt(), token.owner(), token.generation())
        .is_ok()
}

/// The leased run one verb call writes for. Dropping it restores the
/// envelope it replaced.
pub(crate) struct RunWriteScope(Option<RunWriteToken>);

impl Drop for RunWriteScope {
    fn drop(&mut self) {
        let previous = self.0.take();
        RUN_WRITES.with(|slot| *slot.borrow_mut() = previous);
    }
}

/// Opens `token`'s write envelope on this thread until the scope drops: a
/// write the run makes outside a verb call, such as its executor's
/// compaction landing. `None` opens no run's envelope.
pub(crate) fn enter_run_write_token(token: Option<RunWriteToken>) -> RunWriteScope {
    RunWriteScope(RUN_WRITES.with(|slot| slot.replace(token)))
}

/// Opens `lease`'s write envelope on this thread for one verb call. A
/// grouped write runs its closure on the caller's thread, so every batch the
/// call applies sees it.
pub(crate) fn enter_run_writes(lease: &AgentAuthorLease) -> RunWriteScope {
    enter_run_write_token(Some(run_write_token_from_lease(lease)))
}

/// Runs `write` under `token`'s envelope on this thread: the synchronous
/// adapter a write opens on the far side of a thread hop, from the token its
/// caller captured before the hop. `None` runs it under no run's envelope.
pub fn with_run_write_token<T>(token: Option<&RunWriteToken>, write: impl FnOnce() -> T) -> T {
    let _scope = enter_run_write_token(token.cloned());
    write()
}

/// The token of the run whose envelope is open on this thread: what a
/// journaled off-record write keeps as its source run. `None` is unknown.
pub(crate) fn current_run_write_token() -> Option<RunWriteToken> {
    RUN_WRITES.with(|slot| slot.borrow().clone())
}

/// The DerivedFrom edges one batch creates under a leased run's envelope.
pub(crate) struct RunDerivations {
    token: RunWriteToken,
    pairs: Vec<(EntityId, EntityId)>,
}

/// The DerivedFrom edges `ops` create, as (derived, source), when a leased
/// run's envelope is open; none outside one or for a replayed promotion,
/// whose ops keep the run that journaled them instead.
pub(crate) fn run_derivations(ops: &[BatchOp], replay: bool) -> Option<RunDerivations> {
    if replay {
        return None;
    }
    let token = current_run_write_token()?;
    let pairs: Vec<_> = ops.iter().filter_map(derived_from_pair).collect();
    (!pairs.is_empty()).then_some(RunDerivations { token, pairs })
}

/// The (derived, source) pair a DerivedFrom edge op writes.
fn derived_from_pair(op: &BatchOp) -> Option<(EntityId, EntityId)> {
    match op {
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
    }
}

/// Records `derivations` as their run's witnesses once the batch has applied
/// them in `wtxn`: only edges the batch left stored, and only while the run's
/// lease holds. Every edge is kept; the chain's length is measured (Rule 5).
/// Capture-only: a witness that fails is dropped whole and the batch stands.
pub(crate) fn note_run_derivations_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    derivations: Option<&RunDerivations>,
) {
    if let Some(RunDerivations { token, pairs }) = derivations {
        derivation_witness::record_in_txn(store, wtxn, token, pairs, WitnessProducer::Write);
    }
}

/// Records `derived`'s DerivedFrom edge to `source`, which a writer stored
/// directly rather than through a batch, as a derivation of the run whose
/// envelope is open on this thread; nothing outside one. Capture-only.
pub(crate) fn note_direct_derivation_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    derived: EntityId,
    source: EntityId,
) {
    if let Some(token) = current_run_write_token() {
        derivation_witness::record_in_txn(
            store,
            wtxn,
            &token,
            &[(derived, source)],
            WitnessProducer::RevisionLink,
        );
    }
}

/// Records, in an authorized promotion's `wtxn`, the DerivedFrom edges among
/// `landed`, the ops it replayed, each under the run its journal entry
/// captured: never the promoter's, and nothing for an op no run journaled.
/// A run whose lease has ended has its credited outcomes reconciled (FIX
/// 3241). Capture-only, in one savepoint: a witness that fails is dropped
/// whole and the promotion stands.
pub(crate) fn note_promoted_ops_in_txn<'a>(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    landed: impl IntoIterator<Item = (&'a BatchOp, Option<&'a RunWriteToken>)>,
) {
    let mut runs: Vec<(&RunWriteToken, Vec<(EntityId, EntityId)>)> = Vec::new();
    for (op, source_run) in landed {
        let (Some(token), Some(pair)) = (source_run, derived_from_pair(op)) else {
            continue;
        };
        match runs.iter_mut().find(|(run, _)| *run == token) {
            Some((_, pairs)) => pairs.push(pair),
            None => runs.push((token, vec![pair])),
        }
    }
    if runs.is_empty() {
        return;
    }
    derivation_witness::capture_in_txn(&vault.store, wtxn, "promotion", |txn| {
        for (token, pairs) in &runs {
            if derivation_witness::record_pairs_in_txn(
                &vault.store,
                txn,
                token,
                pairs,
                WitnessProducer::Promotion,
            )? {
                derivation_witness::reconcile_landed_in_txn(vault, txn, token);
            }
        }
        Ok(())
    });
}
