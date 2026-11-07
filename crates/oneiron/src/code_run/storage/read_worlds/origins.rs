//! The origins one run's results carry to another run (FIX 7084): the worlds
//! of the run's read-world ledger and the row scopes it proves, read once,
//! on the run's route, when a descriptor of one of its results is made. The
//! descriptor keeps them. A later read of the result by another run notes
//! the kept origins, never this ledger as it stands then.

use heed::RoTxn;

use super::{HEADERS, HeaderKey, ROW_SCOPES, ROW_TAG, ReadWorldSeal, SEEN, seen_prefix};
use crate::code_run::{ExecutorStorage, OriginsUnion, ResultOrigins};
use crate::side_table::SideTableDbs;
use crate::{EntityId, Result};

/// The origins of `run`'s results as its ledger stands in `txn` through
/// `dbs`, when the ledger is complete there: it began with the run, misses
/// nothing, and the one epoch it holds open is the one `seal` names. Every
/// world it holds, the scope of each row whose every proof agrees, and each
/// row whose proofs disagree or one of which proves no scope
/// ([`OriginsUnion`]). `None` when the ledger is not complete.
fn result_origins_in(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    run: EntityId,
    seal: ReadWorldSeal,
) -> Result<Option<ResultOrigins>> {
    let Some(header) = HEADERS.get(dbs, txn, &HeaderKey(run))? else {
        return Ok(None);
    };
    if !header.unknown.is_empty() || header.open.iter().any(|epoch| *epoch != seal.epoch) {
        return Ok(None);
    }
    let mut union = OriginsUnion::default();
    for key in SEEN.scan_keys(dbs, txn, &seen_prefix(run))? {
        union.add_world(key.world);
    }
    let mut prefix = run.as_bytes().to_vec();
    prefix.push(ROW_TAG);
    for row in ROW_SCOPES.iter_from(dbs, txn, &prefix)? {
        let (key, proof) = row?;
        match &proof.scope {
            Some(scope) => union.add_row_scope(key.row, scope),
            None => union.add_conflicted_row(key.row),
        }
    }
    Ok(Some(union.finish()))
}

impl ExecutorStorage<'_> {
    /// The origins of `run`'s results as its ledger stands now
    /// ([`result_origins_in`]) under `seal`, in one read of the run's route.
    pub(crate) fn result_origins(
        &self,
        run: EntityId,
        seal: ReadWorldSeal,
    ) -> Result<Option<ResultOrigins>> {
        self.reader_read(|txn, dbs| result_origins_in(&dbs, txn, run, seal))
    }
}
