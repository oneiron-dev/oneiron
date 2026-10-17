//! A verb hook run's saved copy (ARCH-0080 §6 Replay): the exact input its
//! body saw, the reads it made and what it returned, so replay runs the body
//! on it again. It commits in the chain's write, with the run's receipt and
//! its run index row.

use serde::{Deserialize, Serialize};

use crate::runtime_hooks::store::{self, HookReadPin, HookRunRef, RunKey};
use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::pack_catalog::HookPhase;
use crate::{EntityId, Result, Vault};

use super::InvocationId;

/// Each verb run's saved copy, by run key.
pub(in crate::runtime_hooks) const VERB_RUNS: SideTable<RunKey, HookVerbRunRecord, Named> =
    SideTable::new(&side_table::HOOKS_VERB_RUN);

/// One verb hook run: its hook, its call, what its body saw and read, and
/// what it returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::runtime_hooks) struct HookVerbRunRecord {
    #[serde(with = "crate::serialize::entity_ref")]
    pub(in crate::runtime_hooks) binding: EntityId,
    #[serde(with = "crate::serialize::entity_ref")]
    pub(in crate::runtime_hooks) code: EntityId,
    pub(in crate::runtime_hooks) body_hash: String,
    pub(in crate::runtime_hooks) invocation: InvocationId,
    pub(in crate::runtime_hooks) phase: HookPhase,
    pub(in crate::runtime_hooks) verb: String,
    /// The exact input the body saw; `None` past the pin bound.
    pub(in crate::runtime_hooks) input_json: Option<String>,
    pub(in crate::runtime_hooks) input_hash: String,
    pub(in crate::runtime_hooks) reads: Vec<HookReadPin>,
    /// The outcome the body returned, as it returned it; `None` when it
    /// returned none or past the outcome bound.
    pub(in crate::runtime_hooks) outcome_json: Option<String>,
    /// The outcome kind, or `refused`, `failed` or `timed_out`, as the
    /// receipt tells it.
    pub(in crate::runtime_hooks) outcome: String,
    pub(in crate::runtime_hooks) reason: Option<String>,
    pub(in crate::runtime_hooks) receipt_id: String,
    pub(in crate::runtime_hooks) duration_ms: u64,
    /// Unix milliseconds, as the body saw it.
    pub(in crate::runtime_hooks) now: u64,
    /// Unix milliseconds of the write: its place in the run index.
    pub(in crate::runtime_hooks) committed_at: u64,
}

/// Saves `record` under `key` and indexes it at its write time. A retried
/// invocation writes the same run again; its earlier index row goes.
pub(super) fn put_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &RunKey,
    record: &HookVerbRunRecord,
) -> Result<()> {
    let previous = VERB_RUNS
        .get(&vault.store, txn, key)?
        .map(|old| old.committed_at);
    VERB_RUNS.put(vault, txn, key, record)?;
    store::index_run_in_txn(
        vault,
        txn,
        record.binding,
        previous,
        record.committed_at,
        HookRunRef::Verb(*key),
    )
}
