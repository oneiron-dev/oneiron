//! A blocked report's replay source (FIX 2343, OF-380). A report whose run is
//! no agent dispatch's attempt (a standalone or MCP run, or one with no
//! durable run) names nothing a code fix could replay, so the host keeps
//! what it knows of the run with the report, in the commit that files it:
//! the model request the run's executor bound before it sent the failing
//! call, whole, the run, the reporter, and the scope the run's host gave it.
//! A caller outside this engine, which never gave it a model request, keeps
//! its report and a source with no request: its replay is unavailable, and
//! nothing stands in for the instructions it never sent. Capture is
//! prospective: a report filed before it has no source. The source stays
//! after the Coach settles the report, so a later candidate replays it too,
//! and an erase of the reporter takes it.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// Key: the receipt.
const SOURCE: SideTable<EntityId, BlockedReplaySource, Named> =
    SideTable::new(&side_table::COACH_BLOCKED_SOURCE);

/// The model request a run's executor bound to its dispatcher before it
/// sent the call, as its host assembled it: host-owned, never guest text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BlockedRunRequest {
    /// The request's instructions: its system text, whole.
    pub(crate) instructions: String,
    /// What the call was briefed with beside its task; `None` when the host
    /// put no briefing apart from the task.
    pub(crate) briefing: Option<String>,
    /// The task the run's host gave it, whole.
    pub(crate) task: Option<String>,
}

/// What the run's host knows of it when it files a blocked report.
pub(crate) struct BlockedRunHost {
    /// The host's ref of the run.
    pub(crate) run_ref: String,
    /// The agent attempt the host bound the run to, if any.
    pub(crate) attempt: Option<AttemptId>,
    /// The model request the run's executor bound before the call; `None`
    /// when no request of the run reached this engine.
    pub(crate) request: Option<BlockedRunRequest>,
}

/// The worlds a run's host scoped it to, as the report's filing read them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum RunWorlds {
    /// The agent dispatch the run served: its scope's world and its task's.
    Scoped { worlds: Vec<EntityId> },
    /// The host bound the run to no dispatch: any world it could read may
    /// have been read.
    Unscoped,
    /// A world of the dispatch it served could not be proved.
    Unproved,
}

/// One blocked report's replay source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BlockedReplaySource {
    /// `None`: no model request of the run reached this engine, so its
    /// replay is unavailable.
    pub(crate) request: Option<BlockedRunRequest>,
    pub(crate) run_ref: String,
    /// The run's durable id, its code-run ref, when it had one.
    pub(crate) code_run: Option<EntityId>,
    /// The actor the report was witnessed for.
    pub(crate) reporter: EntityId,
    pub(crate) worlds: RunWorlds,
    pub(crate) reported_at: u64,
}

impl BlockedReplaySource {
    /// The longest text the source keeps, in bytes.
    pub(crate) fn longest_text(&self) -> usize {
        self.request.as_ref().map_or(0, |request| {
            [
                Some(request.instructions.as_str()),
                request.briefing.as_deref(),
                request.task.as_deref(),
            ]
            .into_iter()
            .flatten()
            .map(str::len)
            .max()
            .unwrap_or(0)
        })
    }
}

/// Keeps `source` for the report `receipt`, in the report's filing commit.
pub(super) fn put_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &EntityId,
    source: &BlockedReplaySource,
) -> Result<()> {
    SOURCE.put(&vault.store, txn, receipt, source)
}

/// The replay source the report `receipt` was filed with, if any.
pub(crate) fn blocked_source_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &EntityId,
) -> Result<Option<BlockedReplaySource>> {
    SOURCE.get(&vault.store, txn, receipt)
}

/// An erase of `actor` takes each source of a report witnessed for it, in
/// the erase's own writer: its request is that actor's run's. A row that
/// does not decode names no reporter and stays as it is.
pub(crate) fn erase_blocked_source_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let mut doomed = Vec::new();
    for row in SOURCE.iter_raw_from(&vault.store, &*wtxn, &[])? {
        let (key, bytes) = row?;
        if let Ok(source) = SOURCE.decode_value(&bytes)
            && source.reporter == *actor
            && let Ok(raw) = <[u8; 16]>::try_from(key.as_slice())
        {
            doomed.push(EntityId::from_bytes(raw)?);
        }
    }
    for receipt in &doomed {
        SOURCE.delete(&vault.store, wtxn, receipt)?;
    }
    Ok(())
}
