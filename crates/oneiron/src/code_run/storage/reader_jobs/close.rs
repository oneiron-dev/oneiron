//! Existing base spend scopes whose reader rows evaporated on explicit close.

use super::JOBS;
use crate::agent_dispatch::AgentDispatcher;
use crate::code_run::{ReaderJob, ReaderJobState};
use crate::side_table::{RawValue, SideKey};
use crate::{EntityId, Error, Result, Vault};

/// Visits only the final, retired overlay's live reader-job rows. Private
/// payloads remain borrowed here; only the existing attempt's units and ids
/// are settled in base. No job, finding or wait is copied into base.
pub(crate) fn settle_evaporated_reader_spend(
    vault: &Vault,
    session_ref: &str,
    key: &[u8],
    value: &[u8],
    now: u64,
) -> Result<()> {
    let Some(suffix) = key.strip_prefix(JOBS.decl().prefix) else {
        return Ok(());
    };
    let task =
        EntityId::decode_key(suffix).ok_or(Error::CorruptedIndex("code-run reader job key"))?;
    let job =
        ReaderJob::from_raw(value).map_err(|_| Error::CorruptedIndex("code-run reader job"))?;
    if job.task != task {
        return Err(Error::CorruptedIndex("code-run reader job task"));
    }
    if job.binding.route.session_ref.as_deref() != Some(session_ref)
        || job.binding.spend.scope().is_none()
        || !matches!(job.state, ReaderJobState::Queued | ReaderJobState::Active)
    {
        return Ok(());
    }
    AgentDispatcher::new(vault).settle_child(&job.attempt, now)?;
    Ok(())
}
