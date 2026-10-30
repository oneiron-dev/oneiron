//! Due-time index for provider-outage parks carrying a retry hint.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

use super::store::DreamerRunnerStore;
use super::types::{DreamerParkCause, DreamerParkedAttemptRecord};

const OUTAGE_PARK_REASON: &str = "agent_run_provider_unavailable";
const OUTAGE_DUE: SideTable<(u64, AttemptId), (), Named> =
    SideTable::new(&side_table::DREAMER_OUTAGE_DUE);

/// Encodes a host door's relative retry hint on its park. No hint means no
/// timed resume: recovery or restart still resumes the park.
pub fn outage_park_reason(retry_after: Option<u64>) -> String {
    retry_after.map_or_else(
        || OUTAGE_PARK_REASON.to_owned(),
        |seconds| format!("{OUTAGE_PARK_REASON}:retry_after={seconds}"),
    )
}

/// The provider's retry hint on a host-door outage park, if it carried one.
pub fn outage_retry_after(reason: &str) -> Option<u64> {
    reason
        .strip_prefix(OUTAGE_PARK_REASON)?
        .strip_prefix(":retry_after=")?
        .parse()
        .ok()
}

fn outage_due_at(record: &DreamerParkedAttemptRecord) -> Option<u64> {
    if record.cause != DreamerParkCause::ProviderUnavailable {
        return None;
    }
    outage_retry_after(&record.reason)
        .map(|retry_after| record.parked_at.saturating_add(retry_after))
}

pub(crate) fn index_outage_due_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &DreamerParkedAttemptRecord,
) -> Result<()> {
    let Some(due_at) = outage_due_at(record) else {
        return Ok(());
    };
    OUTAGE_DUE.put(&vault.store, wtxn, &(due_at, record.attempt_id), &())
}

pub(crate) fn unindex_outage_due_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &DreamerParkedAttemptRecord,
) -> Result<()> {
    let Some(due_at) = outage_due_at(record) else {
        return Ok(());
    };
    OUTAGE_DUE.delete(&vault.store, wtxn, &(due_at, record.attempt_id))?;
    Ok(())
}

impl DreamerRunnerStore<'_> {
    /// Due outage-index keys, collected before any caller opens a write
    /// transaction. The first future key ends the read.
    pub fn due_outage_attempts(&self, now: u64) -> Result<Vec<(u64, AttemptId)>> {
        let rtxn = self.vault.store.env.read_txn()?;
        let mut due = Vec::new();
        for row in OUTAGE_DUE.iter_from(&self.vault.store, &rtxn, &[])? {
            let ((due_at, attempt), ()) = row?;
            if due_at > now {
                break;
            }
            due.push((due_at, attempt));
        }
        Ok(due)
    }

    /// Removes one stale due marker after the caller's primary-row recheck.
    pub fn delete_due_outage_marker(&self, due_at: u64, attempt: AttemptId) -> Result<()> {
        self.vault.with_write_txn_grouped(|wtxn| {
            OUTAGE_DUE.delete(&self.vault.store, wtxn, &(due_at, attempt))?;
            Ok(())
        })
    }
}
