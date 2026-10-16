//! Caller-visible queued completion and failure, without exposing runner payloads.

use super::doors::LandedHeader;
use super::request::decode_request;
use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

const RESULT: SideTable<AttemptId, ScopeSummaryResult, Named> =
    SideTable::new(&side_table::SCOPE_SUMMARY_RESULT);

/// Atomic durable landing result, retained across worker replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeSummaryResult {
    pub summary: String,
    pub claim: Option<String>,
    pub record: Option<String>,
}

/// The declaration's public state; parked and failed attempts name their reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeSummaryStatus {
    pub attempt: String,
    pub requester: String,
    pub current_attempt: String,
    pub state: String,
    pub result: Option<ScopeSummaryResult>,
    pub failure: Option<String>,
    pub retry_at: Option<u64>,
    pub updated_at: u64,
}

pub(super) fn result_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Option<ScopeSummaryResult>> {
    RESULT.get(&vault.store, txn, &attempt)
}

pub(super) fn record_result_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    summary: EntityId,
    landed: Option<&LandedHeader>,
) -> Result<()> {
    RESULT.put(
        &vault.store,
        txn,
        &attempt,
        &ScopeSummaryResult {
            summary: summary.to_hex(),
            claim: landed.map(|header| header.claim.to_hex()),
            record: landed.and_then(|header| header.record.map(|id| id.to_hex())),
        },
    )
}

impl Vault {
    /// Reads one declaration only, never a generic queue payload. Wire adapters
    /// must bind the requester to their authenticated caller before returning it.
    pub fn scope_summary_status(&self, attempt: AttemptId) -> Result<ScopeSummaryStatus> {
        let txn = self.store.env.read_txn()?;
        let tip = crate::attempt_queue::AttemptQueue::from_store(&self.store)
            .retry_tip_in_txn(&txn, attempt)?;
        let runner = DreamerRunnerStore::new(self);
        let status = runner.status(tip.id)?.ok_or(Error::EntityNotFound)?;
        if status.payload.attempt_type != DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE {
            return Err(Error::EntityNotFound);
        }
        let request = decode_request(&status.payload.input)?;
        let parked = runner.parked_attempt(tip.id)?;
        let result = result_in_txn(self, &txn, tip.id)?;
        let state = if result.is_some() {
            "completed"
        } else if parked.is_some() {
            "parked"
        } else {
            status.attempt.state.as_str()
        };
        Ok(ScopeSummaryStatus {
            attempt: crate::entity_id::bytes_to_hex_lower(attempt.as_bytes()),
            requester: request.requester.entity_ref().to_hex(),
            current_attempt: crate::entity_id::bytes_to_hex_lower(tip.id.as_bytes()),
            state: state.to_owned(),
            result,
            failure: parked.map(|row| row.reason).or(status.attempt.last_error),
            retry_at: status.attempt.scheduled_at,
            updated_at: status.attempt.updated_at,
        })
    }
}
