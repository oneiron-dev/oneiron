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

mod arc_status;

const RESULT: SideTable<AttemptId, ScopeSummaryResult, Named> =
    SideTable::new(&side_table::SCOPE_SUMMARY_RESULT);

/// Atomic durable landing result, retained across worker replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeSummaryResult {
    pub summary: String,
    pub claim: Option<String>,
    pub record: Option<String>,
}

/// The declaration's public state; parked and failed attempts name their reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScopeSummaryStatus {
    pub attempt: String,
    pub requester: String,
    pub current_attempt: String,
    pub state: String,
    pub result: Option<ScopeSummaryResult>,
    pub failure: Option<String>,
    pub retry_at: Option<u64>,
    pub updated_at: u64,
    /// Why an Arc declaration's row is still owed, typed (FIX 8060, 8291);
    /// `None` for every other summary, and for an Arc that owes nothing.
    pub arc_pending: Option<ArcPendingStatus>,
    /// Why the landed summary no longer reads as it was composed while it
    /// still serves (FIX 6321); `None` while it reads as composed.
    pub stale: Option<SummaryStale>,
}

/// Why an Arc is still owed (FIX 8060, 8291), as its row records it: the
/// cause's code is its `cause` tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "cause", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArcPendingStatus {
    /// A closed sitting below the Arc has no summary yet.
    ArcLowerPending { session: String },
    /// A TURN the Arc must read did not read for the Dreamer, by its id.
    ArcSourceUnavailable { handle: String },
    /// The Arc composes in parts: its work generation, the parts done and
    /// the parts still owed. Its queued attempt goes on at its next wake.
    ArcCompositionPending {
        work_id: String,
        parts_done: u64,
        parts_owed: u64,
    },
    /// The model's window holds the call's frame and not one character of
    /// a source beside it.
    ArcWindowTooSmall { window: u64, frame_tokens: u64 },
}

/// Why a landed summary is stale while it still serves (FIX 6321): its
/// re-derivation is queued by the change that made it so.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub enum SummaryStale {
    /// NOTEs it covers were edited since it was composed, by id.
    NoteSourceEdited { notes: Vec<String> },
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
        status_in_txn(self, &txn, attempt)
    }

    /// The summary attempt `session`'s close queued (FIX 7509), as the
    /// sitting's own `actor` polls it: `None` for any other actor, for a
    /// sitting still open, and for one that closed with none queued. One
    /// snapshot reads the sitting and its attempt.
    pub fn session_summary_status(
        &self,
        session: &EntityId,
        actor: EntityId,
    ) -> Result<Option<ScopeSummaryStatus>> {
        let txn = self.store.env.read_txn()?;
        let Some(record) = self.session_lifecycle_record_in_txn(&txn, session)? else {
            return Ok(None);
        };
        let Some(attempt) = record.summary_attempt.filter(|_| record.key.actor == actor) else {
            return Ok(None);
        };
        status_in_txn(self, &txn, AttemptId::from_bytes(&attempt)?).map(Some)
    }
}

/// One declaration's status, read whole in `txn`: its retry tip, that try's
/// queue row and park, and its landing result.
fn status_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<ScopeSummaryStatus> {
    let tip = crate::attempt_queue::AttemptQueue::from_store(&vault.store)
        .retry_tip_in_txn(txn, attempt)?;
    let (status, parked) = DreamerRunnerStore::new(vault)
        .status_with_park_in_txn(txn, tip.id)?
        .ok_or(Error::EntityNotFound)?;
    if status.payload.attempt_type != DREAMER_SCOPE_SUMMARY_ATTEMPT_TYPE {
        return Err(Error::EntityNotFound);
    }
    let request = decode_request(vault, txn, &status.payload.input)?;
    let result = result_in_txn(vault, txn, tip.id)?;
    let arc_pending = arc_status::arc_pending_in_txn(vault, txn, &status.payload.input);
    let stale = result
        .as_ref()
        .and_then(|result| stale_in_txn(vault, txn, &result.summary));
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
        arc_pending,
        stale,
    })
}

/// Why the landed `summary` is stale (FIX 6321). A summary that does not
/// read, or does not serve, reports none here: its reader answers that.
fn stale_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, summary: &str) -> Option<SummaryStale> {
    let summary = EntityId::from_hex(summary).ok()?;
    match super::doors::summary_stale_in_txn(vault, txn, &summary) {
        Ok(stale) => stale,
        Err(error) => {
            tracing::debug!(kind = ?error.kind(), "a summary's staleness did not read for its status");
            None
        }
    }
}
