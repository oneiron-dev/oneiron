//! Typed passport heads and recorded revisions through the caller's own read lane.
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::calendar::claims::{
    CalendarPassportValue, PREDICATE_CALENDAR_PASSPORT, decode_passport_value,
};
use crate::claim::{
    ClaimReadStatus, ClaimSubject, PointRead, ScopedReadResult, claim_surfaceable,
    decode_claim_body,
};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_EVENT;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarPassportReadRequest {
    pub event_ref: String,
    pub system: String,
    pub uid: String,
}

/// Approval and lifecycle are explicit: a recorded proposal is not an admitted head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarPassportRevision {
    pub claim_ref: String,
    pub event_ref: String,
    pub recorded_at: u64,
    pub approval: String,
    pub lifecycle: String,
    pub stale: bool,
    pub passport: CalendarPassportValue,
}

impl Memory<'_> {
    pub fn calendar_passport_read(
        &self,
        request: &CalendarPassportReadRequest,
    ) -> MemoryResult<ScopedReadResult<Option<CalendarPassportRevision>>> {
        let result = self.calendar_passport_revisions(request, ClaimReadStatus::Surfaceable)?;
        if result.value.len() > 1 {
            return Err(MemoryError::bad_request("competing admitted calendar passports")
                .with_read_receipt(result.receipt));
        }
        Ok(result.map(|mut rows| rows.pop()))
    }

    /// Includes pending, rejected and superseded revisions, under the same
    /// recorded-read authority as claims.history. It grants no import consent.
    pub fn calendar_passport_history(
        &self,
        request: &CalendarPassportReadRequest,
    ) -> MemoryResult<ScopedReadResult<Vec<CalendarPassportRevision>>> {
        self.calendar_passport_revisions(request, ClaimReadStatus::Recorded)
    }

    fn calendar_passport_revisions(
        &self,
        request: &CalendarPassportReadRequest,
        status: ClaimReadStatus,
    ) -> MemoryResult<ScopedReadResult<Vec<CalendarPassportRevision>>> {
        if request.system.is_empty() || request.uid.is_empty() {
            return Err(MemoryError::bad_request(
                "passport system and uid must be non-empty",
            ));
        }
        let event = EntityId::from_hex(&request.event_ref)?;
        let lane = self.read_lane(status)?;
        let event_read = lane.read(&[PointRead::id(event)], None)?;
        let mut receipt = event_read.receipt;
        if !event_read
            .value
            .into_iter()
            .flatten()
            .any(|row| row.entity_type == ENTITY_TYPE_EVENT)
        {
            return Ok(ScopedReadResult {
                value: Vec::new(),
                receipt,
            });
        }
        let ids = self.vault().claims_for_subject(&event)?;
        let reads: Vec<_> = ids.into_iter().map(PointRead::id).collect();
        let read = lane.read_projected(&reads, None, |txn, rows| -> MemoryResult<_> {
            let mut revisions = Vec::new();
            for row in rows.into_iter().flatten() {
                let Some(bytes) = row.body else {
                    continue;
                };
                let body = decode_claim_body(&bytes, true)?;
                if body.predicate != PREDICATE_CALENDAR_PASSPORT
                    || body.subject != ClaimSubject::Entity(event)
                {
                    continue;
                }
                if status == ClaimReadStatus::Surfaceable
                    && (!claim_surfaceable(&body)
                        || !crate::gate::claim_critical_confirm_settled_in_txn(
                            &self.vault().store,
                            txn,
                            &row.id,
                        )?)
                {
                    continue;
                }
                let passport = decode_passport_value(&body.value)
                    .map_err(|error| MemoryError::bad_request(error.to_string()))?;
                if passport.system != request.system || passport.uid != request.uid {
                    continue;
                }
                revisions.push(CalendarPassportRevision {
                    claim_ref: row.id.to_hex(),
                    event_ref: event.to_hex(),
                    recorded_at: row.learned_at,
                    approval: body.approval.as_str().to_owned(),
                    lifecycle: body.lifecycle.as_str().to_owned(),
                    stale: body.stale,
                    passport,
                });
            }
            revisions.sort_unstable_by(|a, b| {
                (a.recorded_at, &a.claim_ref).cmp(&(b.recorded_at, &b.claim_ref))
            });
            Ok(revisions)
        })?;
        receipt.restrict_with(&read.receipt);
        Ok(ScopedReadResult {
            value: read.value,
            receipt,
        })
    }
}
