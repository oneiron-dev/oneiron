//! Typed, caller-bound calendar origin creation. Imported origins belong to ICS admission.
use serde::{Deserialize, Serialize};

use crate::calendar::origin::CalendarEventInput;
use crate::calendar::{CalendarOrigin, CalendarRangeDto};
use crate::claim::ClaimReadStatus;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::{EntityId, WriteActor};

/// The origin union forbids extraction evidence on native entries and requires
/// it on extracted entries. Recorded time and actor are always engine-stamped.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "origin", rename_all = "snake_case", deny_unknown_fields)]
pub enum CalendarEventCreateRequest {
    Native {
        summary: String,
        #[serde(rename = "occurredAt")]
        occurred_at: CalendarRangeDto,
    },
    Dreamer {
        summary: String,
        #[serde(rename = "occurredAt")]
        occurred_at: CalendarRangeDto,
        #[serde(rename = "evidenceTurnIds")]
        evidence_turn_ids: Vec<String>,
        #[serde(rename = "sourceFrontiers")]
        source_frontiers: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarEventCreated {
    pub event_ref: String,
    pub origin: String,
    pub recorded_at: u64,
}

impl Memory<'_> {
    /// Birth and recorded origin use the existing atomic calendar projector,
    /// under this caller's writer and evidence-read lane, not an import actor.
    pub fn calendar_create(
        &self,
        request: &CalendarEventCreateRequest,
    ) -> MemoryResult<CalendarEventCreated> {
        let (input, occurred) = match request {
            CalendarEventCreateRequest::Native {
                summary,
                occurred_at,
            } => (
                CalendarEventInput {
                    origin: Some(CalendarOrigin::Native),
                    name: summary.clone(),
                    ..Default::default()
                },
                *occurred_at,
            ),
            CalendarEventCreateRequest::Dreamer {
                summary,
                occurred_at,
                evidence_turn_ids,
                source_frontiers,
            } => (
                CalendarEventInput {
                    origin: Some(CalendarOrigin::Dreamer),
                    name: summary.clone(),
                    evidence_turn_ids: evidence_turn_ids
                        .iter()
                        .map(|reference| {
                            EntityId::from_hex(reference)
                                .map_err(|_| MemoryError::bad_request("invalid evidence TURN ref"))
                        })
                        .collect::<MemoryResult<Vec<_>>>()?,
                    source_frontiers: source_frontiers.clone(),
                    ..Default::default()
                },
                *occurred_at,
            ),
        };
        let origin = input.validate()?;
        if !occurred.is_ordered() {
            return Err(MemoryError::bad_request(
                "calendar range start must not exceed end",
            ));
        }
        let vault = self.vault();
        let event = vault.store.clock.entity_id()?;
        let recorded_at = vault.now_recorded_at();
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        self.with_verified_actor_write_txn(|txn| {
            if !lane
                .entities_readable_in_txn(txn, &input.evidence_turn_ids)?
                .into_iter()
                .all(|readable| readable)
            {
                return Err(MemoryError::not_found(
                    "calendar evidence is absent or withheld",
                ));
            }
            vault.stage_calendar_event(
                txn,
                &input,
                occurred.to_time_range(),
                WriteActor::new(self.actor(), self.actor_class()),
                event,
                recorded_at,
            )?;
            Ok(())
        })?;
        self.produced_from(input.evidence_turn_ids.iter().copied().chain([event]));
        Ok(CalendarEventCreated {
            event_ref: event.to_hex(),
            origin: origin.as_str().to_owned(),
            recorded_at,
        })
    }
}
