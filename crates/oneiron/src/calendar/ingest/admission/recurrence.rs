//! Detached recurrence admission: UID still resolves the master, never the exception.
use super::*;
use crate::calendar::claims::{PREDICATE_CALENDAR_SERIES_EXCEPTION, decode_series_exception_value};
use crate::calendar::passport::{classify_event_passport, resolve_event_by_uid};
impl PollAdmission<'_> {
    pub(super) fn apply_exception(
        &mut self,
        event: &ParsedVEvent,
        original: u64,
    ) -> Result<(), CalendarError> {
        let master = resolve_event_by_uid(self.vault, &event.uid)?
            .ok_or_else(|| ingest("recurrence exception has no master"))?;
        let event_ref = exception_id(master, original)?;
        let exists = match self.vault.get_entity_type(&event_ref)? {
            None => false,
            Some(ENTITY_TYPE_EVENT) => true,
            Some(_) => return Err(ingest("recurrence identity collides with another kind")),
        };
        let decision = classify_event_passport(
            self.vault,
            event_ref,
            self.system,
            &event.uid,
            event.sequence,
            event.content_hash,
        )?;
        if matches!(decision, PassportDecision::SkipUnchanged { .. }) {
            return Ok(());
        }
        let exception_value = rmpv::Value::Map(vec![
            ("master_ref".into(), rmpv::Value::from(master.to_hex())),
            ("uid".into(), event.uid.as_str().into()),
            ("original_start_utc".into(), original.into()),
        ]);
        crate::calendar::claims::validate_calendar_claim_value(
            PREDICATE_CALENDAR_SERIES_EXCEPTION,
            &exception_value,
        )?;
        if exists {
            self.rewrite_event(event_ref, event)?;
        } else {
            self.mint_event_with_id(event, event_ref)?;
        }
        self.admit_properties(event_ref, event)?;
        let mut active = false;
        for id in self.vault.claims_for_subject(&event_ref)? {
            if self.vault.get_claim(&id)?.is_some_and(|body| {
                body.predicate == PREDICATE_CALENDAR_SERIES_EXCEPTION
                    && body.lifecycle == ClaimLifecycleStatus::Active
            }) {
                active = true;
                break;
            }
        }
        if !active {
            self.admit_screened(
                event_ref,
                &screen_body(event),
                &self.source_record_id(event),
                PREDICATE_CALENDAR_SERIES_EXCEPTION,
                exception_value,
            )?;
        }
        match decision {
            PassportDecision::UpdateExisting { .. } => {
                let next = self.passport_value(event_ref, event, CalendarPassportPresence::Live)?;
                self.admit_superseding_passport(event_ref, &next, &screen_body(event))?;
            }
            _ => self.admit_fresh_passport(event_ref, event)?,
        }
        if !event.cancelled {
            self.clear_absence_cancellation(event_ref)?;
        }
        self.apply_imported_cancel(event_ref, event)?;
        Ok(())
    }
    pub(super) fn clear_absence_cancellation(&self, event: EntityId) -> Result<(), CalendarError> {
        for id in self.vault.claims_for_subject(&event)? {
            if let Some(body) = self.vault.get_claim(&id)?
                && body.predicate == PREDICATE_CALENDAR_STATUS
                && body.lifecycle == ClaimLifecycleStatus::Active
            {
                let status = decode_status_value(&body.value)?;
                if status.basis == CalendarStatusBasis::ImportedAbsence {
                    self.vault.retract_claim(&id, self.now)?;
                }
            }
        }
        Ok(())
    }
    pub(super) fn exception_start(&self, event: EntityId) -> Result<Option<u64>, CalendarError> {
        for id in self.vault.claims_for_subject(&event)? {
            if let Some(body) = self.vault.get_claim(&id)?
                && body.predicate == PREDICATE_CALENDAR_SERIES_EXCEPTION
            {
                return Ok(Some(
                    decode_series_exception_value(&body.value)?.original_start_utc,
                ));
            }
        }
        Ok(None)
    }
    pub(super) fn retract_exception_mask(&self, event: EntityId) -> Result<(), CalendarError> {
        for id in self.vault.claims_for_subject(&event)? {
            if let Some(body) = self.vault.get_claim(&id)?
                && body.predicate == PREDICATE_CALENDAR_SERIES_EXCEPTION
                && body.lifecycle == ClaimLifecycleStatus::Active
            {
                self.vault.retract_claim(&id, self.now)?;
            }
        }
        Ok(())
    }
}

pub(super) fn exception_id(master: EntityId, original: u64) -> Result<EntityId, CalendarError> {
    let key = [&master.as_bytes()[..], &original.to_be_bytes()[..]].concat();
    Ok(derive_entity_id(
        b"oneiron:calendar-series-exception:v1",
        &key,
    )?)
}
