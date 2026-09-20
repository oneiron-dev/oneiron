//! Value-only admission checks shared by feed polls and connector imports.
use super::*;
use crate::calendar::claims::validate_calendar_claim_value;

impl PollAdmission<'_> {
    pub(super) fn preflight_event(&self, event: &ParsedVEvent) -> Result<(), CalendarError> {
        super::super::property_claims::preflight(event)?;
        validate_calendar_claim_value(
            PREDICATE_CALENDAR_ORIGIN,
            &rmpv::Value::from(CalendarOrigin::Imported.as_str()),
        )?;
        // Direction can be inherited at admission. Every possible direction is
        // a closed enum token; all caller-controlled fields are identical here.
        let passport = CalendarPassportValue {
            system: self.system.to_owned(),
            uid: event.uid.clone(),
            last_sequence: event.sequence,
            content_hash: event.content_hash,
            direction: CalendarPassportDirection::Inbound,
            last_seen_at: self.now,
            presence: CalendarPassportPresence::Live,
        };
        validate_calendar_claim_value(
            PREDICATE_CALENDAR_PASSPORT,
            &crate::calendar::passport::encode_passport_value(&passport),
        )?;
        if event.cancelled {
            validate_calendar_claim_value(
                PREDICATE_CALENDAR_STATUS,
                &status_value(CalendarStatus::Cancelled, CalendarStatusBasis::ImportedCancel, self.now),
            )?;
        }
        Ok(())
    }
}

pub(super) fn status_value(
    status: CalendarStatus,
    basis: CalendarStatusBasis,
    now: u64,
) -> rmpv::Value {
    rmpv::Value::Map(vec![
        ("status".into(), status.as_str().into()),
        ("basis".into(), basis.as_str().into()),
        ("recorded_at".into(), now.into()),
    ])
}
