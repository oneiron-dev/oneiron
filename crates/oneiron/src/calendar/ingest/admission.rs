//! Diff-to-claim admission path and its test module.

mod continuation;
mod import_claim;
mod preflight;
mod recurrence;
use super::ingest;
#[cfg(test)]
use super::poll::IcsFeedPollConfig;
use crate::calendar::CalendarError;
use crate::calendar::claims::{
    CalendarOrigin, CalendarPassportDirection, CalendarPassportPresence, CalendarPassportValue,
    CalendarStatus, CalendarStatusBasis, PREDICATE_CALENDAR_ORIGIN, PREDICATE_CALENDAR_PASSPORT,
    PREDICATE_CALENDAR_STATUS, decode_status_value,
};
use crate::calendar::ics::ParsedVEvent;
use crate::calendar::passport::{
    PassportDecision, all_live_inbound_passports_absent, classify_passport, index_passport_uid,
    live_passports_for_event, supersede_calendar_passport,
};
use crate::calendar::safeguard::{CalendarBodyScreener, CalendarInboundBody, screen_then_claim};
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;
use continuation::OwedProperties;
pub use continuation::{
    ICS_PROPERTY_CONTINUATION_ATTEMPT_KIND, IcsPropertyContinuationPayload,
    run_ics_property_continuation,
};
pub(in crate::calendar) use import_claim::admit_calendar_import_claim;
pub(crate) use import_claim::ensure_ics_import_actor;
pub use import_claim::ics_import_actor_id;
use import_claim::{admit_calendar_import_claim_screened, imported_screen};

#[cfg(test)]
use super::fetch::{IcsFeedFetcher, IcsFetchResponse};
#[cfg(test)]
use super::poll::run_ics_feed_poll;

/// Per-poll admission context: everything the claim-writing steps share.
pub(super) struct PollAdmission<'a> {
    pub(crate) vault: &'a Vault,
    pub(crate) screener: Option<&'a dyn CalendarBodyScreener>,
    pub(crate) safeguard_enabled: bool,
    pub(crate) system: &'a str,
    pub(crate) preserve_direction: bool,
    pub(crate) now: u64,
    pub(crate) blob_ref: &'a str,
    pub(crate) verdict_fold: VerdictFold,
    /// The events whose property admissions passed one pass's count, each
    /// queued a continuation once the feed is applied (FIX 11997): `blob_ref`
    /// names an archived feed version the continuation reads again. `None`
    /// for a connector admission, which admits each one.
    pub(crate) continuations: Option<Vec<OwedProperties>>,
}

impl PollAdmission<'_> {
    /// Applies one completely parsed feed: per-VEVENT diff + admission.
    pub(super) fn apply_feed(
        &mut self,
        feed: &super::ics::ParsedIcsFeed,
    ) -> Result<(), CalendarError> {
        // No EVENT, UID index, or claim can be left behind by a value refusal,
        // including when a later detached component is the invalid one.
        for event in &feed.events {
            self.preflight_event(event)?;
        }
        for event in &feed.events {
            self.apply_event(event)?;
        }
        self.queue_property_continuations()
    }

    fn apply_event(&mut self, event: &ParsedVEvent) -> Result<(), CalendarError> {
        self.preflight_event(event)?;
        if let Some(original) = event.properties.recurrence_id_utc {
            return self.apply_exception(event, original);
        }
        let decision = classify_passport(
            self.vault,
            self.system,
            &event.uid,
            event.sequence,
            event.content_hash,
        )?;
        match decision {
            PassportDecision::CreateEvent => {
                let event_ref = self.mint_event(event)?;
                index_passport_uid(self.vault, &event.uid, &event_ref)?;
                self.admit_properties(event_ref, event)?;
                self.admit_fresh_passport(event_ref, event)?;
                if !event.cancelled {
                    self.clear_absence_cancellation(event_ref)?;
                }
                self.apply_imported_cancel(event_ref, event)?;
            }
            PassportDecision::AttachToExisting { event_ref } => {
                self.admit_properties(event_ref, event)?;
                self.admit_fresh_passport(event_ref, event)?;
                if !event.cancelled {
                    self.clear_absence_cancellation(event_ref)?;
                }
                self.apply_imported_cancel(event_ref, event)?;
            }
            PassportDecision::SkipUnchanged { .. } => {}
            PassportDecision::UpdateExisting { event_ref } => {
                // The update verdict moves the EVENT, not just the passport
                // head: occurred and name follow the drifted VEVENT, and
                // `calendar.time` re-mints when its value moved.
                self.rewrite_event(event_ref, event)?;
                self.admit_properties(event_ref, event)?;
                let next = self.passport_value(event_ref, event, CalendarPassportPresence::Live)?;
                let body = screen_body(event);
                self.admit_superseding_passport(event_ref, &next, &body)?;
                if !event.cancelled {
                    self.clear_absence_cancellation(event_ref)?;
                }
                self.apply_imported_cancel(event_ref, event)?;
            }
            PassportDecision::MarkSourceAbsent { .. } => {
                // Constructed only by the absence sweep, never by per-event
                // classification.
            }
        }
        Ok(())
    }

    /// The absence half of the diff: every live inbound passport this system
    /// reported before, whose UID a COMPLETE feed just omitted, flips to
    /// absent — only that passport, never the EVENT. Cancellation derives
    /// afterwards, and only when every live inbound passport reports absence.
    pub(super) fn sweep_absent_sources(
        &mut self,
        feed: &super::ics::ParsedIcsFeed,
    ) -> Result<(), CalendarError> {
        self.sweep_resource(feed, None, CalendarStatusBasis::ImportedAbsence)
    }

    fn sweep_resource(
        &mut self,
        feed: &super::ics::ParsedIcsFeed,
        only_uid: Option<&str>,
        absence_basis: CalendarStatusBasis,
    ) -> Result<(), CalendarError> {
        let present: std::collections::BTreeSet<_> = feed
            .events
            .iter()
            .map(|event| (event.uid.as_str(), event.properties.recurrence_id_utc))
            .collect();
        for event_ref in list_event_ids(self.vault)? {
            let passports = live_passports_for_event(self.vault, &event_ref)?;
            let instance = self.exception_start(event_ref)?;
            if !passports.iter().any(|(_, value)| {
                value.system == self.system && only_uid.is_none_or(|uid| value.uid == uid)
            }) {
                continue;
            }
            for (_, value) in &passports {
                let reports = value.system == self.system
                    && only_uid.is_none_or(|uid| value.uid == uid)
                    && value.direction.is_inbound_bearing()
                    && value.presence == CalendarPassportPresence::Live
                    && !present.contains(&(value.uid.as_str(), instance));
                if !reports {
                    continue;
                }
                let mut absent = value.clone();
                absent.presence = CalendarPassportPresence::Absent;
                absent.last_seen_at = self.now;
                // Absence carries no inbound content, so the screen body is
                // empty — but the admission still crosses the hook and cites
                // the complete feed that proved the omission.
                self.admit_superseding_passport(
                    event_ref,
                    &absent,
                    &CalendarInboundBody::default(),
                )?;
            }
            if all_live_inbound_passports_absent(self.vault, &event_ref)? {
                self.admit_absence_cancellation(event_ref, absence_basis)?;
                if instance.is_some() {
                    self.retract_exception_mask(event_ref)?;
                }
            }
        }
        Ok(())
    }

    /// Birth and recorded import provenance commit together. Screening still
    /// happens before admission; origin is a projector fact, not a proposed
    /// semantic claim that can disappear from the live EVENT projection.
    fn mint_event(&mut self, event: &ParsedVEvent) -> Result<EntityId, CalendarError> {
        let id = self.vault.store.clock.entity_id()?;
        self.mint_event_with_id(event, id)
    }

    fn mint_event_with_id(
        &mut self,
        event: &ParsedVEvent,
        id: EntityId,
    ) -> Result<EntityId, CalendarError> {
        let body = screen_body(event);
        let screened =
            screen_then_claim(self.safeguard_enabled, self.screener, &body, |request| {
                let token = verdict_token(&request.verdict);
                let actor = ensure_ics_import_actor(self.vault, self.now)?;
                let input = crate::calendar::origin::CalendarEventInput {
                    origin: Some(CalendarOrigin::Imported),
                    name: event_name(event).to_owned(),
                    import_source: Some(self.source_record_id(event)),
                    external_id: Some(event.uid.clone()),
                    calendar_name: Some(self.system.to_owned()),
                    ..Default::default()
                };
                let admitted = self.vault.with_write_txn_grouped(|txn| {
                    self.vault.stage_calendar_event(
                        txn,
                        &input,
                        self.event_occurred(event),
                        WriteActor::new(actor, crate::EdgeActorClass::System),
                        id,
                        self.now,
                    )?;
                    Ok(id)
                });
                Ok((admitted, token))
            })?;
        let (admitted, token) = screened.value;
        self.verdict_fold.record(token);
        Ok(admitted?)
    }

    /// Drift changes the EVENT's time/name without erasing its origin or
    /// extraction/import fields. Imported provenance follows this feed version;
    /// a native EVENT with an attached passport remains native.
    fn rewrite_event(
        &self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<(), CalendarError> {
        let input = crate::calendar::origin::CalendarEventInput {
            origin: Some(CalendarOrigin::Imported),
            name: event_name(event).to_owned(),
            import_source: Some(self.source_record_id(event)),
            external_id: Some(event.uid.clone()),
            ..Default::default()
        };
        self.vault.with_write_txn_grouped(|txn| {
            self.vault.update_calendar_import_in_txn(
                txn,
                event_ref,
                &input,
                self.event_occurred(event),
                self.now,
            )
        })?;
        Ok(())
    }

    /// The EVENT's stored occurrence from the parsed times. An unanchored
    /// event uses the existing undated sentinel, never the poll instant.
    fn event_occurred(&self, event: &ParsedVEvent) -> TimeRange {
        match (event.starts_at_utc, event.ends_at_utc) {
            (Some(start), Some(end)) => TimeRange {
                start,
                end: end.max(start),
            },
            (Some(start), None) => TimeRange { start, end: start },
            (None, _) => TimeRange { start: 0, end: 0 },
        }
    }

    /// Reconciles this source's properties, including removing its time kind
    /// when DTSTART disappears. Claims owned by other sources are untouched.
    /// While the admission keeps continuations, one pass admits at most
    /// [`super::property_claims::CALENDAR_PROPERTY_ADMISSIONS_PER_PASS`] new
    /// ones and a queued continuation admits the rest (FIX 11997).
    fn admit_properties(
        &mut self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<(), CalendarError> {
        let body = screen_body(event);
        let source_prefix = super::property_claims::source_prefix(self.system);
        let source_record_id = format!("{source_prefix}{}", self.source_record_id(event));
        let budget = self
            .continuations
            .is_some()
            .then_some(super::property_claims::CALENDAR_PROPERTY_ADMISSIONS_PER_PASS);
        let owed = super::property_claims::reconcile(
            self.vault,
            event_ref,
            event,
            &source_prefix,
            self.now,
            budget,
            |predicate, value| {
                self.admit_screened(event_ref, &body, &source_record_id, predicate, value)
            },
        )?;
        self.signal_property_continuation(event_ref, event, owed);
        Ok(())
    }

    /// Screens and admits the next passport head for `(system × UID)` —
    /// through the same hook + Gate door a fresh admission crosses — then
    /// supersedes exactly the scoped live claim. Supersessions carry the
    /// archived complete feed's provenance (`blob#vN:uid`), never a bare UID.
    fn admit_superseding_passport(
        &mut self,
        event_ref: EntityId,
        next: &CalendarPassportValue,
        body: &CalendarInboundBody,
    ) -> Result<(), CalendarError> {
        let source_record_id = format!("{}:{}", self.blob_ref, next.uid);
        let new_id = self.admit_screened(
            event_ref,
            body,
            &source_record_id,
            PREDICATE_CALENDAR_PASSPORT,
            super::passport::encode_passport_value(next),
        )?;
        supersede_calendar_passport(
            self.vault,
            event_ref,
            &next.system,
            &next.uid,
            &new_id,
            self.now,
        )
    }

    fn admit_fresh_passport(
        &mut self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<(), CalendarError> {
        let value = self.passport_value(event_ref, event, CalendarPassportPresence::Live)?;
        let body = screen_body(event);
        let source_record_id = self.source_record_id(event);
        self.admit_screened(
            event_ref,
            &body,
            &source_record_id,
            PREDICATE_CALENDAR_PASSPORT,
            super::passport::encode_passport_value(&value),
        )?;
        Ok(())
    }

    /// An explicit cancellation in the feed (`METHOD:CANCEL` or
    /// `STATUS:CANCELLED`): write `calendar.status` cancelled with basis
    /// `imported_cancel`, unless a live claim already says exactly that, and
    /// carry it to CAL-07 as pre-start cancellation evidence. Never writes
    /// `confirmed` — resurrection is not a v1 basis.
    fn apply_imported_cancel(
        &mut self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<(), CalendarError> {
        if !event.cancelled {
            return Ok(());
        }
        let body = screen_body(event);
        let source_record_id = self.source_record_id(event);
        if let Some(status_ref) = self.admit_status_if_changed(
            event_ref,
            &body,
            &source_record_id,
            CalendarStatus::Cancelled,
            CalendarStatusBasis::ImportedCancel,
        )? {
            self.record_cancel_outcome(event_ref, status_ref)?;
        }
        Ok(())
    }

    /// The multi-source law's conclusion: every live inbound passport
    /// reports absence, so the EVENT reads cancelled with basis
    /// `imported_absence` for an omission or `imported_cancel` for an explicit
    /// provider tombstone. The EVENT row is never deleted. Only the explicit
    /// tombstone is cancellation evidence for CAL-07; an omission writes the
    /// status alone. The screen body is empty: absence carries no inbound
    /// content to screen.
    fn admit_absence_cancellation(
        &mut self,
        event_ref: EntityId,
        basis: CalendarStatusBasis,
    ) -> Result<(), CalendarError> {
        let status_ref = self.admit_status_if_changed(
            event_ref,
            &CalendarInboundBody::default(),
            if basis == CalendarStatusBasis::ImportedCancel {
                "remote-delete"
            } else {
                "feed-absence"
            },
            CalendarStatus::Cancelled,
            basis,
        )?;
        if let Some(status_ref) = status_ref
            && basis == CalendarStatusBasis::ImportedCancel
        {
            self.record_cancel_outcome(event_ref, status_ref)?;
        }
        Ok(())
    }

    /// Carries one explicit imported cancellation into CAL-07 as
    /// `CancelReceived` machine evidence citing the status claim that
    /// recorded it. Seen before the EVENT's start it records
    /// `cancelled_pre_start`; seen after, or on an EVENT with no anchored
    /// start, it earns nothing. The engine observed the cancellation in the
    /// bytes it fetched, so the outcome lands as `observed`.
    fn record_cancel_outcome(
        &self,
        event_ref: EntityId,
        status_ref: EntityId,
    ) -> Result<(), CalendarError> {
        let Some(header) = self.vault.read_entity_header(&event_ref)? else {
            return Ok(());
        };
        if header.occurred_start == 0 && header.occurred_end == 0 {
            return Ok(());
        }
        crate::calendar::outcome::record_machine_event_outcome(
            self.vault,
            event_ref,
            header.occurred_start,
            &crate::calendar::outcome::MachineOutcomeEvidence::CancelReceived {
                evidence_ref: status_ref,
                observed_at: self.now,
            },
            crate::claim::ClaimSource::Observed,
        )?;
        Ok(())
    }

    /// Admits one `calendar.status` claim, superseding the prior live status
    /// claim, and skips when the live claim already carries the exact value.
    /// Returns the new claim's id, or `None` when nothing was written.
    fn admit_status_if_changed(
        &mut self,
        event_ref: EntityId,
        body: &CalendarInboundBody,
        source_record_id: &str,
        status: CalendarStatus,
        basis: CalendarStatusBasis,
    ) -> Result<Option<EntityId>, CalendarError> {
        let mut prior_live: Option<EntityId> = None;
        for claim_id in self.vault.claims_for_subject(&event_ref)? {
            let Some(claim) = self.vault.get_claim(&claim_id)? else {
                continue;
            };
            if claim.predicate != PREDICATE_CALENDAR_STATUS
                || claim.lifecycle != ClaimLifecycleStatus::Active
            {
                continue;
            }
            let current = decode_status_value(&claim.value)
                .map_err(|_| ingest("stored status claim did not decode"))?;
            if current.status == status && current.basis == basis {
                return Ok(None);
            }
            prior_live = Some(claim_id);
        }
        let value = preflight::status_value(status, basis, self.now);
        let new_id = self.admit_screened(
            event_ref,
            body,
            source_record_id,
            PREDICATE_CALENDAR_STATUS,
            value,
        )?;
        if let Some(old_id) = prior_live {
            self.vault.supersede_claim(&new_id, &old_id, self.now)?;
        }
        Ok(Some(new_id))
    }

    /// The one admission door: CAL-09's hook runs immediately before the
    /// imported-evidence admission, and the admission executes from the
    /// typed `CalendarAdmissionRequest` — never from a zero-argument closure
    /// that could not see the verdict. A screen that ran rides the admitted
    /// claim's evidence, verdict and reason codes, beside its source record;
    /// the run's worst verdict is also folded into the feed cursor.
    fn admit_screened(
        &mut self,
        event_ref: EntityId,
        body: &CalendarInboundBody,
        source_record_id: &str,
        predicate: &str,
        value: rmpv::Value,
    ) -> Result<EntityId, CalendarError> {
        let screened = screen_then_claim(self.safeguard_enabled, self.screener, body, |request| {
            let token = verdict_token(&request.verdict);
            let admitted = admit_calendar_import_claim_screened(
                self.vault,
                &event_ref,
                predicate,
                value,
                source_record_id,
                self.now,
                imported_screen(&request.verdict),
            );
            Ok((admitted, token))
        })?;
        let (admitted, token) = screened.value;
        self.verdict_fold.record(token);
        Ok(admitted?)
    }

    fn passport_value(
        &self,
        event_ref: EntityId,
        event: &ParsedVEvent,
        presence: CalendarPassportPresence,
    ) -> Result<CalendarPassportValue, CalendarError> {
        let direction = if self.preserve_direction {
            crate::calendar::passport::live_passport_for(
                self.vault,
                &event_ref,
                self.system,
                &event.uid,
            )?
            .map_or(CalendarPassportDirection::Inbound, |(_, value)| {
                value.direction
            })
        } else {
            CalendarPassportDirection::Inbound
        };
        Ok(CalendarPassportValue {
            system: self.system.to_owned(),
            uid: event.uid.clone(),
            last_sequence: event.sequence,
            content_hash: event.content_hash,
            direction,
            last_seen_at: self.now,
            presence,
        })
    }

    /// The provenance ref admitted claims carry: the archived feed version
    /// plus the event's UID, so every semantic candidate points back at the
    /// raw bytes it was parsed from.
    fn source_record_id(&self, event: &ParsedVEvent) -> String {
        format!("{}:{}", self.blob_ref, event.uid)
    }
}

/// Connector resources use the same gated importer, but retain their routing.
pub(in crate::calendar) fn connector_event_ref(
    vault: &Vault,
    event: &ParsedVEvent,
) -> Result<Option<EntityId>, CalendarError> {
    let master = crate::calendar::passport::resolve_event_by_uid(vault, &event.uid)?;
    match event.properties.recurrence_id_utc {
        None => Ok(master),
        Some(original) => Ok(Some(recurrence::exception_id(
            master.ok_or_else(|| ingest("recurrence exception has no master"))?,
            original,
        )?)),
    }
}
fn connector_admission<'a>(
    vault: &'a Vault,
    system: &'a str,
    source: &'a str,
    now: u64,
) -> PollAdmission<'a> {
    PollAdmission {
        vault,
        system,
        preserve_direction: true,
        screener: None,
        safeguard_enabled: false,
        now,
        blob_ref: source,
        verdict_fold: VerdictFold::default(),
        continuations: None,
    }
}
pub(in crate::calendar) fn preflight_connector_feed(
    vault: &Vault,
    system: &str,
    source: &str,
    feed: &super::ics::ParsedIcsFeed,
    now: u64,
) -> Result<(), CalendarError> {
    let admission = connector_admission(vault, system, source, now);
    for event in &feed.events {
        admission.preflight_event(event)?;
    }
    Ok(())
}
pub(in crate::calendar) fn admit_connector_event(
    vault: &Vault,
    system: &str,
    source: &str,
    event: &ParsedVEvent,
    now: u64,
) -> Result<(), CalendarError> {
    connector_admission(vault, system, source, now).apply_event(event)
}
pub(in crate::calendar) fn sweep_connector_resource(
    vault: &Vault,
    system: &str,
    source: &str,
    feed: &super::ics::ParsedIcsFeed,
    uid: &str,
    now: u64,
) -> Result<(), CalendarError> {
    connector_admission(vault, system, source, now).sweep_resource(
        feed,
        Some(uid),
        CalendarStatusBasis::ImportedAbsence,
    )
}

/// An explicit provider tombstone cancels with a stronger basis than an omitted feed item.
pub(in crate::calendar) fn delete_connector_resource(
    vault: &Vault,
    system: &str,
    source: &str,
    uid: &str,
    now: u64,
) -> Result<(), CalendarError> {
    connector_admission(vault, system, source, now).sweep_resource(
        &super::ics::ParsedIcsFeed { events: Vec::new() },
        Some(uid),
        CalendarStatusBasis::ImportedCancel,
    )
}

/// The CAL-09 screen body for one VEVENT: its description plus any ATTACH
/// values as attachment text, exactly as the source expressed them.
fn screen_body(event: &ParsedVEvent) -> CalendarInboundBody {
    CalendarInboundBody {
        description: event.description.clone().unwrap_or_default(),
        attachment_text: attachment_text(&event.raw_component),
    }
}

/// Every ATTACH of one raw VEVENT as text: an inline `ENCODING=BASE64`
/// attachment's content when it decodes to UTF-8 text, else the value as the
/// source wrote it (a URI, or inline bytes that are no text). A component
/// that does not read again yields none; its parse already succeeded once.
fn attachment_text(raw_component: &[u8]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(raw_component) else {
        return Vec::new();
    };
    let unfolded = icalendar::parser::unfold(text);
    let Ok(components) = icalendar::parser::read_calendar_simple(&unfolded) else {
        return Vec::new();
    };
    components
        .iter()
        .flat_map(|component| component.properties.iter())
        .filter(|prop| prop.name.as_str().eq_ignore_ascii_case("ATTACH"))
        .map(|prop| {
            let base64 = prop.params.iter().any(|param| {
                param.key.as_str().eq_ignore_ascii_case("ENCODING")
                    && param
                        .val
                        .as_ref()
                        .is_some_and(|val| val.as_str().eq_ignore_ascii_case("BASE64"))
            });
            let value = prop.val.as_str().trim();
            if base64 {
                use base64::Engine;
                if let Some(content) = base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                {
                    return content;
                }
            }
            value.to_owned()
        })
        .collect()
}

/// The EVENT's display name: SUMMARY, with a UID fallback.
fn event_name(event: &ParsedVEvent) -> &str {
    event
        .summary
        .as_deref()
        .filter(|summary| !summary.is_empty())
        .unwrap_or(event.uid.as_str())
}

fn list_event_ids(vault: &Vault) -> Result<Vec<EntityId>, CalendarError> {
    let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let mut ids = Vec::new();
    for entry in vault
        .store
        .port_entity_ids_by_type(&rtxn, ENTITY_TYPE_EVENT, None)?
    {
        ids.push(entry?);
    }
    Ok(ids)
}

/// Compact fold of the run's screen verdicts, persisted on the cursor as the
/// admission-metadata witness: the worst verdict class seen this run.
#[derive(Default)]
pub(super) struct VerdictFold {
    token: Option<&'static str>,
}

impl VerdictFold {
    pub(crate) fn record(&mut self, token: &'static str) {
        let rank = |token: &str| match token {
            "flagged" => 3,
            "indeterminate" => 2,
            "clear" => 1,
            _ => 0,
        };
        if self.token.is_none_or(|current| rank(token) > rank(current)) {
            self.token = Some(token);
        }
    }

    pub(crate) fn token(&self) -> &'static str {
        self.token.unwrap_or("skipped")
    }
}

fn verdict_token(verdict: &super::safeguard::CalendarScreenVerdict) -> &'static str {
    match verdict {
        super::safeguard::CalendarScreenVerdict::Skipped => "skipped",
        super::safeguard::CalendarScreenVerdict::Clear => "clear",
        super::safeguard::CalendarScreenVerdict::Flagged { .. } => "flagged",
        super::safeguard::CalendarScreenVerdict::Indeterminate { .. } => "indeterminate",
    }
}

#[cfg(test)]
mod tests;
