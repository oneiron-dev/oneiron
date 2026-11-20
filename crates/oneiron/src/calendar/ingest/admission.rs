//! Diff-to-claim admission path and its test module.

mod connector;
mod continuation;
mod import_claim;
mod preflight;
mod recurrence;
mod source_events;
use super::ingest;
#[cfg(test)]
use super::poll::IcsFeedPollConfig;
use crate::booking::lifecycle::FeedMoveOutcome;
use crate::calendar::CalendarError;
use crate::calendar::claims::{
    CalendarOrigin, CalendarPassportDirection, CalendarPassportPresence, CalendarPassportSource,
    CalendarPassportValue, CalendarStatus, CalendarStatusBasis, PREDICATE_CALENDAR_ORIGIN,
    PREDICATE_CALENDAR_PASSPORT, PREDICATE_CALENDAR_STATUS, decode_status_value,
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
pub(in crate::calendar) use connector::{
    ConnectorAdmissionSource, ConnectorScreen, admit_connector_event, connector_event_ref,
    delete_connector_resource, preflight_connector_feed, repeat_connector_echo,
    sweep_connector_resource, sweep_connector_uids,
};
use continuation::OwedProperties;
pub(super) use continuation::run_ics_property_continuation_admitting;
pub use continuation::{
    ICS_PROPERTY_CONTINUATION_ATTEMPT_KIND, IcsPropertyContinuationPayload,
    run_ics_property_continuation,
};
pub(crate) use import_claim::ensure_ics_import_actor;
pub use import_claim::ics_import_actor_id;
pub(in crate::calendar) use import_claim::{
    admit_calendar_import_claim, admit_calendar_import_claim_in_txn,
};
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
    pub(crate) source: Option<CalendarPassportSource>,
    pub(crate) verdict_fold: VerdictFold,
    /// The events whose property admissions passed one pass's count, each
    /// queued a continuation once the feed is applied (FIX 11997, FIX
    /// 12163) that reads an archived version of its source again. `None`
    /// admits every property in one pass: a connector source no archived
    /// version holds.
    pub(crate) continuations: Option<Vec<OwedProperties>>,
    /// The items whose booking move a pending emergency delivery held back
    /// this pass (FIX 22385, Engine ruling 16:10, 12 Nov). Each one's feed
    /// passport stays as it was, so the source reads its update again; the
    /// caller keeps the source's read position owed.
    pub(crate) owed_booking_moves: u32,
    /// Every imported claim this pass admitted, in admission order. An
    /// installed feed's poll settles them under the feed's consent (CAL-02):
    /// its first poll's become the one review, a later poll's land Approved.
    pub(crate) admitted_claims: Vec<EntityId>,
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
        // A pack calendar source's EVENTs are its own (FIX 12559).
        if let Some(source) = source_events::pack_source(self.vault, self.system)? {
            return self.apply_source_event(event, source);
        }
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
            PassportDecision::SkipUnchanged { event_ref } => {
                self.repeat_imported_cancel(event_ref, event)?;
            }
            PassportDecision::UpdateExisting { event_ref } => {
                // The update verdict moves the EVENT, not just the passport
                // head: occurred and name follow the drifted VEVENT, and
                // `calendar.time` re-mints when its value moved. A live
                // booking's EVENT moves through its booking instead.
                match self.move_booking(event_ref, event)? {
                    FeedMoveOutcome::NotBooking => self.rewrite_event(event_ref, event)?,
                    FeedMoveOutcome::Unchanged | FeedMoveOutcome::Moved(_) => {}
                    // Only this item waits: no claim, no passport head, and
                    // the next read of the source sees the move again.
                    FeedMoveOutcome::HeldBack => {
                        self.owed_booking_moves += 1;
                        return Ok(());
                    }
                }
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
        only_uids: Option<&std::collections::BTreeSet<&str>>,
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
                value.system == self.system
                    && only_uids.is_none_or(|uids| uids.contains(value.uid.as_str()))
            }) {
                continue;
            }
            for (_, value) in &passports {
                let omitted = value.system == self.system
                    && only_uids.is_none_or(|uids| uids.contains(value.uid.as_str()))
                    && !present.contains(&(value.uid.as_str(), instance));
                let flips = omitted
                    && value.direction.is_inbound_bearing()
                    && value.presence == CalendarPassportPresence::Live;
                // A provider tombstone is this source's report of the UID
                // cancelled, first seen now unless an earlier cancelled
                // version or tombstone already dated it. An omission is no
                // cancellation evidence and dates nothing, so a tombstone
                // also dates a passport an omission already flipped absent.
                // An Outbound passport of a calendar the EVENT was written
                // to never flips, since it is no absence vote, but its
                // tombstone is dated the same way.
                let dates_cancel = omitted
                    && absence_basis == CalendarStatusBasis::ImportedCancel
                    && value.cancelled_since.is_none()
                    && (value.direction.is_inbound_bearing()
                        || names_written_calendar(self.system, value));
                if !flips && !dates_cancel {
                    continue;
                }
                let mut next = value.clone();
                if flips {
                    next.presence = CalendarPassportPresence::Absent;
                    next.last_seen_at = self.now;
                }
                if dates_cancel {
                    next.cancelled_since = Some(self.now);
                }
                // Absence carries no inbound content, so the screen body is
                // empty — but the admission still crosses the hook and cites
                // the complete feed that proved the omission.
                self.admit_superseding_passport(event_ref, &next, &CalendarInboundBody::default())?;
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
                let occurred = self.event_occurred(event);
                let admitted = self.vault.with_write_txn_grouped(|txn| {
                    let landing =
                        crate::mail_pack::calendar_source_landing_in(self.vault, txn, self.system)?;
                    self.vault.stage_calendar_event(
                        txn,
                        &input,
                        None,
                        occurred,
                        WriteActor::new(actor, crate::EdgeActorClass::System),
                        id,
                        self.now,
                    )?;
                    // A pack calendar source's EVENT is stamped with the
                    // source's audience and bound to it in its birth commit
                    // (FIX 12559, fix list row 16256); any other system's
                    // lands unstamped and unbound.
                    if let Some(landing) = &landing {
                        let body = landing.stamp_in_txn(self.vault, txn, &id, &input.encode()?)?;
                        self.vault
                            .batch_in()
                            .put_source_bound(
                                &id,
                                ENTITY_TYPE_EVENT,
                                occurred,
                                self.now,
                                &body,
                                landing.birth(),
                            )
                            .apply(txn)?;
                        landing.bind_in_txn(self.vault, txn, &id)?;
                    }
                    Ok(id)
                });
                Ok((admitted, token))
            })?;
        let (admitted, token) = screened.value;
        self.verdict_fold.record(token);
        Ok(admitted?)
    }

    /// Moves a live booking's EVENT to the drifted VEVENT's slot through the
    /// booking writer (FIX 22385). The host moved it in their own calendar,
    /// so the move lands, and in one transaction the booking passport takes
    /// its next SEQUENCE, the revision receipt is recorded and the booker's
    /// revised invite is queued. The echo of the slot the booking already
    /// sits at writes nothing, and a pending emergency delivery holds the
    /// move back. [`FeedMoveOutcome::NotBooking`] when the EVENT carries no
    /// booking, or one its own status cancelled: the caller then rewrites the
    /// EVENT as any other. A booking a calendar's cancellation stands on keeps
    /// its booked slot ([`FeedMoveOutcome::Unchanged`]), as below.
    ///
    /// A cancellation moves nothing and stays the imported-cancel outcome. A
    /// booking's EVENT keeps its booked slot through it
    /// ([`FeedMoveOutcome::Unchanged`]): the deposit's start rule and CAL-07
    /// measure the cancellation against that slot, and a cancellation that
    /// names no DTSTART would otherwise rewrite it to the undated sentinel
    /// (review round 2 of #9233). Any other EVENT is rewritten as before.
    fn move_booking(
        &self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<FeedMoveOutcome, CalendarError> {
        if event.cancelled {
            let is_booking = crate::booking::lifecycle::is_booking_event(self.vault, &event_ref)
                .map_err(|error| CalendarError::IcsIngest {
                    reason: error.to_string(),
                })?;
            return Ok(if is_booking {
                FeedMoveOutcome::Unchanged
            } else {
                FeedMoveOutcome::NotBooking
            });
        }
        let slot = match (event.starts_at_utc, event.ends_at_utc) {
            (Some(start), Some(end)) => Some(TimeRange { start, end }),
            _ => None,
        };
        let outcome =
            crate::booking::lifecycle::move_booking_by_feed(self.vault, event_ref, slot, self.now)
                .map_err(|error| CalendarError::IcsIngest {
                    reason: error.to_string(),
                })?;
        match &outcome {
            FeedMoveOutcome::Moved(revision) => {
                tracing::debug!(
                    sequence = revision.sequence,
                    "calendar feed moved a booking"
                );
            }
            FeedMoveOutcome::HeldBack => {
                tracing::debug!(
                    "a pending emergency delivery holds a calendar feed's booking move"
                );
            }
            FeedMoveOutcome::NotBooking | FeedMoveOutcome::Unchanged => {}
        }
        Ok(outcome)
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
            // A pack calendar source's EVENT keeps its stamp through drift:
            // its landing marks it born again, rewrites it under its proof
            // and binds it where it was born.
            let landing =
                crate::mail_pack::calendar_source_landing_in(self.vault, txn, self.system)?;
            let birth = landing
                .as_ref()
                .map(|landing| landing.mark_in_txn(self.vault, txn, &event_ref))
                .transpose()?;
            self.vault.update_calendar_import_in_txn(
                txn,
                event_ref,
                &input,
                self.event_occurred(event),
                self.now,
                birth,
            )?;
            match &landing {
                Some(landing) => landing.bind_in_txn(self.vault, txn, &event_ref),
                None => Ok(()),
            }
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
    /// `confirmed` — resurrection is not a v1 basis. When this source is a
    /// calendar the EVENT was written to ([`names_written_calendar`]), a
    /// booking's deposit refund commits first, on every sighting, also when
    /// the status already stood; any other source moves no money. Both are
    /// dated by the source's first report of the cancellation, which its
    /// passport (committed before this runs) carries across versions; a path
    /// with no such passport dates it now.
    fn apply_imported_cancel(
        &mut self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<(), CalendarError> {
        if !event.cancelled {
            return Ok(());
        }
        let passport = crate::calendar::passport::live_passport_for(
            self.vault,
            &event_ref,
            self.system,
            &event.uid,
        )?
        .map(|(_, passport)| passport);
        let seen_at = passport
            .as_ref()
            .and_then(|passport| passport.cancelled_since)
            .unwrap_or(self.now);
        if passport
            .as_ref()
            .is_some_and(|passport| names_written_calendar(self.system, passport))
        {
            self.refund_host_cancelled_deposit(event_ref, seen_at)?;
        }
        self.admit_imported_cancel_status(event_ref, event, seen_at)
    }

    /// The cancellation's `calendar.status` (basis `imported_cancel`) and, when
    /// it is newly written, its CAL-07 evidence observed at `seen_at`.
    fn admit_imported_cancel_status(
        &mut self,
        event_ref: EntityId,
        event: &ParsedVEvent,
        seen_at: u64,
    ) -> Result<(), CalendarError> {
        let body = screen_body(event);
        let source_record_id = self.source_record_id(event);
        if let Some(status_ref) = self.admit_status_if_changed(
            event_ref,
            &body,
            &source_record_id,
            CalendarStatus::Cancelled,
            CalendarStatusBasis::ImportedCancel,
        )? {
            self.record_cancel_outcome(event_ref, status_ref, seen_at)?;
        }
        Ok(())
    }

    /// The multi-source law's conclusion: every live inbound passport
    /// reports absence, so the EVENT reads cancelled with basis
    /// `imported_absence` for an omission or `imported_cancel` for an explicit
    /// provider tombstone. The EVENT row is never deleted. Only the explicit
    /// tombstone is cancellation evidence for CAL-07, observed when this
    /// source first reported it; an omission writes the status alone. The
    /// screen body is empty: absence carries no inbound content to screen.
    /// A tombstone sent again finds its status standing and repairs only a
    /// missing CAL-07 outcome ([`Self::repair_cancel_outcome`]).
    ///
    /// When a calendar the EVENT was written to has reported the
    /// cancellation ([`Self::written_cancel_seen_at`]), the deposit refund
    /// commits first, dated by that report, whichever source's absence
    /// concludes the cancellation: a host tombstone that waited on another
    /// calendar still showing the EVENT settles when that calendar leaves it
    /// out. The omission itself moves no money.
    fn admit_absence_cancellation(
        &mut self,
        event_ref: EntityId,
        basis: CalendarStatusBasis,
    ) -> Result<(), CalendarError> {
        if let Some(seen_at) = self.written_cancel_seen_at(event_ref)? {
            self.refund_host_cancelled_deposit(event_ref, seen_at)?;
        }
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
        if basis == CalendarStatusBasis::ImportedCancel {
            let observed_at = self
                .cancel_seen_at(event_ref, |value| value.system == self.system)?
                .unwrap_or(self.now);
            match status_ref {
                Some(status_ref) => {
                    self.record_cancel_outcome(event_ref, status_ref, observed_at)?
                }
                None => self.repair_cancel_outcome(event_ref, observed_at)?,
            }
        }
        Ok(())
    }

    /// When a calendar the EVENT was written to ([`names_written_calendar`]
    /// of each passport's own system) first reported its cancellation, for
    /// the deposit's start rule (RULING DEPOSIT-HOST-CANCEL-AFTER-START = A);
    /// `None` when none has. Each such report is stored on its passport
    /// (`cancelled_since`) before the refund commits: a tombstone's sweep
    /// stamps it, also on an Outbound passport, which never flips, and a
    /// cancelled version carries it. A stop between the two, a tombstone sent
    /// again, or another calendar's later absence therefore still finds the
    /// first report. A calendar a visitor can write never dates the host's
    /// cancel, and an omission stamps nothing, since it is no cancellation
    /// evidence.
    fn written_cancel_seen_at(&self, event_ref: EntityId) -> Result<Option<u64>, CalendarError> {
        self.cancel_seen_at(event_ref, |value| {
            names_written_calendar(&value.system, value)
        })
    }

    /// The earliest `cancelled_since` among the EVENT's live passports that
    /// `counts` admits, absent or not: the first report of the cancellation
    /// among those sources.
    fn cancel_seen_at(
        &self,
        event_ref: EntityId,
        counts: impl Fn(&CalendarPassportValue) -> bool,
    ) -> Result<Option<u64>, CalendarError> {
        Ok(live_passports_for_event(self.vault, &event_ref)?
            .into_iter()
            .filter(|(_, value)| counts(value))
            .filter_map(|(_, value)| value.cancelled_since)
            .min())
    }

    /// A VEVENT the passport already carries (or an older SEQUENCE of it):
    /// when it is the passport's own version (the same SEQUENCE and content
    /// hash) and an explicit cancellation, the steps after its passport are
    /// asked again. The passport commits before the refund and the status do,
    /// so a stop between them leaves the next read of the feed here, and this
    /// is where they are repaired; a connector pull reaches it through its
    /// echo arm ([`repeat_connector_echo`]). The cancellation was first seen
    /// when the source's first cancelled passport committed
    /// (`cancelled_since`, carried across later cancelled versions), so a
    /// repair after the booking's start still refunds a cancellation first
    /// seen before it, and CAL-07 observes it then. The refund is asked on
    /// every such read, from a source the EVENT was written to
    /// ([`names_written_calendar`]) only. The status is asked only while no
    /// `calendar.status` other than an omission's was admitted after this
    /// version's passport ([`Self::explicit_status_admitted_after`]): one
    /// admitted then is this version's own or a later fact, and a status the
    /// owner retracted is never written back. An omission's status that
    /// concluded the cancellation meanwhile gives way to this explicit one,
    /// as it does when a tombstone concludes. When such a status was
    /// admitted, only a missing CAL-07 outcome of the standing cancellation
    /// is recorded ([`Self::repair_cancel_outcome`]). An older SEQUENCE
    /// replay moves nothing: the passport it lost to may carry a live
    /// booking.
    fn repeat_imported_cancel(
        &mut self,
        event_ref: EntityId,
        event: &ParsedVEvent,
    ) -> Result<(), CalendarError> {
        if !event.cancelled {
            return Ok(());
        }
        let Some((passport_ref, passport)) = crate::calendar::passport::live_passport_for(
            self.vault,
            &event_ref,
            self.system,
            &event.uid,
        )?
        else {
            return Ok(());
        };
        if passport.last_sequence != event.sequence || passport.content_hash != event.content_hash {
            return Ok(());
        }
        let seen_at = passport.cancelled_since.unwrap_or(passport.last_seen_at);
        if names_written_calendar(self.system, &passport) {
            self.refund_host_cancelled_deposit(event_ref, seen_at)?;
        }
        if self.explicit_status_admitted_after(event_ref, passport_ref)? {
            self.repair_cancel_outcome(event_ref, seen_at)
        } else {
            self.admit_imported_cancel_status(event_ref, event, seen_at)
        }
    }

    /// Whether a `calendar.status` claim on the EVENT, live or not, other than
    /// an omission's (basis `imported_absence`) was admitted after the
    /// passport claim `passport_ref`. A store mints claim ids in rising order
    /// (`StoreClock::ulid`, whose floor survives a reopen), so a higher id is
    /// a later admission, also within the one second `recorded_at` counts: a
    /// status another source wrote earlier in that second is no fact recorded
    /// after this version.
    fn explicit_status_admitted_after(
        &self,
        event_ref: EntityId,
        passport_ref: EntityId,
    ) -> Result<bool, CalendarError> {
        for claim_id in self.vault.claims_for_subject(&event_ref)? {
            if claim_id <= passport_ref {
                continue;
            }
            let Some(claim) = self.vault.get_claim(&claim_id)? else {
                continue;
            };
            if claim.predicate == PREDICATE_CALENDAR_STATUS
                && decode_status_value(&claim.value)
                    .map_err(|_| ingest("stored status claim did not decode"))?
                    .basis
                    != CalendarStatusBasis::ImportedAbsence
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Records the CAL-07 outcome of the EVENT's live imported cancellation
    /// when no outcome cites its status yet. The status and its outcome
    /// commit one after the other, so a stop between them leaves the status
    /// standing without its evidence; the next sighting of the same
    /// cancellation writes no new status, and records the outcome here,
    /// observed at `observed_at`. A status the owner retracted, or one of
    /// another basis, is left as it stands.
    fn repair_cancel_outcome(
        &self,
        event_ref: EntityId,
        observed_at: u64,
    ) -> Result<(), CalendarError> {
        let Some(status_ref) = self.live_imported_cancel_status(event_ref)? else {
            return Ok(());
        };
        if crate::calendar::outcome::event_outcome_cites(self.vault, event_ref, status_ref)? {
            return Ok(());
        }
        self.record_cancel_outcome(event_ref, status_ref, observed_at)
    }

    /// The EVENT's live `calendar.status` claim that reads cancelled with
    /// basis `imported_cancel`, if one stands.
    fn live_imported_cancel_status(
        &self,
        event_ref: EntityId,
    ) -> Result<Option<EntityId>, CalendarError> {
        for claim_id in self.vault.claims_for_subject(&event_ref)? {
            let Some(claim) = self.vault.get_claim(&claim_id)? else {
                continue;
            };
            if claim.predicate != PREDICATE_CALENDAR_STATUS
                || claim.lifecycle != ClaimLifecycleStatus::Active
            {
                continue;
            }
            let value = decode_status_value(&claim.value)
                .map_err(|_| ingest("stored status claim did not decode"))?;
            if value.status == CalendarStatus::Cancelled
                && value.basis == CalendarStatusBasis::ImportedCancel
            {
                return Ok(Some(claim_id));
            }
        }
        Ok(None)
    }

    /// The host cancelled the EVENT explicitly, in a calendar it was written
    /// to: a booking's deposit on it comes back whole (BK-DEPOSITS; RULING
    /// DEPOSIT-HOST-CANCEL-REFUND = A; the callers check the source, RULING
    /// DEPOSIT-HOST-CANCEL-SOURCE = A). An omission is no cancellation
    /// evidence and moves no money; an EVENT with no deposit writes nothing.
    /// The refund commits before the cancellation's status does, so the
    /// host's cancel is on record with its full refund owed before a
    /// visitor's cancel can follow it: that cancel then finds the refund owed
    /// and keeps it, while a visitor who cancelled first keeps their own
    /// cancel's refund. Asked on every sighting of the cancellation; the
    /// deposit step is idempotent.
    fn refund_host_cancelled_deposit(
        &self,
        event_ref: EntityId,
        seen_at: u64,
    ) -> Result<(), CalendarError> {
        #[cfg(oneiron_test_support)]
        if crate::test_doors::host_cancel_refund::take_stop_before_refund() {
            return Err(ingest("stopped before the host-cancel refund (test door)"));
        }
        crate::booking::lifecycle::refund_deposit_on_host_cancel(
            self.vault, &event_ref, seen_at, self.now,
        )
        .map_err(|error| CalendarError::IcsIngest {
            reason: error.to_string(),
        })?;
        #[cfg(oneiron_test_support)]
        crate::test_doors::host_cancel_refund::run_between_commits();
        Ok(())
    }

    /// Carries one explicit imported cancellation into CAL-07 as
    /// `CancelReceived` machine evidence citing the status claim that
    /// recorded it. First seen (`observed_at`) before the EVENT's start it
    /// records `cancelled_pre_start`; seen after, or on an EVENT with no
    /// anchored start, it earns nothing. The engine observed the cancellation
    /// in the bytes it fetched, so the outcome lands as `observed`.
    fn record_cancel_outcome(
        &self,
        event_ref: EntityId,
        status_ref: EntityId,
        observed_at: u64,
    ) -> Result<(), CalendarError> {
        #[cfg(oneiron_test_support)]
        if crate::test_doors::host_cancel_refund::take_stop_before_cancel_outcome() {
            return Err(ingest(
                "stopped before the cancellation's CAL-07 outcome (test door)",
            ));
        }
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
                observed_at,
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
                imported_screen(&request.verdict, self.screener),
            );
            Ok((admitted, token))
        })?;
        let (admitted, token) = screened.value;
        self.verdict_fold.record(token);
        let admitted = admitted?;
        self.admitted_claims.push(admitted);
        Ok(admitted)
    }

    fn passport_value(
        &self,
        event_ref: EntityId,
        event: &ParsedVEvent,
        presence: CalendarPassportPresence,
    ) -> Result<CalendarPassportValue, CalendarError> {
        let prior = crate::calendar::passport::live_passport_for(
            self.vault,
            &event_ref,
            self.system,
            &event.uid,
        )?
        .map(|(_, value)| value);
        let direction = match &prior {
            Some(prior) if self.preserve_direction => prior.direction,
            _ => CalendarPassportDirection::Inbound,
        };
        // A cancelled version keeps the first sighting of the cancellation
        // its source already reported: a newer SEQUENCE of a cancel seen
        // before a booking's start is not a cancel first seen now.
        let cancelled_since = event.cancelled.then(|| {
            prior
                .as_ref()
                .and_then(|prior| prior.cancelled_since)
                .unwrap_or(self.now)
        });
        Ok(CalendarPassportValue {
            system: self.system.to_owned(),
            uid: event.uid.clone(),
            last_sequence: event.sequence,
            content_hash: event.content_hash,
            source: self.source,
            direction,
            last_seen_at: self.now,
            presence,
            cancelled_since,
        })
    }

    /// The provenance ref admitted claims carry: the archived feed version
    /// plus the event's UID, so every semantic candidate points back at the
    /// raw bytes it was parsed from.
    fn source_record_id(&self, event: &ParsedVEvent) -> String {
        format!("{}:{}", self.blob_ref, event.uid)
    }
}

/// Whether `passport` is `system`'s own and names a calendar the EVENT was
/// written to: its direction is Outbound or TwoWay (RULING
/// DEPOSIT-HOST-CANCEL-SOURCE = A). Only such a source's cancellation moves
/// deposit money. A source the visitor can write (their own calendar the
/// owner subscribes to, a shared calendar) holds an Inbound passport, so its
/// cancellation writes `calendar.status` and the CAL-07 evidence and leaves
/// the deposit as it stands. The engine's own passports (the booking's and
/// the iMIP invite's) name no calendar.
fn names_written_calendar(system: &str, passport: &CalendarPassportValue) -> bool {
    passport.system == system
        && system != crate::booking::BOOKING_PASSPORT_SYSTEM
        && system != crate::calendar::invite::CALENDAR_INVITE_PASSPORT_SYSTEM
        && matches!(
            passport.direction,
            CalendarPassportDirection::Outbound | CalendarPassportDirection::TwoWay
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

/// The verdict token a flagged screen records on each claim it admits.
pub(super) const FLAGGED_VERDICT: &str = "flagged";

fn verdict_token(verdict: &super::safeguard::CalendarScreenVerdict) -> &'static str {
    match verdict {
        super::safeguard::CalendarScreenVerdict::Skipped => "skipped",
        super::safeguard::CalendarScreenVerdict::Clear => "clear",
        super::safeguard::CalendarScreenVerdict::Flagged { .. } => FLAGGED_VERDICT,
        super::safeguard::CalendarScreenVerdict::Indeterminate { .. } => "indeterminate",
    }
}

#[cfg(test)]
mod tests;
