//! A poll's host cancellations: an explicit cancel in the feed, or an
//! event gone from it, writes `calendar.status` cancelled and carries it to
//! CAL-07, and a booking's deposit refund commits first when the source is a
//! calendar the EVENT was written to.

use super::super::ingest;
use super::{PollAdmission, screen_body};
use crate::calendar::CalendarError;
use crate::calendar::claims::{
    CalendarPassportDirection, CalendarPassportValue, CalendarStatus, CalendarStatusBasis,
    PREDICATE_CALENDAR_STATUS, decode_status_value,
};
use crate::calendar::ics::ParsedVEvent;
use crate::calendar::passport::live_passports_for_event;
use crate::calendar::safeguard::CalendarInboundBody;
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;

impl PollAdmission<'_> {
    /// An explicit cancellation in the feed (`METHOD:CANCEL` or
    /// `STATUS:CANCELLED`): write `calendar.status` cancelled with basis
    /// `imported_cancel`, unless a live claim already says exactly that, and
    /// carry it to CAL-07 as pre-start cancellation evidence. Never writes
    /// `confirmed` — resurrection is not a v1 basis. When this source is a
    /// calendar the EVENT was written to and the cancellation is not the
    /// engine's own cancelled write ([`cancel_moves_deposit`]), a booking's
    /// deposit refund commits first, on every sighting, also when the status
    /// already stood; any other source moves no money. Both are
    /// dated by the source's first report of the cancellation, which its
    /// passport (committed before this runs) carries across versions; a path
    /// with no such passport dates it now.
    pub(super) fn apply_imported_cancel(
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
            .is_some_and(|passport| cancel_moves_deposit(self.system, passport))
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
    /// provider tombstone. A tombstone from a calendar the EVENT was written
    /// to concludes it alone when no inbound source carries the EVENT
    /// (RULING CAL-SEAT-DELETE-OF-WRITTEN-ONLY-EVENT-CANCELS-NOTHING = A). The
    /// EVENT row is never deleted. Only the explicit tombstone is
    /// cancellation evidence for CAL-07, observed when this source first
    /// reported it; an omission writes the status alone. The
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
    pub(super) fn admit_absence_cancellation(
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

    /// When a calendar the EVENT was written to ([`cancel_moves_deposit`]
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
            cancel_moves_deposit(&value.system, value)
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
    /// ([`cancel_moves_deposit`]) only. The status is asked only while no
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
    pub(super) fn repeat_imported_cancel(
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
        if cancel_moves_deposit(self.system, &passport) {
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
}

/// Whether `passport` is `system`'s own and names a calendar the EVENT was
/// written to: its direction is Outbound or TwoWay (RULING
/// DEPOSIT-HOST-CANCEL-SOURCE = A). Only such a source's cancellation moves
/// deposit money, and not when it is the engine's own cancelled write
/// ([`cancel_moves_deposit`]). A source the visitor can write (their own calendar the
/// owner subscribes to, a shared calendar) holds an Inbound passport, so its
/// cancellation writes `calendar.status` and the CAL-07 evidence and leaves
/// the deposit as it stands. The engine's own passports (the booking's and
/// the iMIP invite's) name no calendar.
pub(super) fn names_written_calendar(system: &str, passport: &CalendarPassportValue) -> bool {
    passport.system == system
        && system != crate::booking::BOOKING_PASSPORT_SYSTEM
        && system != crate::calendar::invite::CALENDAR_INVITE_PASSPORT_SYSTEM
        && matches!(
            passport.direction,
            CalendarPassportDirection::Outbound | CalendarPassportDirection::TwoWay
        )
}

/// Whether a cancellation `system` reports through `passport` moves deposit
/// money: the passport names a calendar the EVENT was written to
/// ([`names_written_calendar`]), and the cancellation is not the engine's own
/// write of the EVENT already cancelled to that calendar
/// (`written_cancelled`; BK-DEPOSIT-REWRITTEN-ECHO-OF-OWNER-WRITE-REFUNDS). The
/// owner who writes an EVENT a feed the booking was not written to cancelled
/// mirrors that cancel; a provider that rewrites the written resource sends
/// it back as a new version, which is still no host cancel.
pub(super) fn cancel_moves_deposit(system: &str, passport: &CalendarPassportValue) -> bool {
    names_written_calendar(system, passport) && !passport.written_cancelled
}
