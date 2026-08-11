//! Calendar module home (CAL-00).
//!
//! Owns the `calendar.*` claim family and the single calendar error home. The
//! family is claims-on-EVENT: this layer allocates no entity type byte, no
//! `EdgeKind`, and no serialization profile change. Series, exception,
//! successor, passport, and outcome relations are all claim values.
//!
//! CAL-09 adds the read side on top of that family — [`query`] projects EVENTs
//! and [`freebusy`] projects busy-only occupancy — plus the optional inbound
//! [`safeguard`] hook CAL-02 calls before imported-claim admission.
//!
//! CAL-07 adds [`outcome`]: the evidence ladder that decides what happened at an
//! EVENT, the post-end check-in it arms, and the `calendar.event_outcome` head
//! CA-04 reads as stage-transition evidence.
//!
//! CAL-01 adds [`tz`]: the one border where the `u64` UTC core meets IANA wall
//! time. The IANA database is private to that module — no third-party datetime
//! type crosses a public signature here or anywhere else in the crate.
//!
//! CAL-03 adds [`series`]: recurrence expansion over that border, always
//! windowed by the caller's [`crate::temporal::TimeRange`]. Master, exception
//! and successor stay claims-on-EVENT there too, so a recurring meeting adds
//! no edge and no byte either.
//!
//! CAL-02 adds the ICS ingest adapter: [`ics`] parses RFC 5545 feeds into
//! calendar-owned rows, [`passport`] keeps the UID-first cross-calendar index
//! and the per-`(system × UID)` diff, and [`ingest`] runs the secret-URL poll
//! — custody-ref payloads, door-scoped URL injection, Gate-backed imported
//! admission behind the CAL-09 safeguard hook, and the multi-source absence
//! law.
//!
//! CAL-05 adds the connector rung: [`connectors`] is the shared seat kernel
//! (custody-ref configs, cursors, bounded jitter, kill switch, echo law, and a
//! durable local write outbox) over the [`CalendarRemoteTransport`] seam, and
//! [`caldav`] / [`google_internal`] adapt the two v1.5 provider classes to it.
//! Credential bytes never cross that seam: configs carry SECRET custody
//! `secret_ref` names only, and each wire resolves them at its own egress door.
//!
//! [`CalendarRemoteTransport`]: connectors::CalendarRemoteTransport

pub mod caldav;
pub mod claims;
pub mod connectors;
pub mod freebusy;
pub mod google_internal;
pub mod ics;
pub mod ingest;
pub mod outcome;
pub mod passport;
pub mod query;
pub mod safeguard;
pub mod series;
pub mod tz;

/// Single calendar error home. Later stack layers append variants.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CalendarError {
    /// The named zone is not in the IANA database. Never a silent UTC fallback.
    #[error("unknown IANA time zone: {tz}")]
    UnknownTimeZone {
        /// The zone name as supplied.
        tz: String,
    },
    /// The civil fields are not a real date/time, or they are real in their
    /// zone but their instant is outside the supported range — before the epoch
    /// and so outside the engine's `u64` UTC model, or past the top of it.
    #[error("invalid wall time")]
    InvalidWallTime,
    /// The civil time falls in a spring-forward gap and has no UTC instant. The
    /// caller decides skip-vs-shift; the border never shifts silently. A civil
    /// time that is unique but out of range is [`Self::InvalidWallTime`], not
    /// this.
    #[error("wall time does not exist in time zone {tz}")]
    NonexistentWallTime {
        /// The civil time that has no instant in `tz`.
        wall: tz::WallTime,
        /// The zone whose transition removed it.
        tz: String,
    },
    /// The timestamp is past the supported conversion range.
    #[error("UTC timestamp is outside the supported calendar range: {utc}")]
    TimestampOutOfRange {
        /// The offending timestamp.
        utc: u64,
    },
    /// The recurrence text is not RFC 5545 the engine can expand, or expanding
    /// it over the requested window costs more than the supported walk. Never
    /// answered with a short or empty series.
    #[error("invalid or unsupported recurrence rule: {rule}")]
    InvalidRecurrenceRule {
        /// The rule text as supplied.
        rule: String,
    },
    /// The expansion window runs backwards. A one-instant window is valid; a
    /// window whose start is past its end is a caller bug, not an empty answer.
    #[error("invalid recurrence window")]
    InvalidRecurrenceWindow,
    /// The feed body is not a complete, parseable RFC 5545 `VCALENDAR`. A
    /// parse failure is never interpreted as feed content or event removal.
    #[error("ICS feed parse failure: {reason}")]
    IcsParse {
        /// What failed, without feed content.
        reason: String,
    },
    /// The conditional HTTP fetch failed. The reason never carries the
    /// resolved feed URL.
    #[error("ICS feed HTTP fetch failure: {reason}")]
    IcsFetch {
        /// What failed, URL-scrubbed.
        reason: String,
    },
    /// SECRET custody resolution or the value door refused the read. Carries
    /// the custody record name, never the resolved URL.
    #[error("ICS feed credential custody failure: {reason}")]
    IcsCredential {
        /// What failed, naming custody refs only.
        reason: String,
    },
    /// The adapter's own state or the store underneath it failed.
    #[error("ICS ingest failure: {reason}")]
    IcsIngest {
        /// What failed.
        reason: String,
    },
}

impl From<crate::Error> for CalendarError {
    fn from(err: crate::Error) -> Self {
        Self::IcsIngest {
            reason: err.to_string(),
        }
    }
}

pub use caldav::{
    CALDAV_PROVIDER_KEY, CalDavConnector, CalDavDiscovery, CalDavWire, caldav_write_status_error,
};
pub use claims::{
    CALENDAR_CLAIM_PREDICATES, CalendarBusyTransparency, CalendarOrigin, CalendarPassportDirection,
    CalendarPassportPresence, CalendarPassportValue, CalendarSeriesExceptionValue,
    CalendarSeriesMasterValue, CalendarStatus, CalendarStatusBasis, CalendarStatusValue,
    CalendarSuccessorValue, CalendarTimeKind, CalendarTimeKindValue, ClaimClassDescriptorRow,
    claim_class_descriptors, is_calendar_claim_predicate,
};
pub use connectors::{
    CALDAV_SYNC_ATTEMPT_KIND, CALENDAR_CONNECTOR_PULL_VERB, CALENDAR_CONNECTOR_WRITE_VERB,
    CalendarConnectorError, CalendarConnectorKillSwitchState, CalendarConnectorSeatConfig,
    CalendarConnectorSeatState, CalendarConnectorSyncPayload, CalendarRemoteObjectRow,
    CalendarRemoteTransport, CalendarSyncOutcome, CalendarWriteAction, CalendarWriteOutboxRow,
    CalendarWriteOutboxState, EchoDisposition, GOOGLE_INTERNAL_SYNC_ATTEMPT_KIND,
    RemoteCalendarChange, RemoteCalendarObject, RemoteSyncBatch, RemoteWriteReceipt,
    RemoteWriteRequest, calendar_remote_object_row, calendar_sync_attempt_kind,
    calendar_write_outbox_row, calendar_write_outbox_rows, classify_remote_change,
    run_calendar_connector_sync, write_calendar_event,
};
pub use freebusy::{BusyInterval, BusyUnion, freebusy, freebusy_scoped};
pub use google_internal::{
    GOOGLE_INTERNAL_PROVIDER_KEY, GOOGLE_INTERNAL_SECRET_REF_PREFIX, GoogleInternalConnector,
    GoogleInternalWire, is_workspace_internal_secret_ref,
};
pub use ics::{ParsedIcsFeed, ParsedVEvent, parse_ics_feed};
pub use ingest::{
    CustodyDoorIcsFeedFetcher, ICS_POLL_ATTEMPT_KIND, IcsFeedCursorSnapshot, IcsFeedFetcher,
    IcsFeedPauseException, IcsFeedPollConfig, IcsFeedPollPayload, IcsFeedSource, IcsFetchResponse,
    IcsHttpResponse, IcsHttpTransport, IcsPollRunState, enqueue_ics_feed_poll,
    ics_feed_cursor_snapshot, ics_feed_pause_exceptions, ics_feed_poll_dedupe_key,
    ics_import_actor_id, run_ics_feed_poll, run_ics_feed_poll_with_screener,
};
pub use outcome::{
    CheckInAnswer, CheckInCardModel, CheckInCopy, CheckInResolution, DEFAULT_OUTCOME_GRACE_SECS,
    DueOutcomeCheckIn, EventOutcome, EventOutcomeBasis, EventOutcomeClaimValue,
    MachineOutcomeEvidence, MeetingClassSignals, OUTCOME_CHECK_IN_REASON_TAG, OutcomeCheckInWake,
    PREDICATE_CALENDAR_EVENT_OUTCOME, accept_check_in_recording, build_check_in_lens,
    check_in_is_still_due, check_in_recording_artifact_id, is_meeting_class,
    outcome_from_machine_evidence, plan_outcome_check_in, project_event_outcome,
    read_event_outcome, record_event_outcome, resolve_owner_check_in,
};
pub use passport::{
    CALENDAR_PASSPORT_INDEX_PREFIX, PassportDecision, all_live_inbound_passports_absent,
    classify_passport, index_passport_uid, live_passport_for, live_passports_for_event,
    resolve_event_by_uid, supersede_calendar_passport,
};
pub use query::{
    CalendarEventView, CalendarRangeDto, CalendarRead, CalendarReadRequest, CalendarSearchRequest,
    CalendarSel, MAX_CALENDAR_SEARCH_LIMIT, read_event, read_event_scoped, search_events,
    search_events_scoped,
};
pub use safeguard::{
    CALENDAR_SAFEGUARD_CONFIG_KEY, CALENDAR_SAFEGUARD_REASON_NO_SCREENER, CalendarAdmissionRequest,
    CalendarBodyScreener, CalendarInboundBody, CalendarScreenVerdict, Screened, screen_then_claim,
};
pub use series::{
    SeriesDtStart, SeriesExceptionKey, exception_identity, expand_master_window, expand_window,
    mask_master_exceptions,
};
pub use tz::{WallTime, utc_to_wall, wall_to_utc};

#[cfg(test)]
pub(crate) mod test_support {
    //! Calendar EVENT fixtures shared by the CAL-09 unit tests.
    //!
    //! One builder, so every test writes its EVENTs through the same public
    //! doors (`put_entity` + `put_claim`) the real ingest path uses and no test
    //! grows a private notion of what a calendar EVENT is.

    use rmpv::Value;

    use super::claims::{
        CalendarBusyTransparency, PREDICATE_CALENDAR_ORIGIN, PREDICATE_CALENDAR_STATUS,
        PREDICATE_CALENDAR_TIME_KIND,
    };
    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use crate::config::VaultConfig;
    use crate::entity_id::EntityId;
    use crate::registry::ENTITY_TYPE_EVENT;
    use crate::temporal::TimeRange;
    use crate::vault::Vault;

    /// Opens a temporary vault for calendar fixtures.
    pub(crate) fn open_calendar_vault() -> (tempfile::TempDir, Vault) {
        crate::test_util::open_test_vault_with(VaultConfig::default())
    }

    /// Encodes an EVENT body carrying the `name` field the EVENT profile pins.
    pub(crate) fn event_name_body(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        rmpv::encode::write_value(
            &mut out,
            &Value::Map(vec![(Value::from("name"), Value::from(name))]),
        )
        .expect("encode event body");
        out
    }

    /// One calendar EVENT fixture: an EVENT entity plus its `calendar.*` claims.
    pub(crate) struct CalendarEventFixture {
        seed: u8,
        name: String,
        occurred: TimeRange,
        transparency: CalendarBusyTransparency,
        cancelled: bool,
        approval: ClaimApprovalStatus,
    }

    impl CalendarEventFixture {
        pub(crate) fn new(seed: u8, name: &str, start: u64, end: u64) -> Self {
            Self {
                seed,
                name: name.to_owned(),
                occurred: TimeRange { start, end },
                transparency: CalendarBusyTransparency::Busy,
                cancelled: false,
                approval: ClaimApprovalStatus::Approved,
            }
        }

        pub(crate) fn transparency(mut self, transparency: CalendarBusyTransparency) -> Self {
            self.transparency = transparency;
            self
        }

        pub(crate) fn cancelled(mut self) -> Self {
            self.cancelled = true;
            self
        }

        /// Stores the family claims as `proposed` instead of `approved`, so the
        /// EVENT's calendar facts are present on disk but not surfaceable.
        pub(crate) fn proposed(mut self) -> Self {
            self.approval = ClaimApprovalStatus::Proposed;
            self
        }

        pub(crate) fn store(self, vault: &Vault) -> EntityId {
            let id = crate::test_util::entity(self.seed);
            vault
                .put_entity(
                    &id,
                    ENTITY_TYPE_EVENT,
                    self.occurred,
                    1,
                    &event_name_body(&self.name),
                )
                .expect("put calendar event");

            self.put_claim(
                vault,
                id,
                0,
                PREDICATE_CALENDAR_ORIGIN,
                Value::from("imported"),
            );
            self.put_claim(
                vault,
                id,
                1,
                PREDICATE_CALENDAR_TIME_KIND,
                Value::Map(vec![
                    (Value::from("kind"), Value::from("absolute")),
                    (
                        Value::from("busy_transparency"),
                        Value::from(self.transparency.as_str()),
                    ),
                ]),
            );
            if self.cancelled {
                self.put_claim(
                    vault,
                    id,
                    2,
                    PREDICATE_CALENDAR_STATUS,
                    Value::Map(vec![
                        (Value::from("status"), Value::from("cancelled")),
                        (Value::from("basis"), Value::from("imported_cancel")),
                        (Value::from("recorded_at"), Value::from(1_754_400_000_u64)),
                    ]),
                );
            }
            id
        }

        fn put_claim(
            &self,
            vault: &Vault,
            subject: EntityId,
            index: u8,
            predicate: &str,
            value: Value,
        ) {
            // `(0xC0, event seed, claim index)` keys every fixture claim
            // uniquely without colliding with any generic `entity(seed)` id.
            let mut bytes = [0xC0_u8; 16];
            bytes[1] = self.seed;
            bytes[2] = index;
            let claim_id = EntityId::from_bytes(bytes).expect("claim fixture id");
            vault
                .put_claim(
                    &claim_id,
                    &ClaimBody::new(
                        predicate,
                        ClaimSubject::Entity(subject),
                        value,
                        1.0,
                        self.approval,
                        ClaimLifecycleStatus::Active,
                    ),
                    TimeRange { start: 1, end: 1 },
                    1,
                )
                .expect("put calendar claim");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CalendarError, tz::WallTime};

    #[test]
    fn calendar_error_appends_recurrence_variants_in_owner_module() {
        // One error home for the whole calendar surface, grown by appending.
        // CAL-00 opened it, CAL-01 added the four timezone verdicts, CAL-03
        // the two recurrence verdicts, and CAL-02 the four ingest variants
        // below.
        let variants = [
            CalendarError::UnknownTimeZone {
                tz: "Mars/Olympus_Mons".to_owned(),
            },
            CalendarError::InvalidWallTime,
            CalendarError::NonexistentWallTime {
                wall: WallTime {
                    y: 2026,
                    mo: 3,
                    d: 29,
                    h: 1,
                    mi: 30,
                    s: 0,
                },
                tz: "Europe/London".to_owned(),
            },
            CalendarError::TimestampOutOfRange { utc: u64::MAX },
            CalendarError::InvalidRecurrenceRule {
                rule: "FREQ=NEVER".to_owned(),
            },
            CalendarError::InvalidRecurrenceWindow,
            CalendarError::IcsParse {
                reason: "truncated feed".to_owned(),
            },
            CalendarError::IcsFetch {
                reason: "connection refused".to_owned(),
            },
            CalendarError::IcsCredential {
                reason: "no live custody record".to_owned(),
            },
            CalendarError::IcsIngest {
                reason: "store failure".to_owned(),
            },
        ];

        // Exhaustive and wildcard-free on purpose. A later layer that appends a
        // variant has to come back here and say so; one that *replaces* or
        // reorders an existing variant stops compiling instead of silently
        // changing what an older caller's match arm means.
        for variant in &variants {
            match variant {
                CalendarError::UnknownTimeZone { .. }
                | CalendarError::InvalidWallTime
                | CalendarError::NonexistentWallTime { .. }
                | CalendarError::TimestampOutOfRange { .. } => {}
                CalendarError::InvalidRecurrenceRule { .. }
                | CalendarError::InvalidRecurrenceWindow => {}
                CalendarError::IcsParse { .. }
                | CalendarError::IcsFetch { .. }
                | CalendarError::IcsCredential { .. }
                | CalendarError::IcsIngest { .. } => {}
            }
        }

        assert_eq!(
            variants[4].to_string(),
            "invalid or unsupported recurrence rule: FREQ=NEVER"
        );
        assert_eq!(variants[5].to_string(), "invalid recurrence window");
        assert_eq!(
            variants[6].to_string(),
            "ICS feed parse failure: truncated feed"
        );
        assert_eq!(
            variants[8].to_string(),
            "ICS feed credential custody failure: no live custody record"
        );
    }
}
