//! Shared calendar connector kernel (CAL-05, ONE-1787).
//!
//! Two provider adapters — [`super::caldav`] and [`super::google_internal`] —
//! sit on this one small kernel. It is deliberately *not* a general connector
//! framework: it owns exactly what a calendar seat needs to pull, echo-suppress,
//! and conditionally write one remote calendar.
//!
//! What lives here:
//!
//! * seat configuration carrying a SECRET custody `secret_ref` (never a
//!   credential, never a URL with one embedded), a provider cursor, and an
//!   explicit kill switch;
//! * bounded, non-zero cadence jitter in the same shape
//!   [`super::ingest::IcsFeedPollConfig`] and `linkedin_connector` use;
//! * the provider-neutral remote rows ([`RemoteCalendarObject`],
//!   [`RemoteCalendarChange`], [`RemoteSyncBatch`], [`RemoteWriteRequest`],
//!   [`RemoteWriteReceipt`]) and the [`CalendarRemoteTransport`] seam. No
//!   HTTP/WebDAV/OAuth type crosses that seam, so the orchestration below is
//!   testable offline with fixtures;
//! * the durable local write outbox row, staged BEFORE any remote mutation;
//! * [`classify_remote_change`], the echo law that keeps a two-way seat from
//!   rewriting its own writes.
//!
//! ## The laws this module implements
//!
//! 1. **ICS truth, not transport truth.** A pulled upsert is re-parsed through
//!    [`super::ics::parse_ics_feed`]; the UID, SEQUENCE, and content hash used
//!    for classification come from that parse, never from the fields a
//!    transport happened to fill in. Time crosses only [`super::tz`].
//! 2. **UID before mint.** [`super::passport::resolve_event_by_uid`] runs before
//!    any EVENT is created, so the same UID seen through two providers is one
//!    EVENT with two system-scoped passports.
//! 3. **Echo suppression.** A same-or-older SEQUENCE with the same content hash
//!    is an acknowledgement: no semantic rewrite, no write-back. A newer
//!    SEQUENCE or a same-SEQUENCE hash drift applies once through the CAL-02
//!    Gate-backed imported-evidence door.
//! 4. **Multi-source law, verbatim from the ratified seam:** feed-absence
//!    cancellation applies ONLY when every live inbound passport for the EVENT
//!    reports absence; a single-source absence supersedes only that passport,
//!    never the EVENT status. The EVENT row is never deleted and CAL-07's
//!    outcome predicate is never written here.
//! 5. **Conditional writes only.** A local write stages an outbox row (action,
//!    UID, intended SEQUENCE, content hash, expected ETag) durably before the
//!    provider call, sends the expected ETag as the precondition, and enters
//!    reconciliation on mismatch instead of overwriting blind.
//! 6. **The kill switch is operational, not destructive.** It stops pulls and
//!    writes, empties the advertised verb catalog, and schedules no next poll;
//!    it erases no EVENT, passport, or outbox evidence.
//!
//! ## Custody posture (SECRET-02 swap point)
//!
//! Seat configs carry the custody record NAME only. This kernel never resolves
//! credential bytes at all — resolution happens below the transport seam, at the
//! provider egress door, exactly as [`super::ingest::CustodyDoorIcsFeedFetcher`]
//! does it today with `Vault::resolve_secret_ref` + the crate-private
//! `get_secret_value_in_txn` value door. When SECRET-02's
//! `inject_secret_at_door` / `materialize_secret_lease` land, that door swaps
//! with no signature change here, because nothing in this module — config,
//! cursor, attempt payload, outbox row, receipt, error, or `Debug` — has a
//! place to hold a credential.

mod inbound;
mod outbound;
mod remote;
mod seat;

// `super::` paths inside the moved bodies still name the calendar level
// (one body reads provider keys, one reads ICS transparency constants), so
// the parent re-mounts those modules here; the paths stay byte-identical.
use super::caldav;
use super::claims;
use super::google_internal;

pub use self::inbound::run_calendar_connector_sync;
pub use self::outbound::{
    CalendarRemoteObjectRow, CalendarWriteAction, CalendarWriteOutboxRow, CalendarWriteOutboxState,
    write_calendar_event,
};
pub use self::remote::{
    CalendarRemoteTransport, CalendarSyncOutcome, EchoDisposition, RemoteCalendarChange,
    RemoteCalendarObject, RemoteSyncBatch, RemoteWriteReceipt, RemoteWriteRequest,
    calendar_remote_object_row, calendar_write_outbox_row, calendar_write_outbox_rows,
    classify_remote_change,
};
pub use self::seat::{
    CALDAV_SYNC_ATTEMPT_KIND, CALENDAR_CONNECTOR_PULL_VERB, CALENDAR_CONNECTOR_WRITE_VERB,
    CalendarConnectorError, CalendarConnectorKillSwitchState, CalendarConnectorSeatConfig,
    CalendarConnectorSeatState, CalendarConnectorSyncPayload, GOOGLE_INTERNAL_SYNC_ATTEMPT_KIND,
    calendar_sync_attempt_kind,
};
