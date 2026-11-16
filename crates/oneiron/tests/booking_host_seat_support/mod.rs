//! The host's own calendar as a connector seat the booking is written to.
//!
//! A booking's deposit moves only on a cancellation from a calendar the
//! booking was written to (RULING DEPOSIT-HOST-CANCEL-SOURCE = A): a source
//! whose own live passport for the UID is Outbound or TwoWay. An ICS feed
//! poll always writes its passports Inbound, so the host-cancel deposit
//! tests cancel through this seat instead: each booking is written to it
//! first, then its cancellations arrive as seat pulls.
//!
//! Patterns follow `tests/it/calendar_connector_smoke.rs`: the seat config,
//! the owner-installed operation, a transport implementing
//! [`CalendarRemoteTransport`] directly, and one ICS resource per booking
//! per pull.

#![allow(dead_code)] // each deposit test binary uses a subset of these helpers

use std::collections::VecDeque;
use std::sync::Mutex;

use oneiron::calendar::caldav::CALDAV_PROVIDER_KEY;
use oneiron::calendar::connectors::door::{
    self, CalendarConnectorConfigureRequest, CalendarConnectorOperation, CalendarConnectorRequest,
};
use oneiron::calendar::connectors::{
    CalendarConnectorError, CalendarConnectorSeatConfig, CalendarRemoteTransport,
    CalendarSyncOutcome, RemoteCalendarChange, RemoteCalendarObject, RemoteSyncBatch,
    RemoteWriteReceipt, RemoteWriteRequest, run_calendar_connector_sync, write_calendar_event,
};
use oneiron::calendar::parse_ics_feed;
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Vault};

/// The CalDAV discovery URL every seat here is installed with (smoke :689).
const SEAT_ENDPOINT: &str = "https://calendar.example.test/";

/// Monday 2 Mar 2026 00:00 UTC, the deposit fixtures' Monday.
const MONDAY: u64 = 1_772_409_600;

/// The vault's owner, authenticated: the seats here are the owner's (smoke :692).
fn seat_owner(vault: &Vault) -> (EntityId, AuthenticatedOwner) {
    let id = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let owner = vault
        .authenticate_owner(id, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof");
    (id, owner)
}

/// One pulled change: an ICS resource for one booking, or a provider tombstone.
pub(crate) enum SeatChange {
    /// One booking's resource at its slot, live or cancelled.
    Upsert {
        /// The resource path, as the provider reported it.
        href: String,
        /// The booking's UID.
        uid: String,
        /// The slot's half-open `[start, end)`.
        start: u64,
        end: u64,
        sequence: u32,
        cancelled: bool,
    },
    /// The provider removed the resource carrying one booking's UID.
    Tombstone {
        /// The booking's UID.
        uid: String,
    },
}

impl SeatChange {
    /// One booking's resource at its slot and at `sequence`, live or
    /// cancelled, carried under the href the seat's write of it returned.
    pub(crate) fn upsert(
        receipt: &RemoteWriteReceipt,
        start: u64,
        end: u64,
        sequence: u32,
        cancelled: bool,
    ) -> Self {
        Self::Upsert {
            href: receipt.href.clone(),
            uid: receipt.uid.clone(),
            start,
            end,
            sequence,
            cancelled,
        }
    }

    /// One booking's resource on a seat it was never written to, at its slot
    /// and at `sequence`, under that seat's resource path for the UID.
    pub(crate) fn foreign(
        seat: &Seat,
        uid: &str,
        start: u64,
        end: u64,
        sequence: u32,
        cancelled: bool,
    ) -> Self {
        Self::Upsert {
            href: seat.resource_href(uid),
            uid: uid.to_owned(),
            start,
            end,
            sequence,
            cancelled,
        }
    }

    /// A provider tombstone for one booking's UID.
    pub(crate) fn tombstone(uid: &str) -> Self {
        Self::Tombstone {
            uid: uid.to_owned(),
        }
    }
}

/// The host's seat: its installed config plus the scripted wire its pulls
/// and writes run on.
pub(crate) struct Seat {
    config: CalendarConnectorSeatConfig,
    transport: ScriptedSeatTransport,
}

impl Seat {
    /// Installs the seat under `system` (smoke :261 `caldav_config`, :757
    /// `operation`): the owner installs it through the configure door, as the
    /// host does. A seat may be installed under another system name for a
    /// calendar the booking was never written to.
    pub(crate) fn install(vault: &Vault, system: &str) -> Self {
        let config = CalendarConnectorSeatConfig {
            seat_ref: format!("seat:{system}"),
            secret_ref: format!("seat-secret:{system}"),
            system: system.to_owned(),
            calendar_ref: format!("{system}-calendar"),
            cadence_jitter_min_seconds: 300,
            cadence_jitter_max_seconds: 900,
        };
        let (id, owner) = seat_owner(vault);
        door::configure(
            &vault.memory(id, EdgeActorClass::Human),
            &owner,
            &CalendarConnectorConfigureRequest {
                config: config.clone(),
                endpoint: SEAT_ENDPOINT.to_owned(),
            },
        )
        .expect("the owner installs the seat");
        Self {
            config,
            transport: ScriptedSeatTransport::default(),
        }
    }

    /// Writes one booking EVENT to the seat's calendar. The receipt carries
    /// the booking's UID, since the seat has no passport of its own yet and
    /// the booking's admitted `oneiron.booking` passport is the UID it shares.
    pub(crate) fn write(&self, vault: &Vault, event_ref: EntityId, now: u64) -> RemoteWriteReceipt {
        write_calendar_event(
            vault,
            &self.operation(vault),
            &self.transport,
            event_ref,
            now,
        )
        .expect("write the booking to the seat")
    }

    /// Pulls one batch of booking resources and tombstones, returning the
    /// sync's result so a test can expect an error (smoke :801 `run_sync`).
    pub(crate) fn pull(
        &self,
        vault: &Vault,
        changes: &[SeatChange],
        now: u64,
    ) -> Result<CalendarSyncOutcome, CalendarConnectorError> {
        let changes = changes
            .iter()
            .map(|change| match change {
                SeatChange::Upsert {
                    href,
                    uid,
                    start,
                    end,
                    sequence,
                    cancelled,
                } => {
                    let ics = booking_ics(uid, *start, *end, *sequence, *cancelled);
                    RemoteCalendarChange::Upsert(remote_upsert(
                        href,
                        Some(&format!("{href}-s{sequence}")),
                        &ics,
                    ))
                }
                SeatChange::Tombstone { uid } => RemoteCalendarChange::Delete {
                    href: self.resource_href(uid),
                    uid: uid.to_string(),
                },
            })
            .collect();
        self.run_pull(vault, changes, now)
    }

    /// Pulls back the seat's own last write of one booking byte for byte, as
    /// a provider that keeps the written resource unchanged returns it: the
    /// echo of that write.
    pub(crate) fn pull_own_write(
        &self,
        vault: &Vault,
        receipt: &RemoteWriteReceipt,
        now: u64,
    ) -> Result<CalendarSyncOutcome, CalendarConnectorError> {
        let ics = self
            .transport
            .writes
            .lock()
            .expect("written requests")
            .iter()
            .rev()
            .find(|request| request.uid == receipt.uid)
            .expect("the seat holds a write of this booking")
            .ics
            .clone();
        let echo = remote_upsert(&receipt.href, receipt.etag.as_deref(), &ics);
        self.run_pull(vault, vec![RemoteCalendarChange::Upsert(echo)], now)
    }

    /// Runs one sync whose pull answers `changes`.
    fn run_pull(
        &self,
        vault: &Vault,
        changes: Vec<RemoteCalendarChange>,
        now: u64,
    ) -> Result<CalendarSyncOutcome, CalendarConnectorError> {
        self.transport
            .batches
            .lock()
            .expect("scripted batches")
            .push_back(RemoteSyncBatch {
                next_cursor: None,
                changes,
            });
        run_calendar_connector_sync(vault, &self.operation(vault), &self.transport, now, 7)
    }

    /// The calendar operation on the installed seat: the configure door is
    /// idempotent, so this re-reads the installed row and binds the owner to
    /// it exactly (smoke :757).
    fn operation(&self, vault: &Vault) -> CalendarConnectorOperation {
        let (id, owner) = seat_owner(vault);
        let memory = vault.memory(id, EdgeActorClass::Human);
        door::configure(
            &memory,
            &owner,
            &CalendarConnectorConfigureRequest {
                config: self.config.clone(),
                endpoint: SEAT_ENDPOINT.to_owned(),
            },
        )
        .expect("the owner installs the seat");
        let row = door::get(
            &memory,
            &owner,
            &CalendarConnectorRequest {
                seat_ref: self.config.seat_ref.clone(),
            },
        )
        .expect("read the installed seat")
        .expect("the seat is installed");
        CalendarConnectorOperation::new(vault, owner, row)
            .expect("the operation on the installed seat")
    }

    /// The seat's resource path for one UID, as the receipt's default href
    /// builds it (`parsed_receipt` below).
    fn resource_href(&self, uid: &str) -> String {
        format!("/{}/{uid}.ics", self.config.calendar_ref)
    }
}

/// A scripted wire implementing [`CalendarRemoteTransport`] directly, as
/// `DeleteEventAfterUpsert` does (smoke :509): `pull` pops one scripted
/// batch (an empty batch when none is left), `upsert` records the request
/// and answers an honest receipt, `delete` is unused.
#[derive(Default)]
struct ScriptedSeatTransport {
    batches: Mutex<VecDeque<RemoteSyncBatch>>,
    writes: Mutex<Vec<RemoteWriteRequest>>,
}

impl CalendarRemoteTransport for ScriptedSeatTransport {
    fn provider_key(&self) -> &'static str {
        CALDAV_PROVIDER_KEY
    }

    fn pull(
        &self,
        _secret_ref: &str,
        _calendar_ref: &str,
        _cursor: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError> {
        Ok(self
            .batches
            .lock()
            .expect("scripted batches")
            .pop_front()
            .unwrap_or(RemoteSyncBatch {
                next_cursor: None,
                changes: Vec::new(),
            }))
    }

    fn upsert(
        &self,
        _secret_ref: &str,
        calendar_ref: &str,
        request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        self.writes
            .lock()
            .expect("written requests")
            .push(request.clone());
        Ok(parsed_receipt(
            &format!("/{calendar_ref}/"),
            Some(&format!("{}-write-1", request.uid)),
            request,
        ))
    }

    fn delete(
        &self,
        _secret_ref: &str,
        _calendar_ref: &str,
        _href: &str,
        _expected_etag: Option<&str>,
        _uid: &str,
        _sequence: u32,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        panic!("delete is not used by the host-seat fixture")
    }
}

/// A UTC instant on the fixture Monday as an ICS DATE-TIME.
fn ics_utc(ts: u64) -> String {
    let secs = ts - MONDAY;
    format!(
        "20260302T{:02}{:02}{:02}Z",
        secs / 3_600,
        secs / 60 % 60,
        secs % 60
    )
}

/// One booking's pulled resource: its UID at its slot and at `sequence`,
/// live or cancelled.
fn booking_ics(uid: &str, start: u64, end: u64, sequence: u32, cancelled: bool) -> Vec<u8> {
    let mut out = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n");
    out.push_str("BEGIN:VEVENT\r\n");
    out.push_str(&format!("UID:{uid}\r\n"));
    out.push_str("DTSTAMP:20260302T070000Z\r\n");
    out.push_str(&format!("DTSTART:{}\r\n", ics_utc(start)));
    out.push_str(&format!("DTEND:{}\r\n", ics_utc(end)));
    out.push_str(&format!("SEQUENCE:{sequence}\r\n"));
    out.push_str("SUMMARY:intro-call\r\n");
    if cancelled {
        out.push_str("STATUS:CANCELLED\r\n");
    }
    out.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
    out.into_bytes()
}

/// One remote upsert row whose reported UID/SEQUENCE/hash are read back out of
/// the ICS body itself (smoke :155 `remote_upsert`).
fn remote_upsert(href: &str, etag: Option<&str>, ics: &[u8]) -> RemoteCalendarObject {
    let feed = parse_ics_feed(ics).expect("fixture ics parses");
    let event = feed.events.first().expect("fixture carries a VEVENT");
    RemoteCalendarObject {
        href: href.to_owned(),
        etag: etag.map(str::to_owned),
        uid: event.uid.clone(),
        sequence: event.sequence,
        content_hash: event.content_hash,
        ics: ics.to_vec(),
    }
}

/// The receipt one honest wire returns for a conditional put: every field read
/// back through the ICS parse (smoke :197 `parsed_receipt`).
fn parsed_receipt(
    calendar_href: &str,
    etag: Option<&str>,
    request: &RemoteWriteRequest,
) -> RemoteWriteReceipt {
    let feed = parse_ics_feed(&request.ics).expect("written ics parses");
    let event = feed
        .events
        .iter()
        .find(|event| event.uid == request.uid)
        .or_else(|| feed.events.first())
        .expect("written ics carries a VEVENT");
    RemoteWriteReceipt {
        href: request
            .href
            .clone()
            .unwrap_or_else(|| format!("{calendar_href}{}.ics", event.uid)),
        etag: etag.map(str::to_owned),
        uid: event.uid.clone(),
        sequence: event.sequence,
        content_hash: event.content_hash,
    }
}
