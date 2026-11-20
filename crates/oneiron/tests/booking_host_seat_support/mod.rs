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
//! the operation on the owner's installed seat, a transport implementing
//! [`CalendarRemoteTransport`] directly, and one ICS resource per booking
//! per pull. The owner installs each seat through the
//! `calendar.connector_seat` setting (SETTING-KEYED-A K3a removed the
//! configure door).

#![allow(dead_code)] // each deposit test binary uses a subset of these helpers

use std::collections::VecDeque;
use std::sync::Mutex;

use oneiron::calendar::caldav::CALDAV_PROVIDER_KEY;
use oneiron::calendar::connectors::door::{
    self, CalendarConnectorOperation, CalendarConnectorRequest,
};
use oneiron::calendar::connectors::{
    CalendarConnectorError, CalendarConnectorSeatConfig, CalendarRemoteTransport,
    CalendarSyncOutcome, RemoteCalendarChange, RemoteCalendarObject, RemoteSyncBatch,
    RemoteWriteReceipt, RemoteWriteRequest, calendar_collection_members_for_operation,
    calendar_write_outbox_rows, run_calendar_connector_sync, write_calendar_event,
};
use oneiron::calendar::parse_ics_feed;
use oneiron::consent::AuthenticatedOwner;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::json;

/// The CalDAV discovery URL every seat here is installed with (smoke :689).
const SEAT_ENDPOINT: &str = "https://calendar.example.test/";

/// The setting a CalDAV seat is installed through, one item per seat ref
/// (SETTING-KEYED-A K3a; `tests/setting_keyed_a_3.rs`).
const CONNECTOR_SEAT_KEY: &str = "calendar.connector_seat";

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
    /// One booking's resource with no DTSTART or DTEND, live or cancelled
    /// (calendar/ics/parse.rs takes both as optional).
    Undated {
        /// The resource path, as the provider reported it.
        href: String,
        /// The booking's UID.
        uid: String,
        sequence: u32,
        cancelled: bool,
    },
    /// The provider removed the resource carrying one booking's UID.
    Tombstone {
        /// The booking's UID.
        uid: String,
    },
    /// The seat's complete listing left out the resource carrying one
    /// booking's UID: an omission, which is no cancellation evidence.
    Omitted {
        /// The booking's UID.
        uid: String,
    },
    /// One resource exactly as the provider stores it.
    Stored(RemoteCalendarObject),
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

    /// One booking's resource as a cancellation at `sequence` that names no
    /// DTSTART or DTEND, carried under the href the seat's write of it
    /// returned.
    pub(crate) fn undated_cancel(receipt: &RemoteWriteReceipt, sequence: u32) -> Self {
        Self::Undated {
            href: receipt.href.clone(),
            uid: receipt.uid.clone(),
            sequence,
            cancelled: true,
        }
    }

    /// One booking's resource, live at `sequence`, that names no DTSTART or
    /// DTEND, carried under the href the seat's write of it returned.
    pub(crate) fn undated_live(receipt: &RemoteWriteReceipt, sequence: u32) -> Self {
        Self::Undated {
            href: receipt.href.clone(),
            uid: receipt.uid.clone(),
            sequence,
            cancelled: false,
        }
    }

    /// A provider tombstone for one booking's UID.
    pub(crate) fn tombstone(uid: &str) -> Self {
        Self::Tombstone {
            uid: uid.to_owned(),
        }
    }

    /// A complete listing's omission of one booking's UID.
    pub(crate) fn omitted(uid: &str) -> Self {
        Self::Omitted {
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
    /// Installs the seat under `system` (smoke :261 `caldav_config`): the
    /// owner sets the `calendar.connector_seat` setting at the seat's ref to
    /// its config and endpoint, as the host does. A seat may be installed
    /// under another system name for a calendar the booking was never written
    /// to.
    pub(crate) fn install(vault: &Vault, system: &str) -> Self {
        let config = CalendarConnectorSeatConfig {
            seat_ref: format!("seat:{system}"),
            secret_ref: format!("seat-secret:{system}"),
            system: system.to_owned(),
            calendar_ref: format!("{system}-calendar"),
            cadence_jitter_min_seconds: 300,
            cadence_jitter_max_seconds: 900,
        };
        let (_, owner) = seat_owner(vault);
        let outcome = vault
            .set_setting(
                SettingCaller::Owner(&owner),
                SetSetting {
                    item: Some(config.seat_ref.clone()),
                    ..SetSetting::vault_value(
                        CONNECTOR_SEAT_KEY,
                        json!({ "config": config, "endpoint": SEAT_ENDPOINT }),
                    )
                },
            )
            .expect("the owner installs the seat");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's install applies: {outcome:?}"
        );
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

    /// Writes one booking EVENT to the seat's calendar, which stores it, but
    /// its answer never arrives: the write stays in flight until a later
    /// write resumes it. Returns the SEQUENCE the stored copy carries.
    pub(crate) fn write_with_lost_answer(
        &self,
        vault: &Vault,
        event_ref: EntityId,
        now: u64,
    ) -> u32 {
        *self
            .transport
            .lose_next_answer
            .lock()
            .expect("answer switch") = true;
        let lost = write_calendar_event(
            vault,
            &self.operation(vault),
            &self.transport,
            event_ref,
            now,
        );
        assert!(
            matches!(lost, Err(CalendarConnectorError::Transport { .. })),
            "the write whose answer was lost fails: {lost:?}"
        );
        self.transport
            .writes
            .lock()
            .expect("written requests")
            .last()
            .expect("the seat stored the write")
            .sequence
    }

    /// Pulls one batch of booking resources and tombstones, returning the
    /// sync's result so a test can expect an error (smoke :801 `run_sync`).
    pub(crate) fn pull(
        &self,
        vault: &Vault,
        changes: &[SeatChange],
        now: u64,
    ) -> Result<CalendarSyncOutcome, CalendarConnectorError> {
        let changes = self.remote_changes(vault, changes);
        self.run_pull(vault, changes, now)
    }

    /// The wire form of each scripted change, as the seat's pull answers it.
    fn remote_changes(&self, vault: &Vault, changes: &[SeatChange]) -> Vec<RemoteCalendarChange> {
        changes
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
                SeatChange::Undated {
                    href,
                    uid,
                    sequence,
                    cancelled,
                } => {
                    let ics = undated_ics(uid, *sequence, *cancelled);
                    RemoteCalendarChange::Upsert(remote_upsert(
                        href,
                        Some(&format!("{href}-s{sequence}")),
                        &ics,
                    ))
                }
                SeatChange::Stored(object) => RemoteCalendarChange::Upsert(object.clone()),
                SeatChange::Tombstone { uid } => RemoteCalendarChange::Delete {
                    href: self.resource_href(uid),
                    uid: uid.to_string(),
                },
                // The omission carries the listing snapshot's observation of
                // the UID's row (tests/calendar_google_owed_full_listing.rs).
                SeatChange::Omitted { uid } => {
                    let observation =
                        calendar_collection_members_for_operation(vault, &self.operation(vault))
                            .expect("the seat's collection members")
                            .iter()
                            .find(|member| member.uid == *uid)
                            .expect("the booking is a member of the seat")
                            .observation;
                    RemoteCalendarChange::Omitted {
                        href: self.resource_href(uid),
                        uid: uid.to_string(),
                        observation,
                    }
                }
            })
            .collect()
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
        let ics = self.last_write_ics(&receipt.uid);
        let echo = remote_upsert(&receipt.href, receipt.etag.as_deref(), &ics);
        self.run_pull(vault, vec![RemoteCalendarChange::Upsert(echo)], now)
    }

    /// Pulls back the seat's own last write of one booking as a provider that
    /// rewrites the stored resource returns it: the written VEVENT at
    /// `sequence` (the written one or higher) with a property of the
    /// provider's own added, so its content hash is not the written one's.
    pub(crate) fn pull_rewritten_own_write(
        &self,
        vault: &Vault,
        receipt: &RemoteWriteReceipt,
        sequence: u32,
        now: u64,
    ) -> Result<CalendarSyncOutcome, CalendarConnectorError> {
        let rewrite = self.rewritten_own_write(receipt, sequence, now);
        self.run_pull(vault, vec![RemoteCalendarChange::Upsert(rewrite)], now)
    }

    /// The seat's own last write of one booking as a provider that rewrites
    /// the stored resource holds it (see [`Self::pull_rewritten_own_write`]).
    fn rewritten_own_write(
        &self,
        receipt: &RemoteWriteReceipt,
        sequence: u32,
        now: u64,
    ) -> RemoteCalendarObject {
        let written =
            String::from_utf8(self.last_write_ics(&receipt.uid)).expect("written ICS is UTF-8");
        let mut rewritten = String::new();
        for line in written.split_inclusive("\r\n") {
            if line.starts_with("SEQUENCE:") {
                rewritten.push_str(&format!("SEQUENCE:{sequence}\r\n"));
                continue;
            }
            if line == "END:VEVENT\r\n" {
                rewritten.push_str(&format!("X-PROVIDER-REVISION:{now}\r\n"));
            }
            rewritten.push_str(line);
        }
        let rewrite = remote_upsert(
            &receipt.href,
            Some(&format!("{}-rewritten-{now}", receipt.href)),
            rewritten.as_bytes(),
        );
        assert_ne!(
            rewrite.content_hash, receipt.content_hash,
            "the provider's rewrite is a new version of the written resource"
        );
        rewrite
    }

    /// The seat's own last write of one booking as a provider that rewrites
    /// the stored resource holds it (see [`Self::pull_rewritten_own_write`]).
    pub(crate) fn rewrite_of_own_write(
        &self,
        receipt: &RemoteWriteReceipt,
        sequence: u32,
        now: u64,
    ) -> SeatChange {
        SeatChange::Stored(self.rewritten_own_write(receipt, sequence, now))
    }

    /// The seat's own last write of one booking as a provider that rewrites
    /// the stored resource and drops the properties it does not know holds
    /// it: the rewrite without the write's marker.
    pub(crate) fn stripped_rewrite_of_own_write(
        &self,
        receipt: &RemoteWriteReceipt,
        sequence: u32,
        now: u64,
    ) -> SeatChange {
        let rewrite = self.rewritten_own_write(receipt, sequence, now);
        let rewritten = String::from_utf8(rewrite.ics).expect("rewritten ICS is UTF-8");
        let stripped: String = rewritten
            .split_inclusive("\r\n")
            .filter(|line| !line.starts_with(WRITE_MARKER_LINE))
            .collect();
        SeatChange::Stored(remote_upsert(
            &rewrite.href,
            rewrite.etag.as_deref(),
            stripped.as_bytes(),
        ))
    }

    /// The host's own cancel of one booking at `sequence`, made in a client
    /// over the seat's last write of it, a live one: every other line of that
    /// write stays, and the resource carries the marker of an earlier write
    /// of the seat ([`EARLIER_WRITE_MARKER`]), as a client that keeps the
    /// properties it does not know keeps them.
    pub(crate) fn host_cancel_of_own_write(
        &self,
        receipt: &RemoteWriteReceipt,
        sequence: u32,
    ) -> SeatChange {
        let written =
            String::from_utf8(self.last_write_ics(&receipt.uid)).expect("written ICS is UTF-8");
        assert!(
            !written.contains("STATUS:CANCELLED"),
            "the last write is a live one"
        );
        let mut cancelled = String::new();
        for line in written.split_inclusive("\r\n") {
            if line.starts_with(WRITE_MARKER_LINE) {
                continue;
            }
            if line == "BEGIN:VCALENDAR\r\n" {
                cancelled.push_str(line);
                cancelled.push_str(&format!("{WRITE_MARKER_LINE}{EARLIER_WRITE_MARKER}\r\n"));
                continue;
            }
            if line.starts_with("SEQUENCE:") {
                cancelled.push_str(&format!("SEQUENCE:{sequence}\r\n"));
                continue;
            }
            if line == "END:VEVENT\r\n" {
                cancelled.push_str("STATUS:CANCELLED\r\n");
            }
            cancelled.push_str(line);
        }
        SeatChange::Stored(remote_upsert(
            &receipt.href,
            Some(&format!("{}-host-cancel-s{sequence}", receipt.href)),
            cancelled.as_bytes(),
        ))
    }

    /// The SEQUENCE of the seat's write of `uid` that is staged and not yet
    /// settled.
    pub(crate) fn staged_sequence(&self, vault: &Vault, uid: &str) -> u32 {
        calendar_write_outbox_rows(vault)
            .expect("the outbox rows")
            .into_iter()
            .find(|row| row.system == self.config.system && row.uid == uid)
            .expect("the seat's write of the booking is staged")
            .sequence
    }

    /// The locator of the seat's resource for a booking UID no write of the
    /// seat returned: its href and UID, in a receipt's shape.
    pub(crate) fn resource_locator(&self, uid: &str) -> RemoteWriteReceipt {
        RemoteWriteReceipt {
            href: self.resource_href(uid),
            etag: None,
            uid: uid.to_owned(),
            sequence: 0,
            content_hash: [0; 32],
        }
    }

    /// Writes one booking EVENT to the seat's calendar, which stores it, but
    /// before its answer is settled the host restores the booking live in
    /// that calendar at the next SEQUENCE, at `start`..`end` under the href of
    /// `live`, and a pull at `restore_now` reads that restore: the settlement
    /// comes after a newer version of the resource was read.
    pub(crate) fn write_settled_after_restore(
        &self,
        vault: &Vault,
        event_ref: EntityId,
        live: &RemoteWriteReceipt,
        slot: (u64, u64),
        restore_now: u64,
        now: u64,
    ) -> RemoteWriteReceipt {
        let wire = RestoreBeforeAnswer {
            seat: self,
            vault,
            live,
            slot,
            restore_now,
        };
        write_calendar_event(vault, &self.operation(vault), &wire, event_ref, now)
            .expect("write the booking to the seat")
    }

    /// Writes one booking EVENT to the seat's calendar, but the request never
    /// reaches the provider, which stores nothing: the write stays prepared
    /// until a later write sends it again.
    pub(crate) fn write_unsent(&self, vault: &Vault, event_ref: EntityId, now: u64) {
        *self
            .transport
            .drop_next_request
            .lock()
            .expect("send switch") = true;
        let unsent = write_calendar_event(
            vault,
            &self.operation(vault),
            &self.transport,
            event_ref,
            now,
        );
        assert!(
            matches!(unsent, Err(CalendarConnectorError::Transport { .. })),
            "the write whose request never arrived fails: {unsent:?}"
        );
    }

    /// Sends the seat's prepared write of one booking again, and the provider
    /// refuses it on its precondition: the stored resource no longer carries
    /// the ETag the write expects, since the provider stored the earlier
    /// call's request, whose answer was lost, and rewrote it at `sequence`.
    /// The write's reconciliation reads that stored copy.
    pub(crate) fn replay_refused_over_rewritten_own_write(
        &self,
        vault: &Vault,
        event_ref: EntityId,
        receipt: &RemoteWriteReceipt,
        sequence: u32,
        now: u64,
    ) {
        let stored = self.rewritten_own_write(receipt, sequence, now);
        self.replay_refused(vault, event_ref, RemoteCalendarChange::Upsert(stored), now);
    }

    /// Sends the seat's prepared write of one booking again, and the provider
    /// refuses it on its precondition: another writer changed the stored
    /// resource to `stored`, which the write's reconciliation reads.
    pub(crate) fn replay_refused_over(
        &self,
        vault: &Vault,
        event_ref: EntityId,
        stored: &SeatChange,
        now: u64,
    ) {
        let stored = self
            .remote_changes(vault, std::slice::from_ref(stored))
            .pop()
            .expect("the stored resource");
        self.replay_refused(vault, event_ref, stored, now);
    }

    /// Sends the seat's prepared write of one booking again, and the provider
    /// refuses it on its precondition, but the write's reconciliation pull
    /// fails: the write reads no stored copy.
    pub(crate) fn replay_refused_unread(&self, vault: &Vault, event_ref: EntityId, now: u64) {
        *self.transport.fail_next_pull.lock().expect("pull switch") = true;
        *self
            .transport
            .refuse_next_precondition
            .lock()
            .expect("precondition switch") = true;
        let refused = write_calendar_event(
            vault,
            &self.operation(vault),
            &self.transport,
            event_ref,
            now,
        );
        assert!(
            matches!(refused, Err(CalendarConnectorError::EtagMismatch { .. })),
            "the replayed write is refused on its precondition: {refused:?}"
        );
    }

    /// Sends the seat's prepared write of one booking again, and the provider
    /// refuses it on its precondition. The write's reconciliation reads
    /// `stored`, but before the write takes it in, a pull at `restore_now`
    /// reads the host's newer `restore` of the resource.
    pub(crate) fn replay_refused_over_while_restored(
        &self,
        vault: &Vault,
        event_ref: EntityId,
        stored: &SeatChange,
        restore: &SeatChange,
        restore_now: u64,
        now: u64,
    ) {
        let stored = self
            .remote_changes(vault, std::slice::from_ref(stored))
            .pop()
            .expect("the stored resource");
        self.transport
            .batches
            .lock()
            .expect("scripted batches")
            .push_back(RemoteSyncBatch {
                next_cursor: None,
                changes: vec![stored],
            });
        *self
            .transport
            .refuse_next_precondition
            .lock()
            .expect("precondition switch") = true;
        let wire = PullDuringReconcile {
            seat: self,
            vault,
            change: restore,
            pull_now: restore_now,
        };
        let refused = write_calendar_event(vault, &self.operation(vault), &wire, event_ref, now);
        assert!(
            matches!(refused, Err(CalendarConnectorError::EtagMismatch { .. })),
            "the replayed write is refused on its precondition: {refused:?}"
        );
    }

    /// Writes one booking EVENT to the seat's calendar, and the provider
    /// refuses the write's first call on its precondition, storing nothing;
    /// a pull at `pull_now` reads `change` while that call is out.
    pub(crate) fn write_refused_after_pull(
        &self,
        vault: &Vault,
        event_ref: EntityId,
        change: &SeatChange,
        pull_now: u64,
        now: u64,
    ) {
        let wire = PullBeforeRefusal {
            seat: self,
            vault,
            change,
            pull_now,
        };
        let refused = write_calendar_event(vault, &self.operation(vault), &wire, event_ref, now);
        assert!(
            matches!(refused, Err(CalendarConnectorError::EtagMismatch { .. })),
            "the write is refused on its precondition: {refused:?}"
        );
    }

    /// Sends the prepared write again under a refused precondition, with
    /// `stored` scripted as the reconciliation pull's answer.
    fn replay_refused(
        &self,
        vault: &Vault,
        event_ref: EntityId,
        stored: RemoteCalendarChange,
        now: u64,
    ) {
        self.transport
            .batches
            .lock()
            .expect("scripted batches")
            .push_back(RemoteSyncBatch {
                next_cursor: None,
                changes: vec![stored],
            });
        *self
            .transport
            .refuse_next_precondition
            .lock()
            .expect("precondition switch") = true;
        let refused = write_calendar_event(
            vault,
            &self.operation(vault),
            &self.transport,
            event_ref,
            now,
        );
        assert!(
            matches!(refused, Err(CalendarConnectorError::EtagMismatch { .. })),
            "the replayed write is refused on its precondition: {refused:?}"
        );
    }

    /// The ICS of the seat's last write of `uid`.
    fn last_write_ics(&self, uid: &str) -> Vec<u8> {
        self.transport
            .writes
            .lock()
            .expect("written requests")
            .iter()
            .rev()
            .find(|request| request.uid == uid)
            .expect("the seat holds a write of this booking")
            .ics
            .clone()
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

    /// The calendar operation on the installed seat: this re-reads the
    /// installed row and binds the owner to it exactly (smoke :757).
    fn operation(&self, vault: &Vault) -> CalendarConnectorOperation {
        let (id, owner) = seat_owner(vault);
        let memory = vault.memory(id, EdgeActorClass::Human);
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
/// and answers an honest receipt, or, once `lose_next_answer` is set, a
/// transport failure after it stored the request; once `drop_next_request`
/// is set, a transport failure before it stores anything, and once
/// `refuse_next_precondition` is set, a precondition failure that stores
/// nothing; once `fail_next_pull` is set, a pull fails. `delete` is unused.
#[derive(Default)]
struct ScriptedSeatTransport {
    batches: Mutex<VecDeque<RemoteSyncBatch>>,
    writes: Mutex<Vec<RemoteWriteRequest>>,
    lose_next_answer: Mutex<bool>,
    drop_next_request: Mutex<bool>,
    refuse_next_precondition: Mutex<bool>,
    fail_next_pull: Mutex<bool>,
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
        if std::mem::take(&mut *self.fail_next_pull.lock().expect("pull switch")) {
            return Err(CalendarConnectorError::Transport {
                provider: CALDAV_PROVIDER_KEY,
                operation: "pull",
                detail: "the pull's answer never arrived".to_owned(),
            });
        }
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
        if std::mem::take(&mut *self.drop_next_request.lock().expect("send switch")) {
            return Err(CalendarConnectorError::Transport {
                provider: CALDAV_PROVIDER_KEY,
                operation: "upsert",
                detail: "the request never reached the provider".to_owned(),
            });
        }
        if std::mem::take(
            &mut *self
                .refuse_next_precondition
                .lock()
                .expect("precondition switch"),
        ) {
            return Err(CalendarConnectorError::EtagMismatch {
                href: request
                    .href
                    .clone()
                    .unwrap_or_else(|| format!("/{calendar_ref}/{}.ics", request.uid)),
                expected: request.expected_etag.clone(),
                actual: Some(format!("{}-stored-elsewhere", request.uid)),
            });
        }
        self.writes
            .lock()
            .expect("written requests")
            .push(request.clone());
        if std::mem::take(&mut *self.lose_next_answer.lock().expect("answer switch")) {
            return Err(CalendarConnectorError::Transport {
                provider: CALDAV_PROVIDER_KEY,
                operation: "upsert",
                detail: "the answer was lost after the resource was stored".to_owned(),
            });
        }
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

/// The seat's scripted wire, whose upsert, once the provider stored the
/// request, runs a pull of the host's live restore of the booking at the
/// next SEQUENCE before the answer returns.
struct RestoreBeforeAnswer<'a> {
    seat: &'a Seat,
    vault: &'a Vault,
    live: &'a RemoteWriteReceipt,
    slot: (u64, u64),
    restore_now: u64,
}

impl CalendarRemoteTransport for RestoreBeforeAnswer<'_> {
    fn provider_key(&self) -> &'static str {
        self.seat.transport.provider_key()
    }

    fn pull(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        cursor: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError> {
        self.seat.transport.pull(secret_ref, calendar_ref, cursor)
    }

    fn upsert(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        let receipt = self
            .seat
            .transport
            .upsert(secret_ref, calendar_ref, request)?;
        let (start, end) = self.slot;
        self.seat
            .pull(
                self.vault,
                &[SeatChange::upsert(
                    self.live,
                    start,
                    end,
                    request.sequence + 1,
                    false,
                )],
                self.restore_now,
            )
            .expect("the pull of the host's restore");
        Ok(receipt)
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

/// The seat's scripted wire, whose pull, after it took the scripted batch
/// and before it answers, runs a pull of `change` at `pull_now`: a seat read
/// that lands between a write's reconciliation read and the write.
struct PullDuringReconcile<'a> {
    seat: &'a Seat,
    vault: &'a Vault,
    change: &'a SeatChange,
    pull_now: u64,
}

impl CalendarRemoteTransport for PullDuringReconcile<'_> {
    fn provider_key(&self) -> &'static str {
        self.seat.transport.provider_key()
    }

    fn pull(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        cursor: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError> {
        let batch = self.seat.transport.pull(secret_ref, calendar_ref, cursor)?;
        self.seat
            .pull(self.vault, std::slice::from_ref(self.change), self.pull_now)
            .expect("the pull during the reconciliation");
        Ok(batch)
    }

    fn upsert(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        self.seat
            .transport
            .upsert(secret_ref, calendar_ref, request)
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

/// The seat's scripted wire, whose upsert runs a pull of `change` at
/// `pull_now` and then refuses the request on its precondition, storing
/// nothing.
struct PullBeforeRefusal<'a> {
    seat: &'a Seat,
    vault: &'a Vault,
    change: &'a SeatChange,
    pull_now: u64,
}

impl CalendarRemoteTransport for PullBeforeRefusal<'_> {
    fn provider_key(&self) -> &'static str {
        self.seat.transport.provider_key()
    }

    fn pull(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        cursor: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError> {
        self.seat.transport.pull(secret_ref, calendar_ref, cursor)
    }

    fn upsert(
        &self,
        secret_ref: &str,
        calendar_ref: &str,
        request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        self.seat
            .pull(self.vault, std::slice::from_ref(self.change), self.pull_now)
            .expect("the pull while the write is out");
        *self
            .seat
            .transport
            .refuse_next_precondition
            .lock()
            .expect("precondition switch") = true;
        self.seat
            .transport
            .upsert(secret_ref, calendar_ref, request)
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

/// The VCALENDAR line that carries a connector write's marker.
const WRITE_MARKER_LINE: &str = "X-ONEIRON-OUTBOX:";

/// The marker of a write of the seat before the one a test stages.
const EARLIER_WRITE_MARKER: &str = "0123456789abcdef0123456789abcdef";

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

/// One booking's resource at `sequence` with no DTSTART or DTEND, live or
/// cancelled.
fn undated_ics(uid: &str, sequence: u32, cancelled: bool) -> Vec<u8> {
    let mut out = String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n");
    out.push_str("BEGIN:VEVENT\r\n");
    out.push_str(&format!("UID:{uid}\r\n"));
    out.push_str("DTSTAMP:20260302T070000Z\r\n");
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
