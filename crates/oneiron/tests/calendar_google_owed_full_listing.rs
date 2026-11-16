//! A connector pull that leaves a change owed makes the next pull list the
//! calendar whole, on every transport (FIX-LIST
//! [FEED-MOVE-HOLD-UNTESTED-AND-INCREMENTAL-CURSOR], part b).
//!
//! An owed change is read again only by a pull that lists the calendar
//! whole: an omission whose remote object row does not stand as the listing
//! read it (fix list row 19192), or a booking move a pending emergency
//! delivery held back (FIX 22385). CalDAV drops its DAV token for that. The
//! Workspace-Internal Google transport kept the trait's default, the cursor
//! itself, so its next pull sent the same sync token and the owed change
//! waited for that event's next change on the provider. Main sends the token
//! again; the fix sends none.
//!
//! Both owed kinds share the one cursor rule, so the cheaper one drives it
//! here: an omission of a UID this seat holds no remote object row for is
//! never observed (`omission_observed`), so it stays owed. The wire is a
//! recording stub, as in `tests/it/calendar_connector_smoke.rs`, whose `it`
//! target is a separate binary. Only public paths, so main plus this file
//! builds for the red run.
#![cfg(feature = "test-support")]

mod common;

use std::collections::VecDeque;
use std::sync::Mutex;

use oneiron::calendar::connectors::door::{
    self, CalendarConnectorConfigureRequest, CalendarConnectorOperation, CalendarConnectorRequest,
};
use oneiron::calendar::connectors::{
    CalendarConnectorError, CalendarConnectorSeatConfig, CalendarConnectorSeatState,
    CalendarSyncOutcome, RemoteCalendarChange, RemoteCalendarObject, RemoteSyncBatch,
    RemoteWriteReceipt, RemoteWriteRequest, calendar_collection_members_for_operation,
    run_calendar_connector_sync,
};
use oneiron::calendar::google_internal::{GoogleInternalConnector, GoogleInternalWire};
use oneiron::calendar::parse_ics_feed;
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const T0: u64 = 1_800_000_000;
const T1: u64 = 1_800_000_100;
const T2: u64 = 1_800_000_200;

/// The endpoint the configure door records for the seat.
const SEAT_ENDPOINT: &str = "https://calendar.example.test/";

/// A Google wire that records each sync token it is sent and answers the
/// scripted listings in order (an empty listing once they run out).
#[derive(Default)]
struct RecordingGoogleWire {
    sync_tokens: Mutex<Vec<Option<String>>>,
    listings: Mutex<VecDeque<RemoteSyncBatch>>,
}

impl RecordingGoogleWire {
    fn queue_listing(&self, batch: RemoteSyncBatch) {
        self.listings.lock().expect("listings").push_back(batch);
    }

    fn sync_tokens(&self) -> Vec<Option<String>> {
        self.sync_tokens.lock().expect("sync tokens").clone()
    }
}

impl GoogleInternalWire for RecordingGoogleWire {
    fn list_changes(
        &self,
        _secret_ref: &str,
        _calendar_ref: &str,
        sync_token: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError> {
        self.sync_tokens
            .lock()
            .expect("sync tokens")
            .push(sync_token.map(str::to_owned));
        Ok(self
            .listings
            .lock()
            .expect("listings")
            .pop_front()
            .unwrap_or(RemoteSyncBatch {
                next_cursor: None,
                changes: Vec::new(),
            }))
    }

    fn upsert_event(
        &self,
        _secret_ref: &str,
        _calendar_ref: &str,
        _request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        panic!("this test writes nothing to the provider")
    }

    fn delete_event(
        &self,
        _secret_ref: &str,
        _calendar_ref: &str,
        _href: &str,
        _expected_etag: Option<&str>,
        _uid: &str,
        _sequence: u32,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        panic!("this test deletes nothing on the provider")
    }
}

/// An unseeded vault: the test measures the connector's cursor, not the
/// default policy manifest.
fn temp_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), cfg).expect("open vault");
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    common::provision_engine_machines(&vault);
    (dir, vault)
}

/// The Workspace-Internal seat; its custody name carries the dogfood class
/// prefix, or the transport refuses it.
fn google_seat() -> CalendarConnectorSeatState {
    CalendarConnectorSeatState::new(CalendarConnectorSeatConfig {
        seat_ref: "seat:google:dogfood".to_owned(),
        secret_ref: "google-internal:dogfood".to_owned(),
        system: "google-internal".to_owned(),
        calendar_ref: "primary".to_owned(),
        cadence_jitter_min_seconds: 300,
        cadence_jitter_max_seconds: 900,
    })
}

fn seat_owner(vault: &Vault) -> (EntityId, AuthenticatedOwner) {
    let id = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let owner = vault
        .authenticate_owner(id, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof");
    (id, owner)
}

fn installed_row(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
) -> door::CalendarConnectorRegistration {
    let (id, owner) = seat_owner(vault);
    door::get(
        &vault.memory(id, EdgeActorClass::Human),
        &owner,
        &CalendarConnectorRequest {
            seat_ref: seat.config.seat_ref.clone(),
        },
    )
    .expect("read the installed seat")
    .expect("the seat is installed")
}

/// The owner installs `seat` through the configure door, as the host does,
/// and the operation binds that owner to the installed row.
fn operation(vault: &Vault, seat: &CalendarConnectorSeatState) -> CalendarConnectorOperation {
    let (id, owner) = seat_owner(vault);
    door::configure(
        &vault.memory(id, EdgeActorClass::Human),
        &owner,
        &CalendarConnectorConfigureRequest {
            config: seat.config.clone(),
            endpoint: SEAT_ENDPOINT.to_owned(),
        },
    )
    .expect("the owner installs the seat");
    CalendarConnectorOperation::new(vault, owner, installed_row(vault, seat))
        .expect("the operation on the installed seat")
}

/// The host records `outcome` on the installed row: a re-enqueued sync's
/// cursor is where the next one resumes.
fn observe_sync(vault: &Vault, seat: &CalendarConnectorSeatState, outcome: &CalendarSyncOutcome) {
    let (id, owner) = seat_owner(vault);
    door::observe_sync(
        &vault.memory(id, EdgeActorClass::Human),
        &owner,
        &installed_row(vault, seat),
        outcome,
    )
    .expect("the host records the sync");
}

/// One sync run on the installed seat, resuming from `seat`'s cursor.
fn run_sync<W: GoogleInternalWire>(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    connector: &GoogleInternalConnector<W>,
    now: u64,
) -> CalendarSyncOutcome {
    let operation = operation(vault, seat);
    assert_eq!(
        operation.registration().seat.cursor,
        seat.cursor,
        "the installed seat resumes from this run's cursor"
    );
    run_calendar_connector_sync(vault, &operation, connector, now, 7).expect("connector sync")
}

/// The seat as the host resumes it after `outcome`.
fn resumed_seat(outcome: &CalendarSyncOutcome) -> CalendarConnectorSeatState {
    let CalendarSyncOutcome::Reenqueued { next_cursor, .. } = outcome else {
        panic!("expected a re-enqueued run, got {outcome:?}");
    };
    match next_cursor {
        Some(cursor) => google_seat().with_cursor(cursor.clone()),
        None => google_seat(),
    }
}

fn applied(outcome: &CalendarSyncOutcome) -> u32 {
    let CalendarSyncOutcome::Reenqueued { applied, .. } = outcome else {
        panic!("expected a re-enqueued run, got {outcome:?}");
    };
    *applied
}

/// One VEVENT resource, its UID, SEQUENCE and hash read back from the ICS.
fn resource(uid: &str, summary: &str) -> RemoteCalendarObject {
    let ics = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n\
         BEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:20260805T100000Z\r\n\
         DTSTART:20260806T140000Z\r\nDTEND:20260806T150000Z\r\nSEQUENCE:1\r\n\
         SUMMARY:{summary}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )
    .into_bytes();
    let feed = parse_ics_feed(&ics).expect("fixture ics parses");
    let event = feed.events.first().expect("fixture carries a VEVENT");
    RemoteCalendarObject {
        href: format!("calendars/primary/events/{uid}"),
        etag: Some(format!("etag-{uid}")),
        uid: event.uid.clone(),
        sequence: event.sequence,
        content_hash: event.content_hash,
        ics,
    }
}

#[test]
fn google_pull_that_leaves_an_omission_owed_lists_the_calendar_whole_next() {
    let (_dir, vault) = temp_vault();
    let connector = GoogleInternalConnector::new(RecordingGoogleWire::default());

    // Pull 1, from no cursor: one event lands, and the provider issues tok-1.
    connector.wire().queue_listing(RemoteSyncBatch {
        next_cursor: Some("tok-1".to_owned()),
        changes: vec![RemoteCalendarChange::Upsert(resource(
            "standup@x",
            "standup",
        ))],
    });
    let seat = google_seat();
    let first = run_sync(&vault, &seat, &connector, T0);
    assert_eq!(applied(&first), 1);
    observe_sync(&vault, &seat, &first);
    let seat = resumed_seat(&first);
    assert_eq!(seat.cursor.as_deref(), Some("tok-1"));

    // The listing's snapshot of the seat's collection: the read row's
    // observation, which the omission below carries.
    let members = calendar_collection_members_for_operation(&vault, &operation(&vault, &seat))
        .expect("the seat's collection members");
    let observation = members
        .iter()
        .find(|member| member.uid == "standup@x")
        .expect("the pulled event is a member")
        .observation;

    // Pull 2, incremental from tok-1: a new event lands, and an omission of a
    // UID whose row does not stand stays owed. The provider issues tok-2.
    connector.wire().queue_listing(RemoteSyncBatch {
        next_cursor: Some("tok-2".to_owned()),
        changes: vec![
            RemoteCalendarChange::Upsert(resource("review@x", "review")),
            RemoteCalendarChange::Omitted {
                href: "calendars/primary/events/gone@x".to_owned(),
                uid: "gone@x".to_owned(),
                observation,
            },
        ],
    });
    let second = run_sync(&vault, &seat, &connector, T1);
    assert_eq!(applied(&second), 1, "every other change of the pull stands");
    observe_sync(&vault, &seat, &second);

    // Pull 3 resumes from the cursor pull 2 left: it must list the calendar
    // whole, so the owed omission is read again.
    let seat = resumed_seat(&second);
    run_sync(&vault, &seat, &connector, T2);
    assert_eq!(
        connector.wire().sync_tokens(),
        vec![None, Some("tok-1".to_owned()), None],
        "the pull after an owed change sends no sync token (main sent tok-2 again)"
    );
}
