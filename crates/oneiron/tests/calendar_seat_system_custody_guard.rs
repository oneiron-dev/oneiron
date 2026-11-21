//! FIX CAL-SEAT-SETUP-ADMITS-MASKED-SYSTEM: the setting wall stores each span
//! of a seat's or a feed's `system` that custody keeps as a secret as that
//! record's handle, and the calendar doors compare systems as written. A
//! seat installed under such a system kept the handle as its system, so an
//! owner upload under the system in clear missed the seat's refusal, and the
//! upload's complete sweep could mark the seat's passports absent. So a seat
//! or feed install whose system holds a custody handle is refused, by name.
//!
//! - A seat install under a system custody keeps as a secret, whole or as a
//!   span of it, is refused. Nothing is stored: the seat ref installs again
//!   under a system in clear, and that seat holds uploads off its system.
//! - An ICS feed install under such a system is refused for the same reason
//!   (before, it was refused only because its item and its masked value
//!   differed).
//! - A system the owner typed as handle text is refused the same way
//!   (CAL-SOURCE-SYSTEM-NAME-ADMITS-ENGINE-AND-HANDLE-TEXT, point 2, for seats
//!   and feeds), a bare one (`sc12`) too: a held passport's compare reads a
//!   whole bare handle as its record's value (own review of this row, C1a).
//! - Control: a seat installs beside a custody value its system does not
//!   hold, keeps its system in clear, and holds uploads off it.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test calendar_seat_system_custody_guard`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::calendar::ingest::door::{CalendarIcsImportRequest, import_ics_as_owner};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{BlobArtifactInput, BlobVersionAppendOutcome};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::{Value, json};

const FEED: &str = "calendar.ics_feed";
const SEAT: &str = "calendar.connector_seat";
/// The refusal of a seat or feed install whose system holds a custody handle.
const CUSTODY: &str = "holds a custody handle";
/// The refusal an upload gets under the system of an installed seat.
const HELD: &str = "imports under this system";
/// A system name custody keeps as a secret value.
const SECRET_SYSTEM: &str = "work-calendar-system";
/// 2026-03-02 09:00 UTC.
const NOW: u64 = 1_772_442_000;
/// One complete VCALENDAR with one VEVENT.
const ICS: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n\
BEGIN:VEVENT\r\nUID:export-1@example.test\r\nDTSTAMP:20260302T070000Z\r\n\
DTSTART:20260302T100000Z\r\nDTEND:20260302T110000Z\r\nSEQUENCE:0\r\n\
SUMMARY:Planning\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut config = VaultConfig::device();
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Vault::open(dir.path(), config).expect("seeded vault");
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        oneiron::test_support::provision_engine_machines(&vault);
        let (owner, proof) = embedded_owner(&vault).expect("authenticated embedded owner");
        Self {
            _dir: dir,
            vault,
            owner,
            proof,
        }
    }

    /// Custody registers `value` as the secret of the record `name`.
    fn register_secret(&self, name: &str, value: &str) {
        self.vault
            .register_test_secret(name, value.as_bytes(), Vec::new(), NOW)
            .expect("FIXTURE: custody registers the value");
    }

    /// The owner sets the `key` item `item` to `value`.
    fn set(&self, key: &str, item: &str, value: Value) -> Result<SetSettingOutcome, String> {
        let mut change = SetSetting::vault_value(key, Value::Null);
        change.item = Some(item.to_owned());
        change.value = Some(value);
        self.vault
            .set_setting(SettingCaller::Owner(&self.proof), change)
            .map_err(|error| error.to_string())
    }

    /// The owner installs the CalDAV seat `seat_ref` importing under
    /// `system`. No other field names the system, so only the system meets
    /// a value custody keeps.
    fn install_seat(&self, seat_ref: &str, system: &str) -> Result<SetSettingOutcome, String> {
        self.set(
            SEAT,
            seat_ref,
            json!({
                "config": {
                    "seat_ref": seat_ref,
                    "secret_ref": format!("caldav:{seat_ref}"),
                    "system": system,
                    "calendar_ref": "personal",
                    "cadence_jitter_min_seconds": 300,
                    "cadence_jitter_max_seconds": 900,
                },
                "endpoint": "https://dav.example.test/",
            }),
        )
    }

    /// The owner installs an ICS feed polling under `system`, its item. Its
    /// secret ref does not name the system.
    fn install_feed(&self, system: &str) -> Result<SetSettingOutcome, String> {
        self.set(
            FEED,
            system,
            json!({
                "secret_ref": "ics-feed:owner-feed",
                "system": system,
                "cadence_min_seconds": 300,
                "cadence_max_seconds": 900,
            }),
        )
    }

    /// The owner uploads [`ICS`] as a complete feed under `system`.
    fn upload(&self, system: &str) -> Result<(), String> {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        let artifact = memory
            .put_blob_artifact(&BlobArtifactInput {
                id: None,
                name: "export.ics".to_owned(),
                media_type: "text/calendar".to_owned(),
                occurred_at: NOW,
                learned_at: None,
            })
            .expect("the upload's artifact");
        let BlobVersionAppendOutcome::Landed(version) = memory
            .append_blob_version(&artifact.id_hex, ICS.as_bytes(), None, NOW, None)
            .expect("the upload's bytes")
        else {
            panic!("an owner upload lands at once");
        };
        import_ics_as_owner(
            &memory,
            &self.proof,
            &CalendarIcsImportRequest {
                system: system.to_owned(),
                source_blob_ref: artifact.id_hex,
                source_version: version.version,
            },
            None,
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
    }
}

/// The value an applied install stored.
fn applied(outcome: Result<SetSettingOutcome, String>, what: &str) -> Value {
    match outcome {
        Ok(SetSettingOutcome::Applied { value, .. }) => value,
        other => panic!("{what} applies: {other:?}"),
    }
}

fn refused<T: std::fmt::Debug>(outcome: Result<T, String>, reason: &str, what: &str) {
    match outcome {
        Err(error) => assert!(error.contains(reason), "{what}: {error}"),
        Ok(outcome) => panic!("{what} is refused, but it gave {outcome:?}"),
    }
}

#[test]
fn a_seat_install_under_a_system_custody_keeps_as_a_secret_is_refused() {
    let fx = Fixture::open();
    fx.register_secret("work-calendar-name", SECRET_SYSTEM);

    refused(
        fx.install_seat("work", SECRET_SYSTEM),
        CUSTODY,
        "a seat install whose whole system custody keeps as a secret",
    );
    refused(
        fx.install_seat("team", &format!("acme-{SECRET_SYSTEM}")),
        CUSTODY,
        "a seat install whose system holds a value custody keeps as a secret",
    );

    // Nothing of the refused install stands: its seat ref is new to the
    // door, which refuses a seat ref an earlier seat named.
    let stored = applied(
        fx.install_seat("work", "work-calendar"),
        "the same seat ref under a system in clear",
    );
    assert_eq!(
        stored["config"]["system"], "work-calendar",
        "the seat stores its system in clear: {stored}"
    );
    refused(
        fx.upload("work-calendar"),
        HELD,
        "an upload on the seat's system, whose sweep would cancel the seat's events",
    );
}

#[test]
fn an_ics_feed_install_under_a_system_custody_keeps_as_a_secret_is_refused_by_name() {
    let fx = Fixture::open();
    fx.register_secret("work-calendar-name", SECRET_SYSTEM);

    refused(
        fx.install_feed(SECRET_SYSTEM),
        CUSTODY,
        "a feed install whose system custody keeps as a secret",
    );

    applied(
        fx.install_feed("owner-feed"),
        "FIXTURE: a feed install under a system in clear",
    );
}

#[test]
fn a_seat_or_feed_install_under_a_system_spelled_as_a_custody_handle_is_refused() {
    const HANDLE_TEXT: &str = "[secret sc99]";

    let fx = Fixture::open();
    refused(
        fx.install_seat("typed", HANDLE_TEXT),
        CUSTODY,
        "a seat install whose system the owner typed as a custody handle",
    );
    refused(
        fx.install_seat("wrapped", &format!("team {HANDLE_TEXT} calendar")),
        CUSTODY,
        "a seat install whose system holds text spelled as a custody handle",
    );
    refused(
        fx.install_feed(HANDLE_TEXT),
        CUSTODY,
        "a feed install whose system the owner typed as a custody handle",
    );
}

#[test]
fn a_seat_or_feed_install_under_a_system_that_is_a_bare_custody_handle_is_refused() {
    const BARE_HANDLE: &str = "sc99";

    let fx = Fixture::open();
    refused(
        fx.install_seat("bare", BARE_HANDLE),
        CUSTODY,
        "a seat install whose whole system is a bare custody handle",
    );
    refused(
        fx.install_feed(BARE_HANDLE),
        CUSTODY,
        "a feed install whose whole system is a bare custody handle",
    );

    // Control: a system that opens like a handle but is not one installs,
    // keeps its system in clear, and holds uploads off it.
    let stored = applied(
        fx.install_seat("bare", "sc99-calendar"),
        "FIXTURE: the same seat ref under a system that is no handle",
    );
    assert_eq!(
        stored["config"]["system"], "sc99-calendar",
        "FIXTURE: the seat stores its system in clear: {stored}"
    );
    refused(
        fx.upload("sc99-calendar"),
        HELD,
        "FIXTURE: an upload on the seat's system",
    );
}

// Control: a custody value the system does not hold changes nothing.
#[test]
fn a_seat_install_beside_a_custody_value_keeps_its_system_and_holds_uploads_off_it() {
    let fx = Fixture::open();
    fx.register_secret("work-calendar-name", SECRET_SYSTEM);

    let stored = applied(
        fx.install_seat("work", "team-calendar"),
        "FIXTURE: a seat install under a system that holds no custody value",
    );
    assert_eq!(
        stored["config"]["system"], "team-calendar",
        "FIXTURE: the seat stores its system in clear: {stored}"
    );
    refused(
        fx.upload("team-calendar"),
        HELD,
        "FIXTURE: an upload on the seat's system",
    );
}
