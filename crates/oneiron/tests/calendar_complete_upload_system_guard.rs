//! FIX CALENDAR-COMPLETE-IMPORT-SWEEPS-OTHER-SOURCES: an owner's complete
//! ICS upload marks absent every live inbound passport of its system whose
//! UID the file lacks, and cancels each EVENT no live source reports any more.
//! So the upload never runs under a system another installed source imports
//! under, and no feed, seat or upload takes a pack calendar source's system.
//!
//! - An upload under the system of a CalDAV seat is refused; one under
//!   another system applies.
//! - An upload under the system of an installed ICS feed is refused; once the
//!   owner uninstalls the feed, the retired system is open to an upload.
//! - An upload, a seat install and a feed install under a `mail_pack:` system
//!   are refused: only pack calendar sources take one.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test calendar_complete_upload_system_guard`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::calendar::ingest::door::{CalendarIcsImportRequest, import_ics_as_owner};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{BlobArtifactInput, BlobVersionAppendOutcome, Memory};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::{Value, json};

const FEED: &str = "calendar.ics_feed";
const SEAT: &str = "calendar.connector_seat";
/// The refusal an upload gets under the system of an installed feed or seat.
const HELD: &str = "imports under this system";
/// The refusal for a system with the pack calendar prefix.
const PACK: &str = "names a pack calendar source";
/// A system with the pack calendar prefix.
const PACK_SYSTEM: &str = "mail_pack:00000000000000000000000000000000";
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

    fn memory(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// The owner sets the `key` item `item` to `value`; `None` clears it.
    fn set(
        &self,
        key: &str,
        item: &str,
        value: Option<Value>,
    ) -> Result<SetSettingOutcome, String> {
        let mut change = SetSetting::vault_value(key, Value::Null);
        change.item = Some(item.to_owned());
        change.value = value;
        self.vault
            .set_setting(SettingCaller::Owner(&self.proof), change)
            .map_err(|error| error.to_string())
    }

    /// The owner installs an ICS feed polling under `system`.
    fn install_feed(&self, system: &str) -> Result<SetSettingOutcome, String> {
        self.set(
            FEED,
            system,
            Some(json!({
                "secret_ref": format!("ics-feed:{system}"),
                "system": system,
                "cadence_min_seconds": 300,
                "cadence_max_seconds": 900,
            })),
        )
    }

    /// The owner installs the CalDAV seat `seat_ref` importing under `system`.
    fn install_seat(&self, seat_ref: &str, system: &str) -> Result<SetSettingOutcome, String> {
        self.set(
            SEAT,
            seat_ref,
            Some(json!({
                "config": {
                    "seat_ref": seat_ref,
                    "secret_ref": format!("caldav:{seat_ref}"),
                    "system": system,
                    "calendar_ref": "personal",
                    "cadence_jitter_min_seconds": 300,
                    "cadence_jitter_max_seconds": 900,
                },
                "endpoint": "https://dav.example.test/",
            })),
        )
    }

    /// The owner uploads [`ICS`] as a complete feed under `system`.
    fn upload(&self, system: &str) -> Result<(), String> {
        let memory = self.memory();
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
                source_blob_ref: artifact.id_hex.clone(),
                source_version: version.version,
            },
            None,
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
    }
}

fn applied(outcome: Result<SetSettingOutcome, String>, what: &str) {
    match outcome {
        Ok(SetSettingOutcome::Applied { .. }) => {}
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
fn a_complete_upload_never_runs_under_the_system_of_a_seat() {
    let fx = Fixture::open();
    applied(fx.install_seat("work", "shared"), "the seat install");

    refused(
        fx.upload("shared"),
        HELD,
        "an upload on the seat's system, whose sweep would cancel the seat's events",
    );

    fx.upload("export")
        .expect("an upload under another system applies");
}

#[test]
fn a_complete_upload_never_runs_under_the_system_of_an_installed_feed() {
    let fx = Fixture::open();
    applied(fx.install_feed("shared"), "the feed install");

    refused(
        fx.upload("shared"),
        HELD,
        "an upload on the feed's system, whose sweep would cancel the feed's events",
    );

    applied(fx.set(FEED, "shared", None), "the owner's uninstall");
    fx.upload("shared")
        .expect("an upload on a retired feed system, which no poll sweeps again, applies");
}

#[test]
fn no_upload_seat_or_feed_takes_a_pack_calendar_system() {
    let fx = Fixture::open();

    refused(
        fx.install_seat("work", PACK_SYSTEM),
        PACK,
        "a seat on a pack calendar system",
    );
    refused(
        fx.install_feed(PACK_SYSTEM),
        PACK,
        "a feed on a pack calendar system",
    );
    refused(
        fx.upload(PACK_SYSTEM),
        PACK,
        "an upload on a pack calendar system",
    );
}
