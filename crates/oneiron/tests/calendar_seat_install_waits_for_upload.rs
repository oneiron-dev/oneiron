//! FIX CALENDAR-SEAT-INSTALL-UNSEEN-BY-RUNNING-UPLOAD: an owner's install of a
//! CalDAV seat (a `calendar.connector_seat` item) waits for a running complete
//! upload's admission. The upload checks under the calendar admission turn
//! that no installed feed or seat imports under its system, then admits the
//! file and sweeps every live passport of that system the file lacks. A seat
//! install that committed between that check and the sweep would go unseen,
//! and the sweep could cancel the seat's first events. So the install takes
//! the same turn before its write opens: it lands before the check (the
//! upload is then refused, as `calendar_complete_upload_system_guard` shows)
//! or after the upload's last write.
//!
//! The owner's archive restore can install a seat too, through the key's
//! change hook in the restore's own writer, so it takes the same turn before
//! that writer opens (REVIEW-9493 round 1 P1).
//!
//! The fixture screener runs inside the upload's admission: it lets a second
//! thread install the seat (by a set, or by restoring an archive that holds
//! it) and waits for that install to commit.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test calendar_seat_install_waits_for_upload`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oneiron::calendar::ingest::door::{CalendarIcsImportRequest, import_ics_as_owner};
use oneiron::calendar::{
    CALENDAR_SAFEGUARD_CONFIG_KEY, CalendarBodyScreener, CalendarInboundBody, CalendarScreenVerdict,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{BlobArtifactInput, BlobVersionAppendOutcome, KeyValuePut, Memory};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::{Value, json};

const SEAT: &str = "calendar.connector_seat";
/// The refusal an upload gets under the system of an installed feed or seat.
const HELD: &str = "imports under this system";
/// 2026-03-02 09:00 UTC.
const NOW: u64 = 1_772_442_000;
/// One complete VCALENDAR with one VEVENT.
const ICS: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n\
BEGIN:VEVENT\r\nUID:export-1@example.test\r\nDTSTAMP:20260302T070000Z\r\n\
DTSTART:20260302T100000Z\r\nDTEND:20260302T110000Z\r\nSEQUENCE:0\r\n\
SUMMARY:Planning\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

/// How long the screener waits for the install to commit inside the upload's
/// admission. An install that takes no turn commits in milliseconds.
const INSTALL_WAIT: Duration = Duration::from_secs(2);
/// How long the screener waits for an owner's whole-vault restore to commit
/// inside the upload's admission. A restore that takes no turn commits well
/// within it.
const RESTORE_WAIT: Duration = Duration::from_secs(20);

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

    /// The owner installs the CalDAV seat `seat_ref` importing under `system`.
    fn install_seat(&self, seat_ref: &str, system: &str) -> Result<SetSettingOutcome, String> {
        let mut change = SetSetting::vault_value(SEAT, Value::Null);
        change.item = Some(seat_ref.to_owned());
        change.value = Some(json!({
            "config": {
                "seat_ref": seat_ref,
                "secret_ref": format!("caldav:{seat_ref}"),
                "system": system,
                "calendar_ref": "personal",
                "cadence_jitter_min_seconds": 300,
                "cadence_jitter_max_seconds": 900,
            },
            "endpoint": "https://dav.example.test/",
        }));
        self.vault
            .set_setting(SettingCaller::Owner(&self.proof), change)
            .map_err(|error| error.to_string())
    }

    /// The owner uploads [`ICS`] as a complete feed under `system`, screened
    /// by `screener`.
    fn upload(
        &self,
        system: &str,
        screener: Option<&dyn CalendarBodyScreener>,
    ) -> Result<(), String> {
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
            screener,
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
    }

    /// The owner turns the inbound screen on, so each admission calls the
    /// upload's screener.
    fn screen_on(&self) {
        let (namespace, key) = CALENDAR_SAFEGUARD_CONFIG_KEY
            .rsplit_once('.')
            .expect("a dotted dial key");
        let mut on = serde_json::Map::new();
        on.insert(key.to_owned(), Value::Bool(true));
        self.memory()
            .key_value_put(&KeyValuePut {
                namespace: namespace.split('.').map(str::to_owned).collect(),
                key: key.to_owned(),
                value: Value::Object(on),
                request_id: "safeguard-dial-on".to_owned(),
                source: "user_stated".to_owned(),
            })
            .expect("the owner's keyed value commits");
    }
}

/// A screener that, on its first call, lets the install thread go and waits
/// `wait` for its install to commit; every body screens clear.
struct InstallingScreener {
    go: Mutex<Option<Sender<()>>>,
    installed: Mutex<Receiver<()>>,
    wait: Duration,
    calls: AtomicUsize,
    installed_inside_admission: AtomicBool,
}

impl InstallingScreener {
    fn new(go: Sender<()>, installed: Receiver<()>, wait: Duration) -> Self {
        Self {
            go: Mutex::new(Some(go)),
            installed: Mutex::new(installed),
            wait,
            calls: AtomicUsize::new(0),
            installed_inside_admission: AtomicBool::new(false),
        }
    }
}

impl CalendarBodyScreener for InstallingScreener {
    fn screen(&self, _body: &CalendarInboundBody) -> oneiron::Result<CalendarScreenVerdict> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(go) = self.go.lock().expect("go").take() {
            go.send(())
                .expect("the install thread waits for the screen");
            let committed = self
                .installed
                .lock()
                .expect("installed")
                .recv_timeout(self.wait)
                .is_ok();
            self.installed_inside_admission
                .store(committed, Ordering::SeqCst);
        }
        Ok(CalendarScreenVerdict::Clear)
    }
}

#[test]
fn a_seat_install_during_a_complete_upload_lands_after_its_last_write() {
    let fx = Fixture::open();
    fx.screen_on();

    let (go, go_wait) = channel::<()>();
    let (installed, installed_wait) = channel::<()>();
    let screener = InstallingScreener::new(go, installed_wait, INSTALL_WAIT);
    // The upload checks "shared" for an installed source, finds none, and
    // screens its one event inside its admission.
    let (uploaded, install) = std::thread::scope(|scope| {
        let owner = &fx;
        let install = scope.spawn(move || {
            go_wait.recv().ok()?; // the screener never ran; the upload's asserts say why
            let outcome = owner.install_seat("work", "shared");
            let _ = installed.send(());
            Some(outcome)
        });
        let uploaded = fx.upload("shared", Some(&screener as &dyn CalendarBodyScreener));
        // An upload that never screened lets the install thread end.
        drop(screener.go.lock().expect("go").take());
        (uploaded, install.join().expect("the install thread"))
    });

    assert!(
        screener.calls.load(Ordering::SeqCst) > 0,
        "the upload screened its event inside its admission"
    );
    assert!(
        !screener.installed_inside_admission.load(Ordering::SeqCst),
        "the owner's seat install waited for the upload's admission: it committed while the \
         upload's screener ran inside it, after the upload's check of its system"
    );
    uploaded.expect("the upload applies: no source held its system when it checked");
    match install {
        Some(Ok(SetSettingOutcome::Applied { .. })) => {}
        other => panic!("the seat install lands once the upload's admission ended: {other:?}"),
    }
    match fx.upload("shared", None) {
        Err(error) => assert!(
            error.contains(HELD),
            "a later upload sees the seat on its system: {error}"
        ),
        Ok(()) => panic!("a later upload on the seat's system is refused"),
    }
}

#[test]
fn a_seat_restore_during_a_complete_upload_lands_after_its_last_write() {
    let source = Fixture::open();
    match source.install_seat("work", "shared") {
        Ok(SetSettingOutcome::Applied { .. }) => {}
        other => panic!("the source vault installs its seat: {other:?}"),
    }
    let archive = source
        .vault
        .export_whole_vault(true)
        .expect("the source's whole-vault export")
        .bytes()
        .to_vec();
    // The destination's engine seeds take another wall-clock second than the
    // source's, as in `archive_import_retained_side_rows.rs`.
    std::thread::sleep(Duration::from_millis(1100));
    let fx = Fixture::open();
    fx.screen_on();

    let (go, go_wait) = channel::<()>();
    let (restored, restored_wait) = channel::<()>();
    let screener = InstallingScreener::new(go, restored_wait, RESTORE_WAIT);
    // The upload checks "shared" for an installed source, finds none, and
    // screens its one event inside its admission; the archive's seat on
    // "shared" is absent here, so the owner's restore installs it.
    let (uploaded, restore) = std::thread::scope(|scope| {
        let owner = &fx;
        let archive = &archive;
        let restore = scope.spawn(move || {
            go_wait.recv().ok()?; // the screener never ran; the upload's asserts say why
            let outcome = owner
                .vault
                .import_whole_vault_archive_from_as_owner(Cursor::new(archive), &owner.proof)
                .map(|_| ())
                .map_err(|error| error.to_string());
            let _ = restored.send(());
            Some(outcome)
        });
        let uploaded = fx.upload("shared", Some(&screener as &dyn CalendarBodyScreener));
        // An upload that never screened lets the restore thread end.
        drop(screener.go.lock().expect("go").take());
        (uploaded, restore.join().expect("the restore thread"))
    });

    assert!(
        screener.calls.load(Ordering::SeqCst) > 0,
        "the upload screened its event inside its admission"
    );
    assert!(
        !screener.installed_inside_admission.load(Ordering::SeqCst),
        "the owner's restore waited for the upload's admission: it committed the archive's \
         seat while the upload's screener ran inside it, after the upload's check of its system"
    );
    uploaded.expect("the upload applies: no source held its system when it checked");
    match restore {
        Some(Ok(())) => {}
        other => panic!("the owner's restore commits once the upload's admission ended: {other:?}"),
    }
    match fx.upload("shared", None) {
        Err(error) => assert!(
            error.contains(HELD),
            "a later upload sees the restored seat on its system: {error}"
        ),
        Ok(()) => panic!("a later upload on the restored seat's system is refused"),
    }
}
