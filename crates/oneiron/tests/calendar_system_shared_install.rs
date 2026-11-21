//! FIX CALENDAR-SYSTEM-SHARED-BY-ICS-AND-CONNECTOR: one calendar system is
//! imported by one kind of source. A complete poll of an installed ICS feed
//! cancels every event of its system that the feed body lacks, so a CalDAV
//! seat importing under that system would lose its events at the next poll.
//!
//! - A feed install on the system of an installed seat is refused, and so is
//!   one on the system of a seat the owner stopped.
//! - A seat install on the system of an installed feed is refused.
//! - A system whose feed the owner uninstalled is open to a seat: no poll of
//!   that feed runs again.
//! - Feeds and seats on different systems both install.
//! - A seat of another calendar (another collection, or another account's
//!   credential) on the system of an installed seat is refused: a passport
//!   names its calendar by system, so the two calendars' copies, deletes and
//!   echoes of one booking would read as one calendar's
//!   (CAL-SEAT-DELETE-OF-WRITTEN-ONLY-EVENT-CANCELS-NOTHING review). A new
//!   seat of the same calendar on that system installs.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test calendar_system_shared_install`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::calendar::connectors::door::{
    CalendarConnectorKillRequest, CalendarConnectorRequest, get as seat, kill,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::{Value, json};

const FEED: &str = "calendar.ics_feed";
const SEAT: &str = "calendar.connector_seat";
/// The refusal both install hooks give for a system the other kind holds.
const HELD: &str = "imports under this system";

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
        self.install_seat_of(seat_ref, system, &format!("caldav:{seat_ref}"), "personal")
    }

    /// The owner installs the CalDAV seat `seat_ref` of the collection
    /// `calendar_ref` that the credential named `secret_ref` reads, importing
    /// under `system`.
    fn install_seat_of(
        &self,
        seat_ref: &str,
        system: &str,
        secret_ref: &str,
        calendar_ref: &str,
    ) -> Result<SetSettingOutcome, String> {
        self.set(
            SEAT,
            seat_ref,
            Some(json!({
                "config": {
                    "seat_ref": seat_ref,
                    "secret_ref": secret_ref,
                    "system": system,
                    "calendar_ref": calendar_ref,
                    "cadence_jitter_min_seconds": 300,
                    "cadence_jitter_max_seconds": 900,
                },
                "endpoint": "https://dav.example.test/",
            })),
        )
    }

    fn seat_installed(&self, seat_ref: &str) -> bool {
        seat(
            &self.memory(),
            &self.proof,
            &CalendarConnectorRequest {
                seat_ref: seat_ref.to_owned(),
            },
        )
        .expect("seat read")
        .is_some()
    }
}

fn applied(outcome: Result<SetSettingOutcome, String>, what: &str) {
    match outcome {
        Ok(SetSettingOutcome::Applied { .. }) => {}
        other => panic!("{what} applies: {other:?}"),
    }
}

fn refused_as_held(outcome: Result<SetSettingOutcome, String>, what: &str) {
    match outcome {
        Err(error) => assert!(error.contains(HELD), "{what}: {error}"),
        Ok(outcome) => panic!("{what} is refused, but it gave {outcome:?}"),
    }
}

#[test]
fn a_feed_never_installs_on_the_system_of_a_seat() {
    let fx = Fixture::open();
    applied(fx.install_seat("work", "shared"), "the seat install");

    refused_as_held(
        fx.install_feed("shared"),
        "a feed on the seat's system, which its complete polls would sweep",
    );

    kill(
        &fx.memory(),
        &fx.proof,
        &CalendarConnectorKillRequest {
            seat_ref: "work".to_owned(),
            reason_ref: "owner-stop".to_owned(),
        },
    )
    .expect("the owner stops the seat");
    refused_as_held(
        fx.install_feed("shared"),
        "a feed on the system of a stopped seat, whose events keep their passports",
    );

    applied(fx.install_feed("other"), "a feed on another system");
}

#[test]
fn a_seat_never_installs_on_the_system_of_an_installed_feed() {
    let fx = Fixture::open();
    applied(fx.install_feed("shared"), "the feed install");

    refused_as_held(
        fx.install_seat("work", "shared"),
        "a seat on the feed's system, whose events the feed's complete polls would cancel",
    );
    assert!(
        !fx.seat_installed("work"),
        "the refused write installs no seat"
    );

    applied(fx.install_seat("home", "other"), "a seat on another system");
    assert!(fx.seat_installed("home"));
}

#[test]
fn a_seat_installs_on_the_system_of_an_uninstalled_feed() {
    let fx = Fixture::open();
    applied(fx.install_feed("moved"), "the feed install");
    applied(fx.set(FEED, "moved", None), "the owner's uninstall");

    applied(
        fx.install_seat("work", "moved"),
        "a seat on a retired feed system, which no poll sweeps again",
    );
    assert!(fx.seat_installed("work"));
}

#[test]
fn a_seat_of_another_calendar_never_installs_on_the_system_of_a_seat() {
    let fx = Fixture::open();
    applied(fx.install_seat("work", "shared"), "the seat install");

    refused_as_held(
        fx.install_seat_of("family", "shared", "caldav:work", "family"),
        "a seat of another collection on the seat's system",
    );
    refused_as_held(
        fx.install_seat_of("partner", "shared", "caldav:partner", "personal"),
        "a seat of another account's calendar on the seat's system",
    );
    assert!(
        !fx.seat_installed("family") && !fx.seat_installed("partner"),
        "the refused writes install no seat"
    );

    applied(
        fx.install_seat_of("work-renewed", "shared", "caldav:work", "personal"),
        "a new seat of the same calendar on its system",
    );
    applied(
        fx.install_seat_of("family", "other", "caldav:work", "family"),
        "a seat of another calendar on another system",
    );
}
