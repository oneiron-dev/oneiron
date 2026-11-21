//! The catalogue keys `calendar` declares (DESIGN 15-setting-primitive, stages 1 and 4): the
//! host's iMIP mail submission transport, and the owner's CalDAV seats and ICS feeds, one item
//! each.

use serde::{Deserialize, Serialize};

use oneiron_setting_contract::{RowKey, SettingMode, SettingScope};

use super::connectors::door::{
    CalendarImipTransportConfig, CalendarSeatSetup, is_seat_ref, retired_seats_of_system_in_txn,
    seat_setup_changed_in_txn, validate_endpoint,
};
use super::ingest::feed_door::{
    ics_feed_changed_in_txn, ics_feed_committed, is_feed_system, registration_in_txn,
};
use super::ingest::{ADMISSION_WRITE_TURN, IcsFeedPollConfig};
use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::{ItemDomain, Kind, RefusalSource, RefusedProjection, SettingValue};

/// The longest custody name an iMIP transport may carry, in bytes.
const SECRET_REF_MAX_BYTES: usize = 256;

/// The host's iMIP mail submission endpoint and the custody name of its credential, or none: no
/// invite leaves by mail until the owner installs one. The credential's bytes stay in custody
/// (ARCH-0069); the setting holds only its name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct ImipTransport(pub(crate) Option<CalendarImipTransportConfig>);

impl SettingValue for ImipTransport {
    fn check(self) -> Result<Self> {
        if let Some(config) = &self.0 {
            validate_endpoint(&config.endpoint)
                .map_err(|error| Error::InvalidConfig(error.message))?;
            if config.secret_ref.is_empty()
                || config.secret_ref.len() > SECRET_REF_MAX_BYTES
                || config.secret_ref.chars().any(char::is_control)
            {
                return Err(Error::InvalidConfig(
                    "secret_ref must be a bounded custody name".into(),
                ));
            }
        }
        Ok(self)
    }
}

fn no_transport() -> ImipTransport {
    ImipTransport(None)
}

fn no_seat() -> Option<CalendarSeatSetup> {
    None
}

fn no_feed() -> Option<IcsFeedPollConfig> {
    None
}

/// The seats but `except` that hold `system` here: each installed one, and each this install
/// holds quarantined (its row reads no seat) whose act's seat imports under it, so the owner's
/// pick of a source names every seat of the system (REVIEW-10357 P1-2); with `retired`, each taken
/// out of service that keeps it too.
fn seats_of_system_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    (system, except): (&str, Option<&str>),
    retired: bool,
) -> Result<Vec<String>> {
    let mut seats = Vec::new();
    for seat_ref in CONNECTOR_SEAT.items_in_txn(vault, txn)? {
        if except == Some(seat_ref.as_str()) {
            continue;
        }
        let installed = CONNECTOR_SEAT
            .read_in_txn(vault, txn, &[], Some(&seat_ref))?
            .value;
        let setup = match installed {
            Some(setup) => Some(setup),
            None => {
                let slot = RowKey {
                    name: CONNECTOR_SEAT.spec.name.to_owned(),
                    item: Some(seat_ref.clone()),
                    mode: SettingMode::Value,
                    scope: SettingScope::Vault,
                };
                crate::setting::head_act_value_in_txn(vault, txn, &slot)?
                    .and_then(|value| {
                        serde_json::from_value::<Option<CalendarSeatSetup>>(value).ok()
                    })
                    .flatten()
            }
        };
        if setup.is_some_and(|setup| setup.config.system == system) {
            seats.push(seat_ref);
        }
    }
    if retired {
        for seat_ref in retired_seats_of_system_in_txn(vault, txn, system)? {
            if except != Some(seat_ref.as_str()) && !seats.contains(&seat_ref) {
                seats.push(seat_ref);
            }
        }
    }
    Ok(seats)
}

/// The rows a feed's hook judges the feed of the system `slot` names against: every seat that
/// imports under that system, installed, quarantined here or taken out of service
/// ([`seats_of_system_in_txn`]), so the owner's notice of a refused projection of either names
/// every act, on every machine, as the seat's notice does ([`seat_system_peers`]; row
/// SETTING-PROJECTED-ROW-REFUSING-HOOKS).
fn feed_system_peers(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    slot: &RowKey,
    _value: Option<&serde_json::Value>,
) -> Result<Vec<RowKey>> {
    let Some(system) = slot.item.as_deref() else {
        return Ok(Vec::new());
    };
    seats_of_system_in_txn(vault, txn, (system, None), true)?
        .iter()
        .map(|seat_ref| CONNECTOR_SEAT.deciding_slot_in_txn(vault, txn, Some(seat_ref)))
        .collect()
}

/// The rows a seat's hook judges the seat `value` against: the installed feed of its system and
/// every other seat of its system, installed or quarantined here ([`seats_of_system_in_txn`],
/// [`feed_system_peers`]). A seat whose value is not here (a clear, or a value beside its act
/// that did not arrive) names none.
fn seat_system_peers(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    slot: &RowKey,
    value: Option<&serde_json::Value>,
) -> Result<Vec<RowKey>> {
    let Some(setup) = value
        .and_then(|value| serde_json::from_value::<Option<CalendarSeatSetup>>(value.clone()).ok())
        .flatten()
    else {
        return Ok(Vec::new());
    };
    let system = setup.config.system.as_str();
    let mut peers = Vec::new();
    if registration_in_txn(vault, txn, system)?.is_some() {
        peers.push(ICS_FEED.deciding_slot_in_txn(vault, txn, Some(system))?);
    }
    for seat_ref in seats_of_system_in_txn(vault, txn, (system, slot.item.as_deref()), false)? {
        peers.push(CONNECTOR_SEAT.deciding_slot_in_txn(vault, txn, Some(&seat_ref))?);
    }
    Ok(peers)
}

/// The owner's words of the choice between the sources of one calendar system that the notice of
/// a refused feed or seat names (SETTING-PROJECTED-CALENDAR-SYSTEM-CLAIM = A, in the lead's
/// words): "Your 'work' calendar has two complete sources (an ICS feed set on Laptop, a CalDAV
/// seat set on Desktop). Pick one." The feeds first. `None` for fewer than two sources, a
/// source of another key, and sources of different systems.
fn calendar_source_choice(sources: &[RefusalSource<'_>]) -> Option<String> {
    let mut system: Option<String> = None;
    let mut named = Vec::with_capacity(sources.len());
    for source in sources {
        let Some(value) = source.value.filter(|value| !value.is_null()) else {
            continue;
        };
        let (order, what, of) = if source.slot.name == ICS_FEED.spec.name {
            (0, "an ICS feed", source.slot.item.clone())
        } else if source.slot.name == CONNECTOR_SEAT.spec.name {
            let of = value
                .pointer("/config/system")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            (1, "a CalDAV seat", of)
        } else {
            return None;
        };
        let of = of?;
        if *system.get_or_insert_with(|| of.clone()) != of {
            return None;
        }
        named.push((order, format!("{what} set on {}", source.machine)));
    }
    let system = system?;
    let count = match named.len() {
        0 | 1 => return None,
        2 => "two".to_owned(),
        3 => "three".to_owned(),
        count => count.to_string(),
    };
    named.sort_by_key(|(order, _)| *order);
    let named = named
        .into_iter()
        .map(|(_, words)| words)
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "Your '{system}' calendar has {count} complete sources ({named}). Pick one."
    ))
}

crate::setting::setting_keys! {
    /// The host's iMIP mail submission endpoint and the custody name of its credential. It
    /// grants no invite consent and no sending identity. None until the owner installs one.
    pub(crate) IMIP_TRANSPORT: ImipTransport = "calendar.imip_transport" {
        kind: Kind::new(no_transport).strictest(no_transport),
    };
    /// One CalDAV seat the owner installed, keyed by its seat ref: the discovery endpoint and the
    /// seat's config (the custody name of its credential, its system, its collection and its poll
    /// cadence). An installed seat never changes: a new configuration takes a new seat ref. A seat
    /// never takes the system of an installed ICS feed or a pack calendar source, whose complete
    /// polls and listings would cancel its events. A change waits for a running calendar
    /// admission, a complete upload's among them, so none lands inside one. A machine whose hook
    /// refuses a signed seat holds it out of service (quarantined), and the owner picks the
    /// source the calendar keeps.
    pub(crate) CONNECTOR_SEAT: Option<CalendarSeatSetup> = "calendar.connector_seat" {
        kind: Kind::new(no_seat).strictest(no_seat),
        item: Some(ItemDomain { name: "calendar seat refs", admits: is_seat_ref }),
        on_change: Some(seat_setup_changed_in_txn),
        refusal_peers: Some(seat_system_peers),
        refused_projection: RefusedProjection::Quarantine { choice: calendar_source_choice },
        write_turn: Some(ADMISSION_WRITE_TURN),
    };
    /// One ICS feed the owner installed, keyed by its system: the custody name of its URL and its
    /// poll cadence. It grants no import consent. An installed feed never changes: a new
    /// configuration takes a new system, never one an installed CalDAV seat or a pack calendar
    /// source imports under.
    /// Installing one starts its poll chain. Clearing one uninstalls it: its standing consent
    /// ends, its cursor goes and its pending polls are cancelled; a system it polled under stays
    /// retired. A change waits for a running poll's admission, so none lands inside one. A
    /// machine whose hook refuses a signed feed holds it uninstalled (quarantined), and the
    /// owner picks the source the calendar keeps.
    pub(crate) ICS_FEED: Option<IcsFeedPollConfig> = "calendar.ics_feed" {
        kind: Kind::new(no_feed).strictest(no_feed),
        item: Some(ItemDomain { name: "ICS feed systems", admits: is_feed_system }),
        on_change: Some(ics_feed_changed_in_txn),
        refusal_peers: Some(feed_system_peers),
        refused_projection: RefusedProjection::Quarantine { choice: calendar_source_choice },
        after_commit: Some(ics_feed_committed),
        write_turn: Some(ADMISSION_WRITE_TURN),
    };
}
