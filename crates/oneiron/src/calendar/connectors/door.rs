//! Owner-installed calendar seats, and the host read of the iMIP submission transport, with
//! custody names only. A seat's setup is the `calendar.connector_seat` setting, one item per
//! seat ref; this module keeps what the seat's syncs and its kill switch write.
use serde::{Deserialize, Serialize};

use super::seat::ref_parses;
use super::{
    CalendarConnectorKillSwitchState, CalendarConnectorSeatConfig, CalendarConnectorSeatState,
    CalendarSyncOutcome,
};
use crate::calendar::setting_keys::CONNECTOR_SEAT;
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::setting::{Kind, SettingChange, SettingMode, SettingValue};
use crate::side_table::{self, Named, SideTable};
use crate::{EdgeActorClass, Vault};

/// What a seat's syncs and kill switch wrote, by seat ref. The setup is the setting's.
const STATES: SideTable<String, CalendarConnectorSeatRecord, Named> =
    SideTable::new(&side_table::CALENDAR_CONNECTOR_SEAT_STATE);

#[doc(hidden)]
pub use oneiron_verb_wire::calendar::connectors::door::{
    CalendarConnectorKillRequest, CalendarConnectorRequest, CalendarConnectorWriteRequest,
    CalendarImipTransportConfig,
};

/// One seat's setup, the value of `calendar.connector_seat` at the seat's ref: the CalDAV
/// discovery URL and the seat's configuration. Credentials belong in the named custody record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CalendarSeatSetup {
    pub(crate) config: CalendarConnectorSeatConfig,
    /// CalDAV discovery URL, HTTPS or loopback HTTP, with no credential, query or fragment.
    pub(crate) endpoint: String,
}

impl SettingValue for CalendarSeatSetup {
    fn check(self) -> crate::Result<Self> {
        validate_endpoint(&self.endpoint)
            .map_err(|error| crate::Error::InvalidConfig(error.message))?;
        CalendarConnectorSeatState::new(self.config.clone())
            .validate()
            .map_err(|error| crate::Error::InvalidConfig(error.to_string()))?;
        Ok(self)
    }
}

/// The seat refs `calendar.connector_seat` admits as items: the bounded refs a seat config
/// itself admits.
pub(crate) fn is_seat_ref(item: &str) -> bool {
    ref_parses(item)
}

/// A seat's syncs and kill switch, everything of a registration but its setup.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct CalendarConnectorSeatRecord {
    cursor: Option<String>,
    kill_switch: Option<CalendarConnectorKillSwitchState>,
    last_sync: Option<CalendarSyncOutcome>,
}

/// The installed seat at `seat_ref` joined with what its syncs and kill switch wrote, or none
/// when no seat is installed there (or its setup row does not read).
pub(crate) fn registration_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    seat_ref: &str,
) -> crate::Result<Option<CalendarConnectorRegistration>> {
    if !is_seat_ref(seat_ref) {
        return Ok(None);
    }
    let Some(setup) = CONNECTOR_SEAT
        .read_in_txn(vault, txn, &[], Some(seat_ref))?
        .value
    else {
        return Ok(None);
    };
    let record = STATES
        .get(&vault.store, txn, &setup.config.seat_ref)?
        .unwrap_or_default();
    Ok(Some(CalendarConnectorRegistration {
        endpoint: setup.endpoint,
        seat: CalendarConnectorSeatState {
            config: setup.config,
            cursor: record.cursor,
            kill_switch: record.kill_switch,
        },
        last_sync: record.last_sync,
    }))
}

fn put_record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &CalendarConnectorRegistration,
) -> crate::Result<()> {
    STATES.put(
        &vault.store,
        txn,
        &row.seat.config.seat_ref,
        &CalendarConnectorSeatRecord {
            cursor: row.seat.cursor.clone(),
            kill_switch: row.seat.kill_switch.clone(),
            last_sync: row.last_sync.clone(),
        },
    )?;
    Ok(())
}

/// The `calendar.connector_seat` hook, in the write that changes a seat's row. It keeps the
/// rules the configure door had: a value row at a seat ref, naming that ref, installed once.
/// A configured seat is immutable (a change or a clear is refused; a new configuration takes a
/// new seat ref), and a seat ref that a seat already used is never installed again, so no
/// cursor or kill switch outlives its seat.
///
/// # Errors
///
/// `InvalidConfig` for a pin, a row with no seat ref, a value naming another seat ref, a change
/// to an installed seat, or a seat ref used before.
pub(crate) fn seat_setup_changed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &SettingChange,
) -> crate::Result<()> {
    if change.mode != SettingMode::Value {
        return Err(crate::Error::InvalidConfig(
            "a calendar seat takes no pin".into(),
        ));
    }
    let Some(seat_ref) = change.item.as_deref() else {
        return Err(crate::Error::InvalidConfig(
            "calendar.connector_seat is set per seat: name the seat_ref as the item".into(),
        ));
    };
    let decode = |value: Option<&crate::setting::EncodedValue>| {
        value
            .and_then(Kind::<Option<CalendarSeatSetup>>::decode)
            .flatten()
    };
    if decode(change.prior.as_ref()).is_some() {
        return Err(crate::Error::InvalidConfig(
            "a configured seat is immutable; use a new seat_ref".into(),
        ));
    }
    let setup = decode(change.value.as_ref());
    if let Some(setup) = setup {
        if setup.config.seat_ref != seat_ref {
            return Err(crate::Error::InvalidConfig(
                "the seat's config.seat_ref must be the setting's item".into(),
            ));
        }
        if STATES.contains(&vault.store, &*txn, &seat_ref.to_owned())? {
            return Err(crate::Error::InvalidConfig(
                "this seat_ref named an earlier seat; use a new seat_ref".into(),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarConnectorRegistration {
    pub endpoint: String,
    pub seat: CalendarConnectorSeatState,
    pub last_sync: Option<CalendarSyncOutcome>,
}

/// The live authenticated owner and exact installed seat of one calendar operation.
/// It authorizes continuation of that seat's own preconditions, not secret disclosure.
#[derive(Clone)]
pub struct CalendarConnectorOperation {
    owner: AuthenticatedOwner,
    row: CalendarConnectorRegistration,
}

impl CalendarConnectorOperation {
    pub fn new(
        vault: &Vault,
        owner: AuthenticatedOwner,
        row: CalendarConnectorRegistration,
    ) -> crate::Result<Self> {
        let operation = Self { owner, row };
        let txn = vault.store.env.read_txn()?;
        operation.check_registration_in_txn(vault, &txn)?;
        Ok(operation)
    }

    #[must_use]
    pub fn registration(&self) -> &CalendarConnectorRegistration {
        &self.row
    }

    pub fn revalidate(&self, vault: &Vault) -> crate::Result<()> {
        let txn = vault.store.env.read_txn()?;
        self.revalidate_in_txn(vault, &txn)
    }

    pub(super) fn revalidate_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> crate::Result<()> {
        self.check_registration_in_txn(vault, txn)?;
        if self.row.seat.kill_switch_engaged() {
            return Err(crate::Error::InvalidConfig(
                "calendar seat is stopped or moved".into(),
            ));
        }
        Ok(())
    }

    fn check_registration_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> crate::Result<()> {
        self.owner.revalidate_in_txn(vault, txn)?;
        let current = registration_in_txn(vault, txn, &self.row.seat.config.seat_ref)?;
        if current.as_ref() != Some(&self.row) {
            return Err(crate::Error::InvalidConfig(
                "calendar seat is stopped or moved".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn literal_scope(&self) -> crate::Result<[u8; 32]> {
        let mut config = self.row.seat.config.clone();
        // Only the installed-seat label differs for the same logical operation.
        // Live admission above still uses this operation's unmodified registration.
        config.seat_ref.clear();
        super::literal::digest(&(&self.row.endpoint, &config))
    }
}

pub fn validate_endpoint(endpoint: &str) -> MemoryResult<()> {
    let url = reqwest::Url::parse(endpoint)
        .map_err(|_| MemoryError::bad_request("calendar endpoint is not a URL"))?;
    let local = matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    if !(url.scheme() == "https" || url.scheme() == "http" && local)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(MemoryError::bad_request(
            "calendar endpoint must be HTTPS or loopback HTTP, without credentials, query or fragment",
        ));
    }
    Ok(())
}

fn check_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    txn: &heed::RoTxn<'_>,
) -> MemoryResult<()> {
    if owner.revalidate_in_txn(memory.vault(), txn)? != memory.actor()
        || memory.actor_class() != EdgeActorClass::Human
    {
        return Err(MemoryError::bad_request(
            "calendar setup must act as its authenticated owner",
        ));
    }
    Ok(())
}

pub fn get(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &CalendarConnectorRequest,
) -> MemoryResult<Option<CalendarConnectorRegistration>> {
    let txn = memory
        .vault()
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)?;
    check_owner(memory, owner, &txn)?;
    Ok(registration_in_txn(memory.vault(), &txn, &input.seat_ref)?)
}

pub fn kill(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &CalendarConnectorKillRequest,
) -> MemoryResult<CalendarConnectorRegistration> {
    memory.with_verified_actor_write_txn(|txn| {
        check_owner(memory, owner, txn)?;
        let vault = memory.vault();
        let mut row = registration_in_txn(vault, txn, &input.seat_ref)?
            .ok_or_else(|| MemoryError::not_found("calendar seat is not configured"))?;
        row.seat = row
            .seat
            .mark_killed(vault.now_recorded_at(), &input.reason_ref)
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
        put_record_in_txn(vault, txn, &row)?;
        Ok(row)
    })
}

pub fn observe_sync(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    prior: &CalendarConnectorRegistration,
    outcome: &CalendarSyncOutcome,
) -> MemoryResult<()> {
    memory.with_verified_actor_write_txn(|txn| {
        check_owner(memory, owner, txn)?;
        let vault = memory.vault();
        let mut current = registration_in_txn(vault, txn, &prior.seat.config.seat_ref)?
            .ok_or_else(|| MemoryError::not_found("calendar seat is not configured"))?;
        if current != *prior {
            return Err(MemoryError::bad_request("calendar seat moved during sync"));
        }
        if let CalendarSyncOutcome::Reenqueued { next_cursor, .. } = outcome {
            current.seat.cursor = next_cursor.clone();
        }
        current.last_sync = Some(outcome.clone());
        put_record_in_txn(vault, txn, &current)?;
        Ok(())
    })
}

/// Host-side read for the existing connector-send executor, never a public
/// configuration or authority fallback. The executor has already admitted the effect.
/// The owner installs the transport with `vault.settings.set` on
/// `calendar.imip_transport`; a row that does not read reads as none.
pub fn imip_transport(vault: &Vault) -> crate::Result<Option<CalendarImipTransportConfig>> {
    let txn = vault.store.env.read_txn()?;
    Ok(crate::calendar::setting_keys::IMIP_TRANSPORT
        .read_in_txn(vault, &txn, &[], None)?
        .value
        .0)
}

/// The installed seat's standing authority at each provider call. A stopped
/// seat, withdrawn owner credential or another sync's cursor never sends.
pub fn check_installed_connector(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    expected: &CalendarConnectorRegistration,
) -> crate::Result<()> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    let current = registration_in_txn(vault, &txn, &expected.seat.config.seat_ref)?;
    if current.as_ref() != Some(expected) || expected.seat.kill_switch_engaged() {
        return Err(crate::Error::InvalidConfig(
            "calendar seat is stopped or moved".to_owned(),
        ));
    }
    Ok(())
}
