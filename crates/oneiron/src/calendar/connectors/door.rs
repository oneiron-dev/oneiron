//! Owner-installed calendar seats and host iMIP submission, with custody names only.
use serde::{Deserialize, Serialize};

use super::{CalendarConnectorSeatConfig, CalendarConnectorSeatState, CalendarSyncOutcome};
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::{EdgeActorClass, Vault};

const SEATS: SideTable<String, CalendarConnectorRegistration, Named> =
    SideTable::new(&side_table::CALENDAR_CONNECTOR_SEAT);
const IMIP: SideTable<(), CalendarImipTransportConfig, Named> =
    SideTable::new(&side_table::CALENDAR_IMIP_TRANSPORT);

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarConnectorConfigureRequest {
    pub config: CalendarConnectorSeatConfig,
    /// CalDAV discovery URL. Credentials belong in the named custody record.
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarConnectorRequest {
    pub seat_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarConnectorWriteRequest {
    pub seat_ref: String,
    pub event_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarConnectorKillRequest {
    pub seat_ref: String,
    pub reason_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarConnectorRegistration {
    pub endpoint: String,
    pub seat: CalendarConnectorSeatState,
    pub last_sync: Option<CalendarSyncOutcome>,
}

/// An HTTP mail submission service installed by the host's owner. It accepts
/// one RFC 5322 MIME message per POST; a 2xx means accepted for delivery.
/// The credential must have a read binding for `calendar.imip`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarImipTransportConfig {
    pub endpoint: String,
    pub secret_ref: String,
}

pub fn validate_endpoint(endpoint: &str) -> MemoryResult<()> {
    let url = reqwest::Url::parse(endpoint)
        .map_err(|_| MemoryError::bad_request("calendar endpoint is not a URL"))?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]" | "::1"));
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

fn check_owner(memory: &Memory<'_>, owner: &AuthenticatedOwner, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
    if owner.revalidate_in_txn(memory.vault(), txn)? != memory.actor()
        || memory.actor_class() != EdgeActorClass::Human
    {
        return Err(MemoryError::bad_request("calendar setup must act as its authenticated owner"));
    }
    Ok(())
}

pub fn configure(
    memory: &Memory<'_>, owner: &AuthenticatedOwner, input: &CalendarConnectorConfigureRequest,
) -> MemoryResult<CalendarConnectorRegistration> {
    validate_endpoint(&input.endpoint)?;
    let seat = CalendarConnectorSeatState::new(input.config.clone());
    seat.validate().map_err(|error| MemoryError::bad_request(error.to_string()))?;
    memory.with_verified_actor_write_txn(|txn| {
        check_owner(memory, owner, txn)?;
        let key = input.config.seat_ref.clone();
        if let Some(existing) = SEATS.get(&memory.vault().store, txn, &key)? {
            if existing.endpoint == input.endpoint && existing.seat.config == input.config {
                return Ok(existing);
            }
            return Err(MemoryError::bad_request("a configured seat is immutable; use a new seat_ref"));
        }
        let row = CalendarConnectorRegistration { endpoint: input.endpoint.clone(), seat, last_sync: None };
        SEATS.put(&memory.vault().store, txn, &key, &row)?;
        Ok(row)
    })
}

pub fn get(
    memory: &Memory<'_>, owner: &AuthenticatedOwner, input: &CalendarConnectorRequest,
) -> MemoryResult<Option<CalendarConnectorRegistration>> {
    let txn = memory.vault().store.env.read_txn().map_err(crate::Error::from)?;
    check_owner(memory, owner, &txn)?;
    Ok(SEATS.get(&memory.vault().store, &txn, &input.seat_ref)?)
}

pub fn kill(
    memory: &Memory<'_>, owner: &AuthenticatedOwner, input: &CalendarConnectorKillRequest,
) -> MemoryResult<CalendarConnectorRegistration> {
    memory.with_verified_actor_write_txn(|txn| {
        check_owner(memory, owner, txn)?;
        let vault = memory.vault();
        let mut row = SEATS.get(&vault.store, txn, &input.seat_ref)?
            .ok_or_else(|| MemoryError::not_found("calendar seat is not configured"))?;
        row.seat = row.seat.mark_killed(vault.now_recorded_at(), &input.reason_ref)
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
        SEATS.put(&vault.store, txn, &input.seat_ref, &row)?;
        Ok(row)
    })
}

pub fn observe_sync(
    memory: &Memory<'_>, owner: &AuthenticatedOwner,
    prior: &CalendarConnectorRegistration, outcome: &CalendarSyncOutcome,
) -> MemoryResult<()> {
    memory.with_verified_actor_write_txn(|txn| {
        check_owner(memory, owner, txn)?;
        let vault = memory.vault();
        let key = prior.seat.config.seat_ref.clone();
        let mut current = SEATS.get(&vault.store, txn, &key)?
            .ok_or_else(|| MemoryError::not_found("calendar seat is not configured"))?;
        if current != *prior {
            return Err(MemoryError::bad_request("calendar seat moved during sync"));
        }
        if let CalendarSyncOutcome::Reenqueued { next_cursor, .. } = outcome {
            current.seat.cursor = next_cursor.clone();
        }
        current.last_sync = Some(outcome.clone());
        SEATS.put(&vault.store, txn, &key, &current)?;
        Ok(())
    })
}

pub fn configure_imip(
    memory: &Memory<'_>, owner: &AuthenticatedOwner, input: &CalendarImipTransportConfig,
) -> MemoryResult<CalendarImipTransportConfig> {
    validate_endpoint(&input.endpoint)?;
    if input.secret_ref.is_empty() || input.secret_ref.len() > 256 || input.secret_ref.chars().any(char::is_control) {
        return Err(MemoryError::bad_request("secret_ref must be a bounded custody name"));
    }
    memory.with_verified_actor_write_txn(|txn| {
        check_owner(memory, owner, txn)?;
        IMIP.put(&memory.vault().store, txn, &(), input)?;
        Ok(input.clone())
    })
}

pub fn get_imip(memory: &Memory<'_>, owner: &AuthenticatedOwner) -> MemoryResult<Option<CalendarImipTransportConfig>> {
    let txn = memory.vault().store.env.read_txn().map_err(crate::Error::from)?;
    check_owner(memory, owner, &txn)?;
    Ok(IMIP.get(&memory.vault().store, &txn, &())?)
}

/// Host-side read for the existing connector-send executor, never a public
/// configuration or authority fallback. The executor has already admitted the effect.
pub fn imip_transport(vault: &Vault) -> crate::Result<Option<CalendarImipTransportConfig>> {
    let txn = vault.store.env.read_txn()?;
    IMIP.get(&vault.store, &txn, &())
}

/// The installed seat's standing authority at each provider call. A stopped
/// seat, withdrawn owner credential or another sync's cursor never sends.
pub fn check_installed_connector(
    vault: &Vault, owner: &AuthenticatedOwner, expected: &CalendarConnectorRegistration,
) -> crate::Result<()> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    let current = SEATS.get(&vault.store, &txn, &expected.seat.config.seat_ref)?;
    if current.as_ref() != Some(expected) || expected.seat.kill_switch_engaged() {
        return Err(crate::Error::InvalidConfig("calendar seat is stopped or moved".to_owned()));
    }
    Ok(())
}
