//! Conditional writes plus durable outbox and remote-object cursor store.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::inbound::{admit_screened, reconcile_remote_object};
use super::remote::{
    CalendarRemoteTransport, RemoteWriteReceipt, RemoteWriteRequest, ics_content_hash, local_uid,
    render_owner_vevent, shared_uid,
};
use super::seat::{CalendarConnectorError, CalendarConnectorSeatState};

use crate::calendar::CalendarError;
use crate::calendar::claims::{
    CalendarPassportDirection, CalendarPassportPresence, CalendarPassportValue,
    PREDICATE_CALENDAR_PASSPORT,
};
use crate::calendar::passport::{
    encode_passport_value, index_passport_uid, live_passport_for, live_passports_for_event,
    supersede_calendar_passport,
};
use crate::calendar::safeguard::CalendarInboundBody;
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::vault::Vault;

/// `vault_meta` prefix for this module's private rows. Two kinds live under it
/// ([`OUTBOX_ROW_TAG`], [`REMOTE_OBJECT_TAG`]): no second prefix, no entity byte.
pub(super) const CALENDAR_WRITE_OUTBOX_PREFIX: &[u8] = b"calendar.connector-write.v1:";

/// Sub-tag for durable write-outbox rows.
pub(super) const OUTBOX_ROW_TAG: &[u8] = b"row:";

/// Sub-tag for the node-local `(system, calendar_ref, uid)` href/ETag cursor.
const REMOTE_OBJECT_TAG: &[u8] = b"obj:";

/// Id-derivation domain for [`CalendarWriteOutboxRow::outbox_id`].
const OUTBOX_ID_DOMAIN: &[u8] = b"oneiron:calendar-connector-write:v1:";

/// The UID domain a locally originated EVENT gets when no passport names it.
/// `.invalid` is the RFC 2606 reserved TLD: a calendar UID must be globally
/// unique, and must never look like a resolvable address.
pub(super) const LOCAL_UID_DOMAIN: &str = "calendar.invalid";

/// What a local write intends to do to the remote calendar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarWriteAction {
    /// Create or replace one resource.
    Upsert,
    /// Remove one resource.
    Delete,
}

impl CalendarWriteAction {
    /// Wire token for this action.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::Delete => "delete",
        }
    }
}

/// The four states one durable write-outbox row moves through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarWriteOutboxState {
    /// Staged and durable; the provider has not been called yet.
    Prepared,
    /// The provider accepted the write; the local commit has not landed.
    RemoteApplied,
    /// The precondition failed: resume by reconciling, never by rewriting.
    ReconcileRequired,
    /// The passport and cursor caught up; the row is closed.
    Committed,
}

impl CalendarWriteOutboxState {
    /// Wire token for this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::RemoteApplied => "remote_applied",
            Self::ReconcileRequired => "reconcile_required",
            Self::Committed => "committed",
        }
    }
}

/// One durable local write-outbox row.
///
/// Staged under `CALENDAR_WRITE_OUTBOX_PREFIX` BEFORE the provider call, so a
/// crash between the remote mutation and the local commit resumes from the row
/// instead of repeating a blind write. Carries refs and hashes only — never a
/// credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarWriteOutboxRow {
    /// Deterministic row id over `(system, calendar_ref, uid, action)`.
    pub outbox_id: [u8; 32],
    /// Where the row is in its lifecycle.
    pub state: CalendarWriteOutboxState,
    /// What the write intends.
    pub action: CalendarWriteAction,
    /// The EVENT this write projects.
    pub event_ref: EntityId,
    /// Provider key of the transport that will run it.
    pub provider: String,
    /// The seat's foreign system identifier.
    pub system: String,
    /// The seat's remote collection.
    pub calendar_ref: String,
    /// The UID the write preserves.
    pub uid: String,
    /// The SEQUENCE the write intends.
    pub sequence: u32,
    /// The content hash the write intends.
    pub content_hash: [u8; 32],
    /// The precondition the write carries.
    pub expected_etag: Option<String>,
    /// The resource the write targets, when one is known.
    pub href: Option<String>,
    /// The provider receipt after the remote mutation has landed.
    pub receipt: Option<RemoteWriteReceipt>,
    /// When the row was first staged.
    pub staged_at: u64,
    /// When the row last moved.
    pub updated_at: u64,
}

/// Node-local href/ETag cursor for one `(system, calendar_ref, uid)`.
///
/// Pulls refresh it; writes read it as their `If-Match` precondition and refresh
/// it from the receipt. It is a lookup accelerator over provider state, never
/// synced truth — the passport claim remains the synced record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarRemoteObjectRow {
    /// The seat's foreign system identifier.
    pub system: String,
    /// The seat's remote collection.
    pub calendar_ref: String,
    /// The VEVENT UID.
    pub uid: String,
    /// Last known resource path.
    pub href: Option<String>,
    /// Last known ETag.
    pub etag: Option<String>,
    /// Last observed SEQUENCE.
    pub last_sequence: u32,
    /// Last observed content hash.
    pub content_hash: [u8; 32],
    /// When the row was last refreshed.
    pub last_seen_at: u64,
}

/// Writes one local EVENT to the seat's remote calendar.
///
/// The UID is preserved (or minted once for a locally originated EVENT), the
/// SEQUENCE bumps only when this seat already carries a passport for that UID,
/// the durable outbox row is staged BEFORE the provider call, and the expected
/// ETag rides as the conditional precondition. A precondition failure records
/// `reconcile_required`, refreshes the local view of the remote object, and
/// returns [`CalendarConnectorError::EtagMismatch`] — it never overwrites blind.
///
/// # Errors
///
/// [`CalendarConnectorError::KillSwitchEngaged`] on a killed seat, plus the
/// seat, store, parse, and transport variants.
pub fn write_calendar_event(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    transport: &dyn CalendarRemoteTransport,
    event_ref: EntityId,
    now: u64,
) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
    seat.validate()?;
    if seat.kill_switch_engaged() {
        return Err(CalendarConnectorError::KillSwitchEngaged);
    }
    if vault.get_entity_type(&event_ref)? != Some(ENTITY_TYPE_EVENT) {
        return Err(ingest_error("write target is not an EVENT"));
    }

    let system = seat.config.system.as_str();
    let passports = live_passports_for_event(vault, &event_ref)?;
    let own = passports
        .iter()
        .find(|(_, value)| value.system == system)
        .map(|(_, value)| value.clone());
    let uid = match &own {
        Some(value) => value.uid.clone(),
        None => shared_uid(&passports).unwrap_or_else(|| local_uid(&event_ref)),
    };
    let outbox_id = derive_outbox_id(
        system,
        &seat.config.calendar_ref,
        &uid,
        CalendarWriteAction::Upsert,
    );

    if let Some(mut row) = read_outbox_row(vault, &outbox_id)? {
        ensure_outbox_matches(&row, seat, transport, event_ref, &uid)?;
        match row.state {
            CalendarWriteOutboxState::Prepared => {
                let ics = render_owner_vevent(vault, &event_ref, &uid, row.sequence, now)?;
                let rendered_hash = ics_content_hash(&ics, &uid)?;
                if rendered_hash != row.content_hash {
                    return Err(CalendarConnectorError::Outbox {
                        outbox_id,
                        detail: "staged intent no longer matches the local EVENT".to_owned(),
                    });
                }
                let request = RemoteWriteRequest {
                    href: row.href.clone(),
                    expected_etag: row.expected_etag.clone(),
                    uid: uid.clone(),
                    sequence: row.sequence,
                    ics,
                };
                let receipt =
                    issue_prepared_upsert(vault, seat, transport, &uid, now, &mut row, &request)?;
                return finish_remote_applied_write(
                    vault,
                    seat,
                    transport,
                    event_ref,
                    own.as_ref(),
                    &mut row,
                    receipt,
                    now,
                );
            }
            CalendarWriteOutboxState::ReconcileRequired => {
                return Err(reconcile_required_error(
                    vault, seat, transport, &row, &uid, now,
                )?);
            }
            CalendarWriteOutboxState::RemoteApplied => {
                let receipt =
                    row.receipt
                        .clone()
                        .ok_or_else(|| CalendarConnectorError::Outbox {
                            outbox_id,
                            detail: "remote-applied row carries no provider receipt".to_owned(),
                        })?;
                return finish_remote_applied_write(
                    vault,
                    seat,
                    transport,
                    event_ref,
                    own.as_ref(),
                    &mut row,
                    receipt,
                    now,
                );
            }
            CalendarWriteOutboxState::Committed => {
                // A closed row is not an in-flight retry. Derive and stage the
                // next owner mutation below, replacing this stable-key row.
            }
        }
    }

    let sequence = match &own {
        // A UID this seat already tracks: the mutation is an update, so the
        // calendar contract requires the bump.
        Some(value) => value.last_sequence.saturating_add(1),
        // First write of this UID to this seat: carry the highest SEQUENCE any
        // sibling source reported, so a two-provider EVENT stays ordered.
        None => passports
            .iter()
            .filter(|(_, value)| value.uid == uid)
            .map(|(_, value)| value.last_sequence)
            .max()
            .unwrap_or(0),
    };
    let ics = render_owner_vevent(vault, &event_ref, &uid, sequence, now)?;
    let content_hash = ics_content_hash(&ics, &uid)?;
    let object = read_remote_object(vault, system, &seat.config.calendar_ref, &uid)?;
    let expected_etag = object.as_ref().and_then(|row| row.etag.clone());
    let href = object.as_ref().and_then(|row| row.href.clone());
    let mut row = CalendarWriteOutboxRow {
        outbox_id,
        state: CalendarWriteOutboxState::Prepared,
        action: CalendarWriteAction::Upsert,
        event_ref,
        provider: transport.provider_key().to_owned(),
        system: system.to_owned(),
        calendar_ref: seat.config.calendar_ref.clone(),
        uid: uid.clone(),
        sequence,
        content_hash,
        expected_etag: expected_etag.clone(),
        href: href.clone(),
        receipt: None,
        staged_at: now,
        updated_at: now,
    };
    write_outbox_row(vault, &row)?;

    let request = RemoteWriteRequest {
        href,
        expected_etag,
        uid: uid.clone(),
        sequence,
        ics,
    };
    let receipt = issue_prepared_upsert(vault, seat, transport, &uid, now, &mut row, &request)?;
    finish_remote_applied_write(
        vault,
        seat,
        transport,
        event_ref,
        own.as_ref(),
        &mut row,
        receipt,
        now,
    )
}

fn ensure_outbox_matches(
    row: &CalendarWriteOutboxRow,
    seat: &CalendarConnectorSeatState,
    transport: &dyn CalendarRemoteTransport,
    event_ref: EntityId,
    uid: &str,
) -> Result<(), CalendarConnectorError> {
    if row.action != CalendarWriteAction::Upsert
        || row.event_ref != event_ref
        || row.provider != transport.provider_key()
        || row.system != seat.config.system
        || row.calendar_ref != seat.config.calendar_ref
        || row.uid != uid
    {
        return Err(CalendarConnectorError::Outbox {
            outbox_id: row.outbox_id,
            detail: "stable outbox key resolves to a different write".to_owned(),
        });
    }
    Ok(())
}

fn issue_prepared_upsert(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    transport: &dyn CalendarRemoteTransport,
    uid: &str,
    now: u64,
    row: &mut CalendarWriteOutboxRow,
    request: &RemoteWriteRequest,
) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
    let receipt =
        match transport.upsert(&seat.config.secret_ref, &seat.config.calendar_ref, request) {
            Ok(receipt) => receipt,
            Err(CalendarConnectorError::EtagMismatch {
                href,
                expected,
                actual,
            }) => {
                row.state = CalendarWriteOutboxState::ReconcileRequired;
                row.updated_at = now;
                write_outbox_row(vault, row)?;
                // Reconciliation reads the current remote state so a caller can
                // intentionally rebase. Blind retries remain blocked on this row.
                reconcile_remote_object(vault, seat, transport, uid, now);
                return Err(CalendarConnectorError::EtagMismatch {
                    href,
                    expected,
                    actual,
                });
            }
            // Any other failure leaves the row `prepared`: the retry replays it.
            Err(err) => return Err(err),
        };

    row.state = CalendarWriteOutboxState::RemoteApplied;
    row.href = Some(receipt.href.clone());
    row.receipt = Some(receipt.clone());
    row.updated_at = now;
    write_outbox_row(vault, row)?;
    Ok(receipt)
}

fn reconcile_required_error(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    transport: &dyn CalendarRemoteTransport,
    row: &CalendarWriteOutboxRow,
    uid: &str,
    now: u64,
) -> Result<CalendarConnectorError, CalendarConnectorError> {
    let mut object = read_remote_object(vault, &row.system, &row.calendar_ref, uid)?;
    let still_stale =
        object.as_ref().and_then(|current| current.etag.as_ref()) == row.expected_etag.as_ref();
    if object.is_none() || still_stale {
        reconcile_remote_object(vault, seat, transport, uid, now);
        object = read_remote_object(vault, &row.system, &row.calendar_ref, uid)?;
    }
    Ok(CalendarConnectorError::EtagMismatch {
        href: row
            .href
            .clone()
            .or_else(|| object.as_ref().and_then(|current| current.href.clone()))
            .unwrap_or_else(|| uid.to_owned()),
        expected: row.expected_etag.clone(),
        actual: object.and_then(|current| current.etag),
    })
}

#[allow(clippy::too_many_arguments)]
fn finish_remote_applied_write(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    transport: &dyn CalendarRemoteTransport,
    event_ref: EntityId,
    own: Option<&CalendarPassportValue>,
    row: &mut CalendarWriteOutboxRow,
    receipt: RemoteWriteReceipt,
    now: u64,
) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
    // UID and SEQUENCE are provider-preserved invariants. The receipt hash
    // describes the stored representation and is committed below as ground truth.
    if receipt.uid != row.uid || receipt.sequence != row.sequence {
        return Err(CalendarConnectorError::Outbox {
            outbox_id: row.outbox_id,
            detail: "provider receipt does not match the staged intent".to_owned(),
        });
    }

    write_remote_object(
        vault,
        &CalendarRemoteObjectRow {
            system: row.system.clone(),
            calendar_ref: row.calendar_ref.clone(),
            uid: row.uid.clone(),
            href: Some(receipt.href.clone()),
            etag: receipt.etag.clone(),
            last_sequence: receipt.sequence,
            content_hash: receipt.content_hash,
            last_seen_at: now,
        },
    )?;

    // Direction is a routing fact: a seat that also reads this UID is two-way,
    // a seat that only writes it is outbound. Neither is an approval gate.
    let direction = if own.is_some_and(|value| value.direction.is_inbound_bearing()) {
        CalendarPassportDirection::TwoWay
    } else {
        CalendarPassportDirection::Outbound
    };
    let next = CalendarPassportValue {
        system: row.system.clone(),
        uid: row.uid.clone(),
        last_sequence: receipt.sequence,
        content_hash: receipt.content_hash,
        direction,
        last_seen_at: now,
        presence: CalendarPassportPresence::Live,
    };
    let current = live_passport_for(vault, &event_ref, &row.system, &row.uid)?;
    let already_applied = current.as_ref().is_some_and(|(_, value)| {
        value.last_sequence == next.last_sequence
            && value.content_hash == next.content_hash
            && value.direction == next.direction
            && value.presence == next.presence
    });
    if !already_applied {
        let source_record_id = write_source_record_id(transport.provider_key(), seat, &row.uid);
        let new_id = admit_screened(
            vault,
            event_ref,
            &CalendarInboundBody::default(),
            &source_record_id,
            PREDICATE_CALENDAR_PASSPORT,
            encode_passport_value(&next),
            now,
        )?;
        if current.is_some() {
            supersede_calendar_passport(vault, event_ref, &row.system, &row.uid, &new_id, now)?;
        }
    }
    index_passport_uid(vault, &row.uid, &event_ref)?;

    // The outbox closes before the next poll can run, so the echo the poll sees
    // is already known to be ours.
    row.state = CalendarWriteOutboxState::Committed;
    row.updated_at = now;
    write_outbox_row(vault, row)?;

    Ok(receipt)
}

/// The stored form of a write-outbox row. `EntityId` and `[u8; 32]` travel as
/// byte arrays so the row round-trips without a hex convention of its own.
#[derive(Serialize, Deserialize)]
pub(super) struct StoredOutboxRow {
    outbox_id: [u8; 32],
    state: CalendarWriteOutboxState,
    action: CalendarWriteAction,
    event_ref: [u8; 16],
    provider: String,
    system: String,
    calendar_ref: String,
    uid: String,
    sequence: u32,
    content_hash: [u8; 32],
    #[serde(default)]
    expected_etag: Option<String>,
    #[serde(default)]
    href: Option<String>,
    #[serde(default)]
    receipt: Option<RemoteWriteReceipt>,
    staged_at: u64,
    updated_at: u64,
}

impl StoredOutboxRow {
    fn from_row(row: &CalendarWriteOutboxRow) -> Self {
        Self {
            outbox_id: row.outbox_id,
            state: row.state,
            action: row.action,
            event_ref: *row.event_ref.as_bytes(),
            provider: row.provider.clone(),
            system: row.system.clone(),
            calendar_ref: row.calendar_ref.clone(),
            uid: row.uid.clone(),
            sequence: row.sequence,
            content_hash: row.content_hash,
            expected_etag: row.expected_etag.clone(),
            href: row.href.clone(),
            receipt: row.receipt.clone(),
            staged_at: row.staged_at,
            updated_at: row.updated_at,
        }
    }

    pub(super) fn into_row(self) -> Result<CalendarWriteOutboxRow, CalendarConnectorError> {
        Ok(CalendarWriteOutboxRow {
            outbox_id: self.outbox_id,
            state: self.state,
            action: self.action,
            event_ref: EntityId::from_bytes(self.event_ref)
                .map_err(|_| ingest_error("outbox row carries no entity id"))?,
            provider: self.provider,
            system: self.system,
            calendar_ref: self.calendar_ref,
            uid: self.uid,
            sequence: self.sequence,
            content_hash: self.content_hash,
            expected_etag: self.expected_etag,
            href: self.href,
            receipt: self.receipt,
            staged_at: self.staged_at,
            updated_at: self.updated_at,
        })
    }
}

/// The stored form of a remote-object cursor row.
#[derive(Serialize, Deserialize)]
struct StoredRemoteObjectRow {
    system: String,
    calendar_ref: String,
    uid: String,
    #[serde(default)]
    href: Option<String>,
    #[serde(default)]
    etag: Option<String>,
    last_sequence: u32,
    content_hash: [u8; 32],
    last_seen_at: u64,
}

fn outbox_row_key(outbox_id: &[u8; 32]) -> Vec<u8> {
    let mut key = CALENDAR_WRITE_OUTBOX_PREFIX.to_vec();
    key.extend_from_slice(OUTBOX_ROW_TAG);
    key.extend_from_slice(outbox_id);
    key
}

fn remote_object_key(system: &str, calendar_ref: &str, uid: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for part in [system, calendar_ref, uid] {
        hasher.update(part.len().to_le_bytes());
        hasher.update(part.as_bytes());
    }
    let mut key = CALENDAR_WRITE_OUTBOX_PREFIX.to_vec();
    key.extend_from_slice(REMOTE_OBJECT_TAG);
    key.extend_from_slice(&hasher.finalize());
    key
}

pub(super) fn read_outbox_row(
    vault: &Vault,
    outbox_id: &[u8; 32],
) -> Result<Option<CalendarWriteOutboxRow>, CalendarConnectorError> {
    let key = outbox_row_key(outbox_id);
    let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &key)? else {
        return Ok(None);
    };
    let stored: StoredOutboxRow = serde_json::from_slice(raw.as_ref())
        .map_err(|_| ingest_error("connector outbox row did not decode"))?;
    Ok(Some(stored.into_row()?))
}

fn write_outbox_row(
    vault: &Vault,
    row: &CalendarWriteOutboxRow,
) -> Result<(), CalendarConnectorError> {
    let encoded = serde_json::to_vec(&StoredOutboxRow::from_row(row)).map_err(|_| {
        CalendarConnectorError::Outbox {
            outbox_id: row.outbox_id,
            detail: "outbox row did not encode".to_owned(),
        }
    })?;
    let key = outbox_row_key(&row.outbox_id);
    vault.try_with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok::<_, crate::Error>(())
    })?;
    Ok(())
}

pub(super) fn read_remote_object(
    vault: &Vault,
    system: &str,
    calendar_ref: &str,
    uid: &str,
) -> Result<Option<CalendarRemoteObjectRow>, CalendarConnectorError> {
    let key = remote_object_key(system, calendar_ref, uid);
    let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &key)? else {
        return Ok(None);
    };
    let stored: StoredRemoteObjectRow = serde_json::from_slice(raw.as_ref())
        .map_err(|_| ingest_error("connector remote-object row did not decode"))?;
    Ok(Some(CalendarRemoteObjectRow {
        system: stored.system,
        calendar_ref: stored.calendar_ref,
        uid: stored.uid,
        href: stored.href,
        etag: stored.etag,
        last_sequence: stored.last_sequence,
        content_hash: stored.content_hash,
        last_seen_at: stored.last_seen_at,
    }))
}

pub(super) fn write_remote_object(
    vault: &Vault,
    row: &CalendarRemoteObjectRow,
) -> Result<(), CalendarConnectorError> {
    let encoded = serde_json::to_vec(&StoredRemoteObjectRow {
        system: row.system.clone(),
        calendar_ref: row.calendar_ref.clone(),
        uid: row.uid.clone(),
        href: row.href.clone(),
        etag: row.etag.clone(),
        last_sequence: row.last_sequence,
        content_hash: row.content_hash,
        last_seen_at: row.last_seen_at,
    })
    .map_err(|_| ingest_error("connector remote-object row did not encode"))?;
    let key = remote_object_key(&row.system, &row.calendar_ref, &row.uid);
    vault.try_with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok::<_, crate::Error>(())
    })?;
    Ok(())
}

/// Provenance ref for a locally originated write's passport head.
fn write_source_record_id(provider: &str, seat: &CalendarConnectorSeatState, uid: &str) -> String {
    format!(
        "calendar-connector-write:{provider}:{}:{}:{uid}",
        seat.config.system, seat.config.calendar_ref
    )
}

/// The deterministic outbox row id: the same intent resumes the same row.
pub(super) fn derive_outbox_id(
    system: &str,
    calendar_ref: &str,
    uid: &str,
    action: CalendarWriteAction,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(OUTBOX_ID_DOMAIN);
    for part in [system, calendar_ref, uid, action.as_str()] {
        hasher.update(part.len().to_le_bytes());
        hasher.update(part.as_bytes());
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

pub(super) fn ingest_reason(reason: &'static str) -> CalendarError {
    CalendarError::IcsIngest {
        reason: reason.to_owned(),
    }
}

pub(super) fn ingest_error(reason: &'static str) -> CalendarConnectorError {
    CalendarConnectorError::Calendar(ingest_reason(reason))
}
