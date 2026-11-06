//! Conditional writes plus durable outbox and remote-object cursor store.

mod archived;

pub(crate) use self::archived::{plan_archived_calendar_rows, read_back_archived_calendar_rows};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::door::CalendarConnectorOperation;
use super::inbound::{admit_screened_in_txn, reconcile_remote_object};
use super::literal::{self, LiteralCarrier, LiteralKind, LiteralValues};
use super::remote::{
    CalendarRemoteTransport, RemoteWriteReceipt, RemoteWriteRequest, ics_content_hash, local_uid,
    render_owner_vevent, shared_uid,
};
use super::seat::{CalendarConnectorError, CalendarConnectorSeatState};

use crate::batch::secret_scan::{admitted_from, named_tree};
use crate::calendar::CalendarError;
use crate::calendar::claims::{
    CalendarPassportDirection, CalendarPassportPresence, CalendarPassportValue,
    PREDICATE_CALENDAR_PASSPORT,
};
use crate::calendar::passport::{
    admitted_passports_for_event_in_txn, carries_admitted_uid_in_txn, encode_passport_value,
    index_passport_uid_in_txn, live_passport_for_in_txn,
};
use crate::calendar::safeguard::CalendarInboundBody;
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::side_table::{self, LegacyJson, SideKey, SideTable};
use crate::vault::Vault;

/// Sub-tag for durable write-outbox rows.
pub(super) const OUTBOX_ROW_TAG: &[u8] = b"row:";

/// Sub-tag for the node-local `(system, calendar_ref, uid)` href/ETag cursor.
const REMOTE_OBJECT_TAG: &[u8] = b"obj:";

/// Durable local write-outbox rows: `CALENDAR_CONNECTOR_WRITE`'s [`OUTBOX_ROW_TAG`]
/// shape. Key: `row:` ‖ the 32-byte outbox id.
pub(super) const OUTBOX: SideTable<OutboxKey, StoredOutboxRow, LegacyJson> =
    SideTable::new(&side_table::CALENDAR_CONNECTOR_WRITE);

/// Node-local remote-object cursors: `CALENDAR_CONNECTOR_WRITE`'s
/// [`REMOTE_OBJECT_TAG`] shape, the same declaration as `OUTBOX` under its
/// own tag and row type. Key: `obj:` ‖ `sha256(system, calendar_ref, uid)`.
const REMOTE_OBJECT: SideTable<RemoteObjectKey, StoredRemoteObjectRow, LegacyJson> =
    SideTable::new(&side_table::CALENDAR_CONNECTOR_WRITE);

/// The declaration carries both current typed rows, under distinct key tags.
pub(crate) fn calendar_connector_write_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<StoredOutboxRow, LegacyJson>(bytes)
        || crate::side_table::decodes::<StoredRemoteObjectRow, LegacyJson>(bytes)
}

pub(super) struct OutboxKey(pub(super) [u8; 32]);

impl SideKey for OutboxKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(OUTBOX_ROW_TAG);
        out.extend_from_slice(&self.0);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        Some(Self(bytes.strip_prefix(OUTBOX_ROW_TAG)?.try_into().ok()?))
    }
}

struct RemoteObjectKey([u8; 32]);

impl SideKey for RemoteObjectKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(REMOTE_OBJECT_TAG);
        out.extend_from_slice(&self.0);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        Some(Self(
            bytes.strip_prefix(REMOTE_OBJECT_TAG)?.try_into().ok()?,
        ))
    }
}

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
/// Staged under `OUTBOX` BEFORE the provider call, so a crash between the
/// remote mutation and the local commit resumes from the row instead of
/// repeating a blind write. Carries refs and hashes only — never a
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
    /// Per-EVENT hashes captured from the staged resource, before transport I/O.
    /// Receipt settlement uses these members even if local content changes.
    pub component_hashes: Vec<(EntityId, [u8; 32])>,
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
    pub(super) carrier: Option<LiteralCarrier>,
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
    /// The archived copy (`hex#vN`) of the ICS this seat last pulled.
    pub source_blob_ref: Option<String>,
    pub(super) carrier: Option<LiteralCarrier>,
}

/// Writes one local EVENT to the seat's remote calendar.
///
/// The UID is preserved (or minted once for a locally originated EVENT) and
/// the SEQUENCE bumps only when this seat already holds that UID. Both derive
/// from admitted passports and the seat's own remote copy, never from a
/// pending, rejected or stale passport proposal. The resource renders over its
/// archived source so fields the render does not own survive, the durable
/// outbox row is staged BEFORE the provider call, and the expected ETag rides
/// as the conditional precondition. A precondition failure records
/// `reconcile_required`, refreshes the local view of the remote object, and
/// returns [`CalendarConnectorError::EtagMismatch`] — it never overwrites blind.
///
/// # Errors
///
/// [`CalendarConnectorError::KillSwitchEngaged`] on a killed seat, plus the
/// seat, store, parse, and transport variants.
pub fn write_calendar_event(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    transport: &dyn CalendarRemoteTransport,
    event_ref: EntityId,
    now: u64,
) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
    let seat = &operation.registration().seat;
    seat.validate()?;
    if seat.kill_switch_engaged() {
        return Err(CalendarConnectorError::KillSwitchEngaged);
    }
    operation.revalidate(vault)?;
    if vault.get_entity_type(&event_ref)? != Some(ENTITY_TYPE_EVENT) {
        return Err(ingest_error("write target is not an EVENT"));
    }

    // A detached edit targets its full UID resource, never a standalone PUT
    // that would replace the master and erase its siblings.
    let event_ref = super::resource::master_for(vault, event_ref)?;
    let system = seat.config.system.as_str();
    let passports = {
        let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        admitted_passports_for_event_in_txn(vault, &rtxn, &event_ref)?
    };
    let own = passports
        .iter()
        .find(|(_, value)| value.system == system)
        .map(|(_, value)| value.clone());
    let uid = match &own {
        Some(value) => value.uid.clone(),
        None => shared_uid(&passports).unwrap_or_else(|| local_uid(&event_ref)),
    };
    let calendar_ref = seat.config.calendar_ref.as_str();
    let source = super::resource::archived_source(vault, system, calendar_ref, &uid, event_ref)?;
    let outbox_id = derive_outbox_id(
        &operation.literal_scope()?,
        system,
        &seat.config.calendar_ref,
        &uid,
        CalendarWriteAction::Upsert,
    );

    let mut prior_instance = None;
    if let Some(mut row) = read_outbox_row(vault, &outbox_id)? {
        ensure_outbox_matches(&row, seat, transport, event_ref, &uid)?;
        open_outbox(vault, operation, transport, &uid, &mut row)?;
        prior_instance = row.carrier.as_ref().map(|carrier| carrier.instance);
        match row.state {
            CalendarWriteOutboxState::Prepared => {
                let ics = render_owner_vevent(
                    vault,
                    &event_ref,
                    &uid,
                    row.sequence,
                    now,
                    source.as_deref(),
                )?
                .ics;
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
                let receipt = issue_prepared_upsert(
                    vault, operation, transport, &uid, now, &mut row, &request,
                )?;
                return finish_remote_applied_write(
                    vault, operation, transport, event_ref, &mut row, receipt, now,
                );
            }
            CalendarWriteOutboxState::ReconcileRequired => {
                return Err(reconcile_required_error(
                    vault, operation, transport, &row, &uid, now,
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
                    vault, operation, transport, event_ref, &mut row, receipt, now,
                );
            }
            CalendarWriteOutboxState::Committed => {
                // A closed row is not an in-flight retry. Derive and stage the
                // next owner mutation below, replacing this stable-key row.
            }
        }
    }

    // The seat's own remote copy is provider truth, not a proposal: the next
    // write must exceed the SEQUENCE it already holds.
    let object = read_remote_object_for_operation(vault, operation, &uid)?;
    let floor = super::resource::sequence_floor(vault, event_ref, &uid)?
        .max(object.as_ref().map_or(0, |row| row.last_sequence));
    let sequence = if own.is_some() || object.is_some() {
        floor
            .checked_add(1)
            .ok_or_else(|| ingest_error("calendar sequence overflow"))?
    } else {
        floor
    };
    let rendered = render_owner_vevent(vault, &event_ref, &uid, sequence, now, source.as_deref())?;
    let ics = rendered.ics;
    let content_hash = ics_content_hash(&ics, &uid)?;
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
        component_hashes: rendered.component_hashes,
        expected_etag: expected_etag.clone(),
        href: href.clone(),
        receipt: None,
        staged_at: now,
        updated_at: now,
        carrier: None,
    };
    write_outbox_row(vault, operation, &mut row, prior_instance)?;

    let request = RemoteWriteRequest {
        href,
        expected_etag,
        uid: uid.clone(),
        sequence,
        ics,
    };
    let receipt =
        issue_prepared_upsert(vault, operation, transport, &uid, now, &mut row, &request)?;
    finish_remote_applied_write(
        vault, operation, transport, event_ref, &mut row, receipt, now,
    )
}

fn ensure_outbox_matches(
    row: &CalendarWriteOutboxRow,
    seat: &CalendarConnectorSeatState,
    transport: &dyn CalendarRemoteTransport,
    event_ref: EntityId,
    uid: &str,
) -> Result<(), CalendarConnectorError> {
    // The side-row wall may have masked a secret-shaped span in a string
    // field when the row was stored (FIX 10951): compare each string as the
    // replay compare reads it, so the same secret offered again matches
    // instead of refusing the resumed write.
    let same = |held: &str, offered: &str| -> Result<bool, CalendarConnectorError> {
        Ok(held == offered || admitted_from(&named_tree(&held)?, &named_tree(&offered)?)?)
    };
    if row.action != CalendarWriteAction::Upsert
        || row.event_ref != event_ref
        || !same(&row.provider, transport.provider_key())?
        || !same(&row.system, &seat.config.system)?
        || !same(&row.calendar_ref, &seat.config.calendar_ref)?
        || !same(&row.uid, uid)?
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
    operation: &CalendarConnectorOperation,
    transport: &dyn CalendarRemoteTransport,
    uid: &str,
    now: u64,
    row: &mut CalendarWriteOutboxRow,
    request: &RemoteWriteRequest,
) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
    let seat = &operation.registration().seat;
    operation.revalidate(vault)?;
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
                write_outbox_row(vault, operation, row, None)?;
                // Reconciliation reads the current remote state so a caller can
                // intentionally rebase. Blind retries remain blocked on this row.
                reconcile_remote_object(vault, operation, transport, uid, now);
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
    write_outbox_row(vault, operation, row, None)?;
    Ok(receipt)
}

fn reconcile_required_error(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    transport: &dyn CalendarRemoteTransport,
    row: &CalendarWriteOutboxRow,
    uid: &str,
    now: u64,
) -> Result<CalendarConnectorError, CalendarConnectorError> {
    let mut object = read_remote_object_for_operation(vault, operation, uid)?;
    let still_stale =
        object.as_ref().and_then(|current| current.etag.as_ref()) == row.expected_etag.as_ref();
    if object.is_none() || still_stale {
        reconcile_remote_object(vault, operation, transport, uid, now);
        object = read_remote_object_for_operation(vault, operation, uid)?;
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

fn finish_remote_applied_write(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    transport: &dyn CalendarRemoteTransport,
    event_ref: EntityId,
    row: &mut CalendarWriteOutboxRow,
    receipt: RemoteWriteReceipt,
    now: u64,
) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
    // UID and SEQUENCE are provider-preserved invariants. The receipt's content
    // hash is the provider's claim about what it stored, not evidence of it:
    // the echo state below records what was staged, so a provider copy that
    // differs reads as a remote change the next pull imports, never as an
    // echo of this write. A divergent receipt still settles the write.
    if receipt.uid != row.uid || receipt.sequence != row.sequence {
        return Err(CalendarConnectorError::Outbox {
            outbox_id: row.outbox_id,
            detail: "provider receipt does not match the staged intent".to_owned(),
        });
    }

    enum CompletionError {
        Stale,
        Failed(CalendarConnectorError),
    }

    impl From<crate::Error> for CompletionError {
        fn from(error: crate::Error) -> Self {
            Self::Failed(error.into())
        }
    }

    // FIX 4797: the completion can turn an inbound passport two-way and
    // supersede its head, so it runs in the vault's one calendar admission
    // turn, taken before its writer.
    let _turn = crate::calendar::ingest::admission_turn(vault)?;
    let carrier = match vault.try_with_write_txn_grouped(|txn| {
        finish_remote_applied_write_in_txn(
            vault, txn, operation, transport, event_ref, row, &receipt, now,
        )
        .map_err(CompletionError::Failed)?
        // A stale final CAS discards this member's earlier staged rows too.
        .ok_or(CompletionError::Stale)
    }) {
        Ok(carrier) => carrier,
        Err(CompletionError::Stale) => return Ok(receipt),
        Err(CompletionError::Failed(error)) => return Err(error),
    };
    row.state = CalendarWriteOutboxState::Committed;
    row.updated_at = now;
    row.carrier = Some(carrier);
    vault.finish_connector_resume_retirements_after_commit();
    Ok(receipt)
}

fn finish_remote_applied_write_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    operation: &CalendarConnectorOperation,
    transport: &dyn CalendarRemoteTransport,
    event_ref: EntityId,
    row: &CalendarWriteOutboxRow,
    receipt: &RemoteWriteReceipt,
    now: u64,
) -> Result<Option<LiteralCarrier>, CalendarConnectorError> {
    // The exact RemoteApplied carrier guards every publication below. Cursor,
    // claims, index and final outbox CAS share this writer or all roll back.
    let source_blob_ref =
        read_remote_object_in_txn(vault, txn, &row.system, &row.calendar_ref, &row.uid)?
            .and_then(|prior| prior.source_blob_ref);
    if !write_remote_object_in_txn(
        vault,
        txn,
        operation,
        &CalendarRemoteObjectRow {
            system: row.system.clone(),
            calendar_ref: row.calendar_ref.clone(),
            uid: row.uid.clone(),
            href: Some(receipt.href.clone()),
            etag: receipt.etag.clone(),
            last_sequence: receipt.sequence,
            content_hash: row.content_hash,
            last_seen_at: now,
            source_blob_ref,
            carrier: None,
        },
        Some(row),
    )? {
        return Ok(None);
    }

    // A receipt settles the staged members, not newer local EVENT contents.
    if row.component_hashes.first().map(|(member, _)| *member) != Some(event_ref) {
        return Err(CalendarConnectorError::Outbox {
            outbox_id: row.outbox_id,
            detail: "staged resource does not name its master".to_owned(),
        });
    }
    for (member, _) in &row.component_hashes {
        crate::calendar::claims::require_event_subject_in_txn(vault, txn, member)?;
    }
    let source_record_id = write_source_record_id(
        transport.provider_key(),
        &operation.registration().seat,
        &row.uid,
    );
    for &(member, content_hash) in &row.component_hashes {
        // Direction remains approval-blind, while the UID-index gate below
        // still requires an admitted passport for a non-local UID.
        let current = live_passport_for_in_txn(vault, txn, &member, &row.system, &row.uid)?;
        let direction = if current
            .as_ref()
            .is_some_and(|(_, value)| value.direction.is_inbound_bearing())
        {
            CalendarPassportDirection::TwoWay
        } else {
            CalendarPassportDirection::Outbound
        };
        let next = CalendarPassportValue {
            system: row.system.clone(),
            uid: row.uid.clone(),
            last_sequence: receipt.sequence,
            content_hash,
            direction,
            last_seen_at: now,
            presence: CalendarPassportPresence::Live,
        };
        let already_applied = current.as_ref().is_some_and(|(_, value)| {
            value.last_sequence == next.last_sequence
                && value.content_hash == next.content_hash
                && value.direction == next.direction
                && value.presence == next.presence
        });
        if !already_applied {
            let new_id = admit_screened_in_txn(
                vault,
                txn,
                member,
                &CalendarInboundBody::default(),
                &source_record_id,
                PREDICATE_CALENDAR_PASSPORT,
                encode_passport_value(&next),
                now,
            )?;
            if let Some((old_id, _)) = current {
                vault.supersede_claim_in_txn(txn, &new_id, &old_id, now)?;
            }
        }
    }
    if row.uid == local_uid(&event_ref)
        || carries_admitted_uid_in_txn(vault, txn, &event_ref, &row.uid)?
    {
        index_passport_uid_in_txn(vault, txn, &row.uid, &event_ref)?;
    }

    let mut committed = row.clone();
    committed.state = CalendarWriteOutboxState::Committed;
    committed.updated_at = now;
    Ok(write_outbox_row_in_txn(
        vault, txn, operation, &committed, None,
    )?)
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
    component_hashes: Vec<([u8; 16], [u8; 32])>,
    expected_etag: Option<String>,
    href: Option<String>,
    receipt: Option<RemoteWriteReceipt>,
    staged_at: u64,
    updated_at: u64,
    carrier: LiteralCarrier,
}

impl StoredOutboxRow {
    fn from_row(row: &CalendarWriteOutboxRow, carrier: LiteralCarrier) -> crate::Result<Self> {
        Ok(Self {
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
            component_hashes: row
                .component_hashes
                .iter()
                .map(|(member, hash)| (*member.as_bytes(), *hash))
                .collect(),
            expected_etag: literal::projection(&row.expected_etag)?,
            href: literal::projection(&row.href)?,
            receipt: literal::projection(&row.receipt)?,
            staged_at: row.staged_at,
            updated_at: row.updated_at,
            carrier,
        })
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
            component_hashes: self
                .component_hashes
                .into_iter()
                .map(|(member, hash)| {
                    Ok((
                        EntityId::from_bytes(member)
                            .map_err(|_| ingest_error("outbox component carries no entity id"))?,
                        hash,
                    ))
                })
                .collect::<Result<_, CalendarConnectorError>>()?,
            expected_etag: self.expected_etag,
            href: self.href,
            receipt: self.receipt,
            staged_at: self.staged_at,
            updated_at: self.updated_at,
            carrier: Some(self.carrier),
        })
    }
}

/// The stored form of a remote-object cursor row.
#[derive(Serialize, Deserialize)]
struct StoredRemoteObjectRow {
    system: String,
    calendar_ref: String,
    uid: String,
    href: Option<String>,
    etag: Option<String>,
    last_sequence: u32,
    content_hash: [u8; 32],
    last_seen_at: u64,
    source_blob_ref: Option<String>,
    carrier: LiteralCarrier,
}

fn remote_object_digest(scope: &[u8; 32], system: &str, calendar_ref: &str, uid: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(scope);
    for part in [system, calendar_ref, uid] {
        hasher.update(part.len().to_le_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.finalize().into()
}

pub(super) fn read_outbox_row(
    vault: &Vault,
    outbox_id: &[u8; 32],
) -> Result<Option<CalendarWriteOutboxRow>, CalendarConnectorError> {
    let rtxn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let Some(stored) = OUTBOX.get(&vault.store, &rtxn, &OutboxKey(*outbox_id))? else {
        return Ok(None);
    };
    Ok(Some(stored.into_row()?))
}

fn outbox_digest(row: &CalendarWriteOutboxRow) -> crate::Result<[u8; 32]> {
    literal::digest(&(
        row.action,
        row.event_ref,
        row.sequence,
        row.content_hash,
        &row.component_hashes,
        row.staged_at,
    ))
}

fn open_outbox(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    transport: &dyn CalendarRemoteTransport,
    uid: &str,
    row: &mut CalendarWriteOutboxRow,
) -> Result<(), CalendarConnectorError> {
    let carrier = row.carrier.as_ref().ok_or_else(literal::invalid)?;
    let (held_uid, values) = carrier.open(
        vault,
        operation,
        LiteralKind::Outbox,
        row.outbox_id,
        outbox_digest(row)?,
    )?;
    let seat = &operation.registration().seat;
    if held_uid != uid
        || row.outbox_id
            != derive_outbox_id(
                &operation.literal_scope()?,
                &seat.config.system,
                &seat.config.calendar_ref,
                uid,
                row.action,
            )
    {
        return Err(literal::invalid().into());
    }
    row.provider = transport.provider_key().into();
    row.system = seat.config.system.clone();
    row.calendar_ref = seat.config.calendar_ref.clone();
    row.uid = held_uid;
    row.href = values.href;
    row.expected_etag = values.etag;
    row.receipt = values.receipt;
    Ok(())
}

fn write_outbox_row(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    row: &mut CalendarWriteOutboxRow,
    expected_prior: Option<[u8; 16]>,
) -> Result<bool, CalendarConnectorError> {
    let carrier = vault.try_with_write_txn_grouped(|txn| {
        write_outbox_row_in_txn(vault, txn, operation, row, expected_prior)
    })?;
    let Some(carrier) = carrier else {
        return Ok(false);
    };
    row.carrier = Some(carrier);
    vault.finish_connector_resume_retirements_after_commit();
    Ok(true)
}

fn write_outbox_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    operation: &CalendarConnectorOperation,
    row: &CalendarWriteOutboxRow,
    expected_prior: Option<[u8; 16]>,
) -> crate::Result<Option<LiteralCarrier>> {
    let digest = outbox_digest(row)?;
    if row.carrier.is_none() {
        operation.revalidate_in_txn(vault, txn)?;
    }
    let prior = OUTBOX.get(&vault.store, txn, &OutboxKey(row.outbox_id))?;
    let actual_prior = prior.as_ref().map(|old| old.carrier.instance);
    let expected = row
        .carrier
        .as_ref()
        .map(|held| held.instance)
        .or(expected_prior);
    if let Some(held) = row.carrier.as_ref() {
        if prior.as_ref().is_none_or(|old| old.carrier != *held) {
            // The admitted effect is already truthful; never resurrect its
            // retired reference over a deleted or newer stable-key row.
            return Ok(None);
        }
    } else if actual_prior != expected {
        return Err(literal::invalid());
    }
    let instance = match row.carrier.as_ref() {
        Some(held) => held.instance,
        None => vault.store.clock.ulid()?,
    };
    let carrier = LiteralCarrier::seal(
        vault,
        txn,
        operation,
        LiteralKind::Outbox,
        instance,
        row.outbox_id,
        digest,
        &row.uid,
        LiteralValues {
            href: row.href.clone(),
            etag: row.expected_etag.clone(),
            receipt: row.receipt.clone(),
        },
    )?;
    let stored = StoredOutboxRow::from_row(row, carrier.clone())?;
    crate::ports::persist_id_floor_in_txn(&vault.store, txn)?;
    OUTBOX.put(vault, txn, &OutboxKey(row.outbox_id), &stored)?;
    if let Some(prior) = prior
        && prior.carrier.instance != instance
    {
        prior.carrier.retire(vault, txn, LiteralKind::Outbox)?;
    }
    Ok(Some(carrier))
}

fn remote_projection(stored: StoredRemoteObjectRow) -> CalendarRemoteObjectRow {
    CalendarRemoteObjectRow {
        system: stored.system,
        calendar_ref: stored.calendar_ref,
        uid: stored.uid,
        href: stored.href,
        etag: stored.etag,
        last_sequence: stored.last_sequence,
        content_hash: stored.content_hash,
        last_seen_at: stored.last_seen_at,
        source_blob_ref: stored.source_blob_ref,
        carrier: Some(stored.carrier),
    }
}

pub(super) fn read_remote_object(
    vault: &Vault,
    system: &str,
    calendar_ref: &str,
    uid: &str,
) -> Result<Option<CalendarRemoteObjectRow>, CalendarConnectorError> {
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    read_remote_object_in_txn(vault, &txn, system, calendar_ref, uid)
}

fn read_remote_object_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    system: &str,
    calendar_ref: &str,
    uid: &str,
) -> Result<Option<CalendarRemoteObjectRow>, CalendarConnectorError> {
    let latest = REMOTE_OBJECT
        .scan_from(&vault.store, txn, REMOTE_OBJECT_TAG)?
        .into_iter()
        .filter(|(key, row)| {
            key.0 == remote_object_digest(&row.carrier.seat, system, calendar_ref, uid)
        })
        .map(|(_, row)| row)
        // Instances are minted by StoreClock inside each serialized cursor writer.
        // They retain the former shared row's last-write order even when timestamps tie or regress.
        .max_by_key(|row| row.carrier.instance);
    Ok(latest.map(remote_projection))
}

fn cursor_digest(row: &CalendarRemoteObjectRow) -> crate::Result<[u8; 32]> {
    literal::digest(&(
        row.last_sequence,
        row.content_hash,
        row.last_seen_at,
        &row.source_blob_ref,
    ))
}

fn open_cursor(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    key: [u8; 32],
    row: &mut CalendarRemoteObjectRow,
) -> Result<(), CalendarConnectorError> {
    let carrier = row.carrier.as_ref().ok_or_else(literal::invalid)?;
    let (uid, values) = carrier.open(
        vault,
        operation,
        LiteralKind::Cursor,
        key,
        cursor_digest(row)?,
    )?;
    let seat = &operation.registration().seat;
    if key
        != remote_object_digest(
            &operation.literal_scope()?,
            &seat.config.system,
            &seat.config.calendar_ref,
            &uid,
        )
    {
        return Err(literal::invalid().into());
    }
    row.system = seat.config.system.clone();
    row.calendar_ref = seat.config.calendar_ref.clone();
    row.uid = uid;
    row.href = values.href;
    row.etag = values.etag;
    Ok(())
}

fn read_remote_object_for_operation(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    uid: &str,
) -> Result<Option<CalendarRemoteObjectRow>, CalendarConnectorError> {
    let seat = &operation.registration().seat;
    let key = remote_object_digest(
        &operation.literal_scope()?,
        &seat.config.system,
        &seat.config.calendar_ref,
        uid,
    );
    let stored = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        REMOTE_OBJECT.get(&vault.store, &txn, &RemoteObjectKey(key))?
    };
    let Some(stored) = stored else {
        return Ok(None);
    };
    let mut row = remote_projection(stored);
    open_cursor(vault, operation, key, &mut row)?;
    if row.uid != uid {
        return Err(literal::invalid().into());
    }
    Ok(Some(row))
}

pub(super) fn write_remote_object(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    row: &CalendarRemoteObjectRow,
    settlement: Option<&CalendarWriteOutboxRow>,
) -> Result<bool, CalendarConnectorError> {
    let written = vault.try_with_write_txn_grouped(|txn| {
        write_remote_object_in_txn(vault, txn, operation, row, settlement)
    })?;
    vault.finish_connector_resume_retirements_after_commit();
    Ok(written)
}

fn write_remote_object_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    operation: &CalendarConnectorOperation,
    row: &CalendarRemoteObjectRow,
    settlement: Option<&CalendarWriteOutboxRow>,
) -> crate::Result<bool> {
    let key = remote_object_digest(
        &operation.literal_scope()?,
        &row.system,
        &row.calendar_ref,
        &row.uid,
    );
    let row_digest = cursor_digest(row)?;
    if let Some(outbox) = settlement {
        let current = OUTBOX.get(&vault.store, txn, &OutboxKey(outbox.outbox_id))?;
        let held = outbox.carrier.as_ref().ok_or_else(literal::invalid)?;
        if current.as_ref().is_none_or(|current| {
            current.state != CalendarWriteOutboxState::RemoteApplied || current.carrier != *held
        }) {
            return Ok(false);
        }
    }
    let prior = REMOTE_OBJECT.get(&vault.store, txn, &RemoteObjectKey(key))?;
    let instance = vault.store.clock.ulid()?;
    let carrier = LiteralCarrier::seal(
        vault,
        txn,
        operation,
        LiteralKind::Cursor,
        instance,
        key,
        row_digest,
        &row.uid,
        LiteralValues {
            href: row.href.clone(),
            etag: row.etag.clone(),
            receipt: None,
        },
    )?;
    let stored = StoredRemoteObjectRow {
        system: row.system.clone(),
        calendar_ref: row.calendar_ref.clone(),
        uid: row.uid.clone(),
        href: literal::projection(&row.href)?,
        etag: literal::projection(&row.etag)?,
        last_sequence: row.last_sequence,
        content_hash: row.content_hash,
        last_seen_at: row.last_seen_at,
        source_blob_ref: row.source_blob_ref.clone(),
        carrier,
    };
    crate::ports::persist_id_floor_in_txn(&vault.store, txn)?;
    REMOTE_OBJECT.put(vault, txn, &RemoteObjectKey(key), &stored)?;
    if let Some(prior) = prior {
        prior.carrier.retire(vault, txn, LiteralKind::Cursor)?;
    }
    Ok(true)
}

/// Matches a provider removal only within this authenticated installed seat.
/// The opened values never leave this comparison; only the existing UID does.
pub fn calendar_remote_uid_for_href_for_operation(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    href: &str,
) -> Result<Option<String>, CalendarConnectorError> {
    operation.revalidate(vault)?;
    let scope = operation.literal_scope()?;
    // Drop the table reader before any custody snapshot is acquired.
    let rows = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        REMOTE_OBJECT.scan_from(&vault.store, &txn, REMOTE_OBJECT_TAG)?
    };
    for (key, stored) in rows {
        if stored.carrier.seat != scope {
            continue;
        }
        let mut row = CalendarRemoteObjectRow {
            system: stored.system,
            calendar_ref: stored.calendar_ref,
            uid: stored.uid,
            href: stored.href,
            etag: stored.etag,
            last_sequence: stored.last_sequence,
            content_hash: stored.content_hash,
            last_seen_at: stored.last_seen_at,
            source_blob_ref: stored.source_blob_ref,
            carrier: Some(stored.carrier),
        };
        open_cursor(vault, operation, key.0, &mut row)?;
        if row.href.as_deref() == Some(href) {
            return Ok(Some(row.uid));
        }
    }
    Ok(None)
}

/// Resolves a provider deletion against our retained href cursor, not a
/// provider-asserted UID. Unknown removals have no local source to retract.
pub fn calendar_remote_uid_for_href(
    vault: &Vault,
    system: &str,
    calendar_ref: &str,
    href: &str,
) -> Result<Option<String>, CalendarConnectorError> {
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    for (_, row) in REMOTE_OBJECT.scan_from(&vault.store, &txn, REMOTE_OBJECT_TAG)? {
        if row.system == system
            && row.calendar_ref == calendar_ref
            && row.href.as_deref() == Some(href)
        {
            return Ok(Some(row.uid));
        }
    }
    Ok(None)
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
    scope: &[u8; 32],
    system: &str,
    calendar_ref: &str,
    uid: &str,
    action: CalendarWriteAction,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(OUTBOX_ID_DOMAIN);
    hasher.update(scope);
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

#[cfg(test)]
mod tests;
