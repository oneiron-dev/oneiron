//! A credential's value at rest (KS-6, FIX-LIST 5687 part 1): stored
//! custody schema 2 (CALLS `KS-6 credential schema 2`), the value sealed
//! under its own erasable custody key, one per credential generation
//! (`crate::store` `credential_value_leaf_in_txn`).
//!
//! Three forms of one record, never confused:
//!
//! * opened: [`SecretCustodyRecord`] in memory, its value in the clear,
//!   wiped by its holder;
//! * stored: the entity row's body, stamped
//!   [`SECRET_CUSTODY_STORED_SCHEMA_VERSION`], every field but the value as
//!   before and the value under `sealed_value`: nonce (12) | AES-256-GCM
//!   ciphertext, bound to the credential's id, its generation and its role.
//!   Every write seals before the row is put ([`sealed_body_in_txn`]), in
//!   the writer that minted the key; an empty value (a revoked record's) is
//!   stored empty, under no key;
//! * plaintext DTO: the body codec with `value_bytes`, stamped
//!   [`SECRET_CUSTODY_SCHEMA_VERSION`] as on main, the owner archive's and a
//!   protected input's and a transition's body (CALLS `KS-6 archive form`),
//!   never a row at rest: a checkpoint image carries each row as it rests,
//!   sealed (KS-6 part 2, [`image`], CALLS `KS-6 image value form`).
//!
//! A record read from storage comes back stamped as its DTO is, so every
//! carrier built from it is byte for byte main's.
//!
//! A read that needs the value opens it ([`read_opened_in_txn`]) in the
//! caller's writer, or under the custody read guard its caller took before
//! its snapshot; a read that needs none never touches custody
//! ([`read_secret_custody_meta_in_txn`]), so a credential whose key does not
//! open is still listed, revoked, rebound and reported as before.

use std::collections::BTreeSet;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::store::{CredentialLeaf, CustodyKind, Store};
use crate::vault::Vault;

mod connector_resume;
mod image;

pub(crate) use self::image::{
    CredentialDisposition, CredentialRoute, ImageCredentialRow, PlannedCredentials,
    image_credential_row, plan_archived_credentials, withheld_credential_row,
};

pub(crate) use self::connector_resume::{
    open_connector_resume_in_txn, retire_connector_resume_in_txn, seal_connector_resume_in_txn,
};
use super::codec::{BodyValue, decode_custody_map, encode_custody_map};
use super::types::{
    CustodyClass, SECRET_CUSTODY_SCHEMA_VERSION, SECRET_CUSTODY_STORED_SCHEMA_VERSION,
    SecretCustodyRecord, SecretCustodyStatus,
};

/// The domain a sealed value's associated data opens with.
const VALUE_AAD_DOMAIN: &[u8] = b"oneiron/credential-value/v2\0";
/// The role byte of a credential's own value (a carrier's are its own).
const ROLE_VALUE: u8 = 0;
const NONCE_BYTES: usize = 12;

/// A stored value: sealed under its custody key, the only form a value
/// rests in (KS-6 part 2: the restored carrier form is gone, FIX 7456).
pub(crate) enum StoredValue {
    /// `nonce | ciphertext`, sealed at `generation`; empty for no value.
    Sealed { generation: u32, bytes: Vec<u8> },
}

impl StoredValue {
    /// Whether a value is held at all: a revoked record's is not.
    pub(crate) fn holds_value(&self) -> bool {
        let Self::Sealed { bytes, .. } = self;
        !bytes.is_empty()
    }
}

/// One stored record: its fields, value-free, and its value as stored.
pub(crate) struct StoredCustody {
    pub(crate) record: SecretCustodyRecord,
    pub(crate) value: StoredValue,
}

/// The associated data a value is sealed under: its credential, generation
/// and role (CALLS `KS-6 leaf ids`, CUSTODY_REF_BINDING).
fn value_aad(credential: &EntityId, generation: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(VALUE_AAD_DOMAIN.len() + 16 + 4 + 1);
    aad.extend_from_slice(VALUE_AAD_DOMAIN);
    aad.extend_from_slice(credential.as_bytes());
    aad.extend_from_slice(&generation.to_be_bytes());
    aad.push(ROLE_VALUE);
    aad
}

fn sealed_corrupt() -> Error {
    CustodyKind::CredentialValue.corrupt()
}

/// Seals `value` under `leaf` for `credential` at `generation`.
fn seal_value(
    leaf: &CredentialLeaf,
    credential: &EntityId,
    generation: u32,
    value: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0; NONCE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&leaf[..]).map_err(|_| sealed_corrupt())?;
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: value,
                aad: &value_aad(credential, generation),
            },
        )
        .map_err(|_| sealed_corrupt())?;
    let mut sealed = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Opens `sealed` under `leaf` for `credential` at `generation`.
fn open_value(
    leaf: &CredentialLeaf,
    credential: &EntityId,
    generation: u32,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let (nonce, ciphertext) = sealed
        .split_first_chunk::<NONCE_BYTES>()
        .ok_or_else(sealed_corrupt)?;
    let cipher = Aes256Gcm::new_from_slice(&leaf[..]).map_err(|_| sealed_corrupt())?;
    cipher
        .decrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad: &value_aad(credential, generation),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| sealed_corrupt())
}

/// Decodes a stored body: its fields and its value as stored. A value
/// rests sealed, with the stored stamp, or not at all: a body holding its
/// value in the clear is no stored body (KS-6 part 2, no old-format
/// reader). The record comes back stamped as its DTO is.
pub(crate) fn decode_stored_custody_body(body: &[u8]) -> Result<StoredCustody> {
    let (mut record, value) = decode_custody_map(body)?;
    let value = match (record.schema_version, value) {
        (SECRET_CUSTODY_STORED_SCHEMA_VERSION, BodyValue::Sealed(bytes)) => StoredValue::Sealed {
            generation: record.rotation_generation,
            bytes,
        },
        _ => {
            return Err(super::codec::invalid_body(
                "unsupported secret custody schema version",
            ));
        }
    };
    record.schema_version = SECRET_CUSTODY_SCHEMA_VERSION;
    Ok(StoredCustody { record, value })
}

/// The stored body of `stored`: its value as stored, never opened. A
/// sealed value goes only with the generation it was sealed at.
fn encode_stored_body(stored: &StoredCustody) -> Result<Vec<u8>> {
    let StoredValue::Sealed { generation, bytes } = &stored.value;
    if !bytes.is_empty() && *generation != stored.record.rotation_generation {
        return Err(super::codec::invalid_body(
            "a sealed value goes only with its own generation",
        ));
    }
    encode_custody_map(&stored.record, BodyValue::Sealed(bytes.clone()))
}

/// The stored body `rec` is written as, in `wtxn`: its value sealed under
/// its generation's key, minted here when custody holds none yet, published
/// and journaled before the row commits (CALLS `KS-6 leaf deposit`). An
/// empty value is stored empty, under no key, so a revoke never waits on
/// custody. A custody that cannot take the key (an archived vault's, or a
/// fault) answers the typed, recoverable `credential_custody_unavailable`
/// for record `id`, every write path alike (register, the owner's door,
/// mask, reclaim, import, rotate, receive): a value never rests in the
/// clear (Engine 10-21 19:5x, CALLS `KS-6 seal fault refuses`).
pub(super) fn sealed_body_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    rec: &SecretCustodyRecord,
) -> Result<Vec<u8>> {
    if rec.value_bytes.is_empty() {
        return encode_custody_map(rec, BodyValue::Sealed(Vec::new()));
    }
    match CUSTODY_SEAL_FAULT {
        CustodySealFault::TypedRetryNeverClear => {}
    }
    let sealed = store
        .credential_value_leaf_in_txn(wtxn, id, rec.rotation_generation)
        .and_then(|leaf| seal_value(&leaf, id, rec.rotation_generation, &rec.value_bytes));
    match sealed {
        Ok(sealed) => encode_custody_map(rec, BodyValue::Sealed(sealed)),
        Err(error) => Err(custody_unavailable(store, wtxn, id, &rec.name, &error)),
    }
}

/// What a write does when custody cannot take a value's key (CALLS `KS-6
/// seal fault refuses`, Engine 10-21 19:5x: keep the at-rest seal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodySealFault {
    /// The write answers `credential_custody_unavailable`, naming the
    /// credential's handle and the way out (retry: a custody store fault),
    /// logged by key and kind: never a raw custody or I/O error, no value
    /// in the clear, and no carrier kept beside a sealed one.
    TypedRetryNeverClear,
}

const CUSTODY_SEAL_FAULT: CustodySealFault = CustodySealFault::TypedRetryNeverClear;

/// The handle a typed custody answer, or a restore's note, names record
/// `id` by: its short id, or, for a record that has none yet, its name.
pub(crate) fn credential_handle(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    name: &str,
) -> String {
    crate::ports::ShortIdStoreRead::port_short_id_reference(store, txn, id)
        .ok()
        .flatten()
        .map_or_else(
            || name.to_owned(),
            |(short, hash)| format!("{short}:{hash:02x}"),
        )
}

/// `credential_custody_unavailable` for record `id`, named `name` (Engine
/// 10-21 19:5x): custody could not mint or publish its new value's key.
/// Logged by key and kind, never a byte.
fn custody_unavailable(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    name: &str,
    error: &Error,
) -> Error {
    tracing::warn!(
        credential = %id.to_hex(),
        kind = ?error.kind(),
        "credential_custody_unavailable: custody could not take a credential value's key"
    );
    Error::Secret(crate::error::SecretError::CredentialCustodyUnavailable {
        handle: credential_handle(store, txn, id, name),
    })
}

/// Opens `stored`'s value for record `id` into its record. The caller holds
/// a writer, or took the custody read guard before its snapshot.
fn open_stored(store: &Store, id: &EntityId, stored: StoredCustody) -> Result<SecretCustodyRecord> {
    let StoredCustody { mut record, value } = stored;
    let StoredValue::Sealed { generation, bytes } = value;
    record.value_bytes = if bytes.is_empty() {
        Vec::new()
    } else {
        let leaf = store.read_credential_value_leaf(id, generation)?;
        open_value(&leaf, id, generation, &bytes)?.to_vec()
    };
    Ok(record)
}

/// Record `id`'s stored form under either txn kind, never opened.
pub(crate) fn read_stored_custody_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<StoredCustody>> {
    let Some(raw) = store.port_entity_raw_wiped(txn, id)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("secret custody entity header"));
    };
    if header.entity_type != ENTITY_TYPE_SECRET_CUSTODY {
        return Err(Error::CorruptedIndex("secret custody entity type"));
    }
    decode_stored_custody_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

/// Whether record `id`'s stored value, sealed at `generation`, opens now
/// under the exact leaf `leaf` gives for it: a restore's or an activation's
/// read-back of a value it landed sealed (KS-6 part 2). The opened bytes are
/// wiped at once; any fault reads as `false`.
pub(crate) fn stored_value_opens_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    generation: u32,
    leaf: impl FnOnce(&EntityId, u32) -> Result<CredentialLeaf>,
) -> bool {
    let Ok(Some(stored)) = read_stored_custody_in_txn(store, txn, id) else {
        return false;
    };
    let StoredValue::Sealed {
        generation: sealed_at,
        bytes,
    } = &stored.value;
    *sealed_at == generation
        && !bytes.is_empty()
        && leaf(id, generation)
            .and_then(|leaf| open_value(&leaf, id, generation, bytes))
            .is_ok()
}

/// Whether entity row `raw`, record `id`'s as an image carried it, holds a
/// value sealed at `generation` that opens now under the exact leaf `leaf`
/// gives: a pending restore's check before it lands the row (FIX-LIST 10671
/// (a)). The opened bytes are wiped at once; any fault reads as `false`.
pub(crate) fn stored_row_opens(
    raw: &[u8],
    id: &EntityId,
    generation: u32,
    leaf: impl FnOnce(&EntityId, u32) -> Result<CredentialLeaf>,
) -> bool {
    let stored = EntityMetadataHeader::parse(raw)
        .filter(|header| header.entity_type == ENTITY_TYPE_SECRET_CUSTODY)
        .and_then(|_| decode_stored_custody_body(&raw[ENTITY_METADATA_HEADER_LEN..]).ok());
    let Some(StoredCustody {
        value: StoredValue::Sealed {
            generation: sealed_at,
            bytes,
        },
        ..
    }) = stored
    else {
        return false;
    };
    sealed_at == generation
        && !bytes.is_empty()
        && leaf(id, generation)
            .and_then(|leaf| open_value(&leaf, id, generation, &bytes))
            .is_ok()
}

/// Record `id` with its value opened from current custody: the read every
/// door that hands the value on takes. Strict: a key that does not open is
/// an error, never an empty value.
pub(super) fn read_opened_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<SecretCustodyRecord>> {
    let Some(stored) = read_stored_custody_in_txn(store, txn, id)? else {
        return Ok(None);
    };
    let name = stored.record.name.clone();
    open_stored(store, id, stored)
        .map(Some)
        .map_err(|error| leaf_unreadable(store, txn, id, &name, &error))
}

/// `credential_leaf_unreadable` for record `id`, named `name` (Engine
/// 10-21 19:1x): an integrity fault the caller answers typed, naming the
/// credential's handle and the way out (retry, or re-enter or reissue it).
/// Logged by key and kind, never a byte.
fn leaf_unreadable(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    name: &str,
    error: &Error,
) -> Error {
    tracing::warn!(
        credential = %id.to_hex(),
        kind = ?error.kind(),
        "credential_leaf_unreadable: a credential's custody key did not open its value"
    );
    Error::Secret(crate::error::SecretError::CredentialLeafUnreadable {
        handle: credential_handle(store, txn, id, name),
    })
}

/// Record `id` with no value: every field a door reads but the value,
/// read without custody, so a record whose key does not open still reads.
pub(crate) fn read_secret_custody_meta_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<SecretCustodyRecord>> {
    Ok(read_stored_custody_in_txn(store, txn, id)?.map(|stored| stored.record))
}

/// Whether record `id` holds a value at rest, sealed, read without
/// custody.
pub(crate) fn stored_value_held_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(
        read_stored_custody_in_txn(store, txn, id)?
            .is_some_and(|stored| stored.value.holds_value()),
    )
}

/// Re-puts `stored` as record `id` with its value as stored, never opened:
/// a change of status or bindings at the same generation, which needs no
/// key and so never waits on custody.
pub(crate) fn put_stored_custody_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    stored: &StoredCustody,
    occurred_at: u64,
) -> Result<()> {
    let data = encode_stored_body(stored)?;
    let at = crate::temporal::TimeRange {
        start: occurred_at,
        end: occurred_at,
    };
    super::doors::apply_custody_body_in_txn(
        &super::doors::CustodyWrite::of(vault),
        wtxn,
        id,
        &stored.record,
        data,
        (at, occurred_at),
    )
}

/// What the owner archive takes of one custody record's value (FIX
/// 4624(b)): the two ways it goes as its handle stay apart, so only a value
/// the archive carries that did not open here asks its holder for it.
pub(crate) enum ArchiveCustodyValue {
    /// Opened from current custody: its plaintext DTO body.
    Opened(Zeroizing<Vec<u8>>),
    /// The archive's own rule leaves it out (secrets left out, not active,
    /// a cloud slot, a device-bound value off its device).
    Excluded,
    /// The archive carries it, and it did not open on this install: warned.
    Unopened,
}

impl ArchiveCustodyValue {
    /// The opened body, when the value opened.
    pub(crate) fn into_opened(self) -> Option<Zeroizing<Vec<u8>>> {
        match self {
            Self::Opened(body) => Some(body),
            Self::Excluded | Self::Unopened => None,
        }
    }

    /// Whether the archive carries the value and it did not open here.
    pub(crate) fn is_unopened(&self) -> bool {
        matches!(self, Self::Unopened)
    }
}

/// The owner archive's plaintext DTO of stored body `body`, record `id`
/// (CALLS `KS-6 archive form`): its value opened explicitly from current
/// custody when `with_value`, else excluded. A value that does not open is
/// warned and is unopened: the record then travels as its handle, to
/// re-enter after import, as a value the export withholds does. The caller
/// reads `txn`'s rows under the custody read guard, or accepts a key an
/// erase destroys mid-read as one that does not open.
pub(crate) fn archive_custody_body(
    store: &Store,
    id: &EntityId,
    body: &[u8],
    with_value: impl FnOnce(&SecretCustodyRecord) -> bool,
) -> Result<(SecretCustodyRecord, ArchiveCustodyValue)> {
    let stored = decode_stored_custody_body(body)?;
    let record = stored.record.clone();
    if !with_value(&record) {
        return Ok((record, ArchiveCustodyValue::Excluded));
    }
    let plain = open_stored(store, id, stored).and_then(|mut opened| {
        let body = super::codec::encode_secret_custody_body(&opened).map(Zeroizing::new);
        zeroize::Zeroize::zeroize(&mut opened.value_bytes);
        body
    });
    match plain {
        Ok(body) => Ok((record, ArchiveCustodyValue::Opened(body))),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a credential's value did not open for the owner archive; it goes as its handle"
            );
            Ok((record, ArchiveCustodyValue::Unopened))
        }
    }
}

/// What an owner archive does when it cannot take the custody read guard
/// (CALLS `KS-6 archive same id`, CUSTODY_ARCHIVE_GUARD_FAULT, Engine 10-21
/// 22:2x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyArchiveGuardFault {
    /// Warned, and the archive goes on unguarded: a value whose key an erase
    /// destroys mid-read goes as its handle, as before. No export refusal.
    WarnAndKeepHandleFallback,
}

const CUSTODY_ARCHIVE_GUARD_FAULT: CustodyArchiveGuardFault =
    CustodyArchiveGuardFault::WarnAndKeepHandleFallback;

/// The custody read guard an owner archive that opens credential values
/// takes before its snapshot and holds through its last open, as a
/// checkpoint's snapshot does, so no key its rows seal under goes between
/// the row and its open (KS-6). Taken outside any writer and never inside
/// another guard's pass. `None`, warned, when it does not take.
pub(crate) fn archive_custody_guard(store: &Store) -> Option<std::sync::RwLockReadGuard<'_, ()>> {
    match CUSTODY_ARCHIVE_GUARD_FAULT {
        CustodyArchiveGuardFault::WarnAndKeepHandleFallback => {}
    }
    match store.gate_custody_read_guard() {
        Ok(guard) => Some(guard),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "the owner archive took no custody read guard; a value whose key goes mid-read \
                 goes as its handle"
            );
            None
        }
    }
}

/// What an owner archive's import of a record whose id is already here
/// finds (CALLS `KS-6 archive same id`, CUSTODY_ARCHIVE_SAME_ID, Engine
/// 10-21 22:2x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyArchiveSameId {
    /// The record here, its value opened in the import's writer, is
    /// compared with the archive's plaintext DTO as one record: the same
    /// record stays unchanged, a different one is today's collision, and a
    /// comparison that faults leaves the record here as it is, warned for a
    /// retry: never overwritten, never a collision it did not find, and no
    /// plaintext kept.
    CompareOpenedDtoElsePending,
}

const CUSTODY_ARCHIVE_SAME_ID: CustodyArchiveSameId =
    CustodyArchiveSameId::CompareOpenedDtoElsePending;

/// What an owner archive's import finds of a record whose id is already
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchiveSameId {
    /// The same record: unchanged.
    Same,
    /// Another record: a collision, refused as before.
    Different,
    /// The comparison faulted: the record here stays as it is, pending.
    Pending,
}

/// Compares entity row `existing`, record `id`, read in the import's writer
/// `txn`, with `incoming`, the archive's plaintext DTO of it (CALLS `KS-6
/// archive same id`): the stored value opened from current custody, never
/// the sealed bytes, nonce or stamp.
pub(crate) fn archive_same_custody_in_txn(
    store: &Store,
    id: &EntityId,
    existing: &[u8],
    incoming: &SecretCustodyRecord,
) -> ArchiveSameId {
    match CUSTODY_ARCHIVE_SAME_ID {
        CustodyArchiveSameId::CompareOpenedDtoElsePending => {}
    }
    if !EntityMetadataHeader::parse(existing)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_SECRET_CUSTODY)
    {
        return ArchiveSameId::Different;
    }
    let opened = decode_stored_custody_body(&existing[ENTITY_METADATA_HEADER_LEN..])
        .and_then(|stored| open_stored(store, id, stored));
    match opened {
        Ok(mut opened) => {
            let same = opened == *incoming;
            zeroize::Zeroize::zeroize(&mut opened.value_bytes);
            if same {
                ArchiveSameId::Same
            } else {
                ArchiveSameId::Different
            }
        }
        Err(error) => {
            tracing::warn!(
                credential = %id.to_hex(),
                kind = ?error.kind(),
                "an archive's custody record could not be compared with the one here; the one \
                 here stays as it is, retry the import"
            );
            ArchiveSameId::Pending
        }
    }
}

/// The credentials whose value and carrier keys a custody head may carry
/// (CALLS `KS-6 entry eligibility`, CUSTODY_ENTRY_RECOVERY): each record
/// custody-portable, not "this device only" and active. A suspended or
/// revoked one, and a device-bound, cross-vault (K30) or device-only (K29)
/// one, stays local. Read without custody; the caller keeps every
/// credential local when this faults.
pub(crate) fn credentials_eligible_for_heads(vault: &Vault) -> Result<BTreeSet<[u8; 16]>> {
    match CUSTODY_ENTRY_RECOVERY {
        CustodyEntryRecovery::LocalOnlyUnlessCurrentlyPermittedPortable => {}
    }
    let txn = vault.store.env.read_txn()?;
    let mut eligible = BTreeSet::new();
    for entry in vault
        .store
        .port_entity_ids_by_type(&txn, ENTITY_TYPE_SECRET_CUSTODY, None)?
    {
        let id = entry?;
        if let Some(record) = read_secret_custody_meta_in_txn(&vault.store, &txn, &id)?
            && head_eligible(&record)
        {
            eligible.insert(*id.as_bytes());
        }
    }
    Ok(eligible)
}

/// Whether `record`'s keys may ride a custody head (CALLS `KS-6 entry
/// eligibility`): custody-portable, not "this device only", and active.
pub(crate) fn head_eligible(record: &SecretCustodyRecord) -> bool {
    record.class == CustodyClass::CustodyPortable
        && !record.device_only
        && record.status == SecretCustodyStatus::Active
}

/// Which custody entries a head may carry (CALLS `KS-6 entry eligibility`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyEntryRecovery {
    /// An active portable credential's keys ride the head's owner-only
    /// compartment, wrapped to the recovery root alone; every other
    /// credential's (suspended, revoked, device-bound, device-only,
    /// cross-vault) stay in this machine's custody: a same-install restore
    /// takes them, a new host re-enters them or imports the owner's
    /// archive.
    LocalOnlyUnlessCurrentlyPermittedPortable,
}

const CUSTODY_ENTRY_RECOVERY: CustodyEntryRecovery =
    CustodyEntryRecovery::LocalOnlyUnlessCurrentlyPermittedPortable;
