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
//!   and the form a checkpoint image carries a row in until part 2 strips it
//!   ([`image_credential_carrier`]), which a restored row keeps only until
//!   the restore seals it again (a row it could not seal stays pending, never
//!   opened from it, [`CUSTODY_RESEAL_PENDING`]).
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

/// A stored value: sealed under its custody key, or a checkpoint image's
/// carrier, in the clear.
pub(crate) enum StoredValue {
    /// `nonce | ciphertext`, sealed at `generation`; empty for no value.
    Sealed { generation: u32, bytes: Vec<u8> },
    /// The value in the clear: a row a checkpoint image carried.
    Carrier(Zeroizing<Vec<u8>>),
}

impl StoredValue {
    /// Whether a value is held at all: a revoked record's is not.
    pub(crate) fn holds_value(&self) -> bool {
        match self {
            Self::Sealed { bytes, .. } => !bytes.is_empty(),
            Self::Carrier(value) => !value.is_empty(),
        }
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

/// Decodes a stored body: its fields and its value as stored. A sealed
/// value goes only with the stored stamp and a carrier only with the DTO's;
/// the record comes back stamped as its DTO is.
pub(crate) fn decode_stored_custody_body(body: &[u8]) -> Result<StoredCustody> {
    let (mut record, value) = decode_custody_map(body)?;
    let value = match (record.schema_version, value) {
        (SECRET_CUSTODY_STORED_SCHEMA_VERSION, BodyValue::Sealed(bytes)) => StoredValue::Sealed {
            generation: record.rotation_generation,
            bytes,
        },
        (SECRET_CUSTODY_SCHEMA_VERSION, BodyValue::Plain(value)) => {
            StoredValue::Carrier(Zeroizing::new(value))
        }
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
    let value = match &stored.value {
        StoredValue::Sealed { generation, bytes } => {
            if !bytes.is_empty() && *generation != stored.record.rotation_generation {
                return Err(super::codec::invalid_body(
                    "a sealed value goes only with its own generation",
                ));
            }
            BodyValue::Sealed(bytes.clone())
        }
        StoredValue::Carrier(value) => BodyValue::Plain(value.to_vec()),
    };
    encode_custody_map(&stored.record, value)
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
        .and_then(|leaf| seal_value(&leaf, id, rec.rotation_generation, &rec.value_bytes))
        .map_err(|error| custody_unavailable(store, wtxn, id, &rec.name, &error))?;
    encode_custody_map(rec, BodyValue::Sealed(sealed))
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

/// The handle a typed custody answer names record `id` by: its short id,
/// or, for a record that has none yet, its name.
fn credential_handle(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId, name: &str) -> String {
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
    record.value_bytes = match value {
        StoredValue::Sealed { bytes, .. } if bytes.is_empty() => Vec::new(),
        StoredValue::Sealed { generation, bytes } => {
            let leaf = store.read_credential_value_leaf(id, generation)?;
            open_value(&leaf, id, generation, &bytes)?.to_vec()
        }
        StoredValue::Carrier(value) => value.to_vec(),
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

/// Whether record `id` holds a value at rest, sealed or carried, read
/// without custody.
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

impl Vault {
    /// Seals again, under this vault's custody, each credential row a
    /// checkpoint image landed in the clear (KS-6 part 1: images carry the
    /// opened value until part 2), in one writer, each row keeping its own
    /// times: a restored value rests sealed as every other does. Returns
    /// how many it sealed.
    ///
    /// # Errors
    /// Custody's, for a key it cannot mint; storage faults.
    pub(crate) fn reseal_credential_carriers(&self) -> Result<usize> {
        self.with_write_txn(|wtxn| {
            let ids = self
                .store
                .port_entity_ids_by_type(wtxn, ENTITY_TYPE_SECRET_CUSTODY, None)?
                .collect::<Result<Vec<_>>>()?;
            let write = super::doors::CustodyWrite::of(self);
            let mut resealed = 0_usize;
            for id in ids {
                let Some(raw) = self.store.port_entity_raw_wiped(wtxn, &id)? else {
                    continue;
                };
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("secret custody entity header"))?;
                let stored = decode_stored_custody_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
                let StoredValue::Carrier(value) = stored.value else {
                    continue;
                };
                let mut record = stored.record;
                record.value_bytes = value.to_vec();
                let data = sealed_body_in_txn(&self.store, wtxn, &id, &record);
                zeroize::Zeroize::zeroize(&mut record.value_bytes);
                let occurred = crate::temporal::TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                };
                super::doors::apply_custody_body_in_txn(
                    &write,
                    wtxn,
                    &id,
                    &record,
                    data?,
                    (occurred, header.learned_at),
                )?;
                resealed = resealed.saturating_add(1);
            }
            Ok(resealed)
        })
    }
}

/// A checkpoint image's form of entity row `value` under key `key`, when it
/// is a credential whose value is sealed: the row with its value opened
/// from current custody into the plaintext DTO, the carrier a restore of
/// this image lands as on main (KS-6 part 1; part 2 strips it, CALLS `KS-6
/// image form`). The snapshot holds the custody read guard. `None` keeps
/// the row as it is: not a credential, no value, or a key that does not
/// open, warned with no byte.
pub(crate) fn image_credential_carrier(store: &Store, key: &[u8], value: &[u8]) -> Option<Vec<u8>> {
    let header = EntityMetadataHeader::parse(value)?;
    if header.entity_type != ENTITY_TYPE_SECRET_CUSTODY {
        return None;
    }
    let opened = (|| -> Result<Option<Vec<u8>>> {
        let id = EntityId::from_bytes(<[u8; 16]>::try_from(key).map_err(|_| sealed_corrupt())?)?;
        let stored = decode_stored_custody_body(&value[ENTITY_METADATA_HEADER_LEN..])?;
        if !matches!(&stored.value, StoredValue::Sealed { bytes, .. } if !bytes.is_empty()) {
            return Ok(None);
        }
        let record = stored.record.clone();
        let opened = open_stored(store, &id, stored)?;
        let stored = StoredCustody {
            record,
            value: StoredValue::Carrier(Zeroizing::new(opened.value_bytes)),
        };
        let mut row = value[..ENTITY_METADATA_HEADER_LEN].to_vec();
        row.extend_from_slice(&encode_stored_body(&stored)?);
        Ok(Some(row))
    })();
    match opened {
        Ok(row) => row,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a credential's value did not open for this image; its row rides sealed"
            );
            None
        }
    }
}

/// The owner archive's plaintext DTO of stored body `body`, record `id`
/// (CALLS `KS-6 archive form`): its value opened explicitly from current
/// custody when `with_value`, else none. A value that does not open is
/// warned and goes as none: the record then travels as its handle, to
/// re-enter after import, as a value the export withholds does. The caller
/// reads `txn`'s rows under the custody read guard, or accepts a key an
/// erase destroys mid-read as one that does not open.
pub(crate) fn archive_custody_body(
    store: &Store,
    id: &EntityId,
    body: &[u8],
    with_value: impl FnOnce(&SecretCustodyRecord) -> bool,
) -> Result<(SecretCustodyRecord, Option<Zeroizing<Vec<u8>>>)> {
    let stored = decode_stored_custody_body(body)?;
    let record = stored.record.clone();
    if !with_value(&record) {
        return Ok((record, None));
    }
    let plain = open_stored(store, id, stored).and_then(|mut opened| {
        let body = super::codec::encode_secret_custody_body(&opened).map(Zeroizing::new);
        zeroize::Zeroize::zeroize(&mut opened.value_bytes);
        body
    });
    match plain {
        Ok(body) => Ok((record, Some(body))),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a credential's value did not open for the owner archive; it goes as its handle"
            );
            Ok((record, None))
        }
    }
}

/// Plans every credential value this archived store's rows seal, through
/// its activation's one `plan` (KS-6 part 1), so the fork copies their keys
/// with the claim keys, bodies, history and pads: a key that is not there
/// is not copied, warned, and its row keeps its sealed value.
pub(crate) fn plan_archived_credentials(
    store: &Store,
    plan: &mut crate::store::CustodyPlan,
) -> Result<()> {
    let txn = store.env.read_txn()?;
    let mut values = Vec::new();
    for entry in store.port_entity_ids_by_type(&txn, ENTITY_TYPE_SECRET_CUSTODY, None)? {
        let id = entry?;
        if let Some(StoredCustody {
            value: StoredValue::Sealed { generation, bytes },
            ..
        }) = read_stored_custody_in_txn(store, &txn, &id)?
            && !bytes.is_empty()
        {
            values.push((id, generation));
        }
    }
    drop(txn);
    crate::store::plan_credential_values(plan, &values)
}

/// The credentials whose value and carrier keys a custody head may carry
/// (CALLS `KS-6 entry eligibility`, CUSTODY_ENTRY_RECOVERY): each record
/// custody-portable, not "this device only" and not revoked. A device-bound,
/// cross-vault (K30) or device-only (K29) one stays local. Read without
/// custody.
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
            && record.class == CustodyClass::CustodyPortable
            && !record.device_only
            && record.status != SecretCustodyStatus::Revoked
        {
            eligible.insert(*id.as_bytes());
        }
    }
    Ok(eligible)
}

/// Which custody entries a head may carry (CALLS `KS-6 entry eligibility`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyEntryRecovery {
    /// A portable credential's keys ride the head's owner-only compartment,
    /// wrapped to the recovery root alone; every other credential's stay in
    /// this machine's custody: a same-install restore takes them, a new
    /// host re-enters them or imports the owner's archive.
    LocalOnlyUnlessCurrentlyPermittedPortable,
}

const CUSTODY_ENTRY_RECOVERY: CustodyEntryRecovery =
    CustodyEntryRecovery::LocalOnlyUnlessCurrentlyPermittedPortable;
