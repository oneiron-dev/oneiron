//! The erasable overlay of AUTHORITY_LOG entries (census L5-22; DEC-0005
//! #vault:8): the plaintext leaves and seed of an entry
//! (`oneiron_authority::authority::AuthorityOverlayRecord`), sealed under an
//! erasable key (`key_custody::erasable`) whose parent is the subject the
//! entry names, one key per subject.
//!
//! The log row keeps only the scaffold: its signature and hash cover the
//! commitments, never the values. The sealed record is the row's
//! `AUTHORITY_OVERLAY` side-table row, written in the writer that appends the
//! log row, after the subject's key is minted and journaled there. Retiring
//! the subject's key (an erase) leaves every such row unopenable wherever it
//! was copied, and the commitments in the log name nothing: their seed was
//! sealed with the values.

use getrandom::SysRng;
use heed::{RoTxn, RwTxn};
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, SuiteId,
    WrapType, seal_with_aad,
};
use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::{Error, Result, StoreError};
use crate::store::Store;
use crate::store::key_custody::{
    EntryState, ErasableItem, ErasablePurpose, put_erasable_ref_in_txn, retirement_in_txn,
};

const RECIPIENT: &[u8] = b"oneiron/authority-overlay/v1";
const AEAD: SuiteId = SuiteId::AES256GCM_V1;
const EPOCH: u64 = 1;

/// The context a subject derives its key's incarnation under: one key per
/// subject, so an erase retires one key.
const INCARNATION_CONTEXT: &str = "oneiron/authority-overlay/erasable-incarnation/v1";

/// The width of a sealed row's head: subject (16) | key ref (32).
const HEAD_LEN: usize = 48;

fn corrupt() -> Error {
    Error::CorruptedIndex("authority overlay custody")
}

fn incarnation(subject: &EntityId) -> [u8; 32] {
    blake3::derive_key(INCARNATION_CONTEXT, subject.as_bytes())
}

fn item(subject: &EntityId, key_ref: &[u8; 32]) -> ErasableItem {
    ErasableItem {
        purpose: ErasablePurpose::AuthorityOverlay,
        parent: *subject.as_bytes(),
        incarnation: incarnation(subject),
        key_ref: *key_ref,
    }
}

fn aad(entry_hash: &[u8; 32], subject: &EntityId) -> [u8; 48] {
    let mut aad = [0u8; 48];
    aad[..32].copy_from_slice(entry_hash);
    aad[32..].copy_from_slice(subject.as_bytes());
    aad
}

/// One entry's sealed overlay as its side-table row holds it: the subject
/// whose key seals it, the key's ref, and the envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SealedOverlay {
    pub(crate) subject: EntityId,
    key_ref: [u8; 32],
    envelope: Vec<u8>,
}

impl SealedOverlay {
    /// The row's bytes: subject (16) | key ref (32) | envelope.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEAD_LEN + self.envelope.len());
        bytes.extend_from_slice(self.subject.as_bytes());
        bytes.extend_from_slice(&self.key_ref);
        bytes.extend_from_slice(&self.envelope);
        bytes
    }

    /// The row `bytes` hold.
    ///
    /// # Errors
    /// A row too short to hold its head, or one naming a reserved id.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() <= HEAD_LEN {
            return Err(corrupt());
        }
        let subject: [u8; 16] = bytes[..16].try_into().map_err(|_| corrupt())?;
        let key_ref: [u8; 32] = bytes[16..HEAD_LEN].try_into().map_err(|_| corrupt())?;
        Ok(Self {
            subject: EntityId::from_bytes(subject).map_err(|_| corrupt())?,
            key_ref,
            envelope: bytes[HEAD_LEN..].to_vec(),
        })
    }
}

/// Seals `record` (an encoded overlay record) for the entry of hash
/// `entry_hash` under `subject`'s key, minting that key in `txn`, the writer
/// that appends the entry, with the custody binding pinned there: the key is
/// synced and journaled before this returns, and its ref row is written in
/// `txn`.
///
/// # Errors
/// An archived vault; a subject whose key is retired (an erased subject is
/// named by no new entry); custody and crypto faults.
pub(crate) fn seal(
    store: &Store,
    txn: &mut RwTxn<'_>,
    subject: &EntityId,
    entry_hash: &[u8; 32],
    record: &[u8],
) -> Result<SealedOverlay> {
    if store.core.gate_custody_archived() {
        return Err(Error::Store(StoreError::ArchivedVault));
    }
    store.core.key_custody.pin_in_txn(store, txn)?;
    let custody = store.core.key_custody.bind_in_txn(store, txn)?;
    let (item, secret) = custody.mint_erasable(
        ErasablePurpose::AuthorityOverlay,
        subject.as_bytes(),
        &incarnation(subject),
    )?;
    let key: &[u8; 32] = secret.expose().try_into().map_err(|_| corrupt())?;
    let kek = Kek::from_bytes_ref(key);
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::ErasableKey,
        epoch: EPOCH,
        key_id: &item.key_ref,
        recipient: RECIPIENT,
        vault_id: &item.key_ref,
    };
    let envelope = seal_with_aad(
        &params,
        SealKey::SymmetricKek(&kek),
        record,
        &aad(entry_hash, subject),
        &mut SysRng,
    )
    .map_err(|_| corrupt())?
    .to_bytes();
    put_erasable_ref_in_txn(store, txn, &item)?;
    Ok(SealedOverlay {
        subject: *subject,
        key_ref: item.key_ref,
        envelope,
    })
}

/// The overlay record `sealed` holds for the entry of hash `entry_hash`.
/// `None` when the subject's key is retired, staged to retire, or not held
/// here: the entry's overlay is erased, or has not reached this install.
///
/// # Errors
/// An envelope that does not open under a live key (a damaged row, or a row
/// moved to another entry); custody faults.
pub(crate) fn open(
    store: &Store,
    txn: &RoTxn<'_>,
    entry_hash: &[u8; 32],
    sealed: &SealedOverlay,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let Some(custody) = store.core.key_custody.local() else {
        return Ok(None);
    };
    let item = item(&sealed.subject, &sealed.key_ref);
    if retirement_in_txn(store, txn, &item.subject(&custody)?)?.is_some()
        || custody.erasable_state(&item)? != EntryState::Live
    {
        return Ok(None);
    }
    let secret = custody.read_erasable(&item)?;
    let key: &[u8; 32] = secret.expose().try_into().map_err(|_| corrupt())?;
    let kek = Kek::from_bytes_ref(key);
    let policy = OpenPolicy {
        purpose: Purpose::ErasableKey,
        vault_id: &sealed.key_ref,
        recipient: RECIPIENT,
        key_id: &sealed.key_ref,
        wraps: &[WrapType::SymmetricKek],
        aead_suites: &[AEAD],
        kem_suites: &[],
        min_epoch: EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let record = Envelope::parse(&sealed.envelope)
        .map_err(|_| corrupt())?
        .open_with_aad(
            OpenKey::SymmetricKek(&kek),
            &policy,
            &aad(entry_hash, &sealed.subject),
        )
        .map_err(|_| corrupt())?;
    Ok(Some(record))
}


/// The red base of census L5-22 1a-iii commit 6 (branch
/// opus-e2e-4/authority-overlay-c6-red, never landed): commit 6's three test
/// doors on commit 5's raw custody primitives, with no ready mark, no
/// openness epoch and no Open-only hooks.
#[cfg(test)]
type HeldOverlayCustody = (
    Vec<([u8; 32], crate::store::key_custody::CustodySecret)>,
    Vec<[u8; 32]>,
);

#[cfg(test)]
fn held_overlay_custody_for_test(
    source: &crate::Vault,
    subject: &EntityId,
) -> Result<HeldOverlayCustody> {
    let txn = source.store.env.read_txn()?;
    let custody = source.store.core.key_custody.local().ok_or_else(corrupt)?;
    let mut live = Vec::new();
    let mut retired = Vec::new();
    for item in custody.erasable_keys_of(ErasablePurpose::AuthorityOverlay, subject.as_bytes())? {
        if item.incarnation != incarnation(subject) {
            continue;
        }
        let state = custody.erasable_state(&item)?;
        if state == EntryState::Retired
            || retirement_in_txn(&source.store, &txn, &item.subject(&custody)?)?.is_some()
        {
            retired.push(item.key_ref);
        } else if state == EntryState::Live {
            live.push((item.key_ref, custody.read_erasable(&item)?));
        }
    }
    Ok((live, retired))
}

#[cfg(test)]
fn raw_install_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    subject: &EntityId,
    key_ref: &[u8; 32],
    secret: &crate::store::key_custody::CustodySecret,
) -> Result<()> {
    store.core.key_custody.pin_in_txn(store, txn)?;
    let custody = store.core.key_custody.bind_in_txn(store, txn)?;
    let item = item(subject, key_ref);
    custody.install_erasable(&item, secret)?;
    put_erasable_ref_in_txn(store, txn, &item)
}

#[cfg(test)]
fn raw_retire_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    subject: &EntityId,
    refs: &[[u8; 32]],
) -> Result<()> {
    store.core.key_custody.pin_in_txn(store, txn)?;
    let custody = store.core.key_custody.bind_in_txn(store, txn)?;
    let mut items =
        custody.erasable_keys_of(ErasablePurpose::AuthorityOverlay, subject.as_bytes())?;
    items.extend(refs.iter().map(|key_ref| item(subject, key_ref)));
    for item in &items {
        crate::store::key_custody::stage_erasable_retirement_in_txn(store, txn, &custody, item)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn deliver_authority_overlay_custody_for_test(
    source: &crate::Vault,
    destination: &crate::Vault,
    subject: &EntityId,
) -> Result<()> {
    let (live, retired) = held_overlay_custody_for_test(source, subject)?;
    if !retired.is_empty() {
        destination.with_write_txn_grouped(|txn| {
            raw_retire_in_txn(&destination.store, txn, subject, &retired)
        })?;
        destination.store.finish_erasable_retirements()?;
        return Ok(());
    }
    for (key_ref, secret) in &live {
        destination.with_write_txn_grouped(|txn| {
            raw_install_in_txn(&destination.store, txn, subject, key_ref, secret)
        })?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn deliver_authority_overlay_custody_then_abort_for_test(
    source: &crate::Vault,
    destination: &crate::Vault,
    subject: &EntityId,
) -> Result<()> {
    let (live, _) = held_overlay_custody_for_test(source, subject)?;
    for (key_ref, secret) in &live {
        let aborted = destination.with_write_txn_grouped(|txn| {
            raw_install_in_txn(&destination.store, txn, subject, key_ref, secret)?;
            Err::<(), _>(Error::InvariantViolation(
                "the writer aborts after the install",
            ))
        });
        match aborted {
            Err(Error::InvariantViolation("the writer aborts after the install")) => {}
            Err(err) => return Err(err),
            Ok(()) => return Err(corrupt()),
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn retire_authority_overlay_subject_for_test(
    vault: &crate::Vault,
    subject: &EntityId,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| raw_retire_in_txn(&vault.store, txn, subject, &[]))?;
    vault.store.finish_erasable_retirements()?;
    Ok(())
}
