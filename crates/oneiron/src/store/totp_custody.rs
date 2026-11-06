//! The seed's erasable custody leaf. Only ciphertext and a key ref enter
//! the enrollment row. The native envelope binds the person and enrollment.

use std::collections::BTreeSet;

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
    EntryState, ErasableItem, ErasablePurpose, LocalCustody, delete_erasable_ref_in_txn,
    erasable_refs_of_in_txn, put_erasable_ref_in_txn, retirement_in_txn,
    stage_erasable_retirement_in_txn,
};

/// Random seed bytes for the authenticator-app enrollment.
pub(crate) const SEED_BYTES: usize = 32;

const RECIPIENT: &[u8] = b"oneiron/step-up/totp-seed/v1";
const AEAD: SuiteId = SuiteId::AES256GCM_V1;
const EPOCH: u64 = 1;

fn corrupt() -> Error {
    Error::CorruptedIndex("step-up TOTP seed custody")
}

fn item(person: EntityId, enrollment: &[u8; 32], key_ref: &[u8; 32]) -> ErasableItem {
    ErasableItem {
        purpose: ErasablePurpose::TotpEnrollment,
        parent: *person.as_bytes(),
        incarnation: *enrollment,
        key_ref: *key_ref,
    }
}

fn aad(person: EntityId, enrollment: &[u8; 32]) -> [u8; 48] {
    let mut aad = [0u8; 48];
    aad[..16].copy_from_slice(person.as_bytes());
    aad[16..].copy_from_slice(enrollment);
    aad
}

pub(crate) fn seal(
    store: &Store,
    txn: &mut RwTxn<'_>,
    person: EntityId,
    enrollment: &[u8; 32],
    seed: &[u8],
) -> Result<([u8; 32], Vec<u8>)> {
    if store.core.gate_custody_archived() {
        return Err(Error::Store(StoreError::ArchivedVault));
    }
    store.core.key_custody.pin_in_txn(store, txn)?;
    let custody = store.core.key_custody.bind_in_txn(store, txn)?;
    let (item, secret) = custody.mint_erasable(
        ErasablePurpose::TotpEnrollment,
        person.as_bytes(),
        enrollment,
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
    let sealed = seal_with_aad(
        &params,
        SealKey::SymmetricKek(&kek),
        seed,
        &aad(person, enrollment),
        &mut SysRng,
    )
    .map_err(|_| corrupt())?
    .to_bytes();
    put_erasable_ref_in_txn(store, txn, &item)?;
    Ok((item.key_ref, sealed))
}

fn local(store: &Store) -> Result<LocalCustody<'_>> {
    store.core.key_custody.local().ok_or_else(corrupt)
}

pub(crate) fn live(
    store: &Store,
    txn: &RoTxn<'_>,
    person: EntityId,
    enrollment: &[u8; 32],
    key_ref: &[u8; 32],
) -> Result<bool> {
    let Some(custody) = store.core.key_custody.local() else {
        return Ok(false);
    };
    let item = item(person, enrollment, key_ref);
    Ok(
        retirement_in_txn(store, txn, &item.subject(&custody)?)?.is_none()
            && custody.erasable_state(&item)? == EntryState::Live,
    )
}

pub(crate) fn open(
    store: &Store,
    txn: &RoTxn<'_>,
    person: EntityId,
    enrollment: &[u8; 32],
    key_ref: &[u8; 32],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if !live(store, txn, person, enrollment, key_ref)? {
        return Err(corrupt());
    }
    let custody = local(store)?;
    let secret = custody.read_erasable(&item(person, enrollment, key_ref))?;
    let key: &[u8; 32] = secret.expose().try_into().map_err(|_| corrupt())?;
    let kek = Kek::from_bytes_ref(key);
    let policy = OpenPolicy {
        purpose: Purpose::ErasableKey,
        vault_id: key_ref,
        recipient: RECIPIENT,
        key_id: key_ref,
        wraps: &[WrapType::SymmetricKek],
        aead_suites: &[AEAD],
        kem_suites: &[],
        min_epoch: EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let seed = Envelope::parse(sealed)
        .map_err(|_| corrupt())?
        .open_with_aad(
            OpenKey::SymmetricKek(&kek),
            &policy,
            &aad(person, enrollment),
        )
        .map_err(|_| corrupt())?;
    if seed.len() != SEED_BYTES {
        return Err(corrupt());
    }
    Ok(seed)
}

pub(crate) fn retire(
    store: &Store,
    txn: &mut RwTxn<'_>,
    person: EntityId,
    enrollment: &[u8; 32],
    key_ref: &[u8; 32],
) -> Result<()> {
    let item = item(person, enrollment, key_ref);
    if !store.core.gate_custody_archived() {
        if let Some(custody) = store.core.key_custody.local() {
            stage_erasable_retirement_in_txn(store, txn, &custody, &item)?;
        }
    }
    delete_erasable_ref_in_txn(store, txn, &item)
}

/// An actor erase includes an aborted enrollment writer's orphan leaves.
pub(crate) fn retire_person(store: &Store, txn: &mut RwTxn<'_>, person: EntityId) -> Result<()> {
    let mut items: BTreeSet<ErasableItem> = erasable_refs_of_in_txn(
        store,
        txn,
        ErasablePurpose::TotpEnrollment,
        person.as_bytes(),
    )?
    .into_iter()
    .collect();
    if !store.core.gate_custody_archived() {
        if let Some(custody) = store.core.key_custody.local() {
            items.extend(
                custody.erasable_keys_of(ErasablePurpose::TotpEnrollment, person.as_bytes())?,
            );
            for item in &items {
                stage_erasable_retirement_in_txn(store, txn, &custody, item)?;
            }
        }
    }
    for item in items {
        delete_erasable_ref_in_txn(store, txn, &item)?;
    }
    Ok(())
}
