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
//!
//! A key opens rows only once a committed writer here made it ready (census
//! L5-22 1a-iii): the writer that sealed under it, or the one that installed
//! it when custody delivered it. A key file an aborted writer left opens
//! nothing. Retiring a subject clears its marks in the writer that stages
//! the retirement, so no snapshot from its commit on opens the subject's
//! rows, before custody's finisher destroys the keys.
//!
//! The vault's machines carry these keys to each other live (census L5-22
//! 1a-iii commit 7, `crate::sync::authority_overlay_custody`): each compares
//! its [`OverlayInventory`] with its home's, never a secret; a key travels
//! only sealed to the receiver's session-ephemeral key
//! ([`export_key`], [`open_received_key`]), its receiver recorded as a
//! holder first, and an erased subject travels as its refs alone. A seal is
//! never stored, so a key destroyed at every holder is gone.
#![cfg_attr(
    not(feature = "sync"),
    allow(
        dead_code,
        reason = "the key events and the carrier's half here serve only the sync carrier"
    )
)]

use std::collections::{BTreeMap, BTreeSet};

use getrandom::SysRng;
use heed::{RoTxn, RwTxn};
use oneiron_crypto::{
    Argon2Cost, Envelope, HybridSecretKey, Kek, OpenKey, OpenPolicy, Purpose, SealKey, SealParams,
    SuiteId, WrapType, seal_with_aad,
};
use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::{Error, Result, StoreError};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::store::home_handoff_custody::{
    LiveTarget, SessionBinding, TransitSeal, open_transit, seal_transit,
};
use crate::store::key_custody::{
    CustodyKind, CustodySecret, EntryState, ErasableItem, ErasablePurpose, LocalCustody,
    delete_erasable_ref_in_txn, erasable_refs_of_in_txn, put_erasable_ref_in_txn,
    retirement_in_txn, retirements_in_txn, stage_erasable_retirement_in_txn,
};

/// Each overlay key a committed writer here made ready to open its rows, by
/// ref (census L5-22 1a-iii).
const KEY_READY: SideTable<[u8; 32], (), Raw> =
    SideTable::new(&side_table::AUTHORITY_OVERLAY_KEY_READY);

const RECIPIENT: &[u8] = b"oneiron/authority-overlay/v1";
const AEAD: SuiteId = SuiteId::AES256GCM_V1;
const EPOCH: u64 = 1;

/// The context a subject derives its key's incarnation under: one key per
/// subject, so an erase retires one key.
const INCARNATION_CONTEXT: &str = "oneiron/authority-overlay/erasable-incarnation/v1";

/// The width of a key's transit record, as the home handoff's: purpose (1)
/// | subject (16) | incarnation (32) | secret (32).
const TRANSIT_LEN: usize = 81;

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
/// synced and journaled before this returns, and its ref row and ready mark
/// are written in `txn`.
///
/// The mark moves no openness epoch: no stored row is sealed under a key
/// minted here whose mark is unset. A new ref is fresh; the rows of a key an
/// earlier writer filed committed with its mark, and an aborted writer's
/// rows never committed.
///
/// # Errors
/// An archived vault; a subject whose key is retired or staged to retire
/// (an erased subject is named by no new entry); custody and crypto faults.
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
    if retirement_in_txn(store, txn, &item.subject(&custody)?)?.is_some() {
        return Err(CustodyKind::ErasableKey.corrupt());
    }
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
    KEY_READY.put(store, txn, &item.key_ref, &())?;
    Ok(SealedOverlay {
        subject: *subject,
        key_ref: item.key_ref,
        envelope,
    })
}

/// The overlay record `sealed` holds for the entry of hash `entry_hash`.
/// `None` when the subject's key is retired, staged to retire, not held
/// here, or held without the ready mark of a committed writer: the entry's
/// overlay is erased, or has not reached this install.
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
    if !KEY_READY.contains(store, txn, &sealed.key_ref)?
        || retirement_in_txn(store, txn, &item.subject(&custody)?)?.is_some()
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

/// Every overlay key of `subject` this install knows (census L5-22 1a-iii):
/// each custody holds a directory for (live, retired, or an aborted
/// writer's), each with a ref row, each a sealed row of `heads` names for
/// `subject`, and each ref of `refs`, held here or not.
fn subject_keys_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    custody: &LocalCustody<'_>,
    subject: &EntityId,
    heads: &[SealedOverlay],
    refs: &[[u8; 32]],
) -> Result<BTreeSet<ErasableItem>> {
    let parent = subject.as_bytes();
    let mut items: BTreeSet<ErasableItem> = custody
        .erasable_keys_of(ErasablePurpose::AuthorityOverlay, parent)?
        .into_iter()
        .collect();
    items.extend(erasable_refs_of_in_txn(
        store,
        txn,
        ErasablePurpose::AuthorityOverlay,
        parent,
    )?);
    items.extend(
        heads
            .iter()
            .filter(|head| head.subject == *subject)
            .map(|head| item(subject, &head.key_ref)),
    );
    items.extend(refs.iter().map(|key_ref| item(subject, key_ref)));
    Ok(items)
}

/// Whether `subject` is erased here: a key of it is retired, or a
/// retirement of one is staged. An erased subject's rows never open again,
/// under any key or ref.
fn subject_erased_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    custody: &LocalCustody<'_>,
    subject: &EntityId,
    known: &BTreeSet<ErasableItem>,
) -> Result<bool> {
    for item in known {
        if custody.erasable_state(item)? == EntryState::Retired
            || retirement_in_txn(store, txn, &item.subject(custody)?)?.is_some()
        {
            return Ok(true);
        }
    }
    // A staged retirement of a key with no directory and no ref row here.
    Ok(retirements_in_txn(store, txn, CustodyKind::ErasableKey)?
        .iter()
        .filter_map(|intent| ErasableItem::of_item(intent.subject.item()))
        .any(|item| {
            item.purpose == ErasablePurpose::AuthorityOverlay && &item.parent == subject.as_bytes()
        }))
}

/// Installs `secret`, the overlay key of `subject` under ref `key_ref` that
/// custody delivered here, in `txn` (census L5-22 1a-iii): the key is synced
/// and its Mint journaled before this returns, and its ref row and ready
/// mark are written in `txn`, so the rows sealed under it open in every
/// snapshot from `txn`'s commit on. The same bytes installed again are
/// accepted. The fold side of the event is the caller's
/// (`crate::authority::install_authority_overlay_key_in_txn`).
///
/// # Errors
/// An archived vault; a secret that is not a 32-byte key; an erased
/// subject (a key of it retired or staged to retire, under any ref); other
/// bytes already under `key_ref`; custody faults.
pub(crate) fn install_key_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    subject: &EntityId,
    key_ref: &[u8; 32],
    secret: &CustodySecret,
) -> Result<()> {
    if store.core.gate_custody_archived() {
        return Err(Error::Store(StoreError::ArchivedVault));
    }
    if secret.expose().len() != 32 {
        return Err(corrupt());
    }
    store.core.key_custody.pin_in_txn(store, txn)?;
    let custody = store.core.key_custody.bind_in_txn(store, txn)?;
    let known = subject_keys_in_txn(store, txn, &custody, subject, &[], &[*key_ref])?;
    if subject_erased_in_txn(store, txn, &custody, subject, &known)? {
        return Err(CustodyKind::ErasableKey.corrupt());
    }
    let item = item(subject, key_ref);
    custody.install_erasable(&item, secret)?;
    put_erasable_ref_in_txn(store, txn, &item)?;
    KEY_READY.put(store, txn, key_ref, &())
}

/// Stages in `txn` the retirement of every overlay key of `subject` this
/// install knows (census L5-22 1a-iii): custody's, those with a ref row,
/// those `heads` name and the delivered `refs`, held here or not. Their ref
/// rows and ready marks go in `txn`, so no snapshot from its commit on opens
/// a row of `subject`; custody's finisher destroys each key after the
/// commit (`Store::finish_erasable_retirements`). The fold side of the event
/// is the caller's (`crate::authority::retire_authority_overlay_subject_in_txn`).
///
/// # Errors
/// An archived vault; custody faults.
pub(crate) fn retire_subject_keys_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    subject: &EntityId,
    heads: &[SealedOverlay],
    refs: &[[u8; 32]],
) -> Result<()> {
    if store.core.gate_custody_archived() {
        return Err(Error::Store(StoreError::ArchivedVault));
    }
    store.core.key_custody.pin_in_txn(store, txn)?;
    let custody = store.core.key_custody.bind_in_txn(store, txn)?;
    for item in subject_keys_in_txn(store, txn, &custody, subject, heads, refs)? {
        stage_erasable_retirement_in_txn(store, txn, &custody, &item)?;
        delete_erasable_ref_in_txn(store, txn, &item)?;
        KEY_READY.delete(store, txn, &item.key_ref)?;
    }
    Ok(())
}

/// One subject erased here, as the carrier names it: every ref of its keys
/// this install knows, and those whose keys are destroyed here. Never a
/// secret.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(not(feature = "sync"), allow(unreachable_pub))]
pub struct ErasedSubject {
    /// Every ref of the subject's keys this install knows.
    pub refs: BTreeSet<[u8; 32]>,
    /// The refs whose keys are destroyed here.
    pub destroyed: BTreeSet<[u8; 32]>,
}

/// This install's overlay custody, as the carrier between the vault's
/// machines compares it (census L5-22 1a-iii commit 7): each key held here
/// live and ready, of a subject not erased here, by subject and ref; and
/// each subject erased here (a key of it retired, or a retirement of one
/// staged, held here or not). Never a secret.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OverlayInventory {
    pub(crate) ready: BTreeSet<(EntityId, [u8; 32])>,
    pub(crate) erased: BTreeMap<EntityId, ErasedSubject>,
}

/// This install's [`OverlayInventory`], read in one snapshot: custody's
/// overlay keys by directory and the staged retirements of any, a key with
/// no directory here among them. An install with no custody holds none.
///
/// # Errors
/// Storage and custody faults.
pub(crate) fn overlay_inventory(store: &Store) -> Result<OverlayInventory> {
    let Some(custody) = store.core.key_custody.local() else {
        return Ok(OverlayInventory::default());
    };
    let txn = store.env.read_txn()?;
    let staged: BTreeSet<ErasableItem> = retirements_in_txn(store, &txn, CustodyKind::ErasableKey)?
        .iter()
        .filter_map(|intent| ErasableItem::of_item(intent.subject.item()))
        .filter(|item| item.purpose == ErasablePurpose::AuthorityOverlay)
        .collect();
    let mut by_subject: BTreeMap<EntityId, BTreeSet<ErasableItem>> = BTreeMap::new();
    let held = custody
        .subjects_with_prefix(
            CustodyKind::ErasableKey,
            &[ErasablePurpose::AuthorityOverlay.code()],
        )?
        .iter()
        .filter_map(|subject| ErasableItem::of_item(subject.item()))
        .collect::<Vec<_>>();
    for item in held.into_iter().chain(staged.iter().copied()) {
        let Ok(subject) = EntityId::from_bytes(item.parent) else {
            continue;
        };
        if item.incarnation == incarnation(&subject) {
            by_subject.entry(subject).or_default().insert(item);
        }
    }
    let mut inventory = OverlayInventory::default();
    for (subject, items) in by_subject {
        let mut erased = ErasedSubject::default();
        let mut is_erased = false;
        let mut ready = Vec::new();
        for item in items {
            erased.refs.insert(item.key_ref);
            match custody.erasable_state(&item)? {
                EntryState::Retired => {
                    is_erased = true;
                    erased.destroyed.insert(item.key_ref);
                }
                _ if staged.contains(&item) => is_erased = true,
                EntryState::Live if KEY_READY.contains(store, &txn, &item.key_ref)? => {
                    ready.push(item.key_ref);
                }
                _ => {}
            }
        }
        if is_erased {
            inventory.erased.insert(subject, erased);
        } else {
            inventory
                .ready
                .extend(ready.into_iter().map(|key_ref| (subject, key_ref)));
        }
    }
    Ok(inventory)
}

/// The overlay key of `subject` under `key_ref`, sealed to `target`'s live
/// session (census L5-22 1a-iii commit 7). Only a key held here live and
/// ready, of a subject not erased here, travels. `target`'s machine is
/// recorded as a holder of it, synced, before the seal is returned, so an
/// erase of the subject owes that holder's retirement whatever happens next.
/// The key is checked again once the holder is on record: a retirement that
/// committed after the first check refuses the seal, and one that commits
/// after the second owes the holder's retirement.
///
/// # Errors
/// An archived vault; a key not held here live and ready, or of an erased
/// subject, at either check; custody and sealing faults.
pub(crate) fn export_key(
    store: &Store,
    subject: &EntityId,
    key_ref: &[u8; 32],
    target: &LiveTarget,
) -> Result<TransitSeal> {
    export_key_checked(store, subject, key_ref, target, || Ok(()))
}

/// [`export_key`], running `before_read` between its first check and its
/// read of the key: the seam a test retires the subject through.
fn export_key_checked(
    store: &Store,
    subject: &EntityId,
    key_ref: &[u8; 32],
    target: &LiveTarget,
    before_read: impl FnOnce() -> Result<()>,
) -> Result<TransitSeal> {
    if store.core.gate_custody_archived() {
        return Err(Error::Store(StoreError::ArchivedVault));
    }
    let custody = store
        .core
        .key_custody
        .local()
        .ok_or_else(|| CustodyKind::ErasableKey.corrupt())?;
    let item = item(subject, key_ref);
    check_exportable(store, &custody, subject, &item)?;
    before_read()?;
    let secret = custody.read_erasable(&item)?;
    custody.record_holder(key_ref, &target.machine)?;
    let mut plain = Zeroizing::new(Vec::with_capacity(TRANSIT_LEN));
    plain.push(ErasablePurpose::AuthorityOverlay.code());
    plain.extend_from_slice(subject.as_bytes());
    plain.extend_from_slice(&item.incarnation);
    plain.extend_from_slice(secret.expose());
    let sealed = seal_transit(target, key_ref, &plain)?;
    check_exportable(store, &custody, subject, &item)?;
    Ok(sealed)
}

/// Refuses `item`, the overlay key of `subject`, unless it is held here
/// live and ready and `subject` is not erased here, in one snapshot.
fn check_exportable(
    store: &Store,
    custody: &LocalCustody<'_>,
    subject: &EntityId,
    item: &ErasableItem,
) -> Result<()> {
    let txn = store.env.read_txn()?;
    let known = subject_keys_in_txn(store, &txn, custody, subject, &[], &[])?;
    if !KEY_READY.contains(store, &txn, &item.key_ref)?
        || custody.erasable_state(item)? != EntryState::Live
        || subject_erased_in_txn(store, &txn, custody, subject, &known)?
    {
        return Err(CustodyKind::ErasableKey.corrupt());
    }
    Ok(())
}

/// The subject and key that `sealed`, a transit record for the ref
/// `key_ref`, carries to this install (census L5-22 1a-iii commit 7): opened
/// with `session`, the live session's ephemeral secret, against `receiver`
/// (this machine) and `binding`. Only an overlay key's record opens: purpose
/// 5, a valid subject id, and that subject's incarnation. Installing it is
/// the caller's, through `crate::authority::install_authority_overlay_key_in_txn`.
///
/// # Errors
/// A seal that does not open for this session, ref and machine; a record of
/// another purpose, subject or incarnation.
pub(crate) fn open_received_key(
    session: &HybridSecretKey,
    receiver: &EntityId,
    binding: &SessionBinding,
    key_ref: &[u8; 32],
    sealed: &TransitSeal,
) -> Result<(EntityId, CustodySecret)> {
    let plain = open_transit(session, receiver, binding, key_ref, sealed)?;
    if plain.len() != TRANSIT_LEN || plain[0] != ErasablePurpose::AuthorityOverlay.code() {
        return Err(CustodyKind::ErasableKey.corrupt());
    }
    let parent: [u8; 16] = plain[1..17]
        .try_into()
        .map_err(|_| CustodyKind::ErasableKey.corrupt())?;
    let subject = EntityId::from_bytes(parent).map_err(|_| CustodyKind::ErasableKey.corrupt())?;
    if plain[17..49] != incarnation(&subject) {
        return Err(CustodyKind::ErasableKey.corrupt());
    }
    let secret = CustodySecret::from_bytes(Zeroizing::new(plain[49..].to_vec()));
    Ok((subject, secret))
}

/// Records `sender` as a holder of the overlay key `key_ref` this install
/// is receiving from it (census L5-22 1a-iii commit 7), synced, before the
/// key event installs it, as a handoff's receiver does: an erase of its
/// subject here owes that holder's retirement too.
///
/// # Errors
/// Custody faults.
pub(crate) fn record_sender(store: &Store, key_ref: &[u8; 32], sender: &EntityId) -> Result<()> {
    match store.core.key_custody.local() {
        Some(custody) => custody.record_holder(key_ref, sender),
        None => Ok(()),
    }
}

/// Whether this install waits on `holder`'s proof that it destroyed a key of
/// a subject `inventory` (this install's) names erased: a debt for `holder`
/// on one of its refs stands here.
///
/// # Errors
/// Custody faults.
pub(crate) fn awaits_retirement_by(
    store: &Store,
    inventory: &OverlayInventory,
    holder: &EntityId,
) -> Result<bool> {
    let Some(custody) = store.core.key_custody.local() else {
        return Ok(false);
    };
    let debts = custody.holder_debts()?;
    Ok(inventory
        .erased
        .values()
        .flat_map(|erased| erased.refs.iter())
        .any(|key_ref| debts.contains(&(*key_ref, *holder))))
}

/// Clears `holder`'s debt for each overlay key of `destroyed` (census L5-22
/// 1a-iii commit 7): its inventory, on a socket that proved it, names the
/// key destroyed there. A ref of another purpose clears nothing: only its
/// own carrier's proof does.
///
/// # Errors
/// Custody faults.
pub(crate) fn clear_destroyed_holder_debts(
    store: &Store,
    holder: &EntityId,
    destroyed: &BTreeSet<[u8; 32]>,
) -> Result<()> {
    let Some(custody) = store.core.key_custody.local() else {
        return Ok(());
    };
    for key_ref in destroyed {
        if custody
            .erasable_by_ref(key_ref)?
            .is_some_and(|item| item.purpose == ErasablePurpose::AuthorityOverlay)
        {
            custody.clear_holder(key_ref, holder)?;
        }
    }
    Ok(())
}

/// What `source` holds of `subject`'s overlay custody, read in one
/// snapshot: each key it holds ready and live, with its secret, and the ref
/// of each key it retired or staged to retire, never its secret.
#[cfg(test)]
type HeldOverlayCustody = (Vec<([u8; 32], CustodySecret)>, Vec<[u8; 32]>);

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
        } else if state == EntryState::Live
            && KEY_READY.contains(&source.store, &txn, &item.key_ref)?
        {
            live.push((item.key_ref, custody.read_erasable(&item)?));
        }
    }
    Ok((live, retired))
}

/// Delivers `subject`'s overlay custody from `source` to `destination`, two
/// installs of one vault, as custody's carrier will (census L5-22 1a-iii;
/// the carrier is commit 7's): each key the source holds ready and live is
/// installed through the production seam; when the source retired a key of
/// `subject`, or staged its retirement, only the refs travel, never a
/// secret, and the destination retires the subject through the production
/// seam and runs custody's finisher after the commit.
#[cfg(test)]
pub(crate) fn deliver_authority_overlay_custody_for_test(
    source: &crate::Vault,
    destination: &crate::Vault,
    subject: &EntityId,
) -> Result<()> {
    let (live, retired) = held_overlay_custody_for_test(source, subject)?;
    if !retired.is_empty() {
        destination.with_write_txn_grouped(|txn| {
            crate::authority::retire_authority_overlay_subject_in_txn(
                &destination.store,
                txn,
                subject,
                &retired,
            )
        })?;
        destination.store.finish_erasable_retirements()?;
        return Ok(());
    }
    for (key_ref, secret) in &live {
        destination.with_write_txn_grouped(|txn| {
            crate::authority::install_authority_overlay_key_in_txn(
                &destination.store,
                txn,
                subject,
                key_ref,
                secret,
            )
        })?;
    }
    Ok(())
}

/// Retires `subject` on `vault` through the production seam, then runs
/// custody's finisher after the commit (census L5-22 1a-iii): an owner's
/// erase of the subject, whose door is the census's PR 1b.
#[cfg(test)]
pub(crate) fn retire_authority_overlay_subject_for_test(
    vault: &crate::Vault,
    subject: &EntityId,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        crate::authority::retire_authority_overlay_subject_in_txn(&vault.store, txn, subject, &[])
    })?;
    vault.store.finish_erasable_retirements()?;
    Ok(())
}

/// The carrier's seals and holder debts (census L5-22 1a-iii commit 7):
/// what `open_received_key` refuses, and what `export_key` owes and
/// `clear_destroyed_holder_debts` clears.
#[cfg(test)]
mod carrier_tests {
    use std::collections::BTreeSet;

    use getrandom::SysRng;
    use oneiron_crypto::HybridSecretKey;

    use super::{
        clear_destroyed_holder_debts, export_key, incarnation, open_received_key,
        overlay_inventory, seal,
    };
    use crate::entity_id::EntityId;
    use crate::store::home_handoff_custody::{
        LiveTarget, SessionBinding, TransitSeal, seal_transit,
    };
    use crate::store::key_custody::ErasablePurpose;
    use crate::{Vault, VaultConfig};

    /// A vault holding one ready overlay key of a fresh subject, sealed
    /// directly through `seal` (the smallest fixture `overlay_inventory`
    /// lists; the slip doors of overlay_rows.rs T-LAND funnel into the
    /// same call): the vault's tempdir, the vault, the subject and its ref.
    fn vault_with_one_ready_overlay_key() -> (tempfile::TempDir, Vault, EntityId, [u8; 32]) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
        let subject = EntityId::now();
        vault
            .with_write_txn_grouped(|txn| {
                seal(&vault.store, txn, &subject, &[0x5A; 32], b"overlay record")
            })
            .unwrap();
        let inventory = overlay_inventory(&vault.store).unwrap();
        assert_eq!(
            inventory.ready.len(),
            1,
            "the sealed key is the one ready key"
        );
        let (held, key_ref) = inventory.ready.iter().next().copied().unwrap();
        assert_eq!(held, subject, "the ready key is the subject's");
        (dir, vault, subject, key_ref)
    }

    /// A live session for `machine`: its secret, and the target that seals
    /// to it under `binding` with `nonce`.
    fn live_session(
        machine: EntityId,
        binding: [u8; 32],
        nonce: [u8; 32],
    ) -> (HybridSecretKey, LiveTarget) {
        let secret = HybridSecretKey::generate(&mut SysRng).unwrap();
        let target = LiveTarget {
            machine,
            session: SessionBinding { binding, nonce },
            ephemeral: secret.public_key().clone(),
        };
        (secret, target)
    }

    /// A transit record sealed to its receiver's session.
    struct SealedRecord {
        subject: EntityId,
        receiver: EntityId,
        secret: [u8; 32],
        key_ref: [u8; 32],
        binding: SessionBinding,
        session: HybridSecretKey,
        sealed: TransitSeal,
    }

    /// `purpose`'s 81-byte transit record for a fresh subject, carrying a
    /// fixed secret under the subject's incarnation, sealed to a fresh
    /// session of its receiver.
    fn sealed_record(purpose: u8) -> SealedRecord {
        let subject = EntityId::now();
        let receiver = EntityId::now();
        let secret = [0x5E; 32];
        let key_ref = [0x3C; 32];
        let binding = SessionBinding {
            binding: [0x11; 32],
            nonce: [0x22; 32],
        };
        let (session, target) = live_session(receiver, binding.binding, binding.nonce);
        let mut plain = Vec::with_capacity(81);
        plain.push(purpose);
        plain.extend_from_slice(subject.as_bytes());
        plain.extend_from_slice(&incarnation(&subject));
        plain.extend_from_slice(&secret);
        let sealed = seal_transit(&target, &key_ref, &plain).unwrap();
        SealedRecord {
            subject,
            receiver,
            secret,
            key_ref,
            binding,
            session,
            sealed,
        }
    }

    /// A seal to the right session opens for its own receiver and binding,
    /// naming its subject and secret.
    #[test]
    fn a_seal_to_the_right_session_opens_for_its_own_receiver_and_binding() {
        let record = sealed_record(ErasablePurpose::AuthorityOverlay.code());
        let (subject, secret) = open_received_key(
            &record.session,
            &record.receiver,
            &record.binding,
            &record.key_ref,
            &record.sealed,
        )
        .unwrap();
        assert_eq!(subject, record.subject);
        assert_eq!(secret.expose(), &record.secret[..]);
    }

    /// A well-formed transit record of the home handoff's purpose is
    /// refused as an overlay key.
    #[test]
    fn a_home_handoff_record_is_refused_as_an_overlay_key() {
        let record = sealed_record(ErasablePurpose::HomeHandoff.code());
        assert!(
            open_received_key(
                &record.session,
                &record.receiver,
                &record.binding,
                &record.key_ref,
                &record.sealed,
            )
            .is_err(),
            "a purpose-1 record is not an overlay key",
        );
    }

    /// A seal opened with another session's secret is refused.
    #[test]
    fn an_overlay_seal_opened_with_another_sessions_secret_is_refused() {
        let record = sealed_record(ErasablePurpose::AuthorityOverlay.code());
        let (other, _) = live_session(EntityId::now(), [0x33; 32], [0x44; 32]);
        assert!(
            open_received_key(
                &other,
                &record.receiver,
                &record.binding,
                &record.key_ref,
                &record.sealed,
            )
            .is_err(),
            "another session's secret opens nothing",
        );
    }

    /// A seal opened as another receiver is refused.
    #[test]
    fn an_overlay_seal_opened_as_another_receiver_is_refused() {
        let record = sealed_record(ErasablePurpose::AuthorityOverlay.code());
        let stranger = EntityId::now();
        assert!(
            open_received_key(
                &record.session,
                &stranger,
                &record.binding,
                &record.key_ref,
                &record.sealed,
            )
            .is_err(),
            "another receiver opens nothing",
        );
    }

    /// A seal opened under another binding is refused.
    #[test]
    fn an_overlay_seal_opened_under_another_binding_is_refused() {
        let record = sealed_record(ErasablePurpose::AuthorityOverlay.code());
        let binding = SessionBinding {
            binding: [0x77; 32],
            nonce: record.binding.nonce,
        };
        assert!(
            open_received_key(
                &record.session,
                &record.receiver,
                &binding,
                &record.key_ref,
                &record.sealed,
            )
            .is_err(),
            "another binding opens nothing",
        );
    }

    /// An exported key records its receiver as a holder before the seal is
    /// returned.
    #[test]
    fn an_exported_key_records_its_receiver_as_a_holder() {
        let (_dir, vault, subject, key_ref) = vault_with_one_ready_overlay_key();
        let machine = EntityId::now();
        let (_session, target) = live_session(machine, [0x11; 32], [0x22; 32]);
        export_key(&vault.store, &subject, &key_ref, &target).unwrap();
        let debts = vault
            .store
            .core
            .key_custody
            .local()
            .unwrap()
            .holder_debts()
            .unwrap();
        assert!(
            debts.contains(&(key_ref, machine)),
            "exporting a key owes its receiver's retirement",
        );
    }

    /// A destroyed-proof clears the overlay key's debt and leaves a debt
    /// for a ref custody does not know.
    #[test]
    fn a_destroyed_proof_clears_only_the_overlay_keys_debt() {
        let (_dir, vault, _subject, key_ref) = vault_with_one_ready_overlay_key();
        let holder = EntityId::now();
        let mut unknown_ref = key_ref;
        unknown_ref[0] ^= 0xFF;
        unknown_ref[1] ^= 0xFF;
        let custody = vault.store.core.key_custody.local().unwrap();
        custody.record_holder(&key_ref, &holder).unwrap();
        custody.record_holder(&unknown_ref, &holder).unwrap();
        clear_destroyed_holder_debts(
            &vault.store,
            &holder,
            &BTreeSet::from([key_ref, unknown_ref]),
        )
        .unwrap();
        let debts = custody.holder_debts().unwrap();
        assert!(
            !debts.contains(&(key_ref, holder)),
            "the overlay key's proven debt clears",
        );
        assert!(
            debts.contains(&(unknown_ref, holder)),
            "a debt for an unknown ref stands",
        );
    }
}

/// The fence (census L5-22 1a-iii commit 7): the home handoff's carrier
/// asks only a handoff key's holder to retire; an authority overlay key's
/// holder clears through the overlay carrier, never here.
#[cfg(test)]
mod holder_fence_tests {
    use super::{held_overlay_custody_for_test, retire_authority_overlay_subject_for_test, seal};
    use crate::entity_id::EntityId;
    use crate::store::home_handoff_custody::holder_retirements;
    use crate::{Vault, VaultConfig};

    /// A retired overlay key's holder is never asked by the handoff
    /// carrier: not even once this install's custody obligations complete.
    #[test]
    fn a_retired_overlay_keys_holder_is_never_asked_by_the_handoff_carrier() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.create_vault_key().unwrap();
        let subject = EntityId::now();
        vault
            .with_write_txn_grouped(|txn| {
                seal(&vault.store, txn, &subject, &[0xA5; 32], b"overlay record")
            })
            .unwrap();
        let (live, _) = held_overlay_custody_for_test(&vault, &subject).unwrap();
        assert_eq!(live.len(), 1, "the sealed key is the one live key");
        let holder = EntityId::now();
        let custody = vault.store.core.key_custody.local().unwrap();
        custody.record_holder(&live[0].0, &holder).unwrap();
        retire_authority_overlay_subject_for_test(&vault, &subject).unwrap();
        let backup = tempfile::tempdir().unwrap();
        vault.publish_custody(backup.path(), &[], None).unwrap();
        let item = custody.erasable_by_ref(&live[0].0).unwrap().unwrap();
        let obligations = vault
            .store
            .custody_obligations_of(&item.subject(&custody).unwrap())
            .unwrap();
        assert!(
            !obligations.is_empty() && obligations.iter().all(|(_, done)| *done),
            "the fixture completes its retired overlay key's custody obligations",
        );
        let owed = holder_retirements(&vault.store).unwrap();
        assert!(
            owed.iter().all(|debt| debt.holder != holder),
            "the handoff carrier must never ask an overlay key's holder to retire",
        );
    }
}
