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
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
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

/// [`deliver_authority_overlay_custody_for_test`]'s live arm in a writer
/// that aborts after the install seam ran: custody keeps the key file it
/// synced, and nothing the writer staged commits.
#[cfg(test)]
pub(crate) fn deliver_authority_overlay_custody_then_abort_for_test(
    source: &crate::Vault,
    destination: &crate::Vault,
    subject: &EntityId,
) -> Result<()> {
    let (live, _) = held_overlay_custody_for_test(source, subject)?;
    for (key_ref, secret) in &live {
        let aborted = destination.with_write_txn_grouped(|txn| {
            crate::authority::install_authority_overlay_key_in_txn(
                &destination.store,
                txn,
                subject,
                key_ref,
                secret,
            )?;
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
