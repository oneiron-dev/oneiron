//! The home handoff's custody contract (FIX 8875, L04's half): each actor's
//! content a home handoff carries is sealed under an erasable key of its own
//! (`key_custody::erasable`), never under the target's long-lived machine
//! key, so an erase of the actor makes its retained and staged parts
//! unreadable wherever a copy went, while the handoff's content-free history
//! stays.
//!
//! A key is minted for one export incarnation and one actor in the writer
//! that commits what is sealed under it, journaled before that commits; it
//! is exported only to a live target's session-ephemeral key, its holder
//! debt synced first, and installed on the target in its receiving writer,
//! journaled before that commits. An actor's erase stages every key of it
//! here (the catalog scrub) in the erase's own transaction, custody's
//! finisher retires them after commit, and its receipt reads
//! `custody_remote_retirement_pending(<holder>)` until each holder's
//! retirement of its copy is verified: the erase commits at once and never
//! waits on the network. Nothing here does network I/O; the handoff's
//! carrier moves the seals, the retirements and their acks.
#![allow(
    dead_code,
    reason = "L03 pack 08 (FIX 8875) consumes this contract: its carrier mints, exports, \
              installs, seals and opens through it"
)]

mod seal;

use heed::{RoTxn, RwTxn};
use oneiron_crypto::{HybridPublicKey, HybridSecretKey};
use zeroize::Zeroizing;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, StoreError};
use crate::store::Store;
use crate::store::key_custody::{
    CustodyKind, CustodySecret, EntryState, ErasableItem, ErasablePurpose, LocalCustody,
    custody_present, delete_erasable_ref_in_txn, erasable_refs_of_in_txn, put_erasable_ref_in_txn,
    retirement_in_txn, stage_erasable_retirement_in_txn,
};

/// The context an export incarnation's 16 wire bytes derive a key
/// incarnation under.
const HANDOFF_INCARNATION_CONTEXT: &str = "oneiron/home-handoff/erasable-incarnation/v1";

/// The width of a key's transit record: purpose (1) | parent (16) |
/// incarnation (32) | secret (32).
const TRANSIT_LEN: usize = 81;

/// One erasable key's name: 32 random bytes, never its actor or its
/// content. A manifest spells it as 64 lowercase hex digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct KeyRef([u8; 32]);

impl KeyRef {
    /// The ref `text` spells: exactly 64 lowercase hex digits, its one
    /// canonical form.
    ///
    /// # Errors
    /// Any other spelling.
    pub(crate) fn from_hex(text: &str) -> Result<Self> {
        let bytes = (text.len() == 64)
            .then(|| {
                (0..64)
                    .step_by(2)
                    .map(|at| {
                        text.get(at..at + 2)
                            .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                    })
                    .collect::<Option<Vec<u8>>>()
            })
            .flatten()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .filter(|bytes| crate::entity_id::bytes_to_hex_lower(bytes) == text)
            .ok_or(Error::CorruptedIndex("erasable key ref"))?;
        Ok(Self(bytes))
    }

    /// Its 64 lowercase hex digits.
    pub(crate) fn to_hex(&self) -> String {
        crate::entity_id::bytes_to_hex_lower(&self.0)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One export's incarnation as a key names it: 32 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Incarnation([u8; 32]);

impl Incarnation {
    /// The key incarnation of the export whose signed header carries the
    /// 16-byte wire incarnation `wire`, drawn before the header and its
    /// keys: BLAKE3 derive-key of the wire bytes.
    pub(crate) fn of_handoff(wire: &[u8; 16]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(HANDOFF_INCARNATION_CONTEXT);
        hasher.update(wire);
        Self(*hasher.finalize().as_bytes())
    }

    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The live session a key travels in: what its authenticated socket bound,
/// and the target's fresh nonce for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionBinding {
    pub(crate) binding: [u8; 32],
    pub(crate) nonce: [u8; 32],
}

/// The target an export seals a key to: its machine, the live session, and
/// that session's ephemeral public key, never the machine's long-lived key.
pub(crate) struct LiveTarget {
    pub(crate) machine: EntityId,
    pub(crate) session: SessionBinding,
    pub(crate) ephemeral: HybridPublicKey,
}

/// Who sent a key, as the carrier verified it: the source machine, this
/// target machine, the handoff lineage and the live session.
pub(crate) struct VerifiedHolder {
    pub(crate) source: EntityId,
    pub(crate) target: EntityId,
    pub(crate) lineage: [u8; 32],
    pub(crate) session: SessionBinding,
}

/// The target's receiving writer: its store, the transaction that adopts
/// the handoff, and the session's ephemeral secret. Nothing here persists
/// the secret.
pub(crate) struct ReceiveWriter<'s, 't> {
    pub(crate) store: &'s Store,
    pub(crate) wtxn: &'s mut RwTxn<'t>,
    pub(crate) session: &'s HybridSecretKey,
}

/// A key sealed to a live target's session-ephemeral key: key-bearing
/// bytes, zeroized on drop, with no `Debug` and no storage codec.
pub(crate) struct TransitSeal(Zeroizing<Vec<u8>>);

impl TransitSeal {
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// What an install of a received key did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Installed {
    Installed,
    /// The same key was already here.
    AlreadyInstalled,
    Refused {
        reason: Refusal,
    },
}

/// Why a received key was not installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Its actor was erased here.
    ErasedActor,
    /// This custody retired it.
    RetiredKey,
}

/// What reading content sealed under a key gives.
pub(crate) enum Content {
    Open(Zeroizing<Vec<u8>>),
    /// Its key was retired: the actor was erased.
    Erased,
    /// Its key is not here to read.
    Unavailable(Unavailable),
}

/// Why a key is not here to read: what to ask for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unavailable {
    /// This vault holds no custody yet: bind it, then install the key.
    NoCustody,
    /// This custody never installed the key: install it from its holder.
    NotInstalled,
}

/// Where one key stands here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyState {
    Live,
    /// An erase staged its retirement; the finisher has not run yet.
    Staged,
    Retired,
    /// No entry: never installed here, or an aborted mint's.
    Missing,
}

/// One key of an actor: its ref, incarnation and state, and every holder
/// whose copy's retirement is not verified yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyRecord {
    pub(crate) key_ref: KeyRef,
    pub(crate) actor: EntityId,
    pub(crate) incarnation: Incarnation,
    pub(crate) state: KeyState,
    pub(crate) holders: Vec<EntityId>,
}

/// A retired key's copy one holder still keeps: what the carrier asks it to
/// retire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HolderRetirement {
    pub(crate) key_ref: KeyRef,
    pub(crate) incarnation: Incarnation,
    pub(crate) holder: EntityId,
}

fn archived() -> Error {
    Error::Store(StoreError::ArchivedVault)
}

fn unknown_key() -> Error {
    CustodyKind::ErasableKey.corrupt()
}

/// This store's custody, which reads and installs keys.
fn custody(store: &Store) -> Result<LocalCustody<'_>> {
    store.core.key_custody.local().ok_or_else(unknown_key)
}

/// A live key's 32 bytes, straight into guarded storage.
fn content_key(custody: &LocalCustody<'_>, item: &ErasableItem) -> Result<Zeroizing<[u8; 32]>> {
    let secret = custody.read_erasable(item)?;
    let mut key = Zeroizing::new([0u8; 32]);
    if secret.expose().len() != key.len() {
        return Err(unknown_key());
    }
    key.copy_from_slice(secret.expose());
    Ok(key)
}

/// Mints the key actor `actor`'s content in the export incarnation `i` is
/// sealed under, in `w`, the writer that commits what is sealed under it,
/// with the custody binding pinned there: synced and its Mint journaled
/// before this returns. A retry finds and keeps the key an earlier attempt
/// published; a retired one is never minted again.
///
/// # Errors
/// An archived vault, whose custody is its replacement's; a retired key;
/// custody faults.
pub(crate) fn mint(
    s: &Store,
    w: &mut RwTxn<'_>,
    i: Incarnation,
    actor: EntityId,
) -> Result<KeyRef> {
    if s.core.gate_custody_archived() {
        return Err(archived());
    }
    s.core.key_custody.pin_in_txn(s, w)?;
    let custody = s.core.key_custody.bind_in_txn(s, w)?;
    let (item, _) = custody.mint_erasable(ErasablePurpose::HomeHandoff, actor.as_bytes(), &i.0)?;
    put_erasable_ref_in_txn(s, w, &item)?;
    Ok(KeyRef(item.key_ref))
}

/// The key `k` names, sealed to `target`'s session-ephemeral key with its
/// purpose, actor and incarnation. `target`'s machine is recorded as a
/// holder of it, synced, before the seal is returned, so an erase of the
/// actor owes that holder's retirement whatever happens next.
///
/// # Errors
/// A key this custody does not hold live, and custody and sealing faults.
pub(crate) fn export(s: &Store, k: KeyRef, target: &LiveTarget) -> Result<TransitSeal> {
    let custody = custody(s)?;
    let item = custody.erasable_by_ref(&k.0)?.ok_or_else(unknown_key)?;
    let secret = custody.read_erasable(&item)?;
    custody.record_holder(&k.0, &target.machine)?;
    let mut plain = Zeroizing::new(Vec::with_capacity(TRANSIT_LEN));
    plain.push(item.purpose.code());
    plain.extend_from_slice(&item.parent);
    plain.extend_from_slice(&item.incarnation);
    plain.extend_from_slice(secret.expose());
    seal::seal_transit(target, &k, &plain)
}

/// The key and its bytes a transit record names, for the ref `k`.
fn received(k: KeyRef, plain: &[u8]) -> Result<(ErasableItem, CustodySecret)> {
    if plain.len() != TRANSIT_LEN {
        return Err(unknown_key());
    }
    let item = ErasableItem {
        purpose: ErasablePurpose::from_code(plain[0]).ok_or_else(unknown_key)?,
        parent: plain[1..17].try_into().map_err(|_| unknown_key())?,
        incarnation: plain[17..49].try_into().map_err(|_| unknown_key())?,
        key_ref: k.0,
    };
    if item.purpose != ErasablePurpose::HomeHandoff {
        return Err(unknown_key());
    }
    let secret = CustodySecret::from_bytes(Zeroizing::new(plain[49..].to_vec()));
    Ok((item, secret))
}

/// Installs the key `k` a holder sent, opened with the receiving session's
/// ephemeral secret, in `w`'s writer with the custody binding pinned there:
/// synced and its Mint journaled before that commits, its metadata row put
/// and its sender recorded as a holder of it. A key of an actor erased
/// here, or one this custody retired, is refused and never installed; the
/// same key already here is `AlreadyInstalled`.
///
/// # Errors
/// An archived vault; a seal that does not open for this session; another
/// key under the same ref; custody faults.
pub(crate) fn install_received(
    w: &mut ReceiveWriter<'_, '_>,
    k: KeyRef,
    sealed: &TransitSeal,
    holder: &VerifiedHolder,
) -> Result<Installed> {
    let store = w.store;
    if store.core.gate_custody_archived() {
        return Err(archived());
    }
    let plain = seal::open_transit(w.session, holder, &k, sealed)?;
    let (item, secret) = received(k, &plain)?;
    drop(plain);
    let actor = EntityId::from_bytes(item.parent)?;
    if crate::ports::removed_in_txn(store, &*w.wtxn, &actor)? {
        return Ok(Installed::Refused {
            reason: Refusal::ErasedActor,
        });
    }
    store.core.key_custody.pin_in_txn(store, w.wtxn)?;
    let custody = store.core.key_custody.bind_in_txn(store, &*w.wtxn)?;
    let installed = match custody.erasable_state(&item)? {
        EntryState::Retired => {
            return Ok(Installed::Refused {
                reason: Refusal::RetiredKey,
            });
        }
        EntryState::Live => {
            if custody.read_erasable(&item)?.expose() != secret.expose() {
                return Err(unknown_key());
            }
            Installed::AlreadyInstalled
        }
        EntryState::Missing => {
            custody.install_erasable(&item, &secret)?;
            Installed::Installed
        }
    };
    put_erasable_ref_in_txn(store, w.wtxn, &item)?;
    custody.record_holder(&k.0, &holder.source)?;
    Ok(installed)
}

/// Stages the retirement of the key `k` in `w`: an erase's intent, which
/// custody's finisher carries out after commit. Its holders' debts stay
/// until each one's retirement is verified. A key this custody does not
/// hold, or an archived vault, stages nothing.
///
/// # Errors
/// Storage and custody faults.
pub(crate) fn retire(s: &Store, w: &mut RwTxn<'_>, k: KeyRef) -> Result<()> {
    if s.core.gate_custody_archived() {
        return Ok(());
    }
    let Some(custody) = s.core.key_custody.local() else {
        return Ok(());
    };
    match custody.erasable_by_ref(&k.0)? {
        Some(item) => stage_erasable_retirement_in_txn(s, w, &custody, &item),
        None => Ok(()),
    }
}

/// Every key of `actor` this vault knows, whatever handoff it served
/// (frozen, acknowledged, cancelled, fully or partly staged) and an aborted
/// writer's orphans: each metadata row naming it and each key custody holds
/// for it, with its state and the holders whose retirement is not verified.
///
/// # Errors
/// Storage and custody faults.
pub(crate) fn lookup_actor(s: &Store, t: &RoTxn<'_>, actor: EntityId) -> Result<Vec<KeyRecord>> {
    let purpose = ErasablePurpose::HomeHandoff;
    let mut items: std::collections::BTreeSet<ErasableItem> =
        erasable_refs_of_in_txn(s, t, purpose, actor.as_bytes())?
            .into_iter()
            .collect();
    let custody = s
        .core
        .key_custody
        .local()
        .filter(|custody| custody_present(custody.binding().root()).unwrap_or(true));
    let Some(custody) = custody else {
        return Ok(items
            .into_iter()
            .map(|item| KeyRecord {
                key_ref: KeyRef(item.key_ref),
                actor,
                incarnation: Incarnation(item.incarnation),
                state: KeyState::Missing,
                holders: Vec::new(),
            })
            .collect());
    };
    items.extend(custody.erasable_keys_of(purpose, actor.as_bytes())?);
    let debts = custody.holder_debts()?;
    items
        .into_iter()
        .map(|item| {
            let state = match custody.erasable_state(&item)? {
                EntryState::Retired => KeyState::Retired,
                _ if retirement_in_txn(s, t, &item.subject(&custody)?)?.is_some() => {
                    KeyState::Staged
                }
                EntryState::Live => KeyState::Live,
                EntryState::Missing => KeyState::Missing,
            };
            Ok(KeyRecord {
                key_ref: KeyRef(item.key_ref),
                actor,
                incarnation: Incarnation(item.incarnation),
                state,
                holders: debts
                    .iter()
                    .filter(|(key_ref, _)| key_ref == &item.key_ref)
                    .map(|(_, holder)| *holder)
                    .collect(),
            })
        })
        .collect()
}

/// Seals `p` under the key `k`, binding `aad` (the carrier's: vault,
/// incarnation, ref, section, part and order). No custody guard is taken:
/// the caller's writer keeps the finisher away.
///
/// # Errors
/// A key this custody does not hold live, and sealing faults.
pub(crate) fn seal_content(s: &Store, k: KeyRef, aad: &[u8], p: &[u8]) -> Result<Vec<u8>> {
    let custody = custody(s)?;
    let item = custody.erasable_by_ref(&k.0)?.ok_or_else(unknown_key)?;
    let key = content_key(&custody, &item)?;
    seal::seal_content(&k, &key, aad, p)
}

/// Opens `c`, sealed under the key `k` with `aad`: its bytes while the key
/// is live here, `Erased` once it is retired, `Unavailable` with what to
/// ask for while it is not here. A retirement racing the read reads as
/// erased.
///
/// # Errors
/// Bytes that do not open under the live key, and custody faults.
pub(crate) fn open_content(s: &Store, k: KeyRef, aad: &[u8], c: &[u8]) -> Result<Content> {
    let Some(custody) = s.core.key_custody.local() else {
        return Ok(Content::Unavailable(Unavailable::NoCustody));
    };
    if !custody_present(custody.binding().root())? {
        return Ok(Content::Unavailable(Unavailable::NoCustody));
    }
    let Some(item) = custody.erasable_by_ref(&k.0)? else {
        return Ok(Content::Unavailable(Unavailable::NotInstalled));
    };
    match custody.erasable_state(&item)? {
        EntryState::Retired => return Ok(Content::Erased),
        EntryState::Missing => return Ok(Content::Unavailable(Unavailable::NotInstalled)),
        EntryState::Live => {}
    }
    let key = match content_key(&custody, &item) {
        Ok(key) => key,
        Err(_) if custody.erasable_state(&item)? == EntryState::Retired => {
            return Ok(Content::Erased);
        }
        Err(error) => return Err(error),
    };
    Ok(Content::Open(seal::open_content(&k, &key, aad, c)?))
}

/// Every retired key's copy a holder still keeps: what the carrier asks
/// each holder to retire, once this custody retired its own.
///
/// # Errors
/// Custody faults.
pub(crate) fn holder_retirements(s: &Store) -> Result<Vec<HolderRetirement>> {
    let Some(custody) = s.core.key_custody.local() else {
        return Ok(Vec::new());
    };
    let mut owed = Vec::new();
    for (key_ref, holder) in custody.holder_debts()? {
        let Some(item) = custody.erasable_by_ref(&key_ref)? else {
            continue;
        };
        if custody.erasable_state(&item)? == EntryState::Retired {
            owed.push(HolderRetirement {
                key_ref: KeyRef(key_ref),
                incarnation: Incarnation(item.incarnation),
                holder,
            });
        }
    }
    Ok(owed)
}

/// Clears `holder`'s debt for the key `k`: the carrier verified that
/// holder's retirement of its copy. Neither an install, a handoff ack nor
/// an absence is such proof.
///
/// # Errors
/// Custody faults.
pub(crate) fn holder_retired(s: &Store, k: KeyRef, holder: EntityId) -> Result<()> {
    match s.core.key_custody.local() {
        Some(custody) => custody.clear_holder(&k.0, &holder),
        None => Ok(()),
    }
}

/// The catalog scrub of `KEY_CUSTODY_ERASABLE_REF` (FIX 8875), run in an
/// erase of `actor`'s own transaction (an entity that is no actor has
/// none): stages the retirement of every key of the actor, each metadata
/// row's and each orphan custody holds, then deletes the actor's rows. Holder debts stay until each holder's
/// retirement is verified. An archived vault's custody is its
/// replacement's: its rows go, its keys are not touched.
///
/// # Errors
/// Storage and custody faults.
pub(crate) fn scrub_actor_in_txn(vault: &Vault, w: &mut RwTxn<'_>, actor: &EntityId) -> Result<()> {
    if crate::deletion::names_no_actor(vault, w, actor)? {
        return Ok(());
    }
    let store = &vault.store;
    let purpose = ErasablePurpose::HomeHandoff;
    let mut items: std::collections::BTreeSet<ErasableItem> =
        erasable_refs_of_in_txn(store, w, purpose, actor.as_bytes())?
            .into_iter()
            .collect();
    if !store.core.gate_custody_archived()
        && let Some(custody) = store.core.key_custody.local()
    {
        items.extend(custody.erasable_keys_of(purpose, actor.as_bytes())?);
        for item in &items {
            stage_erasable_retirement_in_txn(store, w, &custody, item)?;
        }
    }
    for item in &items {
        delete_erasable_ref_in_txn(store, w, item)?;
    }
    Ok(())
}
