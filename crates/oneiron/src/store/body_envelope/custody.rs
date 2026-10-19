//! Body instances in typed custody (KS-2A, FIX 5683 part A; owner KEY STORE
//! = A).
//!
//! Every body a vault keeps, a result's or an ASSET's, as a file or in its
//! row, on either tier, is one instance: a random id of its own, never the
//! body's digest, whose 32-byte key typed custody holds
//! ([`CustodyKind::BodyInstance`], item `instance (16) | scope (1)`,
//! generation 0). A later body of the same bytes is a new instance, so it
//! never shares a retired one's lifetime. Only the vault's scope is held: an
//! off-record session's file keys stay wrapped in its overlay, in memory,
//! and never reach custody or an image.
//!
//! - A Mint is a synced journal frame (KS-4A1), so an instance is minted
//!   before any writer that names it opens, never inside one ([`BodyMint`]);
//!   a writer that must name new instances takes ones minted before it
//!   opened ([`BodyMint::reserve`]). One minted and never named is ordinary
//!   debris, not an erase.
//! - The transaction that commits a row naming an instance pins the custody
//!   binding with it ([`pin_body_custody_in_txn`]).
//! - A sealed file is the instance's envelope under its key; a plain file
//!   is plain, and its local reads take no key. A checkpoint carries every
//!   body sealed under its instance's key, so no image holds a key or a
//!   wrap that recovers one: only current custody opens it.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};

use heed::{RoTxn, RwTxn};
use zeroize::Zeroizing;

use super::frames::FileKey;
use crate::error::{Error, Result, StoreError};
use crate::side_table::SideTableDbs;
use crate::store::key_custody::{CustodyBinding, CustodyId, CustodyKind, EntryState, LocalCustody};
use crate::store::{ManifestDbs, Store};

/// The scope byte of a vault's body instance, the one scope custody holds.
const VAULT_SCOPE: u8 = 0;

/// `instance (16) | scope (1)`: a body instance's custody item.
fn item(instance: &[u8; 16]) -> [u8; 17] {
    let mut item = [VAULT_SCOPE; 17];
    item[..16].copy_from_slice(instance);
    item
}

/// The custody id of the vault's body instance `instance` under `binding`.
pub(crate) fn instance_id(binding: &CustodyBinding, instance: &[u8; 16]) -> Result<CustodyId> {
    Ok(binding
        .subject(CustodyKind::BodyInstance, &item(instance))?
        .at(0))
}

/// The body instance a custody id names, when it is one of the vault's.
pub(crate) fn instance_of(id: &CustodyId) -> Option<[u8; 16]> {
    let item = id.subject().item();
    if id.kind() != CustodyKind::BodyInstance || item.get(16) != Some(&VAULT_SCOPE) {
        return None;
    }
    item.get(..16)?.try_into().ok()
}

/// What custody holds for `instance` under `binding`: live, retired, or
/// missing.
pub(crate) fn instance_state(binding: &CustodyBinding, instance: &[u8; 16]) -> Result<EntryState> {
    LocalCustody::at(binding).state(&instance_id(binding, instance)?)
}

/// The key of the vault's body instance `instance`, read from `binding`'s
/// custody: strict, a retired or damaged entry reads as body custody's
/// corruption and a missing one fails. Never minted here.
pub(crate) fn body_key_in(binding: &CustodyBinding, instance: &[u8; 16]) -> Result<Arc<FileKey>> {
    let custody = LocalCustody::at(binding);
    let id = instance_id(binding, instance)?;
    match custody.read(&id) {
        Ok(secret) => file_key(binding, *instance, secret.expose()),
        Err(error) => match custody.state(&id) {
            Ok(EntryState::Missing) => Err(custody_unavailable(1)),
            _ => Err(error),
        },
    }
}

/// `body_key_custody_unavailable`: `missing` body instances a read or a
/// restore needs that current custody holds neither live nor retired.
pub(crate) fn custody_unavailable(missing: usize) -> Error {
    crate::error::ArtifactError::BodyKeyCustodyUnavailable { missing }.into()
}

fn file_key(binding: &CustodyBinding, instance: [u8; 16], secret: &[u8]) -> Result<Arc<FileKey>> {
    let mut raw = Zeroizing::new([0u8; 32]);
    if secret.len() != raw.len() {
        return Err(CustodyKind::BodyInstance.corrupt());
    }
    raw.copy_from_slice(secret);
    Ok(Arc::new(FileKey::from_raw(
        *binding.vault().as_bytes(),
        instance,
        raw,
    )))
}

/// One body instance whose key custody holds: published, its Mint
/// journaled and synced, before any row names it.
pub(crate) struct BodyInstance {
    key: Arc<FileKey>,
}

impl BodyInstance {
    pub(crate) fn instance(&self) -> &[u8; 16] {
        self.key.instance()
    }

    pub(super) fn key(&self) -> &Arc<FileKey> {
        &self.key
    }
}

/// Mints the vault's body instances under one custody binding, outside every
/// writer. A clone mints under the same binding and shares its reserve.
#[derive(Clone)]
pub(crate) struct BodyMint {
    binding: CustodyBinding,
    /// Instances minted before a writer opened, which [`Self::mint`] takes
    /// in turn inside it rather than mint one there.
    reserve: Option<Arc<Mutex<VecDeque<[u8; 16]>>>>,
}

impl BodyMint {
    /// A new body instance: a reserved one when this mint holds a reserve,
    /// else a fresh one, its key published and its Mint journaled and
    /// synced before this returns.
    ///
    /// # Errors
    ///
    /// Custody's errors, and a reserve that ran out: a writer never mints.
    pub(crate) fn mint(&self) -> Result<BodyInstance> {
        let custody = LocalCustody::at(&self.binding);
        if let Some(reserve) = &self.reserve {
            let instance = reserve
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front()
                .ok_or(Error::InvariantViolation(
                    "a writer's reserve of body instances ran out",
                ))?;
            return body_key_in(&self.binding, &instance).map(|key| BodyInstance { key });
        }
        let mut instance = [0u8; 16];
        crate::world_keys::os_fill(&mut instance)?;
        let secret = custody.get_or_create(&instance_id(&self.binding, &instance)?)?;
        Ok(BodyInstance {
            key: file_key(&self.binding, instance, secret.expose())?,
        })
    }

    /// A mint holding `count` instances minted now, before the writer that
    /// will name them opens: inside it, [`Self::mint`] takes them in turn
    /// and journals nothing. One the writer leaves unnamed is debris.
    ///
    /// # Errors
    ///
    /// Custody's errors.
    pub(crate) fn reserve(&self, count: usize) -> Result<Self> {
        let mut reserved = VecDeque::with_capacity(count);
        for _ in 0..count {
            let instance = Self {
                binding: self.binding.clone(),
                reserve: None,
            }
            .mint()?;
            reserved.push_back(*instance.instance());
        }
        Ok(Self {
            binding: self.binding.clone(),
            reserve: Some(Arc::new(Mutex::new(reserved))),
        })
    }
}

/// The mint of the store `dbs` writes, its binding read in `txn` (a read
/// transaction, never a writer): bound in memory at its first use, pinned
/// by the first transaction that commits a row naming an instance. An
/// archived vault mints nothing: its custody is its replacement's.
///
/// # Errors
///
/// [`StoreError::ArchivedVault`], and a committed binding of another vault.
pub(crate) fn body_mint_in<D: ManifestDbs + SideTableDbs>(
    dbs: &D,
    txn: &RoTxn<'_>,
) -> Result<BodyMint> {
    if dbs.gate_custody_archived() {
        return Err(Error::Store(StoreError::ArchivedVault));
    }
    let custody = dbs.key_custody().bind_in_txn(dbs, txn)?;
    Ok(BodyMint {
        binding: custody.binding().clone(),
        reserve: None,
    })
}

/// Pins the custody binding of the store `dbs` writes in `wtxn`, the
/// transaction that commits a row naming one of its body instances.
///
/// # Errors
///
/// Storage errors, and a committed binding of another vault.
pub(crate) fn pin_body_custody_in_txn<D: ManifestDbs + SideTableDbs>(
    dbs: &D,
    wtxn: &mut RwTxn<'_>,
) -> Result<()> {
    dbs.key_custody().pin_in_txn(dbs, wtxn)
}

impl Store {
    /// This vault's body mint ([`body_mint_in`]), its binding read in a
    /// fresh read transaction. Call it before the writer that will name
    /// what it mints opens.
    ///
    /// # Errors
    ///
    /// As [`body_mint_in`].
    pub(crate) fn body_mint(&self) -> Result<BodyMint> {
        let rtxn = self.env.read_txn()?;
        body_mint_in(self, &rtxn)
    }

    /// The binding this vault's body instances are read under: `None`
    /// before its first publication, when no row names one.
    pub(crate) fn body_custody(&self) -> Option<CustodyBinding> {
        self.core
            .key_custody
            .local()
            .map(|custody| custody.binding().clone())
    }
}
