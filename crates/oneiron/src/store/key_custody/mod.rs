//! Typed key custody (KS-1): one storage and lifecycle service for the
//! independent, erasable secrets a vault keeps outside its restorable image.
//!
//! An entry is named by (vault, kind, item, generation) within its binding's
//! namespace ([`identity`]), lives in owner-only files beside the vault root
//! ([`files`]), is destroyed through a durable intent committed with its
//! client's redaction ([`retirement`]), and is planned before a restore and
//! forked for a copy served beside its source ([`fork`]). Custody owns
//! storage and lifecycle only, never permission policy: each kind's client
//! decides who may read, what a retirement waits on (its predicate) and which
//! rows a retired entry takes with it. Claim-bound Gate decisions
//! (`gate_decision::orcb`) are its first client.

mod anchor;
mod credential_faults;
mod erase_binding;
mod files;
mod folder;
mod fork;
mod head;
mod home;
mod identity;
mod log;
mod outbox;
mod platform;
pub mod protocol;
mod publication_policy;
mod publish;
mod recipients;
mod recovery;
mod retirement;
mod targets;

use std::path::PathBuf;
use std::sync::{OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

use heed::{RoTxn, RwTxn};

use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable, SideTableDbs};
use crate::store::Store;

pub(crate) use self::anchor::FileAnchor;
#[cfg(test)]
pub(in crate::store) use self::files::arm_after_key_marker_check;
pub(crate) use self::files::{EntryState, LocalCustody, custody_present};
pub(crate) use self::folder::FolderTarget;
pub(crate) use self::fork::{CustodyPlan, ForkedCustodyDir, Requirement};
pub(crate) use self::head::{CUSTODY_HEAD_WRAP_CONTEXT, CustodyRecipients};
pub(crate) use self::identity::{
    CustodyBinding, CustodyId, CustodyKind, CustodySecret, CustodySubject,
};
pub(in crate::store) use self::identity::{decode_native_path, encode_native_path};
pub(crate) use self::outbox::OutboxTarget;
// The one portable directory flush, for the training outbox too (FIX 6880).
pub use self::platform::sync_dir;
pub(crate) use self::publication_policy::TargetRecipients;
pub(crate) use self::publish::{CUSTODY_COMPLETION_NEEDS_ANCHOR, Publication, PublicationState};
pub(crate) use self::recipients::RecipientRetirement;
pub(crate) use self::recovery::{
    CustodyRequirement, CustodyRoute, CustodySourceAt, ROLLBACK_NOT_PROVEN, refuse_foreign_binding,
    route_custody,
};
#[cfg(test)]
pub(crate) use self::retirement::arm_before_retire_lock;
pub(crate) use self::retirement::{
    RetireCause, RetirementIntent, retirement_in_txn, retirement_prefix, retirements_in_rows,
    retirements_in_txn, stage_retirement_in_txn, standing_retirements_in_txn,
};
pub(crate) use self::targets::{MemberProgress, RetirementProgress};

/// The vault's custody binding, pinned by the first publication in the same
/// transaction as what it protects.
const BINDING: SideTable<(), CustodyBinding, Raw> =
    SideTable::new(&side_table::KEY_CUSTODY_BINDING);

/// The store's own identity, which a binding minted here takes as its vault.
const STORE_IDENTITY: SideTable<(), [u8; 32], Raw> =
    SideTable::new(&side_table::VAULT_IDENTITY_LOCAL);

fn binding_mismatch() -> Error {
    Error::CorruptedIndex("key custody binding")
}

/// One open vault's custody: shared by every handle on its store, base,
/// session and overlay alike.
pub(crate) struct KeyCustody {
    /// The canonical root the vault opened at, beside which a binding minted
    /// here keeps its custody.
    home: PathBuf,
    /// The binding read at open, or minted by this store's first
    /// publication; set once.
    binding: OnceLock<CustodyBinding>,
    /// The vault was archived when it opened: the custody it binds is its
    /// replacement's, so no handle on it mints or retires there
    /// ([`crate::store::StoreCore::gate_custody_archived`]).
    archived_at_open: bool,
    /// Readers hold the read half from before their LMDB snapshot to after
    /// their last decrypt; the finisher takes the write half before it
    /// touches an entry.
    lock: RwLock<()>,
}

impl KeyCustody {
    /// The custody of a vault opened at `home`, whose `vault_meta` holds the
    /// binding row `binding` when it is bound.
    pub(in crate::store) fn at_open(
        home: PathBuf,
        binding: Option<&[u8]>,
        archived_at_open: bool,
    ) -> Result<Self> {
        let bound = OnceLock::new();
        if let Some(raw) = binding {
            let _ = bound.set(BINDING.decode_value(raw)?);
        }
        Ok(Self {
            home,
            binding: bound,
            archived_at_open,
            lock: RwLock::new(()),
        })
    }

    pub(in crate::store) fn archived_at_open(&self) -> bool {
        self.archived_at_open
    }

    /// The canonical root the vault opened at.
    pub(in crate::store) fn home(&self) -> &std::path::Path {
        &self.home
    }

    /// The custody this store reads, once it has a binding: none was ever
    /// published under it before then.
    pub(crate) fn local(&self) -> Option<LocalCustody<'_>> {
        self.binding.get().map(LocalCustody::at)
    }

    /// Readers take this BEFORE opening an LMDB snapshot and hold it until
    /// their last decrypt, so no live snapshot loses an entry between its
    /// marker check and its file open.
    pub(crate) fn read_guard(&self) -> Result<RwLockReadGuard<'_, ()>> {
        self.lock
            .read()
            .map_err(|_| Error::InvariantViolation("key custody lock poisoned"))
    }

    fn write_guard(&self) -> Result<RwLockWriteGuard<'_, ()>> {
        self.lock
            .write()
            .map_err(|_| Error::InvariantViolation("key custody lock poisoned"))
    }

    /// Takes `committed` as this store's binding when it has none yet and
    /// `committed` sits beside `home`: a binding a restore's own transaction
    /// wrote under it. One beside another root is another vault's custody.
    pub(in crate::store) fn adopt(&self, committed: Option<&CustodyBinding>) -> Result<()> {
        if self.binding.get().is_none()
            && let Some(committed) = committed
        {
            if committed.root() != self.home.as_path() {
                return Err(binding_mismatch());
            }
            let _ = self.binding.set(committed.clone());
        }
        Ok(())
    }

    /// This store's binding, refused when another one is committed.
    fn checked(&self, committed: Option<&CustodyBinding>) -> Result<LocalCustody<'_>> {
        let binding = self.binding.get().ok_or_else(binding_mismatch)?;
        if committed.is_some_and(|committed| committed != binding) {
            return Err(binding_mismatch());
        }
        Ok(LocalCustody::at(binding))
    }

    /// The custody a publication in `txn` goes under: this store's binding,
    /// minted at its first publication (a fresh namespace beside `home`, for
    /// the store's own identity) and checked against the committed one.
    pub(crate) fn bind_in_txn(
        &self,
        dbs: &impl SideTableDbs,
        txn: &RoTxn<'_>,
    ) -> Result<LocalCustody<'_>> {
        let committed = BINDING.get(dbs, txn, &())?;
        self.adopt(committed.as_ref())?;
        if self.binding.get().is_none() {
            let vault = STORE_IDENTITY.get(dbs, txn, &())?;
            let _ = self
                .binding
                .set(CustodyBinding::mint(self.home.clone(), vault));
        }
        self.checked(committed.as_ref())
    }

    /// [`Self::bind_in_txn`], pinning the binding in `wtxn` when none is
    /// committed yet: the first publication commits it with what it
    /// protects.
    pub(crate) fn pin_in_txn(&self, dbs: &impl SideTableDbs, wtxn: &mut RwTxn<'_>) -> Result<()> {
        let binding = self.bind_in_txn(dbs, wtxn)?.binding().clone();
        if !BINDING.contains(dbs, wtxn, &())? {
            BINDING.put(dbs, wtxn, &(), &binding)?;
        }
        Ok(())
    }

    /// The custody a retirement in `txn` may destroy: this store's binding,
    /// when it is the committed one or none is committed. A restore's first
    /// handle still names its destination while the image's binding already
    /// sits in LMDB; the reopened vault finishes.
    fn committed_in_txn(
        &self,
        dbs: &impl SideTableDbs,
        txn: &RoTxn<'_>,
    ) -> Result<LocalCustody<'_>> {
        let committed = BINDING.get(dbs, txn, &())?;
        self.adopt(committed.as_ref())?;
        self.checked(committed.as_ref())
    }
}

/// The binding among raw `vault_meta` rows, if they hold one.
pub(crate) fn binding_in_rows(rows: &[(Vec<u8>, Vec<u8>)]) -> Result<Option<CustodyBinding>> {
    rows.iter()
        .find(|(key, _)| key == binding_key())
        .map(|(_, value)| BINDING.decode_value(value))
        .transpose()
}

/// Drops the image's custody binding and every retirement intent from a
/// restored vault in `wtxn`: a new-host restore of an image that names no
/// head, whose custody stayed on the old host. Its claim-bound rows are
/// dropped with them; the vault mints a binding of its own when it next
/// takes a key into custody, and no intent of the old custody's reaches a
/// key minted here.
pub(crate) fn unbind_in_txn(dbs: &impl SideTableDbs, wtxn: &mut RwTxn<'_>) -> Result<()> {
    BINDING.delete(dbs, wtxn, &())?;
    retirement::clear_all_in_txn(dbs, wtxn)
}

/// The binding row's full key.
pub(crate) fn binding_key() -> &'static [u8] {
    BINDING.decl().prefix
}

/// Puts `binding` as the vault's in `wtxn`: a fork's, replacing its
/// source's.
pub(crate) fn put_binding_in_txn(
    dbs: &impl SideTableDbs,
    wtxn: &mut RwTxn<'_>,
    binding: &CustodyBinding,
) -> Result<()> {
    BINDING.put(dbs, wtxn, &(), binding)
}

/// The binding committed in `txn`, if any.
pub(crate) fn binding_in_txn(
    dbs: &impl SideTableDbs,
    txn: &RoTxn<'_>,
) -> Result<Option<CustodyBinding>> {
    BINDING.get(dbs, txn, &())
}

/// An LMDB read snapshot taken under the custody read guard. Its fields drop
/// in order: the snapshot closes before the guard releases, so no finisher
/// destroys an entry a row in it still needs.
pub(crate) struct GuardedSnapshot<'a> {
    txn: RoTxn<'a>,
    _guard: RwLockReadGuard<'a, ()>,
}

impl<'a> std::ops::Deref for GuardedSnapshot<'a> {
    type Target = RoTxn<'a>;

    fn deref(&self) -> &RoTxn<'a> {
        &self.txn
    }
}

impl Store {
    /// A read snapshot that may decrypt custody-protected rows: the guard
    /// first, then the snapshot.
    pub(crate) fn custody_snapshot(&self) -> Result<GuardedSnapshot<'_>> {
        let guard = self.core.key_custody.read_guard()?;
        Ok(GuardedSnapshot {
            txn: self.env.read_txn()?,
            _guard: guard,
        })
    }
}
