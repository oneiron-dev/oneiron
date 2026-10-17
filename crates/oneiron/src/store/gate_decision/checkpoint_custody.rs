//! What a checkpoint restore needs from exterior key custody, the side
//! restore's custody fork (ARCH-0038 #erasure-completeness, "Key custody in a
//! side restore"), and the archive a restore in a vault's place sets aside.
//!
//! A restore that takes its vault's place keeps that vault's custody. A copy
//! served beside its source gets custody of its own at restore time: only the
//! keys still live in the source's custody are copied, so a destroyed key
//! stays destroyed, and from then on each vault shreds only its own keys. The
//! vault a restore in place sets aside still binds the custody its
//! replacement now holds, so it is archived: it reads, and refuses every
//! write until an owner activates it as a side vault, which forks its custody
//! the same way.
//!
//! Host-order legal holds are live state of the same kind: runtime rows no
//! image carries (OF-470 C2). A source's whole host-order family is read with
//! its custody, and a restore beside it, or an activation, takes it on.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use heed::types::Bytes;
use heed::{Env, RoTxn, RwTxn};

use crate::error::{Error, Result, StoreError};
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::store::not_an_existing_root;
#[cfg(unix)]
use crate::store::root_directory::{
    FileIdentity, file_identity, make_directory, named_directory_identity, parent_or_here,
    refuse_shared_path, refuse_shared_vault_root, remove_held_directory,
};
use crate::store::{Store, VaultWriterLease, read_existing_vault_meta};

use super::keys::GATE_DECISION_KEY_PREFIX;
use super::ledger::{CUSTODY_ROOT, LEDGER};
use super::orcb::{self, CUSTODY_ROOT_KEY, ForkedCustodyDir, corrupt};
use super::retention::{checkpoint_retirements, retirement_prefixes};
use super::types::GateDecisionId;

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// The host-order legal-hold family in `vault_meta`: its holds, their target
/// index, the host-only log and erase links (`legal_hold`).
const HOST_HOLD_PREFIX: &[u8] = b"legal_hold:host:";

/// A vault's archive mark. [`ARCHIVED_ANYWHERE`]: archived wherever it is.
/// [`LIVE_ONLY_AT`] and a canonical root: archived unless it sits at that
/// root. A restore in a vault's place gives that mark, for the vault's path,
/// to its replacement when it is made and to the vault before the swap, so
/// at every instant of the swap, and after a crash anywhere in it, the one of
/// the two at the vault's path is the one live vault on its custody.
const ARCHIVED: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::VAULT_ARCHIVED_BY_RESTORE);
const ARCHIVED_ANYWHERE: u8 = 1;
const LIVE_ONLY_AT: u8 = 2;

/// The store's own identity, so a source read off its path is known again.
const STORE_IDENTITY: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::VAULT_IDENTITY_LOCAL);

fn archived() -> Error {
    Error::Store(StoreError::ArchivedVault)
}

/// Whether a vault opened at the canonical `own_root`, holding archive mark
/// `mark`, is archived.
pub(in crate::store) fn archived_by(mark: Option<&[u8]>, own_root: &Path) -> Result<bool> {
    match mark {
        None => Ok(false),
        Some([ARCHIVED_ANYWHERE]) => Ok(true),
        Some([LIVE_ONLY_AT, home @ ..]) => Ok(orcb::decode_custody_root(home)? != own_root),
        Some(_) => Err(Error::CorruptedIndex("vault archive mark")),
    }
}

fn live_only_at(home: &Path) -> Result<Vec<u8>> {
    let mut mark = vec![LIVE_ONLY_AT];
    mark.extend(orcb::encode_custody_root(home)?);
    Ok(mark)
}

/// The `vault_meta` rows a vault's live custody state is read from: its
/// custody binding, its archive mark, its store identity, its key-retirement
/// intents, and its host orders, whose target index the intents read.
fn live_custody_prefixes() -> Vec<&'static [u8]> {
    let mut prefixes = vec![
        CUSTODY_ROOT_KEY,
        ARCHIVED.decl().prefix,
        STORE_IDENTITY.decl().prefix,
    ];
    prefixes.extend(
        retirement_prefixes()
            .into_iter()
            .filter(|prefix| !prefix.starts_with(HOST_HOLD_PREFIX)),
    );
    prefixes.push(HOST_HOLD_PREFIX);
    prefixes
}

/// Whether a host-order row is one the key-retirement intents read.
fn host_row_is_intent(key: &[u8]) -> bool {
    retirement_prefixes()
        .iter()
        .any(|prefix| prefix.starts_with(HOST_HOLD_PREFIX) && key.starts_with(prefix))
}

/// Every host-order row of an open vault, read in `txn`.
pub(crate) fn host_hold_rows_in_txn(store: &Store, txn: &RoTxn<'_>) -> Result<Rows> {
    vault_meta_rows(&store.env, txn, &[HOST_HOLD_PREFIX])
}

/// Replaces every host-order row of a vault with `rows`, in `wtxn`. Rows
/// outside the family are refused.
pub(crate) fn replace_host_holds_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    rows: &[(Vec<u8>, Vec<u8>)],
) -> Result<()> {
    if rows
        .iter()
        .any(|(key, _)| !key.starts_with(HOST_HOLD_PREFIX))
    {
        return Err(Error::CorruptedIndex("host-order legal hold rows"));
    }
    let vault_meta = store
        .env
        .open_database::<Bytes, Bytes>(wtxn, Some("vault_meta"))?
        .ok_or(Error::CorruptedIndex("vault holds no side-table database"))?;
    let stale: Vec<Vec<u8>> = vault_meta
        .prefix_iter(wtxn, HOST_HOLD_PREFIX)?
        .map(|row| row.map(|(key, _)| key.to_vec()))
        .collect::<std::result::Result<_, _>>()?;
    for key in stale {
        vault_meta.delete(wtxn, &key)?;
    }
    for (key, value) in rows {
        vault_meta.put(wtxn, key, value)?;
    }
    Ok(())
}

/// One vault's live key-custody state, read when a side restore of it
/// starts: where its custody is, and its key-retirement intents with their
/// erase marks and holds.
pub(crate) struct LiveCustody {
    root: PathBuf,
    store_identity: Option<Vec<u8>>,
    rows: Rows,
    /// Its whole host-order family, for the vault a restore makes beside it.
    host_holds: Rows,
}

impl LiveCustody {
    /// From the [`live_custody_prefixes`] rows of a vault opened at the
    /// canonical `own_root`; with no binding its custody is the one beside
    /// `own_root`. An archived vault's custody belongs to the vault that
    /// replaced it, so its own state is no source's.
    fn from_rows(own_root: &Path, rows: Rows) -> Result<Self> {
        let mut root = own_root.to_path_buf();
        let mut mark = None;
        let mut store_identity = None;
        let mut intents = Vec::new();
        let mut host_holds = Vec::new();
        for (key, value) in rows {
            if key == ARCHIVED.decl().prefix {
                mark = Some(value);
            } else if key == STORE_IDENTITY.decl().prefix {
                store_identity = Some(value);
            } else if key == CUSTODY_ROOT_KEY {
                root = orcb::decode_custody_root(&value)?;
            } else if key.starts_with(HOST_HOLD_PREFIX) {
                if host_row_is_intent(&key) {
                    intents.push((key.clone(), value.clone()));
                }
                host_holds.push((key, value));
            } else {
                intents.push((key, value));
            }
        }
        if archived_by(mark.as_deref(), own_root)? {
            return Err(archived());
        }
        Ok(Self {
            root,
            store_identity,
            rows: intents,
            host_holds,
        })
    }

    /// The source's whole host-order family, as it was read.
    pub(crate) fn host_holds(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.host_holds
    }

    /// Whether `other`, read later, is the state of the same vault: the same
    /// store, bound to the same custody.
    pub(crate) fn same_vault(&self, other: &Self) -> bool {
        self.root == other.root && self.store_identity == other.store_identity
    }
}

/// Refuses a missing vault at `vault_dir` here, not by a later lookup, which
/// could find a vault someone else put under the name: a sticky parent stops
/// no one from making a new entry in it. Links are followed, so a link to a
/// missing directory is missing too (C8 review r9).
fn refuse_missing_vault_root(vault_dir: &Path) -> Result<()> {
    match std::fs::metadata(vault_dir) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(not_an_existing_root(vault_dir, false))
        }
        Err(error) => Err(error.into()),
    }
}

/// Admits the existing vault at `vault_dir` before anything opens it by name,
/// as a restore admits its destination: refused when missing, and where
/// another user could move a directory on its path.
pub(crate) fn admit_existing_vault_root(vault_dir: &Path) -> Result<()> {
    refuse_missing_vault_root(vault_dir)?;
    #[cfg(unix)]
    refuse_shared_vault_root(vault_dir)?;
    Ok(())
}

/// The live custody state of the vault at `vault_dir`, read without opening
/// it as a vault, through the read-only door (`read_existing_vault_meta`): a
/// vault another process serves reads beside it, and one this process holds,
/// under any name, is refused. A missing or unreadable vault refuses.
pub(crate) fn read_live_custody(vault_dir: &Path) -> Result<LiveCustody> {
    // A shared directory on the source's path is no reason to refuse: the
    // vault opens, reads and writes there as it is, so whoever could move it
    // could change it already. The source reports it instead.
    refuse_missing_vault_root(vault_dir)?;
    #[cfg(test)]
    if let Some(callback) = BEFORE_LIVE_CUSTODY_READ.with(|slot| slot.borrow_mut().take()) {
        callback();
    }
    let read = read_existing_vault_meta(vault_dir, &live_custody_prefixes())?;
    LiveCustody::from_rows(&read.root, read.rows)
}

/// The rows under `prefixes` of an open vault's `vault_meta`.
fn vault_meta_rows(env: &Env, txn: &RoTxn<'_>, prefixes: &[&[u8]]) -> Result<Rows> {
    let vault_meta = env
        .open_database::<Bytes, Bytes>(txn, Some("vault_meta"))?
        .ok_or(Error::CorruptedIndex("vault holds no side-table database"))?;
    let mut rows = Vec::new();
    for prefix in prefixes {
        for row in vault_meta.prefix_iter(txn, prefix)? {
            let (key, value) = row?;
            rows.push((key.to_vec(), value.to_vec()));
        }
    }
    Ok(rows)
}

/// The directory `store`'s environment was opened on, by its bound root
/// descriptor: the same directory wherever any name of it now points.
#[cfg(unix)]
fn opened_directory(store: &Store) -> Result<FileIdentity> {
    let root = store
        .owner
        .env
        ._bound_root_dir
        .as_ref()
        .ok_or(Error::InvariantViolation("vault root descriptor missing"))?;
    Ok(file_identity(&root.metadata()?))
}

/// No directory identity here; nothing is archived to check it for.
#[cfg(not(unix))]
fn opened_directory(_: &Store) -> Result<()> {
    Ok(())
}

/// Whether `path` itself, not a link at it, names the directory `opened`.
#[cfg(unix)]
fn names(path: &Path, opened: &FileIdentity) -> Result<bool> {
    Ok(named_directory_identity(path)?.as_ref() == Some(opened))
}

#[cfg(not(unix))]
fn names(_: &Path, (): &()) -> Result<bool> {
    Ok(true)
}

/// The directory a restore made for its copy, and the copy's writer lease.
/// Each open of the copy goes by name, and is checked against the directory
/// made: rows are written into, and a mark lifted from, only that one, never a
/// directory moved in under its name since.
///
/// The lease is taken as the directory is made and held to the commit, where
/// the copy's vault takes it over ([`MadeDestination::keep`]): no other owner
/// opens the copy between the restore's opens. Dropped before that, after the
/// copy's vault has closed, this removes the directory it made with
/// everything in it, through the descriptor it holds and still under the
/// lease. A directory moved in under the name since is left as it is, and so
/// is one another owner leased first (review r1, both F1). Off unix, with no
/// identity to check, it removes the destination by name, still only under
/// the copy's lease, as main's discard did once the copy had opened; no lease
/// is granted off unix today, so there it removes nothing.
pub(crate) struct MadeDestination {
    destination: PathBuf,
    #[cfg(unix)]
    made: std::fs::File,
    #[cfg(unix)]
    identity: FileIdentity,
    lease: Option<VaultWriterLease>,
    kept: bool,
}

impl MadeDestination {
    /// Makes `destination`, which must not exist yet, owner-only, and takes
    /// its writer lease. It is refused unless no other user can move an entry
    /// on the way to it, or, for a copy that will replace the live vault at
    /// `home`, on the way to that vault or inside it: on such a path no name
    /// this restore makes, opens or exchanges can be changed under it.
    pub(crate) fn make(destination: &Path, home: Option<&Path>) -> Result<Self> {
        #[cfg(unix)]
        let made = {
            refuse_shared_path(parent_or_here(destination.parent().unwrap_or(destination)))?;
            if let Some(home) = home {
                refuse_shared_vault_root(home)?;
            }
            make_directory(destination)?
        };
        #[cfg(not(unix))]
        {
            let _ = home;
            std::fs::create_dir(destination)?;
        }
        let mut guard = Self {
            destination: destination.to_owned(),
            #[cfg(unix)]
            identity: file_identity(&made.metadata()?),
            #[cfg(unix)]
            made,
            lease: None,
            kept: false,
        };
        #[cfg(test)]
        if let Some(callback) = AFTER_RESTORE_DESTINATION_MADE.with(|slot| slot.borrow_mut().take())
        {
            callback();
        }
        // Through the directory made, so nothing is locked or written in one
        // moved in under the name (review r2, Astra F2).
        #[cfg(unix)]
        let lease =
            VaultWriterLease::acquire_held(guard.made.try_clone()?, &destination.canonicalize()?)?;
        #[cfg(not(unix))]
        let lease = VaultWriterLease::acquire(&destination.canonicalize()?)?;
        guard.lease = Some(lease);
        Ok(guard)
    }

    /// The copy's writer lease, for each open of it.
    pub(crate) fn lease(&self) -> Result<&VaultWriterLease> {
        self.lease
            .as_ref()
            .ok_or_else(|| Error::InvalidConfig("a restore's copy holds no writer lease".into()))
    }

    /// Refuses unless `store` is open on the directory made.
    pub(crate) fn holds(&self, store: &Store) -> Result<()> {
        #[cfg(unix)]
        if opened_directory(store)? != self.identity {
            return Err(moved());
        }
        #[cfg(not(unix))]
        let _ = store;
        Ok(())
    }

    /// Keeps the copy, its restore committed: `copy`, its vault, takes over
    /// the writer lease.
    pub(crate) fn keep(mut self, copy: &mut crate::Vault) {
        self.kept = true;
        if let Some(lease) = self.lease.take() {
            copy.adopt_writer_lease(lease);
        }
    }
}

/// A restore's copy is no longer where the restore made it.
fn moved() -> Error {
    Error::InvalidConfig("a restore's copy no longer sits where it was made".into())
}

impl Drop for MadeDestination {
    fn drop(&mut self) {
        if self.kept {
            return;
        }
        // Only under its own lease: without it, the copy is another owner's,
        // or, off unix, was never opened (review r3, Sol F3).
        let removed = self.lease.take().is_some_and(|lease| {
            #[cfg(unix)]
            let removed = remove_held_directory(&self.destination, &self.made).is_ok();
            // With no directory identity to check, the destination goes by
            // name after the copy's vault has closed, as main's discard took
            // it (Engine ruling on review r1's F2).
            #[cfg(not(unix))]
            let removed = std::fs::remove_dir_all(&self.destination).is_ok();
            drop(lease);
            removed
        });
        if !removed {
            tracing::warn!("a refused restore left the copy it made in place");
        }
    }
}

/// Syncs the directory holding `path`, so a rename of `path` is on disk.
fn sync_parent(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(parent) => std::fs::File::open(parent)?.sync_all(),
        None => Ok(()),
    }
}

/// The custody a checkpoint's claim-bound receipts bind to, checked before a
/// restore creates its destination.
pub(crate) struct CheckpointCustody {
    bound: Option<PathBuf>,
    erased: Vec<(GateDecisionId, [u8; 16])>,
    /// Per claim: the newest key generation a row or a retirement intent
    /// names, and the newest one a committed retirement destroys.
    claims: BTreeMap<[u8; 16], (u64, Option<u64>)>,
}

impl CheckpointCustody {
    /// The rows a restore drops: their key generation was destroyed after
    /// the image was taken, or a committed retirement destroys it.
    pub(crate) fn erased(&self) -> &[(GateDecisionId, [u8; 16])] {
        &self.erased
    }
}

/// Authenticate encrypted canonical rows against CURRENT exterior keys before
/// restore creates its destination. The image supplies a pointer, not a key;
/// deleted keys remain absent when an old checkpoint is replayed.
///
/// A row whose key generation carries a retirement marker was erased (or
/// aged out) after the image was taken. So was a row under a generation that
/// a committed retirement destroys, though its finisher has not run yet: one
/// among `rows`, or among `source`'s, the live state of the vault a side
/// restore copies, which wins over the image's. Such a row is listed, not
/// decoded, so the restore drops it: the restored vault is the vault at that
/// time without the receipts an erase destroyed. A key that is merely
/// missing, with no marker, is lost custody and still refuses the restore.
pub(crate) fn preflight_checkpoint_rows(
    rows: &[(Vec<u8>, Vec<u8>)],
    source: Option<&LiveCustody>,
) -> Result<CheckpointCustody> {
    let bound = rows
        .iter()
        .find(|(key, _)| key == CUSTODY_ROOT_KEY)
        .map(|(_, value)| orcb::decode_custody_root(value))
        .transpose()?;
    let mut retirements = checkpoint_retirements(rows)?;
    if let Some(source) = source {
        // The source's intents say nothing about another vault's keys.
        if bound.as_ref().is_some_and(|bound| *bound != source.root) {
            return Err(Error::InvalidConfig(
                "this checkpoint's key custody is not its source vault's".into(),
            ));
        }
        retirements.extend(checkpoint_retirements(&source.rows)?);
    }
    let mut claims = BTreeMap::new();
    for (claim, through, committed) in retirements {
        claims.insert(claim, (through, committed.then_some(through)));
    }
    let mut erased = Vec::new();
    for (key, value) in rows {
        if key.starts_with(GATE_DECISION_KEY_PREFIX) && orcb::is_orcb(value) {
            let root = bound.as_deref().ok_or_else(corrupt)?;
            let id = key
                .strip_prefix(GATE_DECISION_KEY_PREFIX)
                .and_then(GateDecisionId::decode_key)
                .ok_or(Error::CorruptedIndex("gate decision ledger key"))?;
            let (claim, generation) = orcb::raw_claim_generation(value).ok_or_else(corrupt)?;
            let (through, committed) = claims.entry(claim).or_insert((generation, None));
            *through = (*through).max(generation);
            if committed.is_some_and(|newest| generation <= newest)
                || orcb::generation_retired(root, &claim, generation)?
            {
                erased.push((id, claim));
            } else {
                orcb::decode_hot(root, id, value)?;
            }
        }
    }
    Ok(CheckpointCustody {
        bound,
        erased,
        claims,
    })
}

/// A side restore forks custody into a directory of its own beside
/// `destination`. One already there, left by a vault removed without its
/// custody, is refused before the destination is created, never merged.
pub(crate) fn refuse_custody_beside(destination: &Path) -> Result<()> {
    if cfg!(unix) && orcb::custody_present(&std::path::absolute(destination)?)? {
        return Err(Error::InvalidConfig(
            "key custody already exists beside the restore destination; restore elsewhere".into(),
        ));
    }
    Ok(())
}

impl Store {
    /// This vault's live custody state, for a side restore of it.
    pub(crate) fn live_custody(&self) -> Result<LiveCustody> {
        if self.env.is_sealed() {
            return Err(archived());
        }
        let txn = self.env.read_txn()?;
        let rows = vault_meta_rows(&self.env, &txn, &live_custody_prefixes())?;
        LiveCustody::from_rows(self.env.path(), rows)
    }

    /// Forks the custody `custody` binds to into this restored copy's own,
    /// beside its root, and binds the copy to it in this transaction. The
    /// copied keys are synced before the binding commits. Returns the
    /// directory the fork created, if it had anything to copy.
    pub(crate) fn fork_gate_custody_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        custody: &CheckpointCustody,
    ) -> Result<Option<ForkedCustodyDir>> {
        self.fork_gate_custody_to_in_txn(wtxn, custody, &self.core.gate_custody_root)
    }

    fn fork_gate_custody_to_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        custody: &CheckpointCustody,
        root: &Path,
    ) -> Result<Option<ForkedCustodyDir>> {
        if cfg!(not(unix)) {
            // No exterior custody exists here, so there is none to fork.
            return Ok(None);
        }
        let binding = orcb::encode_custody_root(root)?;
        let forked = match custody.bound.as_deref() {
            Some(source) => {
                let claims: Vec<_> = custody
                    .claims
                    .iter()
                    .map(|(claim, (through, committed))| (*claim, *through, *committed))
                    .collect();
                orcb::fork_custody(source, root, &claims)?
            }
            None => None,
        };
        if let Err(err) = CUSTODY_ROOT.put(self, wtxn, &(), &binding) {
            if let Some(forked) = forked {
                forked.remove();
            }
            return Err(err);
        }
        Ok(forked)
    }

    /// Marks this restored replacement live only at `home`, the path of the
    /// vault it replaces, in the restore's first transaction: until a swap
    /// puts it there, every open of it is archived.
    pub(crate) fn mark_live_only_at_in_txn(&self, wtxn: &mut RwTxn<'_>, home: &Path) -> Result<()> {
        if cfg!(not(unix)) {
            // No exterior custody exists here, so none is shared.
            return Ok(());
        }
        ARCHIVED.put(self, wtxn, &(), &live_only_at(home)?)
    }

    /// Lifts the seal its open put on this handle of a replacement the
    /// restore marked live only at `home` is still building. The handle
    /// writes its rows; the custody it shares with the vault at `home` stays
    /// out of its reach, as it opened archived.
    pub(crate) fn unseal_replacement(&self, home: &Path) -> Result<()> {
        if cfg!(unix) {
            let mark = ARCHIVED.get(self, &self.env.read_txn()?, &())?;
            if mark != Some(live_only_at(home)?) || !self.core.gate_custody_archived_at_open {
                return Err(Error::InvariantViolation("a replacement's archive mark"));
            }
        }
        self.env.unseal();
        Ok(())
    }

    /// A restore in this vault's place: `replacement`, marked live only at
    /// this vault's path when it was made, takes that place through `swap`,
    /// which exchanges the two directories, and this vault is archived.
    ///
    /// The two paths must name the two directories the handles opened, by
    /// their bound root descriptors, or nothing is marked and nothing moves.
    /// Before the swap this vault gets the same mark, committed under the
    /// writer, and this handle is sealed before any other writer begins. So
    /// whichever of the two sits at the path is the one live vault on the
    /// custody they share, at every instant and after a crash anywhere. A
    /// swap that fails, or returns without each directory found at the
    /// other's path, is refused and leaves both marks as they are. Once the
    /// swap is on disk, this vault is archived wherever it goes and the
    /// replacement's mark is lifted; a failure there is only logged, both
    /// marks already saying the same, and the replacement keeps its mark,
    /// live only at that path.
    ///
    /// `fence` reads this vault under the writer, before the mark: a refusal
    /// there changes nothing, and no write lands between it and the seal.
    pub(crate) fn swap_out(
        &self,
        replacement: &Store,
        fence: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
        swap: impl FnOnce() -> std::io::Result<()>,
    ) -> Result<()> {
        if cfg!(not(unix)) {
            // No exterior custody exists here, so none is shared.
            let txn = self.env.write_txn()?;
            fence(&txn)?;
            drop(txn);
            return Ok(swap()?);
        }
        let mark = live_only_at(self.env.path())?;
        if ARCHIVED.get(replacement, &replacement.env.read_txn()?, &())? != Some(mark.clone()) {
            return Err(Error::InvalidConfig(
                "the replacement was not restored for this vault's place".into(),
            ));
        }
        // Each path must name the directory its handle opened, before any
        // mark: a directory moved under either name refuses, nothing changed.
        let live_dir = opened_directory(self)?;
        let replacement_dir = opened_directory(replacement)?;
        let in_place =
            names(self.env.path(), &live_dir)? && names(replacement.env.path(), &replacement_dir)?;
        if !in_place {
            return Err(Error::InvalidConfig(
                "a vault directory no longer sits at its path".into(),
            ));
        }
        let mut wtxn = self.env.write_txn()?;
        fence(&wtxn)?;
        ARCHIVED.put(self, &mut wtxn, &(), &mark)?;
        self.env.seal();
        wtxn.commit()?;
        // A failed swap is no proof that nothing moved, and a name checked
        // now could move before a lift commits: the mark stays, and whichever
        // of the two sits at the path is still the one live vault.
        swap()?;
        let exchanged =
            names(self.env.path(), &replacement_dir)? && names(replacement.env.path(), &live_dir)?;
        if !exchanged {
            return Err(Error::InvalidConfig(
                "the swap did not exchange the two vault directories".into(),
            ));
        }
        // Neither mark stops depending on where its vault sits before the
        // exchange is on disk: a crash that undid it would leave the two
        // where the marks no longer say which is live.
        if let Err(error) = [self.env.path(), replacement.env.path()]
            .into_iter()
            .try_for_each(sync_parent)
        {
            tracing::warn!(%error, "a swap not yet on disk leaves both vaults live only at its path");
            return Ok(());
        }
        // The replacement's mark is lifted only once this vault's no longer
        // depends on where it sits.
        match self.put_archive_mark(Some(&[ARCHIVED_ANYWHERE])) {
            Ok(()) => {
                if let Err(error) = replacement.put_archive_mark(None) {
                    tracing::warn!(%error, "a replacement stays live only at the path it now holds");
                }
            }
            Err(error) => {
                tracing::warn!(%error, "a replaced vault and its replacement stay archived away from its path");
            }
        }
        Ok(())
    }

    /// Rewrites this vault's archive mark, or lifts it, past the seal.
    fn put_archive_mark(&self, mark: Option<&[u8]>) -> Result<()> {
        let mut wtxn = self.env.past_seal_write_txn()?;
        match mark {
            Some(mark) => ARCHIVED.put(self, &mut wtxn, &(), &mark.to_vec())?,
            None => {
                ARCHIVED.delete(self, &mut wtxn, &())?;
            }
        }
        Ok(wtxn.commit()?)
    }

    /// Seals this handle when its vault is archived; every open ends here.
    pub(crate) fn seal_if_archived(&self) -> Result<()> {
        if self.archived_in_txn(&self.env.read_txn()?)? {
            self.env.seal();
        }
        Ok(())
    }

    /// Whether this vault is archived: by its mark, read in `txn`, or by the
    /// seal a restore's swap put on this handle.
    pub(super) fn archived_in_txn(&self, txn: &RoTxn<'_>) -> Result<bool> {
        Ok(self.env.is_sealed()
            || archived_by(ARCHIVED.get(self, txn, &())?.as_deref(), self.env.path())?)
    }

    /// Refuses when this vault is archived: its live state is not the live
    /// state of the custody it binds to.
    pub(crate) fn refuse_archived(&self) -> Result<()> {
        if self.archived_in_txn(&self.env.read_txn()?)? {
            return Err(archived());
        }
        Ok(())
    }

    /// An owner's activation of this archived vault as a side vault of the
    /// vault whose live custody state is `source`, the one that replaced it.
    /// Its custody forks as a side restore's does, into a directory of its
    /// own beside its root: every receipt it holds is checked against the
    /// custody it binds to first, a key `source` destroyed or has committed
    /// to destroy is not copied and the receipts under it are dropped, every
    /// receipt it keeps is read back under the forked keys, and only then
    /// does the new binding commit, with the archive mark lifted and this
    /// install's machine identity dropped, the replacement keeping it. Anything
    /// short of that leaves it archived, as it was. The caller reopens the
    /// vault, whose handles then shred only its own keys.
    pub(crate) fn activate_archived(&self, source: &LiveCustody) -> Result<()> {
        let rows = {
            let txn = self.env.read_txn()?;
            let mark = ARCHIVED.get(self, &txn, &())?;
            if !archived_by(mark.as_deref(), self.env.path())? {
                return Err(Error::InvalidConfig("this vault is not archived".into()));
            }
            let mut prefixes = live_custody_prefixes();
            prefixes.push(GATE_DECISION_KEY_PREFIX);
            vault_meta_rows(&self.env, &txn, &prefixes)?
        };
        let custody = preflight_checkpoint_rows(&rows, Some(source))?;
        // The environment's path is the canonical root it was opened at.
        let root = self.env.path().to_path_buf();
        refuse_custody_beside(&root)?;
        #[cfg(test)]
        if let Some(callback) = BEFORE_ACTIVATION_FORK.with(|slot| slot.borrow_mut().take()) {
            callback();
        }
        let mut wtxn = self.env.past_seal_write_txn()?;
        let forked = self.fork_gate_custody_to_in_txn(&mut wtxn, &custody, &root)?;
        let committed = self
            .drop_erased_gate_decisions_in_txn(&mut wtxn, custody.erased())
            .and_then(|()| self.read_back_in_txn(&wtxn, &root))
            .and_then(|()| crate::identity::drop_machine_identity_in_txn(self, &mut wtxn))
            // The orders standing on its source now, not the ones it had.
            .and_then(|()| replace_host_holds_in_txn(self, &mut wtxn, source.host_holds()))
            .and_then(|()| ARCHIVED.delete(self, &mut wtxn, &()))
            .and_then(|_| Ok(wtxn.commit()?));
        if let Err(err) = committed {
            if let Some(forked) = forked {
                forked.remove();
            }
            return Err(err);
        }
        Ok(())
    }

    /// Reads every encrypted receipt in `txn` under the custody at `root`.
    fn read_back_in_txn(&self, txn: &RoTxn<'_>, root: &Path) -> Result<()> {
        for row in LEDGER.iter_raw_from(self, txn, &[])? {
            let (key, raw) = row?;
            if orcb::is_orcb(&raw) {
                let id = GateDecisionId::decode_key(&key)
                    .ok_or(Error::CorruptedIndex("gate decision ledger key"))?;
                orcb::decode_hot(root, id, &raw)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
thread_local! {
    static BEFORE_ACTIVATION_FORK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static AFTER_RESTORE_DESTINATION_MADE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static BEFORE_LIVE_CUSTODY_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

/// Runs `callback` once, the next time this thread activates an archived
/// vault, between the checks of its receipts and the fork of its custody.
#[cfg(test)]
pub(crate) fn arm_before_activation_fork(callback: impl FnOnce() + 'static) {
    BEFORE_ACTIVATION_FORK.with(|slot| *slot.borrow_mut() = Some(Box::new(callback)));
}

/// Runs `callback` once, the next time this thread makes a restore's
/// destination, between making it and opening the copy in it.
#[cfg(test)]
pub(crate) fn arm_after_restore_destination_made(callback: impl FnOnce() + 'static) {
    AFTER_RESTORE_DESTINATION_MADE.with(|slot| *slot.borrow_mut() = Some(Box::new(callback)));
}

/// Runs `callback` once, the next time this thread reads a vault's live
/// custody off its directory, between the path's admission and the read.
#[cfg(test)]
pub(crate) fn arm_before_live_custody_read(callback: impl FnOnce() + 'static) {
    BEFORE_LIVE_CUSTODY_READ.with(|slot| *slot.borrow_mut() = Some(Box::new(callback)));
}
