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

mod activation;
mod destination;
mod pad_objects;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use heed::types::Bytes;
use heed::{Env, RoTxn, RwTxn};

use crate::error::{Error, Result, StoreError};
use crate::recovery::checkpoint::{Rejected, RestoreAdmissionReason as R};
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::store::key_custody::{
    self, CustodyBinding, CustodyPlan, ForkedCustodyDir, LocalCustody, Requirement,
    decode_native_path, encode_native_path,
};
#[cfg(unix)]
use crate::store::root_directory::{
    FileIdentity, file_identity, named_directory_identity, refuse_shared_vault_root,
};
use crate::store::{Store, not_an_existing_root, read_existing_custody_pad_rows};

pub(crate) use self::destination::{MadeDestination, replace_host_holds_in_txn};
#[cfg(feature = "sync")]
pub(crate) use self::pad_objects::put_back_pad_objects_in_txn;
pub(crate) use self::pad_objects::{
    ExpectedPadObjects, PAD_SOURCE_IDENTITY, PadObjectsCapture, PadObjectsLanding,
    PadSourceIdentity, UncapturedPadObjects, install_source_pad_objects_in_txn,
};
use super::keys::GATE_DECISION_KEY_PREFIX;
use super::orcb::{self, corrupt};
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
        Some([LIVE_ONLY_AT, home @ ..]) => {
            Ok(decode_native_path(home).ok_or_else(archive_mark_corrupt)? != own_root)
        }
        Some(_) => Err(archive_mark_corrupt()),
    }
}

fn archive_mark_corrupt() -> Error {
    Error::CorruptedIndex("vault archive mark")
}

/// The mark: `LIVE_ONLY_AT`, then the home's native absolute path.
fn live_only_at(home: &Path) -> Result<Vec<u8>> {
    let mut mark = vec![LIVE_ONLY_AT];
    mark.extend(encode_native_path(home).ok_or_else(archive_mark_corrupt)?);
    Ok(mark)
}

/// The `vault_meta` rows a vault's live custody state is read from: its
/// custody binding, its archive mark, its store identity, its body erase
/// receipts (FIX 9066), its key-retirement intents, and its host orders,
/// whose target index the intents read.
fn live_custody_prefixes() -> Vec<&'static [u8]> {
    let mut prefixes = vec![
        key_custody::binding_key(),
        ARCHIVED.decl().prefix,
        STORE_IDENTITY.decl().prefix,
        side_table::PROVENANCE_BODY_ERASED.prefix,
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

/// One vault's live key-custody state, read when a side restore of it
/// starts: its custody binding, and its key-retirement intents with the
/// holds they read.
pub(crate) struct LiveCustody {
    /// The canonical root it opened at.
    own_root: PathBuf,
    binding: Option<CustodyBinding>,
    store_identity: Option<Vec<u8>>,
    rows: Rows,
    /// Its whole host-order family, for the vault a restore makes beside it.
    host_holds: Rows,
    /// The key of each of its body erase receipts: the erasing owner, then
    /// the instance its erase retired (FIX 9066).
    erased_by: BTreeSet<Vec<u8>>,
    /// Its credential erase evidence (KS-6 part 2), read apart from the rest.
    fences: crate::store::CredentialFences,
    /// Its home's current pad objects, from the read of the rows above
    /// (PAD-1).
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) pad_objects: PadObjectsCapture,
}

impl LiveCustody {
    /// From the [`live_custody_prefixes`] rows of a vault opened at the
    /// canonical `own_root`; with no binding its custody is the one beside
    /// `own_root`. An archived vault's custody belongs to the vault that
    /// replaced it, so its own state is no source's.
    fn from_rows(own_root: &Path, rows: Rows, pad_objects: PadObjectsCapture) -> Result<Self> {
        let binding = key_custody::binding_in_rows(&rows)?;
        let mut mark = None;
        let mut store_identity = None;
        let mut intents = Vec::new();
        let mut host_holds = Vec::new();
        let mut erased_by = BTreeSet::new();
        let receipts = side_table::PROVENANCE_BODY_ERASED.prefix;
        for (key, value) in rows {
            if let Some(receipt) = key.strip_prefix(receipts) {
                erased_by.insert(receipt.to_vec());
            } else if key == ARCHIVED.decl().prefix {
                mark = Some(value);
            } else if key == STORE_IDENTITY.decl().prefix {
                store_identity = Some(value);
            } else if key == key_custody::binding_key() {
                // Read above.
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
            own_root: own_root.to_path_buf(),
            binding,
            store_identity,
            rows: intents,
            host_holds,
            erased_by,
            fences: crate::store::CredentialFences::default(),
            pad_objects,
        })
    }

    /// Whether `owner`'s erase retired `instance` here, by its erase
    /// receipt: an archive's prune drops a keyed entry its own caller's
    /// erase retired, as a cold restore does (FIX 7470, 9066).
    pub(crate) fn erased_by(
        &self,
        owner: &crate::entity_id::EntityId,
        instance: &[u8; 16],
    ) -> bool {
        let mut key = owner.as_bytes().to_vec();
        key.extend_from_slice(instance);
        self.erased_by.contains(&key)
    }

    /// The credentials its erases fenced or staged (KS-6 part 2): a copy, a
    /// fork or an activation never brings one back.
    pub(crate) fn credential_fences(&self) -> crate::store::CredentialFences {
        self.fences.clone()
    }

    /// Where its custody is: its binding's root, or beside its own root
    /// while it binds none.
    fn custody_root(&self) -> &Path {
        self.binding
            .as_ref()
            .map_or(self.own_root.as_path(), CustodyBinding::root)
    }

    /// Whether `bound`, an image's binding, is this vault's live custody.
    fn binds(&self, bound: &CustodyBinding) -> bool {
        match &self.binding {
            Some(binding) => binding == bound,
            None => bound.root() == self.own_root.as_path(),
        }
    }

    /// The source's whole host-order family, as it was read.
    pub(crate) fn host_holds(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.host_holds
    }

    /// Whether `other`, read later, is the state of the same vault: the same
    /// store, bound to the same custody. A binding its first publication
    /// pinned since is the same custody.
    pub(crate) fn same_vault(&self, other: &Self) -> bool {
        self.custody_root() == other.custody_root()
            && self.store_identity == other.store_identity
            && (self.binding.is_none() || other.binding.is_none() || self.binding == other.binding)
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
/// it as a vault, through the read-only door's paired read
/// (`read_existing_custody_pad_rows`), its pad object rows in the same
/// transaction: a vault another process serves reads beside it, and one this
/// process holds, under any name, is refused. A sealed vault reads with
/// `page_seal`. A missing or unreadable vault refuses; pad object rows that
/// do not read leave its objects not captured (PAD-1).
pub(crate) fn read_live_custody(
    vault_dir: &Path,
    page_seal: Option<&crate::world_keys::VaultPageSeal>,
) -> Result<LiveCustody> {
    // A shared directory on the source's path is no reason to refuse: the
    // vault opens, reads and writes there as it is, so whoever could move it
    // could change it already. The source reports it instead.
    refuse_missing_vault_root(vault_dir)?;
    #[cfg(test)]
    if let Some(callback) = BEFORE_LIVE_CUSTODY_READ.with(|slot| slot.borrow_mut().take()) {
        callback();
    }
    let read = crate::world_keys::read_sealed(vault_dir, page_seal, || {
        read_existing_custody_pad_rows(
            vault_dir,
            &live_custody_prefixes(),
            &pad_objects::pad_object_prefixes(),
            pad_objects::is_pad_object_row,
        )
    })?;
    let pad_objects = pad_objects::disk_capture(read.sync_state);
    let mut live = LiveCustody::from_rows(&read.root, read.vault_meta, pad_objects)?;
    live.fences = crate::store::CredentialFences::at_vault(&read.root, page_seal);
    Ok(live)
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
    /// The image's binding, the claim keys each row needs and the
    /// retirements it and its live source committed.
    plan: CustodyPlan,
    erased: Vec<(GateDecisionId, [u8; 16])>,
    /// Rows a new-host restore drops because their keys stayed on the old
    /// host ([`preflight_absent_custody_rows`]).
    lost: Vec<(GateDecisionId, [u8; 16])>,
}

impl CheckpointCustody {
    /// The rows a restore drops: their key generation was destroyed after
    /// the image was taken, or a committed retirement destroys it.
    pub(crate) fn erased(&self) -> &[(GateDecisionId, [u8; 16])] {
        &self.erased
    }

    /// The rows a new-host restore drops because their keys stayed on the
    /// old host: its report names them.
    pub(crate) fn lost(&self) -> &[(GateDecisionId, [u8; 16])] {
        &self.lost
    }

    /// Every row the restore drops, erased or lost.
    pub(crate) fn dropped(&self) -> Vec<(GateDecisionId, [u8; 16])> {
        self.erased.iter().chain(&self.lost).copied().collect()
    }

    /// The plan the restore's body instances are required through too, so
    /// one fork copies claim and body keys alike (KS-2A).
    pub(crate) fn plan_mut(&mut self) -> &mut CustodyPlan {
        &mut self.plan
    }
}

/// CALLS CUSTODY_NO_HEAD_GATE_ROWS (Engine 10-20 04:0x): a new-host restore
/// of an image that names no custody head, whose custody is not on this
/// host, drops the claim-bound rows whose keys stayed on the old host and
/// names them in its report; `false` refuses it as before.
pub(crate) const CUSTODY_NO_HEAD_GATE_ROWS: bool = true;

/// [`preflight_checkpoint_rows`] for exactly one case: a restore, wake or
/// migration that keeps the image's custody, where no head is found for the
/// image and its custody is not on this host, or the image carries only the
/// legacy untyped marker with its keys elsewhere. A row whose key is
/// missing there is lost, dropped and named, not refused
/// ([`CUSTODY_NO_HEAD_GATE_ROWS`]); one a committed retirement covers is
/// erased as before. A missing key anywhere else still refuses.
///
/// Each refusal carries the reason its branch names (FIX 6474), beside the
/// error it always returned.
pub(crate) fn preflight_absent_custody_rows(
    rows: &[(Vec<u8>, Vec<u8>)],
) -> std::result::Result<CheckpointCustody, Rejected> {
    let bound = key_custody::binding_in_rows(rows)?;
    let mut plan = CustodyPlan::new(bound.clone(), checkpoint_retirements(rows)?);
    let mut erased = Vec::new();
    let mut lost = Vec::new();
    for (key, value) in rows {
        if key.starts_with(GATE_DECISION_KEY_PREFIX) && orcb::is_orcb(value) {
            let (id, claim, generation) = receipt_header(key, value)?;
            // An image that binds no typed custody (the legacy untyped
            // marker, its keys elsewhere) holds no key here: lost.
            let custody = match bound.as_ref() {
                Some(bound) => LocalCustody::at(bound),
                None if CUSTODY_NO_HEAD_GATE_ROWS => {
                    lost.push((id, claim));
                    continue;
                }
                None => return Err(Rejected::new(R::CustodyLineageMismatch, corrupt())),
            };
            let needed = orcb::claim_subject(custody, &claim)?.at(generation);
            match plan.require_rejected(&needed) {
                Ok(Requirement::Retired) => erased.push((id, claim)),
                Ok(Requirement::Live) => {
                    orcb::decode_hot(custody, id, value).map_err(Rejected::receipt)?;
                }
                Err(_)
                    if CUSTODY_NO_HEAD_GATE_ROWS
                        && custody.state(&needed)? == key_custody::EntryState::Missing =>
                {
                    lost.push((id, claim));
                }
                Err(rejected) => return Err(rejected),
            }
        }
    }
    Ok(CheckpointCustody { plan, erased, lost })
}

/// A sealed receipt row's decision id, custody item (its claim, or a policy
/// row's partition: FIX 7806) and key generation, read without a key: a row
/// that does not spell them is `claim_receipt_invalid` (FIX 6474).
fn receipt_header(
    key: &[u8],
    value: &[u8],
) -> std::result::Result<(GateDecisionId, [u8; 16], u64), Rejected> {
    let invalid = |error: Error| Rejected::new(R::ClaimReceiptInvalid, error);
    let id = key
        .strip_prefix(GATE_DECISION_KEY_PREFIX)
        .and_then(GateDecisionId::decode_key)
        .ok_or_else(|| invalid(Error::CorruptedIndex("gate decision ledger key")))?;
    let (claim, generation) =
        orcb::raw_custody_item_generation(value).ok_or_else(|| invalid(corrupt()))?;
    Ok((id, claim, generation))
}

/// Authenticate encrypted canonical rows against CURRENT exterior keys before
/// restore creates its destination. The image supplies a binding, not a key;
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
    preflight_checkpoint_rows_rejected(rows, source).map_err(Error::from)
}

/// [`preflight_checkpoint_rows`] with the reason each refusal's branch
/// names (FIX 6474): a binding that is not the source's, or none where a
/// receipt needs one, is `custody_lineage_mismatch`; a receipt that does not
/// spell its header, or does not open under its live key, is
/// `claim_receipt_invalid`; a key custody does not hold is
/// `custody_key_missing`. The errors are the wrapper's.
pub(crate) fn preflight_checkpoint_rows_rejected(
    rows: &[(Vec<u8>, Vec<u8>)],
    source: Option<&LiveCustody>,
) -> std::result::Result<CheckpointCustody, Rejected> {
    let bound = key_custody::binding_in_rows(rows)?;
    let mut retirements = checkpoint_retirements(rows)?;
    if let Some(source) = source {
        // The source's intents say nothing about another vault's keys.
        if bound.as_ref().is_some_and(|bound| !source.binds(bound)) {
            return Err(Rejected::new(
                R::CustodyLineageMismatch,
                Error::InvalidConfig(
                    "this checkpoint's key custody is not its source vault's".into(),
                ),
            ));
        }
        retirements.extend(checkpoint_retirements(&source.rows)?);
    }
    let mut plan = CustodyPlan::new(bound.clone(), retirements);
    // The training link key (TL-2) rides a side restore while it is live, so
    // the copy can still withdraw and purge its past codes; the host issuer
    // seed's escrow rides where it reads (FIX-LIST 10770), never required.
    if let Some(bound) = bound.as_ref() {
        crate::store::training_link::require_live_link_key(&mut plan, bound)?;
        crate::store::host_issuer_custody::plan_host_issuer_seed_custody(&mut plan, bound);
    }
    let mut erased = Vec::new();
    for (key, value) in rows {
        if key.starts_with(GATE_DECISION_KEY_PREFIX) && orcb::is_orcb(value) {
            let (id, claim, generation) = receipt_header(key, value)?;
            let binding = bound
                .as_ref()
                .ok_or_else(|| Rejected::new(R::CustodyLineageMismatch, corrupt()))?;
            let custody = LocalCustody::at(binding);
            match plan.require_rejected(&orcb::claim_subject(custody, &claim)?.at(generation))? {
                Requirement::Retired => erased.push((id, claim)),
                Requirement::Live => {
                    orcb::decode_hot(custody, id, value).map_err(Rejected::receipt)?;
                }
            }
        }
    }
    Ok(CheckpointCustody {
        plan,
        erased,
        lost: Vec::new(),
    })
}

/// A side restore forks custody into a directory of its own beside
/// `destination`. One already there, left by a vault removed without its
/// custody, is refused before the destination is created, never merged.
pub(crate) fn refuse_custody_beside(destination: &Path) -> Result<()> {
    if key_custody::custody_present(&std::path::absolute(destination)?)? {
        return Err(Error::InvalidConfig(
            "key custody already exists beside the restore destination; restore elsewhere".into(),
        ));
    }
    Ok(())
}

impl Store {
    /// This vault's live custody state, for a side restore of it, with what
    /// `pad_objects` captures of its pad objects in the same transaction.
    pub(crate) fn live_custody(
        &self,
        pad_objects: impl FnOnce(&RoTxn<'_>) -> PadObjectsCapture,
    ) -> Result<LiveCustody> {
        if self.env.is_sealed() {
            return Err(archived());
        }
        let txn = self.env.read_txn()?;
        let rows = vault_meta_rows(&self.env, &txn, &live_custody_prefixes())?;
        let mut live = LiveCustody::from_rows(self.env.path(), rows, pad_objects(&txn))?;
        live.fences = self.credential_fences_in_txn(&txn);
        Ok(live)
    }

    /// Forks the custody `custody` binds to into this restored copy's own,
    /// in a new namespace beside its root, and binds the copy to it in this
    /// transaction. The copied keys are synced before the binding commits.
    /// Returns the directory the fork created, if it had anything to copy.
    pub(crate) fn fork_gate_custody_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        custody: &CheckpointCustody,
    ) -> Result<Option<ForkedCustodyDir>> {
        let forked =
            self.fork_gate_custody_to_in_txn(wtxn, custody, self.core.key_custody.home())?;
        // This handle reads the copy's receipts under the copy's own custody
        // from here on, as the copy's reopen will (the restore's actor
        // scrubs read them in this transaction).
        let adopted = key_custody::binding_in_txn(self, wtxn)
            .and_then(|binding| self.core.key_custody.adopt(binding.as_ref()));
        if let Err(err) = adopted {
            if let Some(forked) = forked {
                forked.remove();
            }
            return Err(err);
        }
        Ok(forked)
    }

    /// An image that binds no custody holds no claim key: the copy mints its
    /// own at its first claim-bound append.
    fn fork_gate_custody_to_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        custody: &CheckpointCustody,
        root: &Path,
    ) -> Result<Option<ForkedCustodyDir>> {
        let Some(source) = custody.plan.source() else {
            return Ok(None);
        };
        let binding = source.fork_to(root.to_path_buf());
        let forked = LocalCustody::at(source).fork(&binding, &custody.plan)?;
        if let Err(err) = key_custody::put_binding_in_txn(self, wtxn, &binding) {
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
        ARCHIVED.put(self, wtxn, &(), &live_only_at(home)?)
    }

    /// Lifts the seal its open put on this handle of a replacement the
    /// restore marked live only at `home` is still building. The handle
    /// writes its rows; the custody it shares with the vault at `home` stays
    /// out of its reach, as it opened archived.
    pub(crate) fn unseal_replacement(&self, home: &Path) -> Result<()> {
        let mark = ARCHIVED.get(self, &self.env.read_txn()?, &())?;
        if mark != Some(live_only_at(home)?) || !self.core.key_custody.archived_at_open() {
            return Err(Error::InvariantViolation("a replacement's archive mark"));
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
    pub(in crate::store) fn archived_in_txn(&self, txn: &RoTxn<'_>) -> Result<bool> {
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
