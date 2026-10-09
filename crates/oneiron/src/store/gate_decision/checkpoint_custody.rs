//! What a checkpoint restore needs from exterior key custody, the side
//! restore's custody fork (ARCH-0038 #erasure-completeness, "Key custody in a
//! side restore"), and the archive a restore in a vault's place sets aside.
//!
//! A restore that takes its vault's place keeps that vault's custody. A copy
//! served beside its source gets custody of its own at restore time: only the
//! keys still live in the source's custody are copied, so a destroyed key
//! stays destroyed, and from then on each vault shreds only its own keys. The
//! image a restore in place set aside still binds the custody its replacement
//! now holds, so it is archived: it reads, and refuses every write until an
//! owner activates it as a side vault, which forks its custody the same way.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use heed::types::Bytes;
use heed::{Env, RoTxn, RwTxn};

use crate::error::{Error, Result, StoreError};
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::store::{Store, read_existing_vault_meta};

use super::keys::GATE_DECISION_KEY_PREFIX;
use super::ledger::CUSTODY_ROOT;
use super::orcb::{self, CUSTODY_ROOT_KEY, ForkedCustodyDir, corrupt};
use super::retention::{checkpoint_retirements, retirement_prefixes};
use super::types::GateDecisionId;

type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// Marks a vault archived by a restore in its place.
const ARCHIVED: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::VAULT_ARCHIVED_BY_RESTORE);

fn archived() -> Error {
    Error::Store(StoreError::ArchivedVault)
}

/// The `vault_meta` rows a vault's live custody state is read from: its
/// custody binding, its archive mark, and its key-retirement intents.
fn live_custody_prefixes() -> Vec<&'static [u8]> {
    let mut prefixes = vec![CUSTODY_ROOT_KEY, ARCHIVED.decl().prefix];
    prefixes.extend(retirement_prefixes());
    prefixes
}

/// One vault's live key-custody state, read when a side restore of it
/// starts: where its custody is, and its key-retirement intents with their
/// erase marks and holds.
pub(crate) struct LiveCustody {
    root: PathBuf,
    rows: Rows,
}

impl LiveCustody {
    /// From a vault's [`live_custody_prefixes`] rows; with no binding its
    /// custody is the one beside `own_root`. An archived vault's custody
    /// belongs to the vault that replaced it, so its own state is no
    /// source's.
    fn from_rows(own_root: PathBuf, rows: Rows) -> Result<Self> {
        let mut root = own_root;
        let mut intents = Vec::new();
        for (key, value) in rows {
            if key == ARCHIVED.decl().prefix {
                return Err(archived());
            }
            if key == CUSTODY_ROOT_KEY {
                root = orcb::decode_custody_root(&value)?;
            } else {
                intents.push((key, value));
            }
        }
        Ok(Self {
            root,
            rows: intents,
        })
    }

    /// The custody root this state binds to.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
}

/// The live custody state of the vault at `vault_dir`, read without opening
/// it as a vault, through the read-only door (`read_existing_vault_meta`): a
/// vault another process serves reads beside it, and one this process holds,
/// under any name, is refused. A missing or unreadable vault refuses.
pub(crate) fn read_live_custody(vault_dir: &Path) -> Result<LiveCustody> {
    let read = read_existing_vault_meta(vault_dir, &live_custody_prefixes())?;
    LiveCustody::from_rows(read.root, read.rows)
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
        let txn = self.env.read_txn()?;
        let rows = vault_meta_rows(&self.env, &txn, &live_custody_prefixes())?;
        LiveCustody::from_rows(self.core.gate_custody_root.clone(), rows)
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

    /// Archives this vault: a restore swapped a replacement into its place,
    /// and the replacement keeps the key custody this vault binds to. This
    /// handle is sealed at once, and every later open of the vault is sealed
    /// once open: it reads, and refuses every write, erase and key
    /// retirement until [`Store::activate_archived`].
    pub(crate) fn archive_replaced(&self) -> Result<()> {
        self.write_in_group(|wtxn| ARCHIVED.put(self, wtxn, &(), &vec![1]))?;
        self.env.seal();
        Ok(())
    }

    /// Seals this handle when its vault is archived; every open ends here.
    pub(crate) fn seal_if_archived(&self) -> Result<()> {
        if self.archived_in_txn(&self.env.read_txn()?)? {
            self.env.seal();
        }
        Ok(())
    }

    pub(super) fn archived_in_txn(&self, txn: &RoTxn<'_>) -> Result<bool> {
        ARCHIVED.contains(self, txn, &())
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
    /// to destroy is not copied and the receipts under it are dropped, and
    /// the archive mark is lifted in the same commit as the new binding.
    /// The caller reopens the vault, whose handles then shred only its own
    /// keys.
    pub(crate) fn activate_archived(&self, source: &LiveCustody) -> Result<()> {
        let rows = {
            let txn = self.env.read_txn()?;
            if !self.archived_in_txn(&txn)? {
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
        let mut wtxn = self.env.activation_write_txn()?;
        let forked = self.fork_gate_custody_to_in_txn(&mut wtxn, &custody, &root)?;
        let committed = self
            .drop_erased_gate_decisions_in_txn(&mut wtxn, custody.erased())
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
}
