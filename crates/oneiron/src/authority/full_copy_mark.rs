//! Folds each machine's signed full-copy mark (L7-47; CROSS-ARCH-0024
//! `#my-network` item 04: "A full copy earns roles. It is a live backup and
//! a standby home."), reads it for the peer order of a device whose home is
//! down, and keeps the doors this install writes its own through.
//!
//! Each install declares its own machine: whether it holds a full copy, every
//! window it may read synced under sync all ([`FullCopyMark`]), signed by its
//! live install key under the carrier rule every owner act shares
//! ([`super::owner_act_signer_admits`]). The fold keeps each machine's newest
//! mark: one replaces every mark of its machine its parents carry, and of
//! concurrent ones the highest sequence, then hash, reads as newest. A mark
//! lands whatever its machine's standing; the peer order judges it again on
//! the fold it reads, under the key the machine still proves here, so a mark
//! under a key the machine no longer proves counts for nothing.
//!
//! The machine writes `held` once a home session's first round completes
//! while its lane runs sync all, and withdraws it in the transaction of a
//! switch to sync opened; "no mark" already means "not held", so a first
//! `held = false` writes nothing.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Error, Result};
use crate::{EntityId, TimeRange, Vault};

use super::machine_standing::{InstallCounted, Standing};
use super::*;

/// The mark would name more rows than one authority entry may: the log's
/// encoding bound, never a possession test.
const TOO_MANY_HEADS: &str = "the authority log has more concurrent heads than one full-copy mark \
                              may name; nothing was written";

/// One machine's mark as the fold keeps it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct DeclaredFullCopyMark {
    /// The mark's authority entry hash.
    pub(crate) act: AuthorityEntryHash,
    /// The install key that signed it.
    pub(crate) key: [u8; 32],
    /// Its signer's sequence: of one key's marks, the newest is the highest.
    pub(crate) seq: u64,
    /// The machine held a full copy when it signed.
    pub(crate) held: bool,
}

/// The vault's marks in one fold state: each machine's that no later mark of
/// it replaced, and every one a later one replaced.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct FullCopyMarkState {
    live: BTreeMap<EntityId, BTreeMap<AuthorityEntryHash, DeclaredFullCopyMark>>,
    replaced: BTreeSet<AuthorityEntryHash>,
}

impl FullCopyMarkState {
    /// No mark folded: a checkpoint image then carries no field for them.
    pub(super) fn is_empty(&self) -> bool {
        self.live.is_empty() && self.replaced.is_empty()
    }
}

/// The `FullCopyMark` transition, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster
/// check: its signer is the declaring machine's install key, never a roster
/// key (FIX 2222: the host root acts as nobody), and some chain of the
/// machine must name it. It replaces every mark of its machine its parents
/// carry.
pub(super) fn apply_full_copy_mark(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    mark: &FullCopyMark,
    hash: AuthorityEntryHash,
    (pin, counted): (Option<&PinnedRoot>, InstallCounted<'_>),
) -> std::result::Result<(), AuthorityFoldIssue> {
    if !entry.cosigns.is_empty() {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let signer = entry.signer_key();
    let AuthorityKey::Ed25519(key) = signer else {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    };
    let named = Standing::new(state, pin, counted).names_key(mark.machine, key);
    if !named || state.roster.contains_key(signer) {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    if state
        .seqs
        .get(signer)
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    let landed = DeclaredFullCopyMark {
        act: hash,
        key: *key,
        seq: entry.seq,
        held: mark.held,
    };
    let register = &mut state.full_copy_mark;
    let live = register.live.entry(mark.machine).or_default();
    register.replaced.extend(live.keys().copied());
    live.clear();
    live.insert(hash, landed);
    Ok(())
}

/// Joins two states' marks: one a later mark replaced on either side is
/// replaced.
pub(super) fn merge_full_copy_marks(merged: &mut FullCopyMarkState, right: &FullCopyMarkState) {
    merged.replaced.extend(right.replaced.iter().copied());
    for (machine, marks) in &right.live {
        let live = merged.live.entry(*machine).or_default();
        for (hash, mark) in marks {
            live.entry(*hash).or_insert_with(|| mark.clone());
        }
    }
    let FullCopyMarkState { live, replaced } = merged;
    live.retain(|_, marks| {
        marks.retain(|hash, _| !replaced.contains(hash));
        !marks.is_empty()
    });
}

/// Each machine's newest mark: the one no later mark of it replaced; of
/// concurrent ones, the highest sequence, then hash.
pub(super) fn folded_full_copy_marks(
    state: &FoldState,
) -> BTreeMap<EntityId, DeclaredFullCopyMark> {
    state
        .full_copy_mark
        .live
        .iter()
        .filter_map(|(machine, marks)| {
            marks
                .values()
                .max_by_key(|declared| (declared.seq, declared.act))
                .map(|declared| (*machine, declared.clone()))
        })
        .collect()
}

impl AuthorityFold {
    /// Whether `machine` holds a full copy here (L7-47): its newest mark
    /// says held, and the machine still proves here the key that signed it
    /// ([`Self::machine_proof_key`]). A mark under a key the machine no
    /// longer proves here counts for nothing. The peer order of a device
    /// whose home is down reads it.
    pub(crate) fn holds_full_copy(&self, machine: EntityId) -> bool {
        self.full_copy_mark
            .get(&machine)
            .is_some_and(|mark| mark.held && self.machine_proof_key(machine) == Some(mark.key))
    }
}

/// Signs `op` for `machine` with its install `key` over `fold`'s heads in
/// `txn` (L7-47): the frontier join a wide frontier needs, the signer's next
/// sequence, and the stored row. The caller's re-read judges whether the row
/// landed as the machine's newest; this commits nothing.
pub(crate) fn append_install_signed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    fold: AuthorityView,
    machine: EntityId,
    key: &ed25519_dalek::SigningKey,
    op: AuthorityOp,
) -> Result<AuthorityEntryHash> {
    // FIX 7908: join a frontier wider than one entry names, else today's path.
    let joiner = FrontierSigner::Install(machine, key);
    let fold = vault
        .prepare_authority_frontier_in_txn(txn, &fold, joiner, MAX_PARENTS)?
        .unwrap_or(fold);
    let signer = AuthorityKey::Ed25519(key.verifying_key().to_bytes());
    let seq = next_sequence(&fold, &signer)?;
    let parents = fold.append_heads.clone();
    if parents.len() > MAX_PARENTS {
        return Err(Error::InvalidConfig(TOO_MANY_HEADS.to_owned()));
    }
    let now = vault.instant_in_txn(txn)?.secs();
    let entry = sign_side_entry(&fold, key, seq, parents, op, now)?;
    let act = authority_entry_hash(&entry)?;
    let at = TimeRange {
        start: now,
        end: now,
    };
    vault.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
    Ok(act)
}

impl Vault {
    /// Appends `machine`'s full-copy mark saying `held`, signed by its
    /// install `key`, over `fold`'s heads in `txn` (L7-47). Nothing is
    /// written when the fold's newest mark of the machine already says this
    /// `held` under this key, or when there is no mark and `held` is false:
    /// `Ok(None)`. Otherwise `Ok(Some(hash))`, the mark's authority entry
    /// hash, refused [`invalid_authority`] unless the row lands as the
    /// machine's newest. It does not commit.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] for a frontier the
    /// join did not fold; [`invalid_authority`] for a row that lands anywhere
    /// but newest; [`Error::InvalidConfig`] for a frontier wider than one
    /// entry names; storage errors.
    pub(crate) fn append_full_copy_mark_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: AuthorityView,
        machine: EntityId,
        key: &ed25519_dalek::SigningKey,
        held: bool,
    ) -> Result<Option<AuthorityEntryHash>> {
        let public_key = key.verifying_key().to_bytes();
        match fold.full_copy_mark.get(&machine) {
            Some(mark) if mark.key == public_key && mark.held == held => return Ok(None),
            None if !held => return Ok(None),
            Some(_) | None => {}
        }
        let mark = FullCopyMark { machine, held };
        let act = append_install_signed_in_txn(
            self,
            txn,
            fold,
            machine,
            key,
            AuthorityOp::FullCopyMark(mark),
        )?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        if after
            .full_copy_mark
            .get(&machine)
            .is_none_or(|newest| newest.act != act)
        {
            return Err(invalid_authority());
        }
        Ok(Some(act))
    }

    /// Writes this install's own full-copy mark saying `held` in `txn`
    /// (L7-47): the writer the first full round under sync all and the lane
    /// switch to sync opened share. No id, no key, or a key the fold does
    /// not admit here writes nothing (`Ok(None)`): an install that cannot
    /// sign has never written a mark, and a lane switch must not fail for
    /// it. The caller loads the install signing first, with
    /// [`Self::load_install_signing_if_minted`], before opening `txn`. It
    /// does not commit.
    ///
    /// # Errors
    /// As [`Self::append_full_copy_mark_in_txn`]; storage errors.
    pub(crate) fn declare_full_copy_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        held: bool,
    ) -> Result<Option<AuthorityEntryHash>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let Some(machine) = crate::identity::read_machine_id_in_txn(self, txn)? else {
            tracing::debug!("this install has no machine id, so it writes no full-copy mark");
            return Ok(None);
        };
        let Some(key) = crate::identity::read_machine_signing_key_in_txn(self, txn)? else {
            tracing::debug!(
                "this install's machine key is not loaded, so it writes no full-copy mark"
            );
            return Ok(None);
        };
        let public_key = key.verifying_key().to_bytes();
        if !super::owner_act_signer_admits(fold.machine(machine), &fold.roster, &public_key) {
            tracing::debug!(
                "this install's machine key is not admitted here, so it writes no full-copy mark"
            );
            return Ok(None);
        }
        self.append_full_copy_mark_in_txn(txn, fold, machine, &key, held)
    }

    /// Writes this install's own full-copy mark saying `held` (L7-47): its
    /// install key signs the mark, a main-log entry naming the log's heads,
    /// which lands atomically or not at all. Nothing is written when the
    /// fold's newest mark of this machine already says this `held` under
    /// this key, or when there is no mark and `held` is false: `Ok(None)`.
    /// Otherwise `Ok(Some(hash))`, the mark's authority entry hash.
    ///
    /// # Errors
    /// As [`Self::append_full_copy_mark_in_txn`]; storage errors.
    pub fn declare_full_copy(&self, held: bool) -> Result<Option<AuthorityEntryHash>> {
        self.load_install_signing_if_minted()?;
        let mut txn = self.store.env.write_txn()?;
        let written = self.declare_full_copy_in_txn(&mut txn, held)?;
        if written.is_some() {
            txn.commit()?;
        }
        Ok(written)
    }
}
