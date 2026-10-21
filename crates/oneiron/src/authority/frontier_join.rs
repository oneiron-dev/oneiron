//! Joining a wide causal frontier (FIX 7908 and its duplicates, Phase2 B;
//! CALLS "Phase2 frontier join"). An act whose main-log frontier is wider
//! than one entry names is preceded, in its own writer, by signed
//! [`FrontierJoin`] rows over canonical groups of the heads, repeated over
//! the join tips until the act fits. Every head stays in the act's causal
//! past; nothing is dropped and nothing is refused.
//!
//! The writer stages the joins in its own transaction
//! ([`Vault::prepare_authority_frontier_in_txn`]) and then allocates the
//! act's sequence and parents from the fold it reads back, so the act's
//! sequence follows the joins'. The act's seen or revision basis is the one
//! it read before: a join moves no state any basis reads, and the fold judges
//! the act on its parents' merge, which is the heads' merge, so no current
//! answer turns stale. A frontier that fits keeps today's path and bytes.
//!
//! A join is signed by the key that signs the act: the carrier's install
//! key, or the host's slip issuer for a host-issued op. The store doors vouch
//! for it in that key's domain, as for the act, and the fold admits its
//! signer by the lookup the act's own carrier check uses
//! ([`apply_frontier_join`]): an install key some chain of the named carrier
//! names, or a live owner roster key, never a key the join names for itself.
//! A join signed by any other key folds as every unvouched row does: invalid,
//! with no sequence slot, so it never forks or blocks the act's sequence. It
//! reads no role, clearance or owner act beyond that, and grants nothing.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;

use super::machine_standing::{InstallCounted, Standing};
use super::*;
use crate::error::Result;
use crate::{EntityId, TimeRange, Vault};

/// A staged join did not fold here: no head of its group carries the
/// carrier's standing, so the act keeps today's refusal of a frontier wider
/// than one entry names.
const JOIN_NOT_FOLDED: &str = "the authority log has more concurrent heads than one entry may name, \
                               and a join of them did not fold; nothing was written";

/// Who signs an act's joins: the key that signs the act.
#[derive(Clone, Copy)]
pub(crate) enum FrontierSigner<'a> {
    /// The install key of the machine that carries the act.
    Install(EntityId, &'a SigningKey),
    /// The host's slip issuer, for a host-issued op.
    Host(&'a HostSlipIssuer),
}

impl FrontierSigner<'_> {
    /// The first sequence a join takes: the one the act itself would take,
    /// by its signer's own rule.
    fn first_sequence(self, fold: &AuthorityFold) -> Result<u64> {
        match self {
            Self::Install(_, signing) => next_sequence(
                fold,
                &AuthorityKey::Ed25519(signing.verifying_key().to_bytes()),
            ),
            Self::Host(issuer) => fold
                .append_sequences
                .get(&issuer.public_key())
                .map_or(Ok(0), |seq| {
                    seq.checked_add(1).ok_or_else(invalid_authority)
                }),
        }
    }

    fn sign(
        self,
        fold: &AuthorityFold,
        seq: u64,
        parents: BTreeSet<AuthorityEntryHash>,
        now: u64,
    ) -> Result<AuthorityLogEntry> {
        match self {
            Self::Install(carrier, signing) => {
                let join = FrontierJoin {
                    carrier: Some(carrier),
                };
                sign_side_entry(
                    fold,
                    signing,
                    seq,
                    parents,
                    AuthorityOp::FrontierJoin(join),
                    now,
                )
            }
            Self::Host(issuer) => issuer.sign_entry(
                fold.vault_id,
                seq,
                parents.into_iter().collect(),
                AuthorityOp::FrontierJoin(FrontierJoin { carrier: None }),
                now,
            ),
        }
    }
}

/// One level of a frontier's joins: `tips` in hash order, in groups of
/// [`AUTHORITY_FRONTIER_JOIN_ARITY`], a last group of one tip left a tip.
/// Canonical: the groups read the tips' immutable hashes alone, never a
/// clock, an arrival order or a signer.
pub(super) fn plan_frontier_joins(
    tips: &BTreeSet<AuthorityEntryHash>,
) -> Vec<BTreeSet<AuthorityEntryHash>> {
    let tips: Vec<AuthorityEntryHash> = tips.iter().copied().collect();
    tips.chunks(AUTHORITY_FRONTIER_JOIN_ARITY)
        .filter(|group| group.len() > 1)
        .map(|group| group.iter().copied().collect())
        .collect()
}

/// The `FrontierJoin` transition, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster
/// check. Its signer is admitted as the act it leads to admits its own: for
/// a carrier, an install key some chain of that machine names in the join's
/// parent state ([`Standing::names_key`], the floor every carried act's
/// check starts from); for no carrier, a live owner roster key, as the
/// host's slip issuer is. Any other signer is not in its ancestry. Its state
/// is its parents' merge, and only its signer's sequence moves, past its last
/// one there; it applies nothing.
pub(super) fn apply_frontier_join(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    join: &FrontierJoin,
    hash: AuthorityEntryHash,
    (pin, counted): (Option<&PinnedRoot>, InstallCounted<'_>),
) -> std::result::Result<(), AuthorityFoldIssue> {
    let signer = entry.signer_key();
    let admitted = match (join.carrier, signer) {
        (Some(carrier), AuthorityKey::Ed25519(key)) => {
            Standing::new(state, pin, counted).names_key(carrier, key)
        }
        (Some(_), AuthorityKey::P256(_)) => false,
        (None, signer) => roster_has_live_owner(&state.roster, signer),
    };
    if !admitted {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    if state
        .seqs
        .get(signer)
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    state.seqs.insert(signer.clone(), entry.seq);
    Ok(())
}

impl Vault {
    /// Joins `fold`'s main-log heads in `txn` when an act would name more of
    /// them than `room`, the heads it may name beside its other rows (one
    /// entry's [`MAX_PARENTS`] for an act that names the heads alone). Each
    /// level of [`plan_frontier_joins`] is signed by `signer`, at the
    /// sequences its act would take, until the tips fit; the joins land in
    /// one put, and the fold read back is returned, for the act's sequence
    /// and parents. `None` when the heads fit: today's path, nothing written.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] when a join did not
    /// fold valid, which leaves the frontier as wide as today's refusal of it;
    /// signing, store-door and storage errors. A caller's transaction that
    /// fails after this aborts the joins with the act.
    pub(crate) fn prepare_authority_frontier_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        signer: FrontierSigner<'_>,
        room: usize,
    ) -> Result<Option<AuthorityView>> {
        let room = room.max(1);
        if fold.append_heads.len() <= room {
            return Ok(None);
        }
        let now = self.instant_in_txn(txn)?.secs();
        let at = TimeRange {
            start: now,
            end: now,
        };
        let mut seq = signer.first_sequence(fold)?;
        let mut tips = fold.append_heads.clone();
        let mut rows = Vec::new();
        let mut joins = Vec::new();
        while tips.len() > room {
            for group in plan_frontier_joins(&tips) {
                let join = signer.sign(fold, seq, group.clone(), now)?;
                seq = seq.checked_add(1).ok_or_else(invalid_authority)?;
                let hash = authority_entry_hash(&join)?;
                tips.retain(|tip| !group.contains(tip));
                tips.insert(hash);
                joins.push(hash);
                rows.push((join, at, now));
            }
        }
        self.put_authority_log_entries_in_txn(txn, &rows)?;
        let joined = self.authority_view_readonly_in_txn(txn)?;
        if !joins.iter().all(|hash| joined.valid_entries.contains(hash)) {
            return Err(authority_refused(JOIN_NOT_FOLDED));
        }
        Ok(Some(joined))
    }
}
