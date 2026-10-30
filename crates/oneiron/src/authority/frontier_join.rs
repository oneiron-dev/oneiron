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
//! key, the host's slip issuer for a host-issued op, an owner anchor for
//! its own rows (FIX 8498, Engine 09:31: its root record, its marks and the
//! owner's kit push, never a row of another signer family), or the root a
//! ReRoot retires, through the move's signing callback, in the host family
//! (FIX 11867). The fold admits its signer by the act's own rule on the
//! join's parent state ([`admits_join_signer`]): the one carrier rule in the
//! roster view, a live Ed25519 owner roster key, or an anchor the fold
//! recorded for a stored root, never a key the join names for itself. A join
//! signed by any other key folds as every unvouched row does: invalid, with
//! no sequence slot, so it never forks or blocks the act's sequence. Every
//! group names the frontier's admission tip, the lowest-hash head whose own
//! state admits the signer, so each join's parents carry the signer's
//! standing. It reads no role, clearance or owner act beyond that, and
//! grants nothing.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;

use super::machine_standing::{InstallCounted, Standing, StandingView, every_chain};
use super::*;
use crate::error::Result;
use crate::{EntityId, TimeRange, Vault};

/// A staged join did not fold here, so the act keeps today's refusal of a
/// frontier wider than one entry names.
const JOIN_NOT_FOLDED: &str = "the authority log has more concurrent heads than one entry may name, \
                               and a join of them did not fold; nothing was written";

/// Who signs an act's joins: the key that signs the act.
#[derive(Clone, Copy)]
pub(crate) enum FrontierSigner<'a> {
    /// The install key of the machine that carries the act.
    Install(EntityId, &'a SigningKey),
    /// The host's slip issuer, for a host-issued op.
    Host(&'a HostSlipIssuer),
    /// A stored owner root's anchor, for the anchor's own rows alone: its
    /// root record, its marks and the owner's kit push (FIX 8498).
    Anchor(&'a SigningKey),
    /// A ReRoot's signer, the Ed25519 owner root the move retires, held
    /// behind the caller's signing callback, which signs each join's
    /// transcript (FIX 11867). Its joins are in the host family: that
    /// family's rule, a live Ed25519 owner roster key, is the standing the
    /// ReRoot itself stands on.
    Callback([u8; 32], &'a dyn Fn(&[u8]) -> Result<Vec<u8>>),
}

impl FrontierSigner<'_> {
    fn family(self) -> FrontierJoinFamily {
        match self {
            Self::Install(carrier, _) => FrontierJoinFamily::Install(carrier),
            Self::Host(_) | Self::Callback(..) => FrontierJoinFamily::Host,
            Self::Anchor(_) => FrontierJoinFamily::Anchor,
        }
    }

    fn key(self) -> AuthorityKey {
        match self {
            Self::Install(_, signing) | Self::Anchor(signing) => {
                AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
            }
            Self::Host(issuer) => issuer.public_key(),
            Self::Callback(key, _) => AuthorityKey::Ed25519(key),
        }
    }

    /// The first sequence a join takes: the one the act itself would take,
    /// by its signer's own rule.
    fn first_sequence(self, fold: &AuthorityFold) -> Result<u64> {
        match self {
            Self::Install(..) | Self::Anchor(_) | Self::Callback(..) => {
                next_sequence(fold, &self.key())
            }
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
        let op = AuthorityOp::FrontierJoin(FrontierJoin {
            family: self.family(),
        });
        match self {
            Self::Install(_, signing) | Self::Anchor(signing) => {
                sign_side_entry(fold, signing, seq, parents, op, now)
            }
            Self::Host(issuer) => {
                issuer.sign_entry(fold.vault_id, seq, parents.into_iter().collect(), op, now)
            }
            Self::Callback(key, transcript_signer) => {
                let mut entry = unsigned_side_entry(fold, key, seq, parents, op, now)?;
                entry.signer.signature = transcript_signer(&authority_transcript(&entry)?)?;
                Ok(entry)
            }
        }
    }
}

/// Whether `state` admits `signer` to sign a join in `family`, as the rows
/// the join leads to admit their own signer there: for a carrier, the one
/// carrier rule in the roster view ([`super::owner_act_signer_admits`]: not
/// a roster key, no removed chain, a live chain whose machine key it is);
/// for the host, a live Ed25519 owner roster key, as the host's slip issuer
/// and a ReRoot's signer are (FIX 11867); for an anchor, an anchor `state`
/// recorded for a stored root, as its marks are admitted (FIX 8498, Engine
/// 09:31 (2)), never a key the join carries and never a roster key in its
/// place. A P-256 key signs no join.
fn admits_join_signer(
    state: &FoldState,
    family: FrontierJoinFamily,
    signer: &AuthorityKey,
    (pin, counted): (Option<&PinnedRoot>, InstallCounted<'_>),
) -> bool {
    let roster = StandingView::Under(MachineAdmitter::Roster);
    match (family, signer) {
        (FrontierJoinFamily::Install(carrier), AuthorityKey::Ed25519(key)) => {
            Standing::new(state, pin, counted).admits_owner_act_signer(carrier, key, roster)
        }
        (FrontierJoinFamily::Host, AuthorityKey::Ed25519(_)) => {
            roster_has_live_owner(&state.roster, signer)
        }
        (FrontierJoinFamily::Anchor, AuthorityKey::Ed25519(key)) => {
            state.root_anchors.contains_key(key)
        }
        (_, AuthorityKey::P256(_)) => false,
    }
}

/// One level of a frontier's joins: `tips` in hash order, in groups of
/// [`AUTHORITY_FRONTIER_JOIN_ARITY`]. On the first level every group names
/// the admission tip `tip` and at most one fewer other heads; above it, a
/// last group of one join is left a tip. Canonical: the groups read the
/// tips' immutable hashes alone, never a clock, an arrival order or a
/// signer.
pub(super) fn plan_frontier_joins(
    tips: &BTreeSet<AuthorityEntryHash>,
    tip: Option<AuthorityEntryHash>,
) -> Vec<BTreeSet<AuthorityEntryHash>> {
    let others: Vec<AuthorityEntryHash> = tips
        .iter()
        .copied()
        .filter(|head| Some(*head) != tip)
        .collect();
    let arity = AUTHORITY_FRONTIER_JOIN_ARITY - usize::from(tip.is_some());
    others
        .chunks(arity)
        .map(|group| group.iter().copied().chain(tip).collect::<BTreeSet<_>>())
        .filter(|group| group.len() > 1)
        .collect()
}

/// The `FrontierJoin` transition, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster
/// check: its signer must be one [`admits_join_signer`] admits in the join's
/// parent state, else it is not in its ancestry. Its state is its parents'
/// merge, and only its signer's sequence moves, past its last one there; it
/// applies nothing.
pub(super) fn apply_frontier_join(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    join: &FrontierJoin,
    hash: AuthorityEntryHash,
    standing: (Option<&PinnedRoot>, InstallCounted<'_>),
) -> std::result::Result<(), AuthorityFoldIssue> {
    let signer = entry.signer_key();
    if !admits_join_signer(state, join.family, signer, standing) {
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
    /// sequences its act would take, until the tips fit, and every first-level
    /// group names the admission tip; the joins land in one put, and the fold
    /// read back is returned, for the act's sequence and parents. `None` when
    /// the heads fit, or when no single head admits the signer: today's path,
    /// nothing written. A wide frontier is measured on Phase2 A's
    /// `authority_record_items` row, which asks past it and never waits or
    /// refuses.
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
        self.join_authority_heads_in_txn(txn, fold, &fold.append_heads, signer, room)
    }

    /// [`Self::prepare_authority_frontier_in_txn`] over `heads`, the part of
    /// `fold`'s main-log heads an act names (FIX 8497: a world key record
    /// names the heads no side leaf of its world holds beneath it). The
    /// other heads stay heads, and stay out of the joins.
    ///
    /// # Errors
    /// As [`Self::prepare_authority_frontier_in_txn`].
    pub(crate) fn join_authority_heads_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        heads: &BTreeSet<AuthorityEntryHash>,
        signer: FrontierSigner<'_>,
        room: usize,
    ) -> Result<Option<AuthorityView>> {
        let room = room.max(1);
        if heads.len() <= room {
            return Ok(None);
        }
        measure_authority_work(self.limit_watch(), heads.len());
        let Some(tip) = self.admission_tip_in_txn(txn, heads, signer)? else {
            return Ok(None);
        };
        let now = self.instant_in_txn(txn)?.secs();
        let at = TimeRange {
            start: now,
            end: now,
        };
        let mut seq = signer.first_sequence(fold)?;
        let mut tips = heads.clone();
        let mut level_tip = Some(tip);
        let mut rows = Vec::new();
        let mut joins = Vec::new();
        while tips.len() > room {
            for group in plan_frontier_joins(&tips, level_tip) {
                let join = signer.sign(fold, seq, group.clone(), now)?;
                seq = seq.checked_add(1).ok_or_else(invalid_authority)?;
                let hash = authority_entry_hash(&join)?;
                tips.retain(|tip| !group.contains(tip));
                tips.insert(hash);
                joins.push(hash);
                rows.push((join, at, now));
            }
            level_tip = None;
        }
        self.put_authority_log_entries_in_txn(txn, &rows)?;
        let joined = self.authority_view_readonly_in_txn(txn)?;
        if !joins.iter().all(|hash| joined.valid_entries.contains(hash)) {
            return Err(authority_refused(JOIN_NOT_FOLDED));
        }
        Ok(Some(joined))
    }

    /// The admission tip of `heads` for `signer`: the lowest-hash head whose
    /// own state admits it ([`admits_join_signer`]), read from the capture
    /// the causal points read. `None` when no head does, or when the states
    /// cannot be read here ([`AUTHORITY_NEW_CHECK_UNKNOWN_KEEP_CURRENT`]).
    fn admission_tip_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        heads: &BTreeSet<AuthorityEntryHash>,
        signer: FrontierSigner<'_>,
    ) -> Result<Option<AuthorityEntryHash>> {
        let states: Option<BTreeMap<AuthorityEntryHash, Option<FoldState>>> =
            match super::act_standing::head_states_in_txn(&self.store, txn, heads) {
                Ok(states) => states,
                Err(_) if AUTHORITY_NEW_CHECK_UNKNOWN_KEEP_CURRENT => None,
                Err(error) => return Err(error),
            };
        let key = signer.key();
        Ok(states.into_iter().flatten().find_map(|(head, state)| {
            state
                .filter(|state| {
                    admits_join_signer(state, signer.family(), &key, (None, &every_chain))
                })
                .map(|_| head)
        }))
    }
}
