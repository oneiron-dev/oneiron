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
//! (FIX 11867), an Ed25519 or a P-256 root (FIX 11993). The fold admits its
//! signer by the act's own rule on the join's parent state
//! ([`admits_join_signer`]): the one carrier rule in the roster view, a live
//! owner roster key, or an anchor the fold
//! recorded for a stored root, never a key the join names for itself. A join
//! signed by any other key folds as every unvouched row does: invalid, with
//! no sequence slot, so it never forks or blocks the act's sequence. When a
//! head admits the signer, every first-level group names the frontier's
//! admission tip. The writer prefers the
//! lowest-hash admitting head whose planned groups also admit the signer
//! after merging their states (FIX 8499); if none is proven, it keeps the
//! old lowest-hash tip and fold/readback decision. When no head admits the
//! signer alone, the writer first joins a support set of at most one join's
//! heads whose merged state admits it, then carries that join forward: each
//! later join names the one before it and the next heads in hash order, and
//! every merge is proven to admit before any join is signed (FIX 8527). It
//! reads no role, clearance or owner act beyond that, and grants nothing.
//!
//! A writer whose own side heads alone fill one entry joins them the same
//! way first, by the same key, in the scope of the branch they ride (FIX
//! 11868): an anchor its own heads ([`FrontierJoinScope::AnchorSide`]), a
//! carrier a world's side leaves ([`FrontierJoinScope::World`]). Its fold is
//! the main join's; an anchor's side join also records itself among the
//! anchor's own rows, so it retires their heads and no main door names it.

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
    /// A ReRoot's signer, the owner root the move retires, Ed25519 or
    /// P-256 (FIX 11993), held behind the caller's signing callback, which
    /// signs each join's transcript (FIX 11867). Its joins are in the host
    /// family: that family's rule, a live owner roster key, is the standing
    /// the ReRoot itself stands on.
    Callback(&'a AuthorityKey, &'a dyn Fn(&[u8]) -> Result<Vec<u8>>),
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
            Self::Callback(key, _) => key.clone(),
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
        scope: FrontierJoinScope,
        seq: u64,
        parents: BTreeSet<AuthorityEntryHash>,
        now: u64,
    ) -> Result<AuthorityLogEntry> {
        let op = AuthorityOp::FrontierJoin(FrontierJoin {
            family: self.family(),
            scope,
        });
        match self {
            Self::Install(_, signing) | Self::Anchor(signing) => {
                sign_side_entry(fold, signing, seq, parents, op, now)
            }
            Self::Host(issuer) => {
                issuer.sign_entry(fold.vault_id, seq, parents.into_iter().collect(), op, now)
            }
            Self::Callback(key, transcript_signer) => {
                let mut entry = unsigned_side_entry(fold, key.clone(), seq, parents, op, now)?;
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
/// for the host, a live owner roster key, as the host's slip issuer and a
/// ReRoot's signer are (FIX 11867), in either root suite (FIX 11993); for an
/// anchor, an anchor `state` recorded for a stored root, as its marks are
/// admitted (FIX 8498, Engine 09:31 (2)), never a key the join carries and
/// never a roster key in its place. A P-256 key signs no carrier or anchor
/// join.
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
        (FrontierJoinFamily::Host, _) => roster_has_live_owner(&state.roster, signer),
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

/// Where a wide frontier's joins start.
enum JoinStart {
    /// A head whose own state admits the signer: every first-level group of
    /// [`plan_frontier_joins`] names it (FIX 7908, FIX 8499).
    Tip(AuthorityEntryHash),
    /// No head admits the signer alone: a support set whose merge does,
    /// then the joins that carry it forward (FIX 8527).
    Support(SupportJoins),
}

/// A support-set bootstrap (FIX 8527): the first join names `support`, the
/// heads whose merged state admits the signer; each later join names the
/// join before it and the next of `chunks`, the other heads in hash order,
/// until the tips fit. Every join's merged state was proven to admit the
/// signer before any join is signed.
struct SupportJoins {
    support: BTreeSet<AuthorityEntryHash>,
    chunks: Vec<BTreeSet<AuthorityEntryHash>>,
}

/// `state` merged onto `base`, or `state` alone when there is no base.
fn merge_onto(base: Option<&FoldState>, state: &FoldState) -> FoldState {
    base.map_or_else(|| state.clone(), |base| merge_states(base, state))
}

/// The merge of the states at `heads`, as the fold merges a row's parents;
/// `None` when one of them has no state here or none is named.
fn merged_state(
    heads: &BTreeSet<AuthorityEntryHash>,
    states: &BTreeMap<AuthorityEntryHash, Option<FoldState>>,
) -> Option<FoldState> {
    let mut merged: Option<FoldState> = None;
    for head in heads {
        let state = states.get(head)?.as_ref()?;
        merged = Some(merge_onto(merged.as_ref(), state));
    }
    merged
}

/// A support set of at most [`AUTHORITY_FRONTIER_JOIN_ARITY`] of `heads`
/// whose merged state `admits`, with that state (FIX 8527). Each round
/// merges the set so far with the other heads that have a state, in hash
/// order, and adds the first head at which that merge admits, until the
/// set's own merge admits. Deterministic: it reads the heads' hashes and
/// states alone. Bounded by the arity: at most that many rounds, each one
/// pass over `heads`. `None` when a round finds no head, or when the set
/// would outgrow one join.
fn support_set(
    heads: &BTreeSet<AuthorityEntryHash>,
    states: &BTreeMap<AuthorityEntryHash, Option<FoldState>>,
    admits: impl Fn(&FoldState) -> bool,
) -> Option<(BTreeSet<AuthorityEntryHash>, FoldState)> {
    let mut support: BTreeSet<AuthorityEntryHash> = BTreeSet::new();
    let mut merged: Option<FoldState> = None;
    while support.len() < AUTHORITY_FRONTIER_JOIN_ARITY {
        let mut reach = merged.clone();
        let mut found = None;
        for head in heads.iter().filter(|head| !support.contains(*head)) {
            let Some(state) = states.get(head).and_then(Option::as_ref) else {
                continue;
            };
            let next = merge_onto(reach.as_ref(), state);
            if admits(&next) {
                found = Some((*head, state));
                break;
            }
            reach = Some(next);
        }
        let (head, state) = found?;
        support.insert(head);
        let next = merge_onto(merged.as_ref(), state);
        if admits(&next) {
            return Some((support, next));
        }
        merged = Some(next);
    }
    None
}

/// The support-set bootstrap for `heads` when no head admits the signer
/// alone (FIX 8527, Engine 13:54 call B): [`support_set`], then the other
/// heads in hash order, in chunks of one fewer than a join's arity beside
/// the join carried forward, until the heads not yet joined and that join
/// fit `room`. Each carried merge must still admit. `None` when no support
/// set fits one join, or a carried merge does not admit or reads a head
/// with no state here: today's refusal, nothing signed.
fn plan_support_joins(
    heads: &BTreeSet<AuthorityEntryHash>,
    states: &BTreeMap<AuthorityEntryHash, Option<FoldState>>,
    room: usize,
    admits: impl Fn(&FoldState) -> bool,
) -> Option<SupportJoins> {
    let (support, mut merged) = support_set(heads, states, &admits)?;
    let others: Vec<AuthorityEntryHash> = heads
        .iter()
        .copied()
        .filter(|head| !support.contains(head))
        .collect();
    let mut rest = others.as_slice();
    let mut chunks: Vec<BTreeSet<AuthorityEntryHash>> = Vec::new();
    // The tips: the heads not yet joined, and the join carried forward.
    while rest.len() + 1 > room {
        let (chunk, tail) = rest.split_at(rest.len().min(AUTHORITY_FRONTIER_JOIN_ARITY - 1));
        for head in chunk {
            merged = merge_states(&merged, states.get(head)?.as_ref()?);
        }
        if !admits(&merged) {
            return None;
        }
        chunks.push(chunk.iter().copied().collect());
        rest = tail;
    }
    Some(SupportJoins { support, chunks })
}

/// The `FrontierJoin` transition, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster
/// check: its signer must be one [`admits_join_signer`] admits in the join's
/// parent state, else it is not in its ancestry. Its state is its parents'
/// merge, and only its signer's sequence moves, past its last one there; it
/// applies nothing. An anchor's side join is one of the anchor's own rows,
/// as its root and marks are (FIX 11868).
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
    if join.scope == FrontierJoinScope::AnchorSide {
        state.anchor_entries.insert(hash);
    }
    Ok(())
}

impl Vault {
    /// Joins `fold`'s main-log heads in `txn` when an act would name more of
    /// them than `room`, the heads it may name beside its other rows (one
    /// entry's [`MAX_PARENTS`] for an act that names the heads alone). Each
    /// level of [`plan_frontier_joins`] is signed by `signer`, at the
    /// sequences its act would take, until the tips fit, and every first-level
    /// group names the admission tip. When no head admits the signer alone,
    /// the joins are instead [`plan_support_joins`]'s: a support set's join,
    /// carried forward (FIX 8527). The joins land in one put, and the fold
    /// read back is returned, for the act's sequence and parents. `None` when
    /// the heads fit, or when no head admits the signer and no support set
    /// carries it: today's path, nothing written. A wide frontier is
    /// measured on Phase2 A's `authority_record_items` row, which asks past
    /// it and never waits or refuses.
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
        self.join_scoped_heads_in_txn(txn, fold, (heads, FrontierJoinScope::Main), signer, room)
    }

    /// [`Self::join_authority_heads_in_txn`] over `heads` of `scope`: the
    /// main log's, or the signer's own side heads that alone fill one entry
    /// (FIX 11868), each join signed in that scope, so it rides the branch
    /// it joins.
    ///
    /// # Errors
    /// As [`Self::prepare_authority_frontier_in_txn`].
    pub(crate) fn join_scoped_heads_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        heads_scope: (&BTreeSet<AuthorityEntryHash>, FrontierJoinScope),
        signer: FrontierSigner<'_>,
        room: usize,
    ) -> Result<Option<AuthorityView>> {
        Ok(self
            .join_scoped_heads_with_rows_in_txn(txn, fold, heads_scope, signer, room)?
            .map(|(joined, _)| joined))
    }

    /// [`Self::join_scoped_heads_in_txn`], with the rows of the joins it
    /// staged, for a writer that marks and announces them with its act (FIX
    /// 11993).
    ///
    /// # Errors
    /// As [`Self::prepare_authority_frontier_in_txn`].
    pub(crate) fn join_scoped_heads_with_rows_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        (heads, scope): (&BTreeSet<AuthorityEntryHash>, FrontierJoinScope),
        signer: FrontierSigner<'_>,
        room: usize,
    ) -> Result<Option<(AuthorityView, Vec<EntityId>)>> {
        let room = room.max(1);
        if heads.len() <= room {
            return Ok(None);
        }
        measure_authority_work(self.limit_watch(), heads.len());
        let Some(start) = self.join_start_in_txn(txn, heads, signer, room)? else {
            return Ok(None);
        };
        let now = self.instant_in_txn(txn)?.secs();
        let at = TimeRange {
            start: now,
            end: now,
        };
        let mut seq = signer.first_sequence(fold)?;
        let mut rows = Vec::new();
        let mut joins = Vec::new();
        let mut stage = |group: BTreeSet<AuthorityEntryHash>| -> Result<AuthorityEntryHash> {
            let join = signer.sign(fold, scope, seq, group, now)?;
            seq = seq.checked_add(1).ok_or_else(invalid_authority)?;
            let hash = authority_entry_hash(&join)?;
            joins.push(hash);
            rows.push((join, at, now));
            Ok(hash)
        };
        match start {
            JoinStart::Tip(tip) => {
                let mut tips = heads.clone();
                let mut level_tip = Some(tip);
                while tips.len() > room {
                    for group in plan_frontier_joins(&tips, level_tip) {
                        tips.retain(|tip| !group.contains(tip));
                        tips.insert(stage(group)?);
                    }
                    level_tip = None;
                }
            }
            // FIX 8527: the support set's join, then each chunk beside the
            // join before it; every merge was proven to admit the signer.
            JoinStart::Support(SupportJoins { support, chunks }) => {
                let mut carried = stage(support)?;
                for mut group in chunks {
                    group.insert(carried);
                    carried = stage(group)?;
                }
            }
        }
        let staged = self.put_authority_log_entries_in_txn(txn, &rows)?;
        let joined = self.authority_view_readonly_in_txn(txn)?;
        if !joins.iter().all(|hash| joined.valid_entries.contains(hash)) {
            return Err(authority_refused(JOIN_NOT_FOLDED));
        }
        Ok(Some((joined, staged)))
    }

    /// Where `heads`' joins start, read from the same capture as the causal
    /// points. The lowest-hash admitting head whose planned first-level
    /// groups also admit `signer` on their merged states (FIX 8499): a
    /// divergent head can conflict with an older tip's carrier revision while
    /// a newer tip heals that conflict. If no candidate proves its groups,
    /// keep today's lowest admitting tip and fold/readback decision. When no
    /// head admits alone, [`plan_support_joins`] for `room` (FIX 8527).
    /// `None` when no head admits and no support set carries the signer, or
    /// the capture is unavailable
    /// ([`AUTHORITY_NEW_CHECK_UNKNOWN_KEEP_CURRENT`]).
    fn join_start_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        heads: &BTreeSet<AuthorityEntryHash>,
        signer: FrontierSigner<'_>,
        room: usize,
    ) -> Result<Option<JoinStart>> {
        let states: Option<BTreeMap<AuthorityEntryHash, Option<FoldState>>> =
            match super::act_standing::head_states_in_txn(&self.store, txn, heads) {
                Ok(states) => states,
                Err(_) if AUTHORITY_NEW_CHECK_UNKNOWN_KEEP_CURRENT => None,
                Err(error) => return Err(error),
            };
        let Some(states) = states else {
            return Ok(None);
        };
        let key = signer.key();
        let admits = |state: &FoldState| {
            admits_join_signer(state, signer.family(), &key, (None, &every_chain))
        };
        let candidates: Vec<_> = states
            .iter()
            .filter_map(|(head, state)| state.as_ref().filter(|state| admits(state)).map(|_| *head))
            .collect();
        if candidates.is_empty() {
            return Ok(plan_support_joins(heads, &states, room, &admits).map(JoinStart::Support));
        }
        for tip in &candidates {
            let groups_admit = plan_frontier_joins(heads, Some(*tip))
                .iter()
                .all(|group| merged_state(group, &states).as_ref().is_some_and(&admits));
            if groups_admit {
                return Ok(Some(JoinStart::Tip(*tip)));
            }
        }
        // Incomplete evidence or no better partition keeps today's tip and
        // the existing fold/readback decision, never a new refusal here.
        Ok(candidates.first().copied().map(JoinStart::Tip))
    }
}
