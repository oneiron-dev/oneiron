//! Joining a wide causal frontier (FIX 7908 and its duplicates, Phase2 B;
//! CALLS "Phase2 frontier join"). An act whose main-log frontier is wider
//! than one entry names is preceded, in its own writer, by one signed
//! [`FrontierJoin`] that names every head of that frontier (FIX 8527, Engine
//! call A2), and the act names the join. Every head stays in the act's
//! causal past; nothing is dropped and nothing is refused for the count.
//!
//! The writer stages the join in its own transaction
//! ([`Vault::prepare_authority_frontier_in_txn`]) and then allocates the
//! act's sequence and parents from the fold it reads back, so the act's
//! sequence follows the join's. The act's seen or revision basis is the one
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
//! no sequence slot, so it never forks or blocks the act's sequence. The fold
//! judges the signer on the join's parent state, the merge of every head's
//! state, so a signer whose standing is split across heads (a carrier's
//! chain revision on one head, a sibling it needs on another) joins them
//! (FIX 8527). The writer stages a join only when that merge admits the
//! signer; when it does not, or the head states cannot be read, the act
//! keeps today's width refusal and nothing is written. It reads no role,
//! clearance or owner act beyond that, and grants nothing.
//!
//! A writer whose own side heads alone fill one entry joins them the same
//! way first, in one join, by the same key, in the scope of the branch they
//! ride (FIX 11868): an anchor its own heads
//! ([`FrontierJoinScope::AnchorSide`]), a carrier a world's side leaves
//! ([`FrontierJoinScope::World`]). Its fold is the main join's; an anchor's
//! side join also records itself among the anchor's own rows, so it retires
//! their heads and no main door names it.
//!
//! A wide join costs the fold one [`merge_states`] per head, each a clone of
//! the merged state so far, beside the per-parent wait and the
//! ancestor-index walk; the writer runs the same merge once more on its
//! capture before it stages. Each head adds its 32-byte hash to the signed
//! entry, to the join's checkpoint row and its required body, and to each
//! transfer of the entry.

use std::collections::BTreeSet;

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
    /// entry's [`MAX_PARENTS`] for an act that names the heads alone). One
    /// join names every head, signed by `signer` at the sequence its act
    /// would take (FIX 8527), and the fold read back is returned, for the
    /// act's sequence and parents. `None` when the heads fit, or when the
    /// merge of every head's state does not admit the signer or cannot be
    /// read: today's path, nothing written. A wide frontier is measured on
    /// Phase2 A's `authority_record_items` row, which asks past it and never
    /// waits or refuses.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] when the join did not
    /// fold valid, which leaves the frontier as wide as today's refusal of it;
    /// signing, store-door and storage errors. A caller's transaction that
    /// fails after this aborts the join with the act.
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
    /// other heads stay heads, and stay out of the join.
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
    /// (FIX 11868), the join signed in that scope, so it rides the branch it
    /// joins.
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

    /// [`Self::join_scoped_heads_in_txn`], with the row of the join it
    /// staged, for a writer that marks and announces it with its act (FIX
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
        if !self.heads_merge_admits_in_txn(txn, heads, signer)? {
            return Ok(None);
        }
        let now = self.instant_in_txn(txn)?.secs();
        let at = TimeRange {
            start: now,
            end: now,
        };
        let seq = signer.first_sequence(fold)?;
        let join = signer.sign(fold, scope, seq, heads.clone(), now)?;
        let hash = authority_entry_hash(&join)?;
        let staged = self.put_authority_log_entries_in_txn(txn, &[(join, at, now)])?;
        let joined = self.authority_view_readonly_in_txn(txn)?;
        if !joined.valid_entries.contains(&hash) {
            return Err(authority_refused(JOIN_NOT_FOLDED));
        }
        Ok(Some((joined, staged)))
    }

    /// Whether the merge of every one of `heads`' states admits `signer` to
    /// sign their join: the parent state the fold judges the join on (FIX
    /// 8527), read from the same capture as the causal points. Merged in
    /// hash order, one head at a time. `false` when a head has no state
    /// there, as the join would then never fold, and when the capture is
    /// unavailable ([`AUTHORITY_NEW_CHECK_UNKNOWN_KEEP_CURRENT`]).
    fn heads_merge_admits_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        heads: &BTreeSet<AuthorityEntryHash>,
        signer: FrontierSigner<'_>,
    ) -> Result<bool> {
        let states = match super::act_standing::head_states_in_txn(&self.store, txn, heads) {
            Ok(states) => states,
            Err(_) if AUTHORITY_NEW_CHECK_UNKNOWN_KEEP_CURRENT => None,
            Err(error) => return Err(error),
        };
        let Some(states) = states else {
            return Ok(false);
        };
        let mut merged: Option<FoldState> = None;
        for head in heads {
            let Some(state) = states.get(head).and_then(Option::as_ref) else {
                return Ok(false);
            };
            merged = Some(match merged {
                Some(merged) => merge_states(&merged, state),
                None => state.clone(),
            });
        }
        Ok(merged.is_some_and(|state| {
            admits_join_signer(&state, signer.family(), &signer.key(), (None, &every_chain))
        }))
    }
}
