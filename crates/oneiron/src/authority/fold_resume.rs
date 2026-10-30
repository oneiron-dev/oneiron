//! A resumed fold: the stored log's reference fold carried over the new rows
//! past its frontier, without folding the whole log again. It answers only
//! where its guards show the reference reaches the same fold from the same
//! inputs; otherwise it declines, and the caller folds the log.
//!
//! The base is the last once fold of a strict fold that settled in one round
//! with one install round and no fold with no vouch. It keeps the state at
//! its one main head and at each world's side leaf. A new row joins it only
//! when it is an op that changes no earlier row's fate (an agent enrollment,
//! a fresh binding, a slip mint or consume, a fresh federation confirm, a
//! critical-write confirm, a world key record), folds valid on its own
//! parents' states, and stands on that frontier: a main row extends the
//! head as one chain, and a world key record names kept states and earlier
//! new rows alone (FIX 4881, [`side_tail`]).
//!
//! The base also indexes the history it folded (OF-469): each row's signer,
//! sequence, parents and world, and whole only the rows a later fold reads
//! whole. A resumed fold reads the stored rows past the base and nothing
//! else of the log.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::fold_engine::FoldContext;
use super::fold_project::Settled;
use super::*;
use crate::EntityId;

mod capture;
mod heads;
mod image;
mod receipts;
mod resumed;
mod side_tail;

use capture::Once;
pub(super) use capture::{
    ConfirmKeys, FoldCapture, OnceParts, add_bound_keys, add_writers, admits_past,
};
pub(super) use image::ImageFold;
use receipts::BaseReceipts;
pub(super) use resumed::Resumed;

/// The inputs besides the log a base folded under.
#[derive(Clone, PartialEq)]
struct Inputs {
    posture: crate::HostingPrivacyPosture,
    pin: Option<PinnedRoot>,
    policy: AuthorityObservationPolicy,
    peers: BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    vouched: BTreeSet<AuthorityEntryHash>,
    unvouched: bool,
}

impl Inputs {
    fn of(
        posture: crate::HostingPrivacyPosture,
        pin: Option<&PinnedRoot>,
        peers: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
        observations: &AuthorityLocalObservations,
    ) -> Self {
        Self {
            posture,
            pin: pin.copied(),
            policy: observations.policy,
            peers: peers.clone(),
            vouched: observations.vouched.clone(),
            unvouched: observations.unvouched,
        }
    }
}

/// What a fold past the base reads of a row it no longer reads whole.
#[derive(Clone)]
struct RowSummary {
    signer: AuthorityKey,
    seq: u64,
    parents: Vec<AuthorityEntryHash>,
    world: Option<EntityId>,
}

impl RowSummary {
    fn of(entry: &AuthorityLogEntry) -> Self {
        Self {
            signer: entry.signer_key().clone(),
            seq: entry.seq,
            parents: entry.parent_hashes.clone(),
            world: super::world_privacy::side_world(&entry.op),
        }
    }
}

/// Each row a base folded, by hash: a persistent map, so the next base
/// shares it and adds only the tail's rows (FIX 12308).
type BaseRows = im::OrdMap<AuthorityEntryHash, Arc<RowSummary>>;

/// The rows a base reads whole ([`is_projected`]), by hash, shared the same
/// way.
type ProjectedRows = im::OrdMap<AuthorityEntryHash, Arc<AuthorityLogEntry>>;

/// Each row's first-seen seconds or sequence floor, by hash, shared the
/// same way.
type RowSeconds = im::OrdMap<AuthorityEntryHash, u64>;

impl super::fold_project::RowsReadWhole for ProjectedRows {
    fn get(&self, hash: &AuthorityEntryHash) -> Option<&AuthorityLogEntry> {
        im::OrdMap::get(self, hash).map(|entry| &**entry)
    }
}

impl super::stale_roster::FirstSeenMap for RowSeconds {
    fn get(&self, hash: &AuthorityEntryHash) -> Option<&u64> {
        im::OrdMap::get(self, hash)
    }
}

/// A row's metadata, from its signed entry or the base's summary of it: all
/// the heads, the next sequences and the sequence floors read of a row.
#[derive(Clone, Copy)]
pub(super) struct RowMeta<'a> {
    pub(super) hash: Option<AuthorityEntryHash>,
    pub(super) signer: &'a AuthorityKey,
    pub(super) seq: u64,
    pub(super) parents: &'a [AuthorityEntryHash],
    pub(super) world: Option<EntityId>,
}

impl<'a> RowMeta<'a> {
    pub(super) fn of(hash: Option<AuthorityEntryHash>, entry: &'a AuthorityLogEntry) -> Self {
        Self {
            hash,
            signer: entry.signer_key(),
            seq: entry.seq,
            parents: &entry.parent_hashes,
            world: super::world_privacy::side_world(&entry.op),
        }
    }

    fn summarized(hash: AuthorityEntryHash, row: &'a RowSummary) -> Self {
        Self {
            hash: Some(hash),
            signer: &row.signer,
            seq: row.seq,
            parents: &row.parents,
            world: row.world,
        }
    }
}

/// Whether a fold past the base reads `op`'s row whole: the approvals and
/// revocations stale-roster expiry and renewal weigh (`stale_roster`), the
/// world-key records whose envelopes a folded key carries
/// (`world_key_fold::folded_world_keys`), and the owner work requests,
/// results, cancels and import marks an executor, a receipt and a relay
/// read past the base. Every other row's summary is all a later fold reads
/// of it.
pub(super) fn is_projected(op: &AuthorityOp) -> bool {
    matches!(
        op,
        AuthorityOp::BindActor { .. }
            | AuthorityOp::RebindActor { .. }
            | AuthorityOp::FederationConfirm(_)
            | AuthorityOp::CriticalWriteConfirm(_)
            | AuthorityOp::MachineProfile(_)
            | AuthorityOp::RevokeDevice { .. }
            | AuthorityOp::RotateKey { .. }
            | AuthorityOp::ReRoot { .. }
            | AuthorityOp::WorldKeyWraps(_)
            | AuthorityOp::OwnerWorkRequest(_)
            | AuthorityOp::OwnerWorkResult(_)
            | AuthorityOp::OwnerWorkCancel(_)
            | AuthorityOp::ExportSupplementImported(_)
    )
}

/// A stored log's fold, and what a resumed fold needs to carry it on.
pub(in crate::authority) struct FoldBase {
    inputs: Arc<Inputs>,
    /// Every row the base folded, a rejected one too.
    rows: BaseRows,
    /// The rows a fold past the base reads whole: see [`is_projected`].
    projected: ProjectedRows,
    /// Whether a row read whole revokes a device, rotates a key or re-roots
    /// the vault: only past one does the stale-roster window read any row
    /// ([`stale_roster_rows`]).
    revokes_roster_keys: bool,
    receipts: BaseReceipts,
    once: Once,
    /// The heads, scope heads and next sequences of the base's view, which
    /// a fold past it updates from its new rows (FIX 12307).
    heads: heads::LogHeads,
}

impl FoldBase {
    /// The base of `view`, a full fold of `rows` whose last once fold is
    /// `once`.
    fn capture(
        inputs: Inputs,
        once: Once,
        rows: &[(AuthorityEntryHash, &AuthorityLogEntry)],
        first_seen: &BTreeMap<AuthorityEntryHash, u64>,
        floors: &BTreeMap<AuthorityEntryHash, u64>,
        view: &AuthorityFold,
    ) -> Self {
        let expired = once
            .valid
            .iter()
            .filter(|hash| !view.valid_entries.contains(*hash))
            .copied()
            .collect();
        Self {
            inputs: Arc::new(inputs),
            rows: rows
                .iter()
                .map(|(hash, entry)| (*hash, Arc::new(RowSummary::of(entry))))
                .collect(),
            projected: rows
                .iter()
                .filter(|(_, entry)| is_projected(&entry.op))
                .map(|(hash, entry)| (*hash, Arc::new((*entry).clone())))
                .collect(),
            revokes_roster_keys: rows
                .iter()
                .any(|(_, entry)| super::stale_roster::revokes_roster_key(&entry.op)),
            receipts: BaseReceipts {
                first_seen: first_seen
                    .iter()
                    .map(|(hash, secs)| (*hash, *secs))
                    .collect(),
                floors: floors.iter().map(|(hash, floor)| (*hash, *floor)).collect(),
                pinned: im::OrdSet::new(),
                unpinned: rows.iter().map(|(hash, _)| *hash).collect(),
            },
            once,
            heads: heads::LogHeads::of(view, expired),
        }
    }

    /// This base, with `pinned` the rows it took from write-once receipts.
    /// It keeps only its own rows with first-seen seconds; a read pins no
    /// other.
    pub(in crate::authority) fn with_pinned(
        mut self,
        pinned: BTreeSet<AuthorityEntryHash>,
    ) -> Self {
        let pinned: im::OrdSet<_> = pinned
            .into_iter()
            .filter(|hash| {
                self.rows.contains_key(hash) && self.receipts.first_seen.contains_key(hash)
            })
            .collect();
        self.receipts.unpinned = self
            .rows
            .keys()
            .filter(|hash| !pinned.contains(*hash))
            .copied()
            .collect();
        self.receipts.pinned = pinned;
        self
    }

    /// Each row the base folded.
    pub(in crate::authority) fn hashes(&self) -> impl Iterator<Item = &AuthorityEntryHash> {
        self.rows.keys()
    }

    /// The parents each row the base folded names.
    pub(in crate::authority) fn parents(
        &self,
    ) -> impl Iterator<Item = (&AuthorityEntryHash, &[AuthorityEntryHash])> {
        self.rows
            .iter()
            .map(|(hash, row)| (hash, row.parents.as_slice()))
    }

    /// The vault the base's fold names.
    pub(in crate::authority) fn vault_id(&self) -> Option<AuthorityVaultId> {
        self.once.fold.vault_id
    }

    /// The next stale-roster deadline past `now_secs` of `fold`, this
    /// base's view: over the rows read whole, with the hashes and the
    /// first-seen seconds the base holds (FIX 12309).
    pub(in crate::authority) fn stale_roster_deadline(
        &self,
        fold: &AuthorityFold,
        now_secs: u64,
        window_secs: u64,
    ) -> Option<u64> {
        next_stale_roster_deadline(
            &stale_roster_rows(&self.projected, self.revokes_roster_keys),
            fold,
            &self.receipts.first_seen,
            now_secs,
            window_secs,
        )
    }

    /// The metadata of the base's rows and `tail`'s, in hash order: the
    /// order the store's type index reads them in.
    pub(in crate::authority) fn rows_with<'a>(
        &'a self,
        tail: &[(AuthorityEntryHash, &'a AuthorityLogEntry)],
    ) -> Vec<RowMeta<'a>> {
        let mut rows: BTreeMap<_, _> = self
            .rows
            .iter()
            .map(|(hash, row)| (*hash, RowMeta::summarized(*hash, row)))
            .collect();
        for (hash, entry) in tail {
            rows.entry(*hash)
                .or_insert_with(|| RowMeta::of(Some(*hash), *entry));
        }
        rows.into_values().collect()
    }

    /// The metadata of the rows a fold past the base reads the receipts of,
    /// in hash order: `tail`'s, each base row the base does not pin, and
    /// each pinned one `reread` names. The base carries every other row's
    /// first-seen seconds and floor unread, so no other row is visited (FIX
    /// 12282).
    pub(in crate::authority) fn rows_read_with<'a>(
        &'a self,
        tail: &[(AuthorityEntryHash, &'a AuthorityLogEntry)],
        reread: impl IntoIterator<Item = AuthorityEntryHash>,
    ) -> Vec<RowMeta<'a>> {
        let pinned = &self.receipts.pinned;
        let reread = reread.into_iter().filter(|hash| pinned.contains(hash));
        let mut rows: BTreeMap<_, _> = self
            .receipts
            .unpinned
            .iter()
            .copied()
            .chain(reread)
            .filter_map(|hash| Some((hash, RowMeta::summarized(hash, self.rows.get(&hash)?))))
            .collect();
        for (hash, entry) in tail {
            if !self.rows.contains_key(hash) {
                rows.entry(*hash)
                    .or_insert_with(|| RowMeta::of(Some(*hash), *entry));
            }
        }
        rows.into_values().collect()
    }
}

/// The rows the stale-roster window reads of `projected`, the rows read
/// whole, each with the hash the base holds (FIX 12309), where `revokes` says
/// one of them revokes a device, rotates a key or re-roots the vault. Over
/// rows with none of these the window expires no approval and finds no
/// deadline, so then it reads none.
fn stale_roster_rows(
    projected: &ProjectedRows,
    revokes: bool,
) -> Vec<(AuthorityEntryHash, &AuthorityLogEntry)> {
    if !revokes {
        return Vec::new();
    }
    projected
        .iter()
        .map(|(hash, entry)| (*hash, &**entry))
        .collect()
}

/// A stored log and what this vault folds it under.
#[derive(Clone, Copy)]
pub(in crate::authority) struct StoredLog<'a> {
    pub(in crate::authority) entries: &'a [AuthorityLogEntry],
    pub(in crate::authority) first_seen_at_secs: &'a BTreeMap<AuthorityEntryHash, u64>,
    pub(in crate::authority) now_secs: u64,
    pub(in crate::authority) peer_consent_roots:
        &'a BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    pub(in crate::authority) observations: &'a AuthorityLocalObservations,
    pub(in crate::authority) posture: crate::HostingPrivacyPosture,
    pub(in crate::authority) pin: Option<&'a PinnedRoot>,
}

/// The stored rows past a base, and what this vault folds the whole log
/// under: [`StoredLog`]'s inputs over the base's rows and the tail alike.
/// A base row the base pins and this fold did not read keeps the base's
/// first-seen seconds and floor (FIX 12282).
#[derive(Clone, Copy)]
pub(in crate::authority) struct StoredTail<'a> {
    /// Each stored row the base does not hold, with its hash.
    pub(in crate::authority) tail: &'a [(AuthorityEntryHash, &'a AuthorityLogEntry)],
    /// The first-seen seconds of each row this fold read: the tail's, and
    /// each base row's but those the base carries.
    pub(in crate::authority) first_seen_at_secs: &'a BTreeMap<AuthorityEntryHash, u64>,
    pub(in crate::authority) now_secs: u64,
    pub(in crate::authority) peer_consent_roots:
        &'a BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    /// The floors of the same rows, and this vault's observation policy.
    pub(in crate::authority) observations: &'a AuthorityLocalObservations,
    /// The rows read whose first-seen seconds and floor are receipts' (FIX
    /// 1854).
    pub(in crate::authority) pinned: &'a BTreeSet<AuthorityEntryHash>,
    pub(in crate::authority) posture: crate::HostingPrivacyPosture,
    pub(in crate::authority) pin: Option<&'a PinnedRoot>,
}

#[cfg(test)]
thread_local! {
    /// How many folds this thread resumed from a base.
    pub(super) static RESUMED_FOR_TEST: Cell<usize> = const { Cell::new(0) };
}

/// The stored log's fold past `base`, from the base and the tail alone, and
/// the base for the next fold; None wherever a guard fails, and the caller
/// folds the whole log. The caller holds every row the base folded still
/// stored: the base stands in for those rows.
pub(in crate::authority) fn fold_stored_tail(
    log: StoredTail<'_>,
    base: &FoldBase,
) -> Option<(AuthorityFold, FoldBase)> {
    let inputs = Inputs::of(
        log.posture,
        log.pin,
        log.peer_consent_roots,
        log.observations,
    );
    let resumed = base.resume(log, &inputs)?;
    #[cfg(test)]
    RESUMED_FOR_TEST.with(|resumed| resumed.set(resumed.get() + 1));
    Some(resumed)
}

/// The stored log's fold under this vault's observations, posture and pin,
/// resumed from `base` where it can be, and the base for the next fold.
pub(in crate::authority) fn fold_stored_log(
    log: StoredLog<'_>,
    base: Option<&FoldBase>,
) -> (AuthorityFold, Option<FoldBase>) {
    let StoredLog {
        entries,
        first_seen_at_secs,
        now_secs,
        peer_consent_roots,
        observations,
        posture,
        pin,
    } = log;
    let rows: Option<Vec<_>> = entries
        .iter()
        .map(|entry| Some((authority_entry_hash(entry).ok()?, entry)))
        .collect();
    // A base resumes only while every row it folded is still in the log.
    if let (Some(base), Some(rows)) = (base, &rows) {
        let held: BTreeSet<_> = rows.iter().map(|(hash, _)| *hash).collect();
        let tail: Vec<_> = rows
            .iter()
            .filter(|(hash, _)| !base.rows.contains_key(hash))
            .copied()
            .collect();
        if base.rows.keys().all(|hash| held.contains(hash))
            && let Some((fold, next)) = fold_stored_tail(
                StoredTail {
                    tail: &tail,
                    first_seen_at_secs,
                    now_secs,
                    peer_consent_roots,
                    observations,
                    pinned: &BTreeSet::new(),
                    posture,
                    pin,
                },
                base,
            )
        {
            return (fold, Some(next));
        }
    }
    let inputs = Inputs::of(posture, pin, peer_consent_roots, observations);
    let capture = FoldCapture::default();
    let (consent, local) = super::fold_engine::own_log_inputs(posture, pin);
    let fold = super::fold_engine::fold_authority_log_inner(
        entries,
        first_seen_at_secs,
        Some(now_secs),
        peer_consent_roots,
        consent,
        super::fold_engine::FoldLocalInputs {
            observations: Some(observations),
            capture: Some(&capture),
            ..local
        },
    );
    let base = capture.take().zip(rows).map(|(once, rows)| {
        FoldBase::capture(
            inputs,
            *once,
            &rows,
            first_seen_at_secs,
            &observations.sequence_floors,
            &fold,
        )
    });
    (fold, base)
}

impl FoldBase {
    /// The fold of the base's log and the tail, the new rows on its frontier
    /// ([`side_tail`]), as the reference reaches it; None wherever a guard
    /// fails.
    fn resume(&self, log: StoredTail<'_>, inputs: &Inputs) -> Option<(AuthorityFold, Self)> {
        let StoredTail {
            tail,
            first_seen_at_secs,
            now_secs,
            observations,
            pinned,
            ..
        } = log;
        if *inputs != *self.inputs {
            return None;
        }
        let once = &self.once;
        let settlement = &once.settlement;
        let new_rows: BTreeMap<_, _> = tail
            .iter()
            .filter(|(hash, _)| !self.rows.contains_key(hash))
            .map(|(hash, entry)| (*hash, *entry))
            .collect();
        // A row pinned here and in the base holds one receipt's values, and
        // a row the base pins and this fold did not read holds the base's
        // (FIX 12282). Every other base row reads as the base read it: each
        // one the base does not pin, and each pinned one read with no
        // receipt now.
        let base = &self.receipts;
        let mut reread = base.unpinned.iter().chain(
            first_seen_at_secs
                .keys()
                .filter(|hash| base.pinned.contains(*hash) && !pinned.contains(*hash)),
        );
        if new_rows.is_empty()
            || reread.any(|hash| {
                first_seen_at_secs.get(hash) != base.first_seen.get(hash)
                    || observations.sequence_floors.get(hash) != base.floors.get(hash)
            })
        {
            return None;
        }
        let memory_floor_bytes = super::log_budget::fold_memory_floor(Some(&observations.policy));
        let (consent_arm, _) = super::fold_engine::own_log_inputs(inputs.posture, None);
        let no_handoff_line = BTreeSet::new();
        // Only the new rows' floors are read, and this fold read each one.
        let context = FoldContext {
            sequence_floors: Some(&observations.sequence_floors),
            floor_vouched: (!observations.unvouched).then_some(&observations.vouched),
            install_held: None,
            entry_ancestors: None,
            causal_past: None,
            peer_consent_roots: &inputs.peers,
            consent_arm,
            hosted: inputs.posture == crate::HostingPrivacyPosture::Hosted,
            machine_standing: &super::machine_standing::every_chain,
            pre_handoff_entries: Some(&no_handoff_line),
            memory_floor_bytes,
            pin: inputs.pin.as_ref(),
        };
        // The new rows: main rows one chain off the head, and world key
        // records on the kept frontier, each on its own parents' states.
        let mut tail = side_tail::fold_tail(once, &self.rows, &new_rows, context)?;
        let mut merged = once.merged.clone();
        let mut writers = once.writers.clone();
        let mut bound_keys = once.bound_keys.clone();
        for (hash, state) in &tail.states {
            merged = merge_states(&merged, state);
            add_writers(&mut writers, state);
            if tail.main.contains(hash) {
                add_bound_keys(&mut bound_keys, state);
            }
        }
        // The view's own valid entries: the one copy of the base's a fold
        // past it makes (FIX 12308).
        let valid_entries: BTreeSet<_> = once.valid.iter().chain(&tail.order).copied().collect();
        // The projection reads each world-key envelope from the rows read
        // whole, the base's and the tail's.
        let tail_rows: Vec<_> = tail
            .order
            .iter()
            .map(|hash| (*hash, new_rows[hash]))
            .collect();
        let mut projected = self.projected.clone();
        for (hash, entry) in &tail_rows {
            if is_projected(&entry.op) {
                projected.insert(*hash, Arc::new((*entry).clone()));
            }
        }
        let rows = Resumed {
            marks: &settlement.marks,
            fold: &once.fold,
            revocations: &once.revocations,
            bound_keys: &once.bound_keys,
            chain: tail
                .states
                .iter()
                .filter(|(hash, _)| tail.main.contains(*hash))
                .map(|(hash, state)| (*hash, state))
                .collect(),
            writers: &writers,
            missed: Cell::new(false),
        };
        let (mut fold, final_merged) = super::fold_project::project_once(
            Settled {
                merged: Some(merged.clone()),
                valid_entries,
                by_hash: &projected,
                revoke_facts: &settlement.revoke_facts,
                retired_keys: settlement.retired_keys.clone(),
                closed_handoffs: settlement.closed_handoffs.clone(),
                unsettled: settlement.unsettled,
                counted_ancestor_pairs: tail.counted_pairs,
                issues: settlement.issues.clone(),
            },
            &rows,
            context,
        );
        if rows.missed.get()
            || fold.machines != once.fold.machines
            || !super::world_privacy::worlds_unmoved_past(
                &fold,
                &once.fold,
                tail_rows.iter().copied(),
            )
        {
            return None;
        }
        let kept = without_valid_entries(&mut fold);
        // The install's own view, in its first and only round, over the
        // rows its stale-roster window reads.
        let receipts = self.receipts.past(&log, &self.rows, &new_rows);
        let revokes_roster_keys = self.revokes_roster_keys
            || tail_rows
                .iter()
                .any(|(_, entry)| super::stale_roster::revokes_roster_key(&entry.op));
        let (mut view, expired) = super::install_fold::install_view_expiring(
            &stale_roster_rows(&projected, revokes_roster_keys),
            fold,
            &receipts.first_seen,
            Some(now_secs),
            observations.policy.stale_roster_window_secs,
            inputs.pin.as_ref(),
        );
        if view.rests_on_counting() && !super::install_fold::stale_chains(&view).is_empty() {
            return None;
        }
        // The heads from the new rows alone where every base row counts as
        // the base's view counted it, else over every row (FIX 12307).
        let heads = match self.heads.past(&view, &expired, &new_rows) {
            Some(heads) => {
                heads.set_on(&mut view);
                heads
            }
            None => {
                super::install_fold::finish_install_fold_of(&self.rows_with(&tail_rows), &mut view);
                heads::LogHeads::of(&view, expired)
            }
        };
        // Each row-sized part of the next base is this one's, shared, with
        // the tail's rows added (FIX 12308).
        let (mut judged, mut valid) = (once.judged.clone(), once.valid.clone());
        judged.extend(tail.order.iter().copied());
        valid.extend(tail.order.iter().copied());
        let mut rows = self.rows.clone();
        for (hash, entry) in &tail_rows {
            rows.insert(*hash, Arc::new(RowSummary::of(entry)));
        }
        let frontier = tail.take_frontier(once, &new_rows);
        let next = Self {
            inputs: Arc::clone(&self.inputs),
            rows,
            projected,
            revokes_roster_keys,
            receipts,
            once: Once {
                judged,
                head: tail.tip,
                frontier,
                merged,
                revocations: final_merged?.actor_revocation_hashes,
                settlement: Arc::clone(settlement),
                issuers: once.issuers.clone(),
                uncounted: tail.uncounted,
                pairs: tail.pairs,
                counted_pairs: tail.counted_pairs,
                writers,
                bound_keys,
                confirm_ids: tail.confirms.0,
                confirm_nonces: tail.confirms.1,
                valid,
                fold: kept,
            },
            heads,
        };
        Some((view, next))
    }
}

/// A copy of `fold` without its valid entries, which move out and back and
/// are never copied: what the next base keeps of a once fold beside the
/// persistent set of them it shares (FIX 12308).
fn without_valid_entries(fold: &mut AuthorityFold) -> AuthorityFold {
    let valid_entries = std::mem::take(&mut fold.valid_entries);
    let kept = fold.clone();
    fold.valid_entries = valid_entries;
    kept
}
