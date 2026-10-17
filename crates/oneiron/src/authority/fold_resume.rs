//! A resumed fold: the stored log's reference fold carried over a chain of
//! new rows off its one main head, without folding the whole log again. It
//! answers only where its guards show the reference reaches the same fold
//! from the same inputs; otherwise it declines, and the caller folds the log.
//!
//! The base is the last once fold of a strict fold that settled in one round
//! with one install round and no fold with no vouch. A new row joins it only
//! when it extends the head, is an op that changes no earlier row's fate
//! (an agent enrollment, a fresh binding, a slip mint or consume, a fresh
//! federation confirm, a critical-write confirm), and folds valid on its own
//! parent's state.
//!
//! The base also indexes the history it folded (OF-469): each row's signer,
//! sequence, parents and world, and whole only the rows a later fold reads
//! whole. A resumed fold reads the stored rows past the base and nothing
//! else of the log.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::fold_engine::FoldContext;
use super::fold_project::{RowStates, Settled};
use super::revoke_proof::RevokeFacts;
use super::*;
use crate::EntityId;

/// What a strict fold leaves for a resumed one: its last once fold, unless a
/// second strict round, a second install round or a fold with no vouch spoiled
/// it.
#[derive(Default)]
pub(super) struct FoldCapture {
    once: RefCell<Option<Box<Once>>>,
    spoiled: Cell<bool>,
    /// The checkpoint image build's capture (OF-469, checkpoint v2): it keeps
    /// an [`ImageFold`] in place of a resumable once fold.
    image: Option<ImageSlot>,
}

/// The frontier an image build keeps fold states at, and what it kept of the
/// last once fold.
struct ImageSlot {
    frontier: BTreeSet<AuthorityEntryHash>,
    fold: RefCell<Option<Box<ImageFold>>>,
}

impl FoldCapture {
    /// A capture for the checkpoint image build: it keeps the fold state at
    /// each row of `frontier`. No resumed fold reads it.
    pub(super) fn for_image(frontier: BTreeSet<AuthorityEntryHash>) -> Self {
        Self {
            image: Some(ImageSlot {
                frontier,
                fold: RefCell::new(None),
            }),
            ..Self::default()
        }
    }

    /// What the image build kept of the last once fold.
    pub(super) fn take_image(self) -> Option<Box<ImageFold>> {
        self.image.and_then(|image| image.fold.into_inner())
    }

    pub(super) fn spoil(&self) {
        self.spoiled.set(true);
    }

    pub(super) fn record(&self, parts: OnceParts<'_>) {
        if let Some(image) = &self.image {
            *image.fold.borrow_mut() = ImageFold::of(parts, &image.frontier).map(Box::new);
        } else {
            *self.once.borrow_mut() = Once::of(parts).map(Box::new);
        }
    }

    fn take(self) -> Option<Box<Once>> {
        if self.spoiled.get() {
            return None;
        }
        self.once.into_inner()
    }
}

/// A once fold's settlement, as `fold_authority_log_once` reached it.
pub(super) struct OnceParts<'a> {
    pub(super) by_hash: &'a BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    pub(super) states: &'a BTreeMap<AuthorityEntryHash, FoldState>,
    pub(super) entry_ancestors: &'a BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    /// The floors the fold was handed, before causal ancestry cleared any.
    pub(super) original_floors: Option<&'a BTreeMap<AuthorityEntryHash, u64>>,
    pub(super) merged: FoldState,
    pub(super) valid_entries: BTreeSet<AuthorityEntryHash>,
    pub(super) revoke_facts: RevokeFacts,
    pub(super) retired_keys: BTreeSet<AuthorityKey>,
    pub(super) closed_handoffs: BTreeSet<AuthorityEntryHash>,
    pub(super) unsettled: bool,
    pub(super) counted_ancestor_pairs: u64,
    pub(super) issues: Vec<AuthorityFoldIssue>,
    pub(super) final_merged: Option<&'a FoldState>,
    pub(super) fold: &'a AuthorityFold,
}

/// What no row of the chain changes.
struct Settlement {
    revoke_facts: RevokeFacts,
    retired_keys: BTreeSet<AuthorityKey>,
    closed_handoffs: BTreeSet<AuthorityEntryHash>,
    unsettled: bool,
    issues: Vec<AuthorityFoldIssue>,
    /// Parents a judged row names that no judged row is.
    missing_parents: BTreeSet<AuthorityEntryHash>,
    /// The valid machine profiles heading their own roster chain under an
    /// owner-held key, with that key: the marks before custody is judged.
    marks: Vec<(AuthorityEntryHash, AuthorityKey)>,
}

/// One settled once fold, and what its projection read of each row's state.
struct Once {
    judged: BTreeSet<AuthorityEntryHash>,
    head: AuthorityEntryHash,
    head_state: FoldState,
    /// The merge of every surviving state, before any restrictive fact.
    merged: FoldState,
    /// The final merge's revocations, by key.
    revocations: BTreeMap<AuthorityKey, BTreeSet<AuthorityEntryHash>>,
    settlement: Arc<Settlement>,
    /// The judged rows' slip issuers. No op a chain admits names a root or
    /// a consent device, so a chain never adds one.
    issuers: BTreeSet<AuthorityKey>,
    uncounted: BTreeSet<AuthorityEntryHash>,
    pairs: u64,
    counted_pairs: u64,
    head_ancestors: u64,
    head_counted_ancestors: u64,
    head_counted: bool,
    /// Every binding any state holds, by key.
    writers: BTreeMap<AuthorityKey, BTreeSet<(EntityId, String)>>,
    /// The keys some main state holds a live binding for.
    bound_keys: BTreeSet<AuthorityKey>,
    confirm_ids: BTreeSet<[u8; 32]>,
    confirm_nonces: BTreeSet<[u8; 16]>,
    /// The projected once fold, before this install's stale window.
    fold: AuthorityFold,
}

impl Once {
    fn of(parts: OnceParts<'_>) -> Option<Self> {
        let OnceParts {
            by_hash,
            states,
            entry_ancestors,
            original_floors,
            merged,
            valid_entries,
            revoke_facts,
            retired_keys,
            closed_handoffs,
            unsettled,
            counted_ancestor_pairs,
            issues,
            final_merged,
            fold,
        } = parts;
        let is_main = |hash: &AuthorityEntryHash| {
            super::world_privacy::side_world(&by_hash[hash].op).is_none()
        };
        // No row past its floor, so no floor and no vouch decides a row, and
        // every main row folded.
        let below_floor = by_hash.iter().any(|(hash, entry)| {
            original_floors
                .and_then(|floors| floors.get(hash))
                .is_some_and(|floor| entry.seq < *floor)
        });
        if below_floor
            || by_hash
                .keys()
                .any(|hash| is_main(hash) && !states.contains_key(hash))
        {
            return None;
        }
        let main_parents: BTreeSet<_> = by_hash
            .iter()
            .filter(|(hash, _)| is_main(hash))
            .flat_map(|(_, entry)| entry.parent_hashes.iter().copied())
            .collect();
        let mut heads = by_hash
            .keys()
            .filter(|hash| is_main(hash) && !main_parents.contains(*hash));
        let (Some(head), None) = (heads.next().copied(), heads.next()) else {
            return None;
        };
        let head_state = states[&head].clone();
        if head_state.federation_pacts != merged.federation_pacts {
            return None;
        }
        let final_merged = final_merged?;
        let issuers = super::log_structure::authority_structure(by_hash.values()).issuers;
        let uncounted = by_hash
            .iter()
            .filter(|(_, entry)| super::log_budget::is_uncounted(entry, &issuers))
            .map(|(hash, _)| *hash)
            .collect::<BTreeSet<_>>();
        let head_ancestors = &entry_ancestors[&head];
        let mut writers = BTreeMap::<_, BTreeSet<_>>::new();
        let mut bound_keys = BTreeSet::new();
        let (mut confirm_ids, mut confirm_nonces) = (BTreeSet::new(), BTreeSet::new());
        for (hash, state) in states {
            add_writers(&mut writers, state);
            if is_main(hash) {
                add_bound_keys(&mut bound_keys, state);
            }
            if let AuthorityOp::FederationConfirm(action) = &by_hash[hash].op {
                confirm_ids.insert(action.confirm_id);
                confirm_nonces.insert(action.nonce);
            }
        }
        let marks = valid_entries
            .iter()
            .filter_map(|hash| {
                let AuthorityOp::MachineProfile(profile) = &by_hash.get(hash)?.op else {
                    return None;
                };
                let chain = states
                    .get(hash)?
                    .machines
                    .get(&profile.machine)?
                    .get(&MachineAdmitter::Roster)?;
                (chain.head.entry == *hash && chain.head.signer_class == SignerClass::OwnerHeld)
                    .then(|| (*hash, chain.head.signer.clone()))
            })
            .collect();
        let missing_parents = by_hash
            .values()
            .flat_map(|entry| entry.parent_hashes.iter())
            .filter(|parent| !by_hash.contains_key(*parent))
            .copied()
            .collect();
        Some(Self {
            judged: by_hash.keys().copied().collect(),
            head,
            head_state,
            merged,
            revocations: final_merged.actor_revocation_hashes.clone(),
            settlement: Arc::new(Settlement {
                revoke_facts,
                retired_keys,
                closed_handoffs,
                unsettled,
                issues,
                missing_parents,
                marks,
            }),
            pairs: entry_ancestors.values().map(|past| past.len() as u64).sum(),
            counted_pairs: counted_ancestor_pairs,
            head_ancestors: head_ancestors.len() as u64,
            head_counted_ancestors: head_ancestors
                .iter()
                .filter(|hash| !uncounted.contains(*hash))
                .count() as u64,
            head_counted: !uncounted.contains(&head),
            issuers,
            uncounted,
            writers,
            bound_keys,
            confirm_ids,
            confirm_nonces,
            fold: fold.clone(),
        })
    }

    /// Whether `entry` is an op that leaves every earlier row's fate as it
    /// was, given the confirms already in the log (which it joins).
    fn admits(&self, entry: &AuthorityLogEntry, confirms: &mut ConfirmKeys) -> bool {
        let merged = &self.merged;
        let fresh_key = |key: &AuthorityKey| !matches!(key, AuthorityKey::Ed25519(bytes) if merged.machine_keys.contains_key(bytes));
        match &entry.op {
            AuthorityOp::EnrollDevice { device } => {
                device.roles == ROLE_AGENT
                    && !merged.roster.contains_key(&device.key)
                    && fresh_key(&device.key)
            }
            AuthorityOp::BindActor {
                authority_key,
                actor_ref,
                ..
            } => {
                !merged.actor_bindings.contains_key(authority_key)
                    && !merged.actor_binding_revocations.contains_key(authority_key)
                    && !merged.actor_revocation_hashes.contains_key(authority_key)
                    && !merged.actor_rows.contains(actor_ref)
                    && !merged.machines.contains_key(actor_ref)
                    && fresh_key(authority_key)
            }
            AuthorityOp::SlipMint(_)
            | AuthorityOp::SlipConsume { .. }
            | AuthorityOp::CriticalWriteConfirm(_) => true,
            AuthorityOp::FederationConfirm(action) => {
                confirms.0.insert(action.confirm_id) && confirms.1.insert(action.nonce)
            }
            _ => false,
        }
    }
}

/// What the checkpoint image build keeps of the last once fold (OF-469,
/// checkpoint v2): the fold state at each frontier row, not only at one main
/// head, and the merge, projection and safety indexes a fold past the image
/// reads. Unlike [`Once`] it asks for no single head and no settled main row:
/// an image holds forks and rejected rows as they are.
pub(super) struct ImageFold {
    /// Each frontier row's state; None for a row the fold holds none for.
    pub(super) per_parent: BTreeMap<AuthorityEntryHash, Option<FoldState>>,
    /// The merge of every surviving state, before any restrictive fact.
    pub(super) merged: FoldState,
    /// The projected once fold, before any install's stale window.
    pub(super) fold: AuthorityFold,
    pub(super) safety: super::checkpoint_image::CheckpointSafety,
}

impl ImageFold {
    fn of(parts: OnceParts<'_>, frontier: &BTreeSet<AuthorityEntryHash>) -> Option<Self> {
        let OnceParts {
            by_hash,
            states,
            entry_ancestors,
            original_floors: _,
            merged,
            valid_entries,
            revoke_facts,
            retired_keys,
            closed_handoffs,
            unsettled,
            counted_ancestor_pairs,
            issues,
            final_merged,
            fold,
        } = parts;
        let final_merged = final_merged?;
        let is_main = |hash: &AuthorityEntryHash| {
            by_hash
                .get(hash)
                .is_some_and(|entry| super::world_privacy::side_world(&entry.op).is_none())
        };
        let issuers = super::log_structure::authority_structure(by_hash.values()).issuers;
        let uncounted = by_hash
            .iter()
            .filter(|(_, entry)| super::log_budget::is_uncounted(entry, &issuers))
            .map(|(hash, _)| *hash)
            .collect::<BTreeSet<_>>();
        let mut writers = BTreeMap::<_, BTreeSet<_>>::new();
        let mut bound_keys = BTreeSet::new();
        let (mut confirm_ids, mut confirm_nonces) = (BTreeSet::new(), BTreeSet::new());
        for (hash, state) in states {
            add_writers(&mut writers, state);
            if is_main(hash) {
                add_bound_keys(&mut bound_keys, state);
            }
            if let Some(AuthorityOp::FederationConfirm(action)) =
                by_hash.get(hash).map(|entry| &entry.op)
            {
                confirm_ids.insert(action.confirm_id);
                confirm_nonces.insert(action.nonce);
            }
        }
        let marks = valid_entries
            .iter()
            .filter_map(|hash| {
                let AuthorityOp::MachineProfile(profile) = &by_hash.get(hash)?.op else {
                    return None;
                };
                let chain = states
                    .get(hash)?
                    .machines
                    .get(&profile.machine)?
                    .get(&MachineAdmitter::Roster)?;
                (chain.head.entry == *hash && chain.head.signer_class == SignerClass::OwnerHeld)
                    .then(|| (*hash, chain.head.signer.clone()))
            })
            .collect();
        let missing_parents = by_hash
            .values()
            .flat_map(|entry| entry.parent_hashes.iter())
            .filter(|parent| !by_hash.contains_key(*parent))
            .copied()
            .collect();
        let frontier_ancestry = frontier
            .iter()
            .filter_map(|hash| {
                let past = entry_ancestors.get(hash)?;
                let counted = past.iter().filter(|row| !uncounted.contains(*row)).count();
                Some((*hash, (past.len() as u64, counted as u64)))
            })
            .collect();
        let safety = super::checkpoint_image::CheckpointSafety {
            pairs: entry_ancestors.values().map(|past| past.len() as u64).sum(),
            counted_pairs: counted_ancestor_pairs,
            frontier_ancestry,
            issuers,
            uncounted,
            revoke_facts,
            retired_keys,
            closed_handoffs,
            unsettled,
            issues,
            missing_parents,
            marks,
            revocations: final_merged.actor_revocation_hashes.clone(),
            writers,
            bound_keys,
            confirm_ids,
            confirm_nonces,
            nonce_provenance: merged.critical_write_confirm_nonce_provenance.clone(),
        };
        Some(Self {
            per_parent: frontier
                .iter()
                .map(|hash| (*hash, states.get(hash).cloned()))
                .collect(),
            merged,
            fold: fold.clone(),
            safety,
        })
    }
}

type ConfirmKeys = (BTreeSet<[u8; 32]>, BTreeSet<[u8; 16]>);

fn add_writers(
    writers: &mut BTreeMap<AuthorityKey, BTreeSet<(EntityId, String)>>,
    state: &FoldState,
) {
    for (key, binding) in &state.actor_bindings {
        writers
            .entry(key.clone())
            .or_default()
            .insert((binding.actor_ref, binding.actor_class.clone()));
    }
}

fn add_bound_keys(bound_keys: &mut BTreeSet<AuthorityKey>, state: &FoldState) {
    bound_keys.extend(
        state
            .actor_bindings
            .keys()
            .filter(|key| state.live_actor_binding(key).is_some())
            .cloned(),
    );
}

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
/// revocations stale-roster expiry and renewal weigh (`stale_roster`), and
/// the world-key records whose envelopes a folded key carries
/// (`world_key_fold::folded_world_keys`). Every other row's summary is all
/// a later fold reads of it.
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
    )
}

/// A stored log's fold, and what a resumed fold needs to carry it on.
pub(in crate::authority) struct FoldBase {
    inputs: Inputs,
    /// Every row the base folded, a rejected one too.
    rows: BTreeMap<AuthorityEntryHash, RowSummary>,
    /// The rows a fold past the base reads whole: see [`is_projected`].
    projected: BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    first_seen: BTreeMap<AuthorityEntryHash, u64>,
    floors: BTreeMap<AuthorityEntryHash, u64>,
    once: Once,
}

impl FoldBase {
    fn capture(
        inputs: Inputs,
        once: Once,
        rows: &[(AuthorityEntryHash, &AuthorityLogEntry)],
        first_seen: &BTreeMap<AuthorityEntryHash, u64>,
        floors: &BTreeMap<AuthorityEntryHash, u64>,
    ) -> Self {
        Self {
            inputs,
            rows: rows
                .iter()
                .map(|(hash, entry)| (*hash, RowSummary::of(entry)))
                .collect(),
            projected: rows
                .iter()
                .filter(|(_, entry)| is_projected(&entry.op))
                .map(|(hash, entry)| (*hash, (*entry).clone()))
                .collect(),
            first_seen: first_seen.clone(),
            floors: floors.clone(),
            once,
        }
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

    /// The rows the next stale-roster deadline reads: see [`is_projected`].
    pub(in crate::authority) fn projected_rows(&self) -> Vec<&AuthorityLogEntry> {
        self.projected.values().collect()
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
#[derive(Clone, Copy)]
pub(in crate::authority) struct StoredTail<'a> {
    /// Each stored row the base does not hold, with its hash.
    pub(in crate::authority) tail: &'a [(AuthorityEntryHash, &'a AuthorityLogEntry)],
    pub(in crate::authority) first_seen_at_secs: &'a BTreeMap<AuthorityEntryHash, u64>,
    pub(in crate::authority) now_secs: u64,
    pub(in crate::authority) peer_consent_roots:
        &'a BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
    pub(in crate::authority) observations: &'a AuthorityLocalObservations,
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
        )
    });
    (fold, base)
}

impl FoldBase {
    /// The fold of the base's log and the tail, a chain of new rows off its
    /// head, as the reference reaches it; None wherever a guard fails.
    fn resume(&self, log: StoredTail<'_>, inputs: &Inputs) -> Option<(AuthorityFold, Self)> {
        let StoredTail {
            tail,
            first_seen_at_secs,
            now_secs,
            observations,
            ..
        } = log;
        if *inputs != self.inputs {
            return None;
        }
        let once = &self.once;
        let settlement = &once.settlement;
        let new_rows: BTreeMap<_, _> = tail
            .iter()
            .filter(|(hash, _)| !self.rows.contains_key(hash))
            .map(|(hash, entry)| (*hash, *entry))
            .collect();
        let on_base = |map: &BTreeMap<AuthorityEntryHash, u64>| {
            map.iter()
                .filter(|(hash, _)| self.rows.contains_key(*hash))
                .map(|(hash, value)| (*hash, *value))
                .collect::<Vec<_>>()
        };
        if new_rows.is_empty()
            || on_base(first_seen_at_secs) != on_base(&self.first_seen)
            || on_base(&observations.sequence_floors) != on_base(&self.floors)
        {
            return None;
        }
        // The new rows are one chain off the head.
        let mut next = BTreeMap::new();
        for (hash, entry) in &new_rows {
            let [parent] = entry.parent_hashes.as_slice() else {
                return None;
            };
            if next.insert(*parent, *hash).is_some() {
                return None;
            }
        }
        let mut chain = Vec::with_capacity(new_rows.len());
        let mut tip = once.head;
        while let Some(child) = next.get(&tip) {
            chain.push(*child);
            tip = *child;
        }
        if chain.len() != new_rows.len() {
            return None;
        }
        let mut confirms = (once.confirm_ids.clone(), once.confirm_nonces.clone());
        for hash in &chain {
            let entry = new_rows[hash];
            let retired = std::iter::once(&entry.signer)
                .chain(&entry.cosigns)
                .any(|signature| settlement.retired_keys.contains(&signature.public_key));
            if settlement.missing_parents.contains(hash)
                || super::world_privacy::side_world(&entry.op).is_some()
                || observations
                    .sequence_floors
                    .get(hash)
                    .is_some_and(|floor| entry.seq < *floor)
                || retired
                || !once.admits(entry, &mut confirms)
            {
                return None;
            }
        }
        // The memory floor and counted pairs over the whole log, exactly as
        // `entry_ancestor_index` counts them: each new row's ancestry is the
        // head's, the head, and the chain before it. The chain adds no slip
        // issuer, so only its own slip rows join the uncounted.
        let mut uncounted = once.uncounted.clone();
        uncounted.extend(
            chain
                .iter()
                .filter(|hash| super::log_budget::is_uncounted(new_rows[*hash], &once.issuers)),
        );
        let (mut pairs, mut counted_pairs) = (once.pairs, once.counted_pairs);
        let (mut ancestors, mut counted_ancestors) =
            (once.head_ancestors, once.head_counted_ancestors);
        let mut tip_counted = once.head_counted;
        for hash in &chain {
            ancestors += 1;
            counted_ancestors += u64::from(tip_counted);
            pairs += ancestors;
            tip_counted = !uncounted.contains(hash);
            if tip_counted {
                counted_pairs += counted_ancestors;
            }
        }
        let memory_floor_bytes = super::log_budget::fold_memory_floor(Some(&observations.policy));
        if super::log_budget::fold_projected_bytes(once.judged.len() + chain.len(), pairs)
            > memory_floor_bytes
        {
            return None;
        }
        // Each new row folds on its parent's state as the scheduler folds it.
        let (consent_arm, _) = super::fold_engine::own_log_inputs(inputs.posture, None);
        let no_handoff_line = BTreeSet::new();
        let context = FoldContext {
            sequence_floors: Some(&observations.sequence_floors),
            floor_vouched: (!observations.unvouched).then_some(&observations.vouched),
            install_held: None,
            entry_ancestors: None,
            peer_consent_roots: &inputs.peers,
            consent_arm,
            hosted: inputs.posture == crate::HostingPrivacyPosture::Hosted,
            machine_standing: &super::machine_standing::every_chain,
            pre_handoff_entries: Some(&no_handoff_line),
            memory_floor_bytes,
            pin: inputs.pin.as_ref(),
        };
        let mut states = BTreeMap::from([(once.head, once.head_state.clone())]);
        for hash in &chain {
            let entry = new_rows[hash];
            let EntryFold::Ready(state) =
                super::entry_transition::fold_entry_state(entry, *hash, &states, context)
            else {
                return None;
            };
            if state.federation_pacts != once.merged.federation_pacts {
                return None;
            }
            states.insert(*hash, state);
        }
        let mut merged = once.merged.clone();
        let mut writers = once.writers.clone();
        let mut bound_keys = once.bound_keys.clone();
        for hash in &chain {
            merged = merge_states(&merged, &states[hash]);
            add_writers(&mut writers, &states[hash]);
            add_bound_keys(&mut bound_keys, &states[hash]);
        }
        let mut valid_entries = once.fold.valid_entries.clone();
        valid_entries.extend(chain.iter().copied());
        let rows = Resumed {
            once,
            chain: chain.iter().map(|hash| (*hash, &states[hash])).collect(),
            writers: &writers,
            missed: Cell::new(false),
        };
        // The projection reads rows only for world-key envelopes, and no
        // chain row is a world-key record.
        let (fold, final_merged) = super::fold_project::project_once(
            Settled {
                merged: Some(merged.clone()),
                valid_entries,
                by_hash: &self.projected,
                revoke_facts: &settlement.revoke_facts,
                retired_keys: settlement.retired_keys.clone(),
                closed_handoffs: settlement.closed_handoffs.clone(),
                unsettled: settlement.unsettled,
                counted_ancestor_pairs: counted_pairs,
                issues: settlement.issues.clone(),
            },
            &rows,
            context,
        );
        if rows.missed.get()
            || fold.machines != once.fold.machines
            || fold.worlds != once.fold.worlds
            || fold.refused_world_edits != once.fold.refused_world_edits
        {
            return None;
        }
        // The install's own view, in its first and only round, over the
        // rows its stale-roster window reads.
        let projected: Vec<&AuthorityLogEntry> = self
            .projected
            .values()
            .chain(chain.iter().map(|hash| new_rows[hash]))
            .filter(|entry| is_projected(&entry.op))
            .collect();
        let mut view = super::install_fold::install_view(
            &projected,
            fold.clone(),
            first_seen_at_secs,
            Some(now_secs),
            observations.policy.stale_roster_window_secs,
            inputs.pin.as_ref(),
        );
        if !view.worlds.is_empty() && !super::install_fold::stale_chains(&view).is_empty() {
            return None;
        }
        let chained: Vec<_> = chain.iter().map(|hash| (*hash, new_rows[hash])).collect();
        super::install_fold::finish_install_fold_of(&self.rows_with(&chained), &mut view);
        let mut judged = once.judged.clone();
        judged.extend(chain.iter().copied());
        let mut rows = self.rows.clone();
        let mut projected = self.projected.clone();
        for (hash, entry) in &chained {
            rows.insert(*hash, RowSummary::of(entry));
            if is_projected(&entry.op) {
                projected.insert(*hash, (*entry).clone());
            }
        }
        let next = Self {
            inputs: self.inputs.clone(),
            rows,
            projected,
            first_seen: first_seen_at_secs.clone(),
            floors: observations.sequence_floors.clone(),
            once: Once {
                judged,
                head: tip,
                head_state: states.remove(&tip)?,
                merged,
                revocations: final_merged?.actor_revocation_hashes,
                settlement: Arc::clone(settlement),
                issuers: once.issuers.clone(),
                uncounted,
                pairs,
                counted_pairs,
                head_ancestors: ancestors,
                head_counted_ancestors: counted_ancestors,
                head_counted: tip_counted,
                writers,
                bound_keys,
                confirm_ids: confirms.0,
                confirm_nonces: confirms.1,
                fold,
            },
        };
        Some((view, next))
    }
}

/// The base's per-row reads, carried over the chain's states.
struct Resumed<'a> {
    once: &'a Once,
    chain: Vec<(AuthorityEntryHash, &'a FoldState)>,
    writers: &'a BTreeMap<AuthorityKey, BTreeSet<(EntityId, String)>>,
    /// A frontier the base cannot answer: an earlier row may hold a binding
    /// the final one now judges differently.
    missed: Cell<bool>,
}

impl RowStates for Resumed<'_> {
    fn accepted_roster_marks(
        &self,
        merged: &FoldState,
        _valid: &BTreeSet<AuthorityEntryHash>,
    ) -> BTreeSet<AuthorityEntryHash> {
        // No chain row is a machine profile.
        self.once
            .settlement
            .marks
            .iter()
            .filter(|(_, signer)| {
                !(merged.hosted && super::machine_profile::in_host_custody(merged, signer))
            })
            .map(|(hash, _)| *hash)
            .collect()
    }

    fn revocation_affected_writers(&self, merged: &FoldState) -> BTreeSet<(EntityId, String)> {
        merged
            .actor_revocation_hashes
            .keys()
            .filter_map(|key| self.writers.get(key))
            .flatten()
            .cloned()
            .collect()
    }

    fn actor_write_frontiers(
        &self,
        merged: &FoldState,
        bindings: &BTreeMap<AuthorityKey, FoldedActorBinding>,
    ) -> BTreeMap<AuthorityKey, BTreeSet<AuthorityEntryHash>> {
        let mut out = BTreeMap::new();
        for (key, binding) in bindings {
            if binding.status != ActorBindingStatus::Active {
                continue;
            }
            let required = merged
                .actor_revocation_hashes
                .get(key)
                .cloned()
                .unwrap_or_default();
            let unchanged = self.once.fold.actor_bindings.get(key).is_some_and(|old| {
                old.status == ActorBindingStatus::Active
                    && old.actor_ref == binding.actor_ref
                    && old.actor_class == binding.actor_class
                    && self.once.revocations.get(key).cloned().unwrap_or_default() == required
            });
            let mut frontiers = if unchanged {
                self.once
                    .fold
                    .actor_write_frontiers
                    .get(key)
                    .cloned()
                    .unwrap_or_default()
            } else {
                if self.once.bound_keys.contains(key) {
                    self.missed.set(true);
                }
                BTreeSet::new()
            };
            frontiers.extend(
                self.chain
                    .iter()
                    .filter(|(_, state)| {
                        super::causal_write::is_frontier(state, key, binding, &required)
                    })
                    .map(|(hash, _)| *hash),
            );
            out.insert(key.clone(), frontiers);
        }
        out
    }
}
