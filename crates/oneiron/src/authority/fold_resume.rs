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
}

impl FoldCapture {
    pub(super) fn spoil(&self) {
        self.spoiled.set(true);
    }

    pub(super) fn record(&self, parts: OnceParts<'_>) {
        *self.once.borrow_mut() = Once::of(parts).map(Box::new);
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
    /// The tier floors the surviving rows set. No chain row sets one, so
    /// these are the floors a chain row is judged against in settlement.
    floors: Vec<super::tier_floor::ConcurrentFloor>,
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
    valid_entries: BTreeSet<AuthorityEntryHash>,
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
        let uncounted = super::log_budget::uncounted_rows(by_hash);
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
                floors: super::tier_floor::concurrent_tier_floors(states, by_hash, &|_| true),
            }),
            valid_entries,
            pairs: entry_ancestors.values().map(|past| past.len() as u64).sum(),
            counted_pairs: counted_ancestor_pairs,
            head_ancestors: head_ancestors.len() as u64,
            head_counted_ancestors: head_ancestors
                .iter()
                .filter(|hash| !uncounted.contains(*hash))
                .count() as u64,
            head_counted: !uncounted.contains(&head),
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

/// A stored log's fold, and what a resumed fold needs to carry it on.
pub(in crate::authority) struct FoldBase {
    inputs: Inputs,
    hashes: BTreeSet<AuthorityEntryHash>,
    first_seen: BTreeMap<AuthorityEntryHash, u64>,
    floors: BTreeMap<AuthorityEntryHash, u64>,
    once: Once,
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

#[cfg(test)]
thread_local! {
    /// How many folds this thread resumed from a base.
    pub(super) static RESUMED_FOR_TEST: Cell<usize> = const { Cell::new(0) };
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
    let inputs = Inputs {
        posture,
        pin: pin.copied(),
        policy: observations.policy,
        peers: peer_consent_roots.clone(),
        vouched: observations.vouched.clone(),
        unvouched: observations.unvouched,
    };
    if let Some((fold, next)) = base.and_then(|base| base.resume(log, &inputs)) {
        #[cfg(test)]
        RESUMED_FOR_TEST.with(|resumed| resumed.set(resumed.get() + 1));
        return (fold, Some(next));
    }
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
    let hashes: Option<BTreeSet<_>> = entries
        .iter()
        .map(|entry| authority_entry_hash(entry).ok())
        .collect();
    let base = capture.take().zip(hashes).map(|(once, hashes)| FoldBase {
        inputs,
        hashes,
        first_seen: first_seen_at_secs.clone(),
        floors: observations.sequence_floors.clone(),
        once: *once,
    });
    (fold, base)
}

impl FoldBase {
    /// The fold of `entries`, the base's log and a chain of new rows off its
    /// head, as the reference reaches it; None wherever a guard fails.
    fn resume(&self, log: StoredLog<'_>, inputs: &Inputs) -> Option<(AuthorityFold, Self)> {
        let StoredLog {
            entries,
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
        let entry_hashes = entries
            .iter()
            .map(|entry| authority_entry_hash(entry).ok())
            .collect::<Option<Vec<_>>>()?;
        let hashes: BTreeSet<_> = entry_hashes.iter().copied().collect();
        let new_rows: BTreeMap<_, _> = entries
            .iter()
            .zip(&entry_hashes)
            .filter(|(_, hash)| !self.hashes.contains(*hash))
            .map(|(entry, hash)| (*hash, entry))
            .collect();
        let on_base = |map: &BTreeMap<AuthorityEntryHash, u64>| {
            map.iter()
                .filter(|(hash, _)| self.hashes.contains(*hash))
                .map(|(hash, value)| (*hash, *value))
                .collect::<Vec<_>>()
        };
        if new_rows.is_empty()
            || !self.hashes.is_subset(&hashes)
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
        let by_hash: BTreeMap<_, _> = entries
            .iter()
            .zip(&entry_hashes)
            .filter(|(_, hash)| once.judged.contains(*hash) || new_rows.contains_key(*hash))
            .map(|(entry, hash)| (*hash, entry.clone()))
            .collect();
        // The memory floor and counted pairs over the whole log, exactly as
        // `entry_ancestor_index` counts them: each new row's ancestry is the
        // head's, the head, and the chain before it.
        let uncounted = super::log_budget::uncounted_rows(&by_hash);
        if !uncounted
            .iter()
            .filter(|hash| once.judged.contains(*hash))
            .eq(once.uncounted.iter())
        {
            return None;
        }
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
        if super::log_budget::fold_projected_bytes(by_hash.len(), pairs) > memory_floor_bytes {
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
        // No stored row's claimed ancestry holds a chain row, so no floor
        // follows one: an empty index answers as the whole log's would.
        let no_ancestors = BTreeMap::new();
        for hash in &chain {
            let entry = new_rows[hash];
            let EntryFold::Ready(state) =
                super::entry_transition::fold_entry_state(entry, *hash, &states, context)
            else {
                return None;
            };
            // Settlement's judgment of a concurrent floor (H411): a chain row
            // under a floor it did not see softened loses there.
            let below = super::tier_floor::below_a_concurrent_floor(
                hash,
                &state,
                &by_hash,
                &no_ancestors,
                &settlement.floors,
                &|floor| {
                    super::tier_floor::participants_under_floor(entry, &states, floor, context)
                },
            );
            if below.is_some() || state.federation_pacts != once.merged.federation_pacts {
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
        let mut valid_entries = once.valid_entries.clone();
        valid_entries.extend(chain.iter().copied());
        let rows = Resumed {
            once,
            chain: chain.iter().map(|hash| (*hash, &states[hash])).collect(),
            writers: &writers,
            missed: Cell::new(false),
        };
        let (fold, final_merged) = super::fold_project::project_once(
            Settled {
                merged: Some(merged.clone()),
                valid_entries: valid_entries.clone(),
                by_hash: &by_hash,
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
        // The install's own view, in its first and only round.
        let mut view = super::install_fold::install_view(
            entries,
            fold.clone(),
            first_seen_at_secs,
            Some(now_secs),
            observations.policy.stale_roster_window_secs,
            inputs.pin.as_ref(),
        );
        if !view.worlds.is_empty() && !super::install_fold::stale_chains(&view).is_empty() {
            return None;
        }
        super::install_fold::finish_install_fold(entries, &mut view);
        let mut judged = once.judged.clone();
        judged.extend(chain.iter().copied());
        let next = Self {
            inputs: self.inputs.clone(),
            hashes,
            first_seen: first_seen_at_secs.clone(),
            floors: observations.sequence_floors.clone(),
            once: Once {
                judged,
                head: tip,
                head_state: states.remove(&tip)?,
                merged,
                revocations: final_merged?.actor_revocation_hashes,
                settlement: Arc::clone(settlement),
                valid_entries,
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
