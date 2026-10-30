//! What a strict fold leaves for a resumed one (OF-469): its last once fold,
//! settled, and what its projection read of each row's state. See [`Once`].

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::*;
use crate::authority::revoke_proof::RevokeFacts;

/// What a strict fold leaves for a resumed one: its last once fold, unless a
/// second strict round, a second install round or a fold with no vouch spoiled
/// it.
#[derive(Default)]
pub(in crate::authority) struct FoldCapture {
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
    /// Whether it keeps the state at every row off the frontier too: an
    /// image's replay evidence (FIX 3007).
    replay: bool,
    fold: RefCell<Option<Box<ImageFold>>>,
}

impl FoldCapture {
    /// A capture for the checkpoint image build: it keeps the fold state at
    /// each row of `frontier`. No resumed fold reads it.
    pub(in crate::authority) fn for_image(frontier: BTreeSet<AuthorityEntryHash>) -> Self {
        Self {
            image: Some(ImageSlot {
                frontier,
                replay: false,
                fold: RefCell::new(None),
            }),
            ..Self::default()
        }
    }

    /// [`Self::for_image`] for a checkpoint image's build: it keeps the
    /// state at every row off `frontier` as well, the image's replay
    /// evidence (FIX 3007).
    pub(in crate::authority) fn for_checkpoint(frontier: BTreeSet<AuthorityEntryHash>) -> Self {
        Self {
            image: Some(ImageSlot {
                frontier,
                replay: true,
                fold: RefCell::new(None),
            }),
            ..Self::default()
        }
    }

    /// What the image build kept of the last once fold.
    pub(in crate::authority) fn take_image(self) -> Option<Box<ImageFold>> {
        self.image.and_then(|image| image.fold.into_inner())
    }

    pub(in crate::authority) fn spoil(&self) {
        self.spoiled.set(true);
    }

    pub(in crate::authority) fn record(&self, parts: OnceParts<'_>) {
        if let Some(image) = &self.image {
            *image.fold.borrow_mut() =
                ImageFold::of(parts, &image.frontier, image.replay).map(Box::new);
        } else {
            *self.once.borrow_mut() = Once::of(parts).map(Box::new);
        }
    }

    pub(super) fn take(self) -> Option<Box<Once>> {
        if self.spoiled.get() {
            return None;
        }
        self.once.into_inner()
    }
}

/// A once fold's settlement, as `fold_authority_log_once` reached it.
pub(in crate::authority) struct OnceParts<'a> {
    pub(in crate::authority) by_hash: &'a BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    pub(in crate::authority) states: &'a BTreeMap<AuthorityEntryHash, FoldState>,
    pub(in crate::authority) entry_ancestors:
        &'a BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
    /// The floors the fold was handed, before causal ancestry cleared any.
    pub(in crate::authority) original_floors: Option<&'a BTreeMap<AuthorityEntryHash, u64>>,
    pub(in crate::authority) merged: FoldState,
    pub(in crate::authority) valid_entries: BTreeSet<AuthorityEntryHash>,
    pub(in crate::authority) revoke_facts: RevokeFacts,
    pub(in crate::authority) retired_keys: BTreeSet<AuthorityKey>,
    pub(in crate::authority) closed_handoffs: BTreeSet<AuthorityEntryHash>,
    pub(in crate::authority) unsettled: bool,
    pub(in crate::authority) counted_ancestor_pairs: u64,
    pub(in crate::authority) issues: Vec<AuthorityFoldIssue>,
    pub(in crate::authority) final_merged: Option<&'a FoldState>,
    pub(in crate::authority) fold: &'a AuthorityFold,
}

/// What no row of the tail changes.
pub(super) struct Settlement {
    pub(super) revoke_facts: RevokeFacts,
    pub(super) retired_keys: BTreeSet<AuthorityKey>,
    pub(super) closed_handoffs: BTreeSet<AuthorityEntryHash>,
    pub(super) unsettled: bool,
    pub(super) issues: Vec<AuthorityFoldIssue>,
    /// Parents a judged row names that no judged row is.
    pub(super) missing_parents: BTreeSet<AuthorityEntryHash>,
    /// The valid machine profiles heading their own roster chain under an
    /// owner-held key, with that key, or as an admitted owner answer: the
    /// marks before custody is judged ([`MarkProof`]).
    pub(super) marks: Vec<(AuthorityEntryHash, MarkProof)>,
}

/// One settled once fold, and what its projection read of each row's state.
/// Its row-sized sets are persistent: the next base shares them and adds
/// only the tail's rows (FIX 12308).
pub(super) struct Once {
    pub(super) judged: im::OrdSet<AuthorityEntryHash>,
    pub(super) head: AuthorityEntryHash,
    /// The main head and each side leaf, with its state and ancestor counts.
    pub(super) frontier: BTreeMap<AuthorityEntryHash, super::side_tail::FrontierPoint>,
    /// The merge of every surviving state, before any restrictive fact.
    pub(super) merged: FoldState,
    /// The final merge's revocations, by key.
    pub(super) revocations: BTreeMap<AuthorityKey, BTreeSet<AuthorityEntryHash>>,
    pub(super) settlement: Arc<Settlement>,
    /// The judged rows' slip issuers. No op a tail admits names a root or
    /// a consent device, so a tail never adds one.
    pub(super) issuers: BTreeSet<AuthorityKey>,
    pub(super) uncounted: im::OrdSet<AuthorityEntryHash>,
    pub(super) pairs: u64,
    pub(super) counted_pairs: u64,
    /// Every binding any state holds, by key.
    pub(super) writers: BTreeMap<AuthorityKey, BTreeSet<(EntityId, String)>>,
    /// The keys some main state holds a live binding for.
    pub(super) bound_keys: BTreeSet<AuthorityKey>,
    pub(super) confirm_ids: BTreeSet<[u8; 32]>,
    pub(super) confirm_nonces: BTreeSet<[u8; 16]>,
    /// The projected once fold's valid entries.
    pub(super) valid: im::OrdSet<AuthorityEntryHash>,
    /// The projected once fold, before this install's stale window, with no
    /// valid entries: [`Self::valid`] holds them.
    pub(super) fold: AuthorityFold,
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
            crate::authority::world_privacy::side_world(&by_hash[hash].op).is_none()
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
        if states[&head].federation_pacts != merged.federation_pacts {
            return None;
        }
        let final_merged = final_merged?;
        let issuers =
            crate::authority::log_structure::authority_structure(by_hash.values()).issuers;
        let uncounted = by_hash
            .iter()
            .filter(|(_, entry)| crate::authority::log_budget::is_uncounted(entry, &issuers))
            .map(|(hash, _)| *hash)
            .collect::<BTreeSet<_>>();
        let frontier =
            super::side_tail::frontier_of(by_hash, states, entry_ancestors, &uncounted, head)?;
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
                MarkProof::of(&chain.head)
                    .filter(|_| chain.head.entry == *hash)
                    .map(|proof| (*hash, proof))
            })
            .collect();
        let missing_parents = by_hash
            .values()
            .flat_map(|entry| entry.parent_hashes.iter())
            .filter(|parent| !by_hash.contains_key(*parent))
            .copied()
            .collect();
        // The base shares `valid` in place of the fold's own (FIX 12308).
        let mut fold = fold.clone();
        fold.valid_entries.clear();
        Some(Self {
            judged: by_hash.keys().copied().collect(),
            head,
            frontier,
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
            issuers,
            uncounted: uncounted.into_iter().collect(),
            writers,
            bound_keys,
            confirm_ids,
            confirm_nonces,
            valid: valid_entries.into_iter().collect(),
            fold,
        })
    }

    /// Whether `entry` is an op that leaves every earlier row's fate as it
    /// was, given the confirms already in the log (which it joins).
    pub(super) fn admits(&self, entry: &AuthorityLogEntry, confirms: &mut ConfirmKeys) -> bool {
        admits_past(&self.merged, entry, confirms)
    }
}

/// Whether `entry` is an op that leaves the fate of every row folded into
/// `merged` (the merge of every surviving state) as it was, given the confirms
/// already in the log (which it joins): an agent enrollment, a fresh binding,
/// a slip mint or consume, a critical-write confirm, a fresh federation
/// confirm, a world settings edit (it judges only its own world's edits, FIX
/// 4535), a grant travel choice (only its own grant's choices), a checkpoint
/// policy choice or a home pick (each only the vault's choices of its kind),
/// a person's conversation training choice (only that person's choices), a
/// machine's home candidacy (only that machine's declarations), an owner's
/// agent Grant act (it moves no fold state, FIX 5628), a setting's act (only
/// its target's acts) or an export act (it moves no state but its own
/// refusal, FIX 4624), an owner
/// work request, result or cancel (each judges only its own work), a custody
/// permit piece (it keeps only its own place, FIX 11866), a world
/// key record (it fills only its own key's slots, or is refused as a no-op,
/// FIX 4881), a frontier join (it moves no state, FIX 7908, but an anchor's
/// side join's own place among its anchor's rows, FIX 11868), a residence
/// directive (it adds only its own id and machine, which only a result past
/// it reads) or a machine's residence result (it moves only its signer's
/// sequence, FIX 5412). A resumed fold and a fold past an adopted checkpoint
/// take only these, and each still folds through its own transition.
pub(in crate::authority) fn admits_past(
    merged: &FoldState,
    entry: &AuthorityLogEntry,
    confirms: &mut ConfirmKeys,
) -> bool {
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
        | AuthorityOp::CriticalWriteConfirm(_)
        | AuthorityOp::WorldPrivacy(_)
        | AuthorityOp::GrantTravelSet(_)
        | AuthorityOp::CheckpointPolicySet(_)
        | AuthorityOp::HomeNodePick(_)
        | AuthorityOp::ConversationTrainingSet(_)
        | AuthorityOp::ConversationTrainingVaultSet(_)
        | AuthorityOp::HomeCandidacy(_)
        | AuthorityOp::AgentGrantAct(_)
        | AuthorityOp::PolicySettingSet(_)
        | AuthorityOp::ExportAct(_)
        | AuthorityOp::OwnerWorkRequest(_)
        | AuthorityOp::OwnerWorkResult(_)
        | AuthorityOp::OwnerWorkCancel(_)
        | AuthorityOp::ExportSupplementImported(_)
        | AuthorityOp::CustodyPermitPiece(_)
        | AuthorityOp::WorldKeyWraps(_)
        | AuthorityOp::FrontierJoin(_)
        | AuthorityOp::ResidenceDirective(_)
        | AuthorityOp::ResidenceResult(_) => true,
        AuthorityOp::FederationConfirm(action) => {
            confirms.0.insert(action.confirm_id) && confirms.1.insert(action.nonce)
        }
        _ => false,
    }
}

pub(in crate::authority) type ConfirmKeys = (BTreeSet<[u8; 32]>, BTreeSet<[u8; 16]>);

pub(in crate::authority) fn add_writers(
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

pub(in crate::authority) fn add_bound_keys(
    bound_keys: &mut BTreeSet<AuthorityKey>,
    state: &FoldState,
) {
    bound_keys.extend(
        state
            .actor_bindings
            .keys()
            .filter(|key| state.live_actor_binding(key).is_some())
            .cloned(),
    );
}
