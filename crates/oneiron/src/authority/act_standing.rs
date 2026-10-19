//! An owner act signed outside the authority log, judged at its own causal
//! point (FIX 4649, mesh contract §4): a topology decision seal signs the
//! authority-log heads its carrier held when it decided. Its carrier and its
//! owner are judged in the fold state of those heads, as a main-log owner act
//! is judged at its parents ([`super::owner_act_signer_admits`] in the roster
//! view, [`super::owner_act::owner_live_at`]). A removal of its carrier after
//! it is judged by the one removal race ([`Standing::owner_act_race`], FIX
//! 2998): a removal outside the act's signed past must have acknowledged the
//! act's token, else the act no longer counts. A removal inside its signed
//! past refuses it outright, so a removed key never back-dates a new act onto
//! old heads. The owner's say-so counts from any linked surface, and a
//! decision made while its carrier stood keeps standing after a later
//! removal that saw it.
//!
//! The states come from one fold of the stored log that keeps each named
//! head's state (the checkpoint image build's capture), or, on a vault that
//! adopted an image and does not hold its covered history, from the tail's
//! image-grade fold past it. Neither reads a clock. A head in the past of
//! another named head adds nothing to the merge, so an image that kept no
//! state for it (a carrier's old standing row behind the frontier) does not
//! matter. Any other head this vault holds no state for (pruned behind a
//! checkpoint, not yet arrived, above a gap) leaves the act pending: never
//! judged on the fold as it stands now, and never as absent (CALLS "FIX 4649
//! missing signed past"). The topology rows
//! stay outside the pure fold: their readers hand this module the acts, and
//! the removal writers fetch the acts' tokens ([`acknowledged_by_in_txn`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::adopted_fold::{AdoptedImageFold, AdoptedTail};
use super::fold_resume::{FoldCapture, ImageFold};
use super::machine_standing::{InstallHold, Mark, Standing, StandingView, every_chain};
use super::*;
use crate::EntityId;
use crate::error::Result;
use crate::store::Store;

/// What an owner act outside the authority log names of its causal point
/// and its carrier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ExternalAct {
    /// The authority-log heads it signed: its causal point.
    pub(crate) heads: BTreeSet<AuthorityEntryHash>,
    /// The MACHINE that carried it.
    pub(crate) machine: EntityId,
    /// The install key that signed it.
    pub(crate) key: [u8; 32],
    /// The owner whose will it carries.
    pub(crate) owner: EntityId,
    /// Its stable token: what a removal's acknowledged set names.
    pub(crate) token: AuthorityEntryHash,
}

/// How an owner act outside the authority log stands here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalActStanding {
    /// Its carrier and owner stood at its heads, and every removal of the
    /// carrier since saw it.
    Stands,
    /// A head it signed has no fold state here: history this vault does not
    /// hold yet.
    Pending,
    /// Its carrier or owner did not stand at its heads, or a removal of the
    /// carrier outside its signed past did not see it.
    Refused,
}

/// What one authority generation holds of the acts it was asked about: each
/// act at its signed heads, and the merged state its removal race reads.
/// Local and derived: rebuilt on a miss, never stored.
pub(crate) struct CausalPoints {
    generation: u64,
    /// Each act at its heads; `None` where a head has no state here.
    at: BTreeMap<ExternalAct, Option<AtHeads>>,
    now: Option<FoldState>,
    pin: Option<PinnedRoot>,
}

/// An act at its signed heads: whether its carrier and owner stood there,
/// and its carrier's signing chains' marks.
struct AtHeads {
    stood: bool,
    marks: BTreeMap<MachineAdmitter, Mark>,
}

impl CausalPoints {
    /// Whether this set was built for `act`.
    pub(crate) fn judges(&self, act: &ExternalAct) -> bool {
        self.at.contains_key(act)
    }

    /// How `act` stands here; `None` when this set was not built for it. Its
    /// removal race counts this install's chains as `fold`, this install's
    /// own fold, reads them: a chain held or stale here lifts nothing, as for
    /// an owner choice ([`super::owner_choice`]).
    pub(crate) fn standing(
        &self,
        act: &ExternalAct,
        fold: &AuthorityFold,
    ) -> Option<ExternalActStanding> {
        let (Some(at), Some(now)) = (self.at.get(act)?, &self.now) else {
            return Some(ExternalActStanding::Pending);
        };
        if !at.stood {
            return Some(ExternalActStanding::Refused);
        }
        let counted =
            |machine: EntityId, admitter: MachineAdmitter| install_hold(fold, machine, admitter);
        let standing = Standing::new(now, self.pin.as_ref(), &counted);
        Some(
            if standing.owner_act_race(
                act.machine,
                &act.token,
                &act.key,
                &at.marks,
                StandingView::Install,
            ) {
                ExternalActStanding::Stands
            } else {
                ExternalActStanding::Refused
            },
        )
    }
}

/// How this install counts `machine`'s chain under `admitter`, as its own
/// fold projected it: held past its floor or by the fold with no vouch, and
/// stale or with no settled root ([`super::install_fold::stale_chains`]).
fn install_hold(fold: &AuthorityFold, machine: EntityId, admitter: MachineAdmitter) -> InstallHold {
    let Some(folded) = fold.machine(machine) else {
        return InstallHold::default();
    };
    let chains: Vec<&MachineRevision> = match admitter {
        MachineAdmitter::Roster => folded.roster.iter().chain(&folded.roster_trusted).collect(),
        MachineAdmitter::Anchor(key) => folded.anchored.get(&key).into_iter().collect(),
    };
    InstallHold {
        held: chains.iter().any(|chain| chain.floor_held),
        stale: chains
            .iter()
            .any(|chain| chain.stale || chain.admitter_unsettled),
    }
}

/// Every act in `acts` at its signed heads, and the merged state its removal
/// race reads, judged on `txn`'s stored authority log. One fold answers a
/// whole pass; a committed generation's answers are kept for the next pass
/// that asks about no other act. Nothing here reads a clock: this install's
/// holds enter only at [`CausalPoints::standing`].
pub(crate) fn causal_points_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    acts: &BTreeSet<ExternalAct>,
) -> Result<Arc<CausalPoints>> {
    let generation = super::readonly_fold::authority_cache_generation(store, txn)?;
    let cached = store
        .act_causal_points
        .lock()
        .ok()
        .and_then(|cache| cache.as_ref().cloned())
        .filter(|cached| cached.generation == generation);
    let mut asked = acts.clone();
    if let Some(cached) = cached {
        if acts.iter().all(|act| cached.judges(act)) {
            return Ok(cached);
        }
        asked.extend(cached.at.keys().cloned());
    }
    let points = Arc::new(points_in_txn(store, txn, generation, &asked)?);
    // A second read txn on this thread fails with MDB_BAD_RSLOT, as for
    // `per_authority_generation`: only a committed generation is kept.
    let committed = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                store.env.read_txn().ok().and_then(|committed| {
                    super::readonly_fold::authority_cache_generation(store, &committed).ok()
                })
            })
            .join()
            .ok()
            .flatten()
    });
    if committed == Some(generation)
        && let Ok(mut cache) = store.act_causal_points.lock()
    {
        *cache = Some(Arc::clone(&points));
    }
    Ok(points)
}

/// The causal point an act outside the log signs where it is carried: the
/// main-log heads and its carrier's standing rows (CALLS "FIX 4649 seal
/// causal envelope"). The caller bounds it by [`MAX_PARENTS`].
pub(crate) fn act_heads(fold: &AuthorityFold, machine: EntityId) -> BTreeSet<AuthorityEntryHash> {
    let mut heads = fold.append_heads.clone();
    heads.extend(standing_rows(fold, machine));
    heads
}

/// What a new profile revision of `machine` lists as seen (FIX 2998, FIX
/// 4649): the acts in the log it carried ([`super::world_privacy::live_edits_by`]),
/// then the topology decisions it carried, by token, within the codec's one
/// cap. A decision the cap leaves out counts as one its removal raced: the
/// removal retires it (CALLS "FIX 4649 seal causal envelope").
pub(super) fn acknowledged_by_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    machine: EntityId,
) -> Result<BTreeSet<AuthorityEntryHash>> {
    let mut seen = super::world_privacy::live_edits_by(fold, machine);
    let room = MACHINE_SEEN_WORLD_EDITS_MAX.saturating_sub(seen.len());
    seen.extend(
        crate::identity_topology::carried_seal_tokens_in_txn(store, txn, machine)?
            .into_iter()
            .take(room),
    );
    Ok(seen)
}

fn points_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    generation: u64,
    acts: &BTreeSet<ExternalAct>,
) -> Result<CausalPoints> {
    let pin = super::pinned_root::read_pinned_root_in_txn(store, txn)?;
    let mut points = CausalPoints {
        generation,
        at: acts.iter().map(|act| (act.clone(), None)).collect(),
        now: None,
        pin,
    };
    if acts.is_empty() {
        return Ok(points);
    }
    let heads: BTreeSet<_> = acts
        .iter()
        .flat_map(|act| act.heads.iter().copied())
        .collect();
    let Some((
        ImageFold {
            per_parent, merged, ..
        },
        parents,
    )) = capture_in_txn(store, txn, &heads, points.pin.as_ref())?
    else {
        return Ok(points);
    };
    // Acts sort by their heads first: one parent state per causal point.
    let mut parent: Option<(&BTreeSet<AuthorityEntryHash>, Option<FoldState>)> = None;
    for act in acts {
        if parent
            .as_ref()
            .is_none_or(|(heads, _)| *heads != &act.heads)
        {
            parent = Some((&act.heads, parent_state(&per_parent, &parents, &act.heads)));
        }
        if let Some((_, Some(state))) = &parent {
            points
                .at
                .insert(act.clone(), Some(at_heads(state, points.pin.as_ref(), act)));
        }
    }
    points.now = Some(merged);
    Ok(points)
}

/// `act` at its parent state `parent`: its carrier under the one carrier
/// rule in the roster view and its owner live, and its carrier's signing
/// chains' marks, as an owner choice lands at its parents.
fn at_heads(parent: &FoldState, pin: Option<&PinnedRoot>, act: &ExternalAct) -> AtHeads {
    let at = Standing::new(parent, pin, &every_chain);
    let roster = StandingView::Under(MachineAdmitter::Roster);
    AtHeads {
        stood: at.admits_owner_act_signer(act.machine, &act.key, roster)
            && super::owner_act::owner_live_at(parent, act.owner),
        marks: at.live_signing_chains(act.machine, &AuthorityKey::Ed25519(act.key)),
    }
}

/// Each row's parents: the stored rows', and an adopted image's carried
/// metadata.
type Parents = BTreeMap<AuthorityEntryHash, Vec<AuthorityEntryHash>>;

/// The fold state at `heads`: the merge of each head's state. A head with no
/// state here counts only when it is in the past of a head that has one;
/// otherwise, or when no head is named, `None`.
fn parent_state(
    per_parent: &BTreeMap<AuthorityEntryHash, Option<FoldState>>,
    parents: &Parents,
    heads: &BTreeSet<AuthorityEntryHash>,
) -> Option<FoldState> {
    let (stated, mut unstated): (Vec<_>, BTreeSet<_>) = (
        heads
            .iter()
            .filter_map(|head| Some((*head, per_parent.get(head)?.as_ref()?)))
            .collect(),
        heads
            .iter()
            .filter(|head| per_parent.get(*head).is_none_or(Option::is_none))
            .copied()
            .collect(),
    );
    let mut stack: Vec<_> = stated.iter().map(|(head, _)| *head).collect();
    let mut seen = BTreeSet::new();
    while !unstated.is_empty()
        && let Some(row) = stack.pop()
    {
        for parent in parents.get(&row).into_iter().flatten() {
            if seen.insert(*parent) {
                unstated.remove(parent);
                stack.push(*parent);
            }
        }
    }
    if !unstated.is_empty() {
        return None;
    }
    let mut merged: Option<FoldState> = None;
    for (_, state) in stated {
        merged = Some(match merged {
            Some(merged) => merge_states(&merged, state),
            None => state.clone(),
        });
    }
    merged
}

/// The stored log's fold keeping the state at each of `heads`, with no clock,
/// and each row's parents: past the adopted image where this vault does not
/// hold its covered history, else the held log whole. `None` where history
/// the fold needs is not held.
fn capture_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    heads: &BTreeSet<AuthorityEntryHash>,
    pin: Option<&PinnedRoot>,
) -> Result<Option<(ImageFold, Parents)>> {
    let posture = store.privacy_posture;
    let peers = crate::federation::admitted_peer_consent_roots_for_store_in_txn(store, txn)?;
    if let Some(adopted) = super::checkpoint_adopt::adopted_authority_checkpoint_in_txn(store, txn)?
    {
        match capture_past_adopted(store, txn, &adopted, heads, pin, &peers)? {
            (AdoptedImageFold::Captured { fold, .. }, parents) => {
                return Ok(Some((*fold, parents)));
            }
            // Every covered row is held here: the held log folds whole.
            (AdoptedImageFold::NeedHistory(request), _) if request.missing.is_empty() => {}
            (AdoptedImageFold::NeedHistory(_), _) => return Ok(None),
        }
    }
    let entries = authority_log_rows_in_txn(store, txn)?
        .into_iter()
        .map(|(_, body)| decode_authority_log_entry_body(&body))
        .collect::<Result<Vec<_>>>()?;
    let parents = entries
        .iter()
        .map(|entry| Ok((authority_entry_hash(entry)?, entry.parent_hashes.clone())))
        .collect::<Result<Parents>>()?;
    let observations = authority_local_observations_in_txn(store, txn, &entries)?;
    let capture = FoldCapture::for_image(heads.clone());
    let (consent, local) = super::fold_engine::own_log_inputs(posture, pin);
    super::fold_engine::fold_authority_log_inner(
        &entries,
        &BTreeMap::new(),
        None,
        &peers,
        consent,
        super::fold_engine::FoldLocalInputs {
            observations: Some(&observations),
            capture: Some(&capture),
            ..local
        },
    );
    Ok(capture.take_image().map(|image| (*image, parents)))
}

/// The tail's image-grade fold past `adopted`, keeping the state at each of
/// `heads` it folds, as a later image's build folds it, and the parents the
/// image's rows and the tail's name.
fn capture_past_adopted(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    adopted: &VerifiedAuthorityCheckpoint,
    heads: &BTreeSet<AuthorityEntryHash>,
    pin: Option<&PinnedRoot>,
    peers: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
) -> Result<(AdoptedImageFold, Parents)> {
    let image = adopted.image();
    let covered_ids: BTreeMap<EntityId, AuthorityEntryHash> = image
        .covered
        .iter()
        .filter_map(|hash| Some((authority_log_entity_id_from_hash(hash).ok()?, *hash)))
        .collect();
    let mut held_covered = BTreeSet::new();
    let mut tail = BTreeMap::new();
    for (id, body) in authority_log_rows_in_txn(store, txn)? {
        if let Some(hash) = covered_ids.get(&id) {
            held_covered.insert(*hash);
            continue;
        }
        let entry = decode_authority_log_entry_body(&body)?;
        let hash = authority_entry_hash(&entry)?;
        if image.rows.contains_key(&hash) {
            held_covered.insert(hash);
        } else {
            tail.insert(hash, (entry, body));
        }
    }
    let (closed, _, _) = super::adopted_build::tail_closure(image, &tail);
    let closed_tail: Vec<_> = closed
        .iter()
        .filter_map(|hash| Some((*hash, tail.get(hash)?.0.clone())))
        .collect();
    let metas: Vec<_> = closed_tail
        .iter()
        .map(|(hash, entry)| super::fold_resume::RowMeta::of(Some(*hash), entry))
        .collect();
    let observations = super::sequence_observation::authority_local_observations_of_rows_in_txn(
        store, txn, &metas,
    )?;
    let parents = image
        .rows
        .iter()
        .map(|(hash, row)| (*hash, row.parents.clone()))
        .chain(
            closed_tail
                .iter()
                .map(|(hash, entry)| (*hash, entry.parent_hashes.clone())),
        )
        .collect();
    let captured = super::adopted_fold::capture_adopted_checkpoint_tail(
        adopted,
        AdoptedTail {
            tail: &closed_tail,
            held_covered: &held_covered,
            required: heads,
            first_seen_at_secs: &BTreeMap::new(),
            now_secs: 0,
            peer_consent_roots: peers,
            observations: &observations,
            posture: store.privacy_posture,
            pin,
        },
    )?;
    Ok((captured, parents))
}
