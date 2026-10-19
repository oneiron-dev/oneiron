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
//! image-grade fold past it. Neither reads a clock. A head this vault holds
//! no state for (pruned behind a checkpoint, not yet arrived, above a gap)
//! leaves the act pending: never judged on the fold as it stands now, and
//! never as absent (CALLS "FIX 4649 missing signed past"). The topology rows
//! stay outside the pure fold: their readers hand this module the acts, and
//! the removal writers fetch the acts' tokens ([`acknowledged_by_in_txn`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::adopted_fold::{AdoptedImageFold, AdoptedTail};
use super::fold_resume::{FoldCapture, ImageFold};
use super::machine_standing::{Standing, StandingView, every_chain};
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

/// The standing of each act one authority generation was asked about. Local
/// and derived: rebuilt on a miss, never stored.
pub(crate) struct CausalPoints {
    generation: u64,
    standings: BTreeMap<ExternalAct, ExternalActStanding>,
}

impl CausalPoints {
    /// How `act` stands here; `None` when this set was not built for it.
    pub(crate) fn standing(&self, act: &ExternalAct) -> Option<ExternalActStanding> {
        self.standings.get(act).copied()
    }
}

/// The standing of every act in `acts`, judged on `txn`'s stored authority
/// log. One fold answers a whole pass; a committed generation's answers are
/// kept for the next pass that asks about no other act.
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
        if acts.iter().all(|act| cached.standings.contains_key(act)) {
            return Ok(cached);
        }
        asked.extend(cached.standings.keys().cloned());
    }
    let points = Arc::new(CausalPoints {
        generation,
        standings: standings_in_txn(store, txn, &asked)?,
    });
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
/// main-log heads and its carrier's standing rows, as a main-log owner act
/// names its parents (CALLS "FIX 4649 seal causal envelope"). The caller
/// bounds it by [`MAX_PARENTS`].
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

fn standings_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    acts: &BTreeSet<ExternalAct>,
) -> Result<BTreeMap<ExternalAct, ExternalActStanding>> {
    let pending = || {
        acts.iter()
            .map(|act| (act.clone(), ExternalActStanding::Pending))
            .collect()
    };
    if acts.is_empty() {
        return Ok(BTreeMap::new());
    }
    let heads: BTreeSet<_> = acts
        .iter()
        .flat_map(|act| act.heads.iter().copied())
        .collect();
    let pin = super::pinned_root::read_pinned_root_in_txn(store, txn)?;
    let Some(ImageFold {
        per_parent, merged, ..
    }) = capture_in_txn(store, txn, &heads, pin.as_ref())?
    else {
        return Ok(pending());
    };
    let now = Standing::new(&merged, pin.as_ref(), &every_chain);
    let mut standings = BTreeMap::new();
    // Acts sort by their heads first: one parent state per causal point.
    let mut parent: Option<(&BTreeSet<AuthorityEntryHash>, Option<FoldState>)> = None;
    for act in acts {
        if parent
            .as_ref()
            .is_none_or(|(heads, _)| *heads != &act.heads)
        {
            parent = Some((&act.heads, parent_state(&per_parent, &act.heads)));
        }
        let standing = match parent.as_ref().and_then(|(_, state)| state.as_ref()) {
            Some(state) => judge(state, &now, pin.as_ref(), act),
            None => ExternalActStanding::Pending,
        };
        standings.insert(act.clone(), standing);
    }
    Ok(standings)
}

/// The fold state at `heads`, the merge of each head's state; `None` when
/// some head has none here, or none is named.
fn parent_state(
    per_parent: &BTreeMap<AuthorityEntryHash, Option<FoldState>>,
    heads: &BTreeSet<AuthorityEntryHash>,
) -> Option<FoldState> {
    let mut merged: Option<FoldState> = None;
    for head in heads {
        let state = per_parent.get(head)?.as_ref()?;
        merged = Some(match merged {
            Some(merged) => merge_states(&merged, state),
            None => state.clone(),
        });
    }
    merged
}

/// `act` at its parent state `parent`, and its removal race on `now`.
fn judge(
    parent: &FoldState,
    now: &Standing<'_>,
    pin: Option<&PinnedRoot>,
    act: &ExternalAct,
) -> ExternalActStanding {
    let at = Standing::new(parent, pin, &every_chain);
    let roster = StandingView::Under(MachineAdmitter::Roster);
    if !at.admits_owner_act_signer(act.machine, &act.key, roster)
        || !super::owner_act::owner_live_at(parent, act.owner)
    {
        return ExternalActStanding::Refused;
    }
    let marks = at.live_signing_chains(act.machine, &AuthorityKey::Ed25519(act.key));
    if now.owner_act_race(
        act.machine,
        &act.token,
        &act.key,
        &marks,
        StandingView::Install,
    ) {
        ExternalActStanding::Stands
    } else {
        ExternalActStanding::Refused
    }
}

/// The stored log's fold keeping the state at each of `heads`, with no clock:
/// past the adopted image where this vault does not hold its covered history,
/// else the held log whole. `None` where history the fold needs is not held.
fn capture_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    heads: &BTreeSet<AuthorityEntryHash>,
    pin: Option<&PinnedRoot>,
) -> Result<Option<ImageFold>> {
    let posture = store.privacy_posture;
    let peers = crate::federation::admitted_peer_consent_roots_for_store_in_txn(store, txn)?;
    if let Some(adopted) = super::checkpoint_adopt::adopted_authority_checkpoint_in_txn(store, txn)?
    {
        match capture_past_adopted(store, txn, &adopted, heads, pin, &peers)? {
            AdoptedImageFold::Captured { fold, .. } => return Ok(Some(*fold)),
            // Every covered row is held here: the held log folds whole.
            AdoptedImageFold::NeedHistory(request) if request.missing.is_empty() => {}
            AdoptedImageFold::NeedHistory(_) => return Ok(None),
        }
    }
    let entries = authority_log_rows_in_txn(store, txn)?
        .into_iter()
        .map(|(_, body)| decode_authority_log_entry_body(&body))
        .collect::<Result<Vec<_>>>()?;
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
    Ok(capture.take_image().map(|image| *image))
}

/// The tail's image-grade fold past `adopted`, keeping the state at each of
/// `heads` it folds, as a later image's build folds it.
fn capture_past_adopted(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    adopted: &VerifiedAuthorityCheckpoint,
    heads: &BTreeSet<AuthorityEntryHash>,
    pin: Option<&PinnedRoot>,
    peers: &BTreeMap<AuthorityVaultId, BTreeSet<AuthorityKey>>,
) -> Result<AdoptedImageFold> {
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
    super::adopted_fold::capture_adopted_checkpoint_tail(
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
    )
}
