//! Device-only checks, score completion, and model name validation for paid recall.

use std::collections::BTreeSet;
use std::sync::PoisonError;

use crate::entity_id::EntityId;

/// The longest model name a pack repeats from the endpoint that answered.
const SERVED_MODEL_MAX_LEN: usize = 200;

/// The rows a device-only world keeps, of `rows`: each a row and the world
/// its item names at the revision scored. Kept is one the judge every read
/// door asks keeps from a caller off this device (a live row a flag
/// withholds, or one whose world cannot be read), or one whose item names a
/// flagged world. A flag commits under
/// the write side of the store's flag lock and this verdict reads under the
/// read side, as a sync release's does, so a flag committed before the
/// verdict is one it read. It only reads the store while it holds the lock:
/// a scoped read can take the writer, which a flag commit holds while it
/// waits.
pub(super) fn kept_on_device(
    vault: &crate::Vault,
    rows: &[(EntityId, Option<EntityId>)],
) -> crate::Result<BTreeSet<EntityId>> {
    let store = &vault.store;
    let _flags = store
        .device_only_flag_lock
        .read()
        .unwrap_or_else(PoisonError::into_inner);
    let rtxn = store.env.read_txn()?;
    // The reranker sits off this device: a host on it never asks.
    let flagged = crate::settings::device_local_worlds_at(
        vault,
        &rtxn,
        crate::claim::CallerLocality::OffDevice,
    )?;
    let mut kept = BTreeSet::new();
    for (id, world) in rows {
        if world.is_some_and(|world| flagged.contains(&world))
            || crate::settings::device_local_keeps_among(store, &rtxn, &flagged, id)?
        {
            kept.insert(*id);
        }
    }
    Ok(kept)
}

/// Scores for the candidates a rerank that stopped short left unscored
/// (FIX 11772), after the prefix it scored: each below every score the
/// reranker gave and above the empty rows, in fusion order, so the block
/// keeps that order for them; a row sent empty scores last, as a scored
/// one does.
pub(super) fn rank_unscored_below(scores: &mut Vec<f32>, texts: &[String]) {
    let mut next = scores
        .iter()
        .copied()
        .filter(|score| score.is_finite() && *score > f32::MIN)
        .reduce(f32::min)
        .unwrap_or(0.0);
    for text in texts.iter().skip(scores.len()) {
        if text.is_empty() {
            scores.push(f32::MIN);
        } else {
            next = next.next_down();
            scores.push(next);
        }
    }
}

/// Whether an endpoint's name for the model that answered is one a pack
/// repeats: printable ASCII with no spaces, at most [`SERVED_MODEL_MAX_LEN`]
/// bytes. Anything else is dropped, as though it named none.
pub(super) fn reported_model(name: &str) -> bool {
    (1..=SERVED_MODEL_MAX_LEN).contains(&name.len())
        && name.bytes().all(|byte| byte.is_ascii_graphic())
}
