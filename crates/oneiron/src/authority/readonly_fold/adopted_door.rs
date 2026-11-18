//! The adopted-fold door (FIX [ADOPTED-FOLD-GATE-TEST] and
//! [SEQ-FLOOR-S-ADOPTED-FORK-NEEDS-HISTORY]): one vault's log folded past an
//! image of a prefix of it, as a cold install that adopted that image and
//! holds none of its covered rows folds it, beside the vault's own fold of
//! the whole log under the same cache key. The image is the vault's own
//! build over the prefix, taken as verified with no attestation: a fold past
//! an image reads the image and its id alone. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use super::*;
use crate::Vault;
use crate::authority::adopted_build::tail_closure;
use crate::authority::adopted_fold::{
    AdoptedImageFold, AdoptedTail, AdoptedTailFold, capture_adopted_checkpoint_tail,
    fold_adopted_checkpoint_tail,
};
use crate::authority::checkpoint_adopt::VerifiedAuthorityCheckpoint;
use crate::authority::fold_resume::ImageFold;

/// A fold past the image, or the covered rows it asks for.
pub type PastImage<T> = std::result::Result<T, BTreeSet<AuthorityEntryHash>>;

/// What an image keeps of a fold: the safety issues and the projected once
/// fold, with no install bound and no pin, as a decoder reads them back.
#[derive(Debug, Clone, PartialEq)]
pub struct ImageGradeFold {
    pub safety_issues: Vec<AuthorityFoldIssue>,
    pub fold: AuthorityFold,
}

/// One log folded past an image of its prefix on a cold install, and whole.
#[derive(Debug)]
pub struct AdoptedFoldComparison {
    /// The live fold past the image.
    pub adopted: PastImage<AuthorityFold>,
    /// The vault's own live fold of every row it holds.
    pub whole: AuthorityFold,
    /// The image-grade capture past the image, as a later image keeps it.
    pub captured: PastImage<ImageGradeFold>,
    /// The image-grade fold of every row, as a whole-log build keeps it.
    pub whole_captured: ImageGradeFold,
}

/// `vault`'s log folded past the image it builds over `covered` (an
/// ancestor-closed prefix of the rows it holds), on a cold install: no
/// covered row held, the rows past the image as its tail with this vault's
/// first-seen times, observations, peers and pin. Beside it, the vault's own
/// fold of the whole log, live and image-grade.
///
/// # Errors
///
/// The vault cannot build the image over `covered` or fold its log.
pub fn fold_past_prefix_image(
    vault: &Vault,
    covered: &BTreeSet<AuthorityEntryHash>,
) -> Result<AdoptedFoldComparison> {
    let store = &vault.store;
    let posture = vault.privacy_posture();
    let txn = store.env.read_txn()?;
    let prefix = vault.build_authority_checkpoint_v2_as_in_txn(&txn, posture, Some(covered))?;
    let adopted = VerifiedAuthorityCheckpoint::unattested_for_door(prefix)?;
    let image = adopted.image();
    let key = authority_cache_key(store, posture, &txn)?;
    let mut tail = Vec::new();
    let mut bodies = BTreeMap::new();
    for (_, body) in authority_log_rows_in_txn(store, &txn)? {
        let entry = decode_stored_authority_log_body(&body)?;
        let hash = authority_entry_hash(&entry)?;
        if !image.rows.contains_key(&hash) {
            tail.push((hash, entry.clone()));
            bodies.insert(hash, (entry, body));
        }
    }
    let backfilled = AUTHORITY_FIRST_SEEN_BACKFILLED.contains(
        store,
        &txn,
        &authority_first_seen_backfill_key(),
    )?;
    let mut first_seen_at_secs = BTreeMap::new();
    for (hash, _) in &tail {
        let first_seen = readonly_first_seen_for(store, &txn, hash, backfilled, key.now_secs)?;
        first_seen_at_secs.insert(*hash, first_seen);
    }
    let observations =
        crate::authority::sequence_observation::authority_local_observations_in_txn(store, &txn)?;
    let peer_consent_roots =
        crate::federation::admitted_peer_consent_roots_for_store_in_txn(store, &txn)?;
    let cold = BTreeSet::new();
    let none_required = BTreeSet::new();
    let adopted_live = match fold_adopted_checkpoint_tail(
        &adopted,
        AdoptedTail {
            tail: &tail,
            held_covered: &cold,
            // The vault's own rows: every tail row counts.
            believed: None,
            required: &none_required,
            first_seen_at_secs: &first_seen_at_secs,
            now_secs: key.now_secs,
            peer_consent_roots: &peer_consent_roots,
            observations: &observations,
            posture,
            pin: key.pin.as_ref(),
            keep_replay: false,
        },
    )? {
        AdoptedTailFold::Complete { fold, .. } => Ok(fold),
        AdoptedTailFold::NeedHistory(request) => Err(request.missing),
    };
    let (closed, _, _) = tail_closure(image, &bodies);
    let closed_tail = tail
        .iter()
        .filter(|(hash, _)| closed.contains(hash))
        .cloned()
        .collect::<Vec<_>>();
    let no_first_seen = BTreeMap::new();
    let captured = match capture_adopted_checkpoint_tail(
        &adopted,
        AdoptedTail {
            tail: &closed_tail,
            held_covered: &cold,
            believed: None,
            required: &none_required,
            first_seen_at_secs: &no_first_seen,
            now_secs: 0,
            peer_consent_roots: &peer_consent_roots,
            observations: &observations,
            posture,
            pin: key.pin.as_ref(),
            keep_replay: true,
        },
    )? {
        AdoptedImageFold::Captured { fold, .. } => {
            let ImageFold {
                fold: mut once,
                safety,
                ..
            } = *fold;
            once.install = InstallBound::default();
            once.pinned_root = None;
            Ok(ImageGradeFold {
                safety_issues: safety.issues,
                fold: as_decoded(&once)?,
            })
        }
        AdoptedImageFold::NeedHistory(request) => Err(request.missing),
    };
    let whole_image = vault.build_authority_checkpoint_v2_as_in_txn(&txn, posture, None)?;
    let whole_captured = ImageGradeFold {
        safety_issues: whole_image.safety.issues.clone(),
        fold: as_decoded(&whole_image.aggregate.fold)?,
    };
    let whole = (*fold_view_for_key(store, posture, &txn, key, None)?.0.fold).clone();
    Ok(AdoptedFoldComparison {
        adopted: adopted_live,
        whole,
        captured,
        whole_captured,
    })
}

/// `fold` as an image's decoder reads it back: what the encoding skips
/// stays at its default on both sides of a comparison.
fn as_decoded(fold: &AuthorityFold) -> Result<AuthorityFold> {
    let bytes = rmp_serde::to_vec_named(fold).map_err(|_| invalid_authority())?;
    rmp_serde::from_slice(&bytes).map_err(|_| invalid_authority())
}
