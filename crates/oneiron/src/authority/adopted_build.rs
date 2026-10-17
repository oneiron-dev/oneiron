//! A later checkpoint image on a vault that adopted one (OF-469, slice D;
//! identity.md, "Resumable checkpoints and cold authority history").
//!
//! The held-only builder cannot cover history this vault never held, so a
//! vault that adopted an image builds every later one from its adopted
//! baseline and the rows it holds past it. Coverage is the adopted image's
//! covered set and the held tail whose ancestors are all covered or in it;
//! a held tail row above a gap stays unresolved, as the held-only builder
//! keeps it. The tail folds on the adopted image's frontier states exactly as
//! the fold past the image folds it ([`super::adopted_fold`]), and the
//! capture keeps the fold at the new frontier. The adopted image's archive
//! manifests carry over unchanged. Like the held-only builder, the build
//! reads no clock and keeps no install's own facts: no first-seen time,
//! floor, vouch, install bound or pin enters the image.
//!
//! Where the tail cannot extend the baseline (a late fork, an op outside the
//! cold tail scope, another build context, a guard the fold past the image
//! declines at), the build refuses with the typed history-required error,
//! unless every covered row is held here: the held log then builds the image
//! whole. The adopted pin stays the trust baseline: keeping the new image as
//! the head moves no adoption.

use std::collections::{BTreeMap, BTreeSet};

use super::adopted_fold::{AdoptedImageFold, AdoptedTail};
use super::checkpoint_image::{CheckpointAggregate, carries_body};
use super::fold_resume::ImageFold;
use super::*;
use crate::error::{Error, RecordError, Result};
use crate::{EntityId, Vault};

/// One held tail row: its signed entry and its stored canonical body.
type TailRow = (AuthorityLogEntry, Vec<u8>);

fn refused(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(reason))
}

/// The tail rows whose every parent is covered or such a row, the tail rows
/// above a gap, and the parents tail rows name that the image does not cover
/// and this vault does not hold.
fn tail_closure(
    image: &AuthorityCheckpointV2,
    tail: &BTreeMap<AuthorityEntryHash, TailRow>,
) -> (
    BTreeSet<AuthorityEntryHash>,
    BTreeSet<AuthorityEntryHash>,
    BTreeSet<AuthorityEntryHash>,
) {
    let mut children = BTreeMap::<AuthorityEntryHash, Vec<AuthorityEntryHash>>::new();
    let mut waiting = BTreeMap::<AuthorityEntryHash, usize>::new();
    let mut ready = Vec::new();
    let mut missing = BTreeSet::new();
    for (hash, (entry, _)) in tail {
        let parents: BTreeSet<_> = entry
            .parent_hashes
            .iter()
            .filter(|parent| !image.rows.contains_key(*parent))
            .copied()
            .collect();
        for parent in &parents {
            if !tail.contains_key(parent) {
                missing.insert(*parent);
            }
            children.entry(*parent).or_default().push(*hash);
        }
        if parents.is_empty() {
            ready.push(*hash);
        } else {
            waiting.insert(*hash, parents.len());
        }
    }
    let mut closed = BTreeSet::new();
    while let Some(hash) = ready.pop() {
        if !closed.insert(hash) {
            continue;
        }
        for child in children.get(&hash).into_iter().flatten() {
            if let Some(count) = waiting.get_mut(child) {
                *count -= 1;
                if *count == 0 {
                    waiting.remove(child);
                    ready.push(*child);
                }
            }
        }
    }
    let open = tail
        .keys()
        .filter(|hash| !closed.contains(*hash))
        .copied()
        .collect();
    (closed, open, missing)
}

impl Vault {
    /// The next checkpoint v2 image of a vault that adopted `adopted`, from
    /// one read snapshot: the adopted image's coverage and the ancestor-closed
    /// held tail, folded past the adopted image with no clock. Unlinked:
    /// [`Vault::write_authority_checkpoint_v2`] sets its parent and keeps it.
    /// Refuses with the typed history-required error where the tail cannot
    /// extend the baseline and a covered row is not held here; with every
    /// covered row held, the held log builds the image whole.
    pub(super) fn build_authority_checkpoint_from_adopted_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        adopted: &VerifiedAuthorityCheckpoint,
    ) -> Result<AuthorityCheckpointV2> {
        let store = &self.store;
        let image = adopted.image();
        let posture = self.privacy_posture();
        // The store id is the row's content hash: a held covered row is
        // known by its id alone.
        let covered_ids: BTreeMap<EntityId, AuthorityEntryHash> = image
            .covered
            .iter()
            .filter_map(|hash| Some((authority_log_entity_id_from_hash(hash).ok()?, *hash)))
            .collect();
        let mut held_covered = BTreeSet::new();
        let mut tail = BTreeMap::new();
        for (id, body) in super::readonly_fold::authority_log_rows_in_txn(store, txn)? {
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
        let (closed, open, missing) = tail_closure(image, &tail);
        let closed_tail = closed
            .iter()
            .map(|hash| {
                let (entry, _) = tail.get(hash).ok_or_else(invalid_authority)?;
                Ok((*hash, entry.clone()))
            })
            .collect::<Result<Vec<_>>>()?;
        let metas: Vec<_> = closed_tail
            .iter()
            .map(|(hash, entry)| super::fold_resume::RowMeta::of(Some(*hash), entry))
            .collect();
        // The tail's observations alone: none is read for a covered row.
        let observations =
            super::sequence_observation::authority_local_observations_of_rows_in_txn(
                store, txn, &metas,
            )?;
        let peers = crate::federation::admitted_peer_consent_roots_in_txn(self, txn)?;
        let pin = super::pinned_root::read_pinned_root_in_txn(store, txn)?;
        let no_first_seen = BTreeMap::new();
        let none_required = BTreeSet::new();
        let captured = super::adopted_fold::capture_adopted_checkpoint_tail(
            adopted,
            AdoptedTail {
                tail: &closed_tail,
                held_covered: &held_covered,
                required: &none_required,
                first_seen_at_secs: &no_first_seen,
                now_secs: 0,
                peer_consent_roots: &peers,
                observations: &observations,
                posture,
                pin: pin.as_ref(),
            },
        )?;
        let (
            ImageFold {
                per_parent,
                merged,
                fold: mut once,
                safety,
            },
            stale_approvals,
        ) = match captured {
            AdoptedImageFold::Captured {
                fold,
                stale_approvals,
            } => (*fold, stale_approvals),
            // Every covered row is held here: the held log builds it whole.
            AdoptedImageFold::NeedHistory(request) if request.missing.is_empty() => {
                return self.build_authority_checkpoint_v2_in_txn(txn);
            }
            AdoptedImageFold::NeedHistory(request) => {
                return Err(super::readonly_fold::history_required(&request));
            }
        };
        if once.vault_id != Some(image.vault_id) || once.vault_root_is_conflicted() {
            return Err(refused("the covered authority history has no settled root"));
        }
        let mut unsettled_handoffs: Vec<_> = safety
            .issues
            .iter()
            .filter_map(|issue| match issue {
                AuthorityFoldIssue::UnsettledHandoff(hash) => Some(*hash),
                _ => None,
            })
            .collect();
        unsettled_handoffs.sort_unstable();
        unsettled_handoffs.dedup();
        let unresolved = AuthorityCheckpointUnresolved {
            held: open.into_iter().collect(),
            missing: missing.into_iter().collect(),
            unsettled_handoffs,
            held_back: std::mem::take(&mut once.install.held_back)
                .into_iter()
                .collect(),
            stale_approvals: stale_approvals.into_iter().collect(),
        };
        once.install = InstallBound::default();
        once.pinned_root = None;
        let mut rows = image.rows.clone();
        for hash in &closed {
            let (entry, body) = tail.get(hash).ok_or_else(invalid_authority)?;
            rows.insert(
                *hash,
                AuthorityCheckpointRow {
                    signer: entry.signer_key().clone(),
                    seq: entry.seq,
                    parents: entry.parent_hashes.clone(),
                    world: super::world_privacy::side_world(&entry.op),
                    slip_op: super::log_budget::is_slip_op(&entry.op),
                    body: carries_body(&entry.op).then(|| body.clone()),
                },
            );
        }
        let next = AuthorityCheckpointV2 {
            fold_schema: AUTHORITY_CHECKPOINT_FOLD_SCHEMA,
            vault_id: image.vault_id,
            genesis: image.genesis,
            covered: rows.keys().copied().collect(),
            frontier: per_parent.keys().copied().collect(),
            rows,
            per_parent,
            aggregate: CheckpointAggregate {
                posture,
                peers,
                merged,
                fold: once,
            },
            safety,
            unresolved,
            archive_manifests: image.archive_manifests.clone(),
            root_policy: self.checkpoint_root_policy_in_txn(txn)?,
            building_pin: pin,
            parent: None,
        };
        // One serde round trip normalizes what a decoder would, so the image
        // re-encodes to its own bytes.
        let normalized: AuthorityCheckpointV2 = rmp_serde::from_slice(
            &rmp_serde::to_vec_named(&next)
                .map_err(|_| refused("checkpoint image does not encode"))?,
        )
        .map_err(|_| refused("checkpoint image does not decode"))?;
        normalized.encode()?;
        Ok(normalized)
    }
}
