//! Contribution-fork erase ownership (FIX 10754, 11358). Live pairs use
//! their experiment key; an erase moves the whole pair to an opaque key
//! and reissues its receipts in the SAME writer as the CHECK rebind. The
//! scores and answers stay, but no erased subject derives a retained key.
//! A pending owner pair is not moved: the erase deletes it and retires the
//! ask that carries its question, so no answer to it scores anything (FIX
//! 3609).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::super::super::contribution::{
    ContributionReplayUnavailable, FORK_RECEIPT_PREFIX, OwnerPair, OwnerPairRoute,
};
use super::super::super::replay_capsule::StepReplayCapsule;
use super::{FORKS, ForkRow, ForkValue, ForkWrite, actor_gone_in_txn};
use crate::entity_id::{ENTITY_ID_LEN, bytes_to_hex_lower};
use crate::skill_attribution::{ContributionCandidate, ContributionTarget};
use crate::{EntityId, Result, Vault};

/// Actual erase subjects, captured before provider/scorer work: the actor,
/// credited skill, both ends of a used edge and entity spellings retained
/// in the outcome receipt. Receipt spellings are erase metadata, not proof
/// of authority. Removing one leaves the others discoverable for a later erase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ForkProvenance {
    subjects: Vec<EntityId>,
}

impl ForkProvenance {
    pub(crate) fn for_candidate_in_txn(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        candidate: &ContributionCandidate,
        capsules: &[StepReplayCapsule],
        selected: Option<&StepReplayCapsule>,
    ) -> Result<Option<Self>> {
        let mut subjects = vec![candidate.skill];
        subjects.extend(receipt_entities(&candidate.outcome_receipt));
        match candidate.target {
            ContributionTarget::LoadedSkill(skill) => subjects.push(skill),
            ContributionTarget::UsedEdge { derived, source } => subjects.extend([derived, source]),
        }
        match selected {
            Some(capsule) => {
                let Some(actor) = capsule.content.actor() else {
                    return Ok(None);
                };
                subjects.push(actor);
            }
            None => {
                // No exposure still belongs to the attempt's captured actors.
                // Only its latest generation owns this reason; an older
                // erased generation must not hide a newer live attempt.
                let latest = capsules
                    .iter()
                    .map(|capsule| capsule.lease_generation)
                    .max();
                for capsule in capsules
                    .iter()
                    .filter(|capsule| Some(capsule.lease_generation) == latest)
                {
                    let Some(actor) = capsule.content.actor() else {
                        return Ok(None);
                    };
                    subjects.push(actor);
                }
            }
        }
        subjects.sort_unstable();
        subjects.dedup();
        let provenance = Self { subjects };
        Ok(provenance.live_in_txn(vault, txn).then_some(provenance))
    }

    pub(super) fn with_actor(&self, actor: EntityId) -> Self {
        let mut held = self.clone();
        if !held.subjects.contains(&actor) {
            held.subjects.push(actor);
        }
        held
    }

    pub(super) fn live_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> bool {
        self.subjects
            .iter()
            .all(|id| !actor_gone_in_txn(vault, txn, id))
    }

    /// The fence a fork writer reads in `txn` (FIX 6256): `Unfinished` while
    /// a subject is gone. A soft delete, or a deletion marker that does not
    /// read, may lift, so the stop is never lasting. An erase keeps the
    /// fence, and the next pass's provenance reads it before any work.
    pub(super) fn fence_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> ForkWrite<()> {
        if self.live_in_txn(vault, txn) {
            Ok(())
        } else {
            Err(ContributionReplayUnavailable::Unfinished)
        }
    }
}

/// Native full-id spellings anywhere in an opaque receipt, including
/// upper-case hex: the same spelling match used by CHECK's erase pass.
fn receipt_entities(receipt: &str) -> impl Iterator<Item = EntityId> + '_ {
    receipt
        .as_bytes()
        .windows(ENTITY_ID_LEN * 2)
        .filter_map(|hex| std::str::from_utf8(hex).ok())
        .filter_map(|hex| EntityId::from_hex(hex).ok())
}

fn affected_pairs(rows: &[(([u8; 32], String), ForkRow)], entity: &EntityId) -> BTreeSet<[u8; 32]> {
    rows.iter()
        .filter(|(_, row)| {
            row.provenance.subjects.contains(entity)
                || matches!(&row.value, ForkValue::Fork(fork)
                    if receipt_entities(&fork.scoring.outcome_receipt).any(|id| id == *entity))
                || matches!(&row.value, ForkValue::OwnerPair(pair)
                    if receipt_entities(&pair.scoring.outcome_receipt).any(|id| id == *entity))
        })
        .map(|((pair, _), _)| *pair)
        .collect()
}

/// The erase's pending copied-question records, read before actor fields or
/// the pair rows are scrubbed. These records name candidates, not erase authority.
pub(crate) fn contribution_pair_erase_candidates_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
) -> Result<Vec<OwnerPair>> {
    let mut rows = Vec::new();
    for key in FORKS.scan_keys(&vault.store, txn, &[])? {
        let Some(bytes) = FORKS.get_bytes(&vault.store, txn, &key)? else {
            continue;
        };
        if let Ok(row) = FORKS.decode_value(&bytes) {
            rows.push((key, row));
        }
    }
    let affected = affected_pairs(&rows, entity);
    Ok(rows
        .into_iter()
        .filter(|(key, _)| affected.contains(&key.0))
        .filter_map(|(_, row)| match row.value {
            ForkValue::OwnerPair(pair) => Some(*pair),
            _ => None,
        })
        .collect())
}

/// Re-keys every pair naming `entity` and rebinds CHECK's exact fork
/// references without changing a measurement. New fork paths are opaque
/// from birth, so keeping their bodies keeps no target-derived path. A row
/// that no longer decodes (one written before FIX 3607 changed the row)
/// cannot say whom it names, so the erase deletes it rather than fail. A
/// pending owner pair of such a pair is deleted, and its ask is cut Stale in
/// this writer.
pub(crate) fn erase_contribution_forks_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let mut rows = Vec::new();
    let mut undecodable = Vec::new();
    for key in FORKS.scan_keys(&vault.store, wtxn, &[])? {
        let Some(bytes) = FORKS.get_bytes(&vault.store, wtxn, &key)? else {
            continue;
        };
        match FORKS.decode_value(&bytes) {
            Ok(row) => rows.push((key, row)),
            Err(_) => undecodable.push(key),
        }
    }
    for key in &undecodable {
        FORKS.delete(&vault.store, wtxn, key)?;
    }
    let affected = affected_pairs(&rows, entity);
    if affected.is_empty() {
        return Ok(());
    }
    let mut moved = BTreeMap::new();
    for pair in affected {
        moved.insert(pair, *blake3::hash(&vault.store.clock.ulid()?).as_bytes());
    }
    let mut rebound = BTreeMap::new();
    let mut erased_outcomes = BTreeMap::new();
    let mut retired_asks = Vec::new();
    for (key, mut row) in rows {
        let Some(pair) = moved.get(&key.0) else {
            continue;
        };
        if let ForkValue::OwnerPair(pending) = &row.value {
            if let OwnerPairRoute::Asked { ask, .. } = pending.route {
                retired_asks.push(ask);
            }
            FORKS.delete(&vault.store, wtxn, &key)?;
            continue;
        }
        row.provenance.subjects.retain(|id| id != entity);
        if let ForkValue::Fork(fork) = &mut row.value {
            if receipt_entities(&fork.scoring.outcome_receipt).any(|id| id == *entity) {
                let erased = format!("erased:{}", bytes_to_hex_lower(&vault.store.clock.ulid()?));
                let replacement = erased_outcomes
                    .entry(fork.scoring.outcome_receipt.clone())
                    .or_insert(erased);
                fork.scoring.outcome_receipt.clone_from(replacement);
            }
            let fresh = bytes_to_hex_lower(&vault.store.clock.ulid()?);
            let receipt = format!("{FORK_RECEIPT_PREFIX}{fresh}");
            // Every occurrence of the same receipt gets the same new ref.
            let replacement = rebound.entry(fork.receipt.clone()).or_insert(receipt);
            fork.receipt.clone_from(replacement);
        }
        FORKS.delete(&vault.store, wtxn, &key)?;
        FORKS.put(vault, wtxn, &(*pair, key.1), &row)?;
    }
    crate::task_verb::retire_contribution_pair_asks_in(vault, wtxn, &retired_asks)?;
    crate::skill_attribution::rebind_contribution_fork_receipts_in_txn(vault, wtxn, &rebound)
}
