//! A vault data key's generations, folded.
//!
//! Each counted delivery record names one generation's commitment, the
//! commitment it replaces, and the capsules that carry the new key to the
//! owner's other machines. The fold keeps every generation's counted records.
//! A generation is current-eligible only when exactly one commitment is
//! counted for it and its previous equals the eligible commitment of
//! generation one below; generation 1's previous is the vault's original key,
//! which each receiver checks against its own store, so the fold does not
//! judge it. Two counted records of one generation that name different
//! commitments, or different previous keys, conflict it: no device adopts
//! either. A generation past a conflicted or missing one is not eligible
//! either, so receivers stop at the break. Fail closed throughout; the
//! tie-break of a conflict comes in a later change.
//!
//! A record counts here when, at its parents, its signer is an owner-act
//! signer under both the roster and the install views, as a world-key record
//! counts. Any other well-signed record is a valid no-op, kept in the
//! refused set.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::fold_project::RowsReadWhole;
use super::machine_standing::{Standing, StandingView};
use super::*;

/// One counted delivery record of one generation.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub(super) struct CountedDataKeyGeneration {
    /// The commitment the record names for its generation.
    pub(super) commitment: [u8; 32],
    /// The commitment the record says it replaces.
    pub(super) previous: [u8; 32],
    /// The carrying entry.
    pub(super) hash: AuthorityEntryHash,
    /// The machine whose install key signed it.
    pub(super) machine: EntityId,
}

/// One generation's delivery as this fold holds it: the commitment every
/// counted record names, the link and capsules of the first counted entry,
/// and whether anything conflicts it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FoldedDataKeyGeneration {
    /// The generation delivered.
    pub generation: u32,
    /// The commitment naming the generation's key.
    pub commitment: [u8; 32],
    /// The commitment it replaces.
    pub previous: [u8; 32],
    /// Two counted records disagree, or the eligible chain breaks below:
    /// no device adopts this generation.
    pub conflicted: bool,
    /// The link bytes of the first counted entry: the old key sealed under
    /// the new one.
    pub link: Vec<u8>,
    /// The capsules of the first counted entry, ascending by machine.
    pub capsules: Vec<(EntityId, Vec<u8>)>,
    /// The counted entries, ascending by hash.
    pub entries: Vec<AuthorityEntryHash>,
    /// The machines whose install keys signed them.
    pub signers: BTreeSet<EntityId>,
}

impl AuthorityFold {
    /// The folded delivery of data-key generation `generation`, if any
    /// counted record names it.
    pub fn data_key_generation(&self, generation: u32) -> Option<&FoldedDataKeyGeneration> {
        self.data_key_generations.get(&generation)
    }

    /// Every folded generation delivery, in generation order.
    pub fn data_key_generations(&self) -> impl Iterator<Item = &FoldedDataKeyGeneration> {
        self.data_key_generations.values()
    }
}

/// The `DataKeyGeneration` transition, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster check.
/// Its signer is a machine's install key, never a roster key. Some chain of
/// the carrier must name that key, live or not, as for an owner act's
/// carrier; whether the record counts is [`counts`].
pub(super) fn apply_data_key_generation(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    record: &DataKeyGenerationRecord,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> std::result::Result<(), AuthorityFoldIssue> {
    let AuthorityKey::Ed25519(signer) = entry.signer_key() else {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    };
    let standing = Standing::new(state, context.pin, context.machine_standing);
    if !standing.names_key(record.machine, signer) {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    if state
        .seqs
        .get(entry.signer_key())
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    let counted = counts(&standing, record, signer);
    drop(standing);
    if !counted {
        state.refused_data_key_generations.insert(hash);
        return Ok(());
    }
    let held = state
        .data_key_generations
        .entry(record.generation)
        .or_default();
    let counted = CountedDataKeyGeneration {
        commitment: record.commitment,
        previous: record.previous,
        hash,
        machine: record.machine,
    };
    // Kept sorted, as a merge keeps them, so every fold order holds one list.
    if let Err(at) = held.binary_search(&counted) {
        held.insert(at, counted);
    }
    Ok(())
}

/// Whether a well-signed record counts here, judged in its parent state as
/// this install counts machines: the carrier is an owner-act signer under
/// both the roster and the install views. The same parent state and view give
/// the same answer on a full, a resumed and a checkpoint fold.
fn counts(standing: &Standing<'_>, record: &DataKeyGenerationRecord, signer: &[u8; 32]) -> bool {
    if record.generation == 0 {
        return false;
    }
    let roster = StandingView::Under(MachineAdmitter::Roster);
    standing.admits_owner_act_signer(record.machine, signer, roster)
        && standing.admits_owner_act_signer(record.machine, signer, StandingView::Install)
}

/// Joins two histories' generations: a generation both hold keeps what both
/// counted. Order-free.
pub(super) fn merge_data_key_generations(
    merged: &mut BTreeMap<u32, Vec<CountedDataKeyGeneration>>,
    right: &BTreeMap<u32, Vec<CountedDataKeyGeneration>>,
) {
    for (generation, counted) in right {
        let held = merged.entry(*generation).or_default();
        held.extend(counted.iter().cloned());
        held.sort();
        held.dedup();
    }
}

/// The fold's public view of every generation with a counted record, in
/// generation order, with the link and capsules read from the first counted
/// entry's row. A generation whose rows read as nothing counts as conflicted:
/// a receiver never adopts what the fold cannot show it.
pub(super) fn folded_data_key_generations(
    state: &FoldState,
    by_hash: &dyn RowsReadWhole,
) -> BTreeMap<u32, FoldedDataKeyGeneration> {
    let mut out = BTreeMap::new();
    let mut eligible: BTreeMap<u32, [u8; 32]> = BTreeMap::new();
    for (generation, counted) in &state.data_key_generations {
        let commitments: BTreeSet<[u8; 32]> =
            counted.iter().map(|entry| entry.commitment).collect();
        let previous_set: BTreeSet<[u8; 32]> = counted.iter().map(|entry| entry.previous).collect();
        let mut entries: Vec<AuthorityEntryHash> = counted.iter().map(|entry| entry.hash).collect();
        entries.sort_unstable();
        entries.dedup();
        let signers: BTreeSet<EntityId> = counted.iter().map(|entry| entry.machine).collect();
        let chained = match *generation {
            0 => false,
            1 => true,
            g => {
                previous_set.len() == 1
                    && eligible
                        .get(&(g - 1))
                        .is_some_and(|commitment| previous_set.contains(commitment))
            }
        };
        let (commitment, previous) = (
            commitments.iter().next().copied().unwrap_or([0; 32]),
            previous_set.iter().next().copied().unwrap_or([0; 32]),
        );
        let (link, capsules) = entries
            .iter()
            .find_map(|hash| {
                let AuthorityOp::DataKeyGeneration(record) = &by_hash.get(hash)?.op else {
                    return None;
                };
                Some((record.link.clone(), record.capsules.clone()))
            })
            .unwrap_or_default();
        // A valid record never carries empty link bytes, so an empty link
        // means no counted row read: fail closed.
        let conflicted =
            commitments.len() != 1 || previous_set.len() != 1 || link.is_empty() || !chained;
        if !conflicted {
            eligible.insert(*generation, commitment);
        }
        out.insert(
            *generation,
            FoldedDataKeyGeneration {
                generation: *generation,
                commitment,
                previous,
                conflicted,
                link,
                capsules,
                entries,
                signers,
            },
        );
    }
    out
}
