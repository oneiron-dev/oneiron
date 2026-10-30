//! A selection retry's widening, part by part (FIX 7524). Each part reads its
//! own conversation's TURN peers at the wake's snapshot, against its own
//! parent's axes and its own watermark; each keeps every original. A part
//! whose parent no longer reads or whose originals changed splits off as an
//! owed sibling so the other parts run (Engine ruling B). A branch cut for a
//! thing keeps its originals only: what widening finds there may be another
//! thing's, so it is owed as per-conversation sibling work and never
//! attached to this thing. Any other retry runs its originals with the
//! oldest other sources that fit, the rest owed as before (Rule 5). A Micro
//! retry widens only to peers whose current words no round has taken yet
//! (FIX 12246): a peer another window already queued is that window's work,
//! and taking it again re-extracts the same facts (Dreamer proof run 2).

use std::collections::{BTreeMap, BTreeSet};

use super::super::branch::QueuedBranch;
use super::super::watermark::decode_turn_body;
use super::chunk_identity::ChunkPin;
use super::chunks::{self, WakePreparationChunks};
use super::{AttemptPreparation, held_round_away_in};
use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::dreamer_runner::{
    DreamerConsolidationScope, dreamer_extraction_role_admissible, dreamer_turn_role,
};
use crate::registry::ENTITY_TYPE_TURN;
use crate::scan_check::{EngineScan, ScanCount};
use crate::{EntityId, Result, Vault};

/// The queue lineage a prepared attempt's owed work is queued under: its
/// own parent and run, and the attempt whose split first owed it.
#[derive(Debug, Clone)]
pub(super) struct Lineage {
    pub(super) parent: Option<AttemptId>,
    pub(super) run_id: Option<String>,
    pub(super) origin: AttemptId,
}

/// One prepared selection retry, before its widening resolves.
pub(super) struct Retry {
    pub(super) attempt: [u8; 16],
    pub(super) branch: QueuedBranch,
    /// Each part's incoming `ChildOf` TURN peers, in part order.
    pub(super) peers: Vec<Vec<EntityId>>,
}

/// What every retry of one wake resolves against: the wake's frozen sources,
/// each attempt's held round and lineage, and the lane's completed chunk
/// keys (FIX 7488), read at one snapshot.
pub(super) struct Snapshot<'s, 't> {
    pub(super) vault: &'s Vault,
    pub(super) txn: &'s heed::RoTxn<'t>,
    pub(super) scope: DreamerConsolidationScope,
    pub(super) sources: &'s BTreeMap<EntityId, (u8, u64, Vec<u8>)>,
    pub(super) completed: &'s BTreeSet<String>,
    pub(super) rounds: &'s BTreeMap<[u8; 16], (String, String)>,
    pub(super) lineage: &'s BTreeMap<[u8; 16], Lineage>,
}

/// Why a part cannot be widened at the snapshot.
enum Drift {
    ParentUnreadable,
    Membership(Vec<EntityId>),
}

/// One admissible peer: its selection position, key and id.
type Peer = (u64, EntityId, EntityId);

impl Snapshot<'_, '_> {
    /// Resolves every retry against the frozen pool, returning the work each
    /// one owes as siblings.
    pub(super) fn resolve(
        &self,
        preparations: &mut BTreeMap<[u8; 16], AttemptPreparation>,
        retries: Vec<Retry>,
    ) -> Result<Vec<WakePreparationChunks>> {
        let admission_time = crate::ports::job_recorded_at_in_txn(&self.vault.store, self.txn)?;
        let pin = ChunkPin {
            sources: self.sources,
            completed: self.completed,
        };
        let mut owed = Vec::new();
        for retry in retries {
            let limit = match preparations.get(&retry.attempt) {
                Some(AttemptPreparation::Ready(plan)) => plan.retry_budget().max_sources(),
                _ => return Err(invalid_consolidation("prepared retry budget missing")),
            };
            let lineage = self
                .lineage
                .get(&retry.attempt)
                .ok_or_else(|| invalid_consolidation("prepared retry lineage missing"))?;
            let mut fresh = Vec::new();
            let mut drifted = Vec::new();
            for index in 0..retry.branch.parts.len() {
                let peers = retry.peers.get(index).map_or(&[][..], Vec::as_slice);
                match self.part_peers(&retry.branch, index, peers, admission_time)? {
                    Ok(turns) => fresh.push((index, turns)),
                    Err(drift) => drifted.push((index, drift)),
                }
            }
            // Every part drifted: the first keeps the whole attempt's
            // outcome, as a one-part retry's; the rest split off.
            let first = (fresh.is_empty() && !drifted.is_empty()).then(|| drifted.remove(0).1);
            let split: Vec<usize> = drifted.iter().map(|(index, _)| *index).collect();
            owed.extend(WakePreparationChunks::new(
                retry.attempt,
                lineage,
                chunks::split_parts(&retry.branch, &split),
                pin,
            ));
            if let Some(first) = first {
                let outcome = self.drift_outcome(&retry.attempt, first)?;
                preparations.insert(retry.attempt, outcome);
                continue;
            }
            let (branch, overflow) = widen(&retry.branch, fresh, limit);
            if let Some(AttemptPreparation::Ready(plan)) = preparations.get_mut(&retry.attempt) {
                plan.sources_truncated = !overflow.is_empty();
                plan.turn_ids = branch.turn_ids();
                plan.input = super::super::partition::encode_branch_payload(&branch, None);
                plan.branch = branch;
            }
            owed.extend(WakePreparationChunks::new(
                retry.attempt,
                lineage,
                chunks::overflow_chunks(&retry.branch, overflow, limit),
                pin,
            ));
        }
        Ok(owed)
    }

    /// Part `index`'s admissible peers, read against its own parent: every
    /// peer is read, and past the conversation's threshold row the retry
    /// raises one check and reads on.
    fn part_peers(
        &self,
        branch: &QueuedBranch,
        index: usize,
        peers: &[EntityId],
        admission_time: u64,
    ) -> Result<std::result::Result<Vec<Peer>, Drift>> {
        let part = &branch.parts[index];
        let Some(parent) = self.sources.get(&part.conversation_ref) else {
            return Ok(Err(Drift::ParentUnreadable));
        };
        let parent = decode_turn_body(&parent.2);
        let original: BTreeSet<_> = part.turns.iter().copied().collect();
        let mut scanned = ScanCount::start(
            &self.vault.store,
            self.txn,
            EngineScan::DreamerRetryPeers,
            part.conversation_ref.as_bytes(),
        )?;
        let mut turns = Vec::new();
        for id in peers {
            scanned.row();
            let Some((kind, stored, bytes)) = self.sources.get(id) else {
                continue;
            };
            if *kind != ENTITY_TYPE_TURN {
                continue;
            }
            // Membership and order read the effective selection key, as
            // the scan does; the source pin keeps the row's own learned_at.
            let carrier = super::super::redirty::carrier_key_in_txn(
                self.vault, self.txn, self.scope, id, *stored,
            )?;
            let (learned_at, key) = carrier.unwrap_or((*stored, *id));
            let facts = decode_turn_body(bytes);
            let role = dreamer_turn_role(
                facts.speaker.as_deref(),
                &self.vault.config.assistant_display_names,
            );
            if *stored <= admission_time
                && dreamer_extraction_role_admissible(role)
                && facts.world_ref.or(parent.world_ref) == branch.world_ref
                && facts.facet_ref.or(parent.facet_ref) == branch.facet_ref
                && (original.contains(id)
                    || (learned_at >= part.watermark_last_learned_at
                        && !self.taken_elsewhere(id)?))
            {
                turns.push((learned_at, key, *id));
            }
        }
        scanned.finish(self.vault);
        let missing: Vec<EntityId> = original
            .iter()
            .filter(|id| !turns.iter().any(|(_, _, got)| got == *id))
            .copied()
            .collect();
        if !missing.is_empty() {
            return Ok(Err(Drift::Membership(missing)));
        }
        Ok(Ok(turns))
    }

    /// Whether another Micro round already took `turn`'s current words, so
    /// this retry's widening leaves it to that round (FIX 12246). Other
    /// scopes read their own rounds and widen as before.
    fn taken_elsewhere(&self, turn: &EntityId) -> Result<bool> {
        if self.scope != DreamerConsolidationScope::Micro {
            return Ok(false);
        }
        crate::dreamer_wake::words_taken_in_txn(self.vault, self.txn, turn)
    }

    /// What a drifted part's whole attempt comes to: a held round's member
    /// away from this replica waits for its promotion; any other change of
    /// membership, or an unreadable parent, refuses.
    fn drift_outcome(&self, attempt: &[u8; 16], drift: Drift) -> Result<AttemptPreparation> {
        Ok(match drift {
            Drift::ParentUnreadable => AttemptPreparation::Refused {
                reason: "selection retry parent not readable",
                scope_error: false,
            },
            Drift::Membership(missing) => {
                if held_round_away_in(self.vault, self.txn, self.rounds.get(attempt), &missing)? {
                    AttemptPreparation::ResidencyDeferred
                } else {
                    AttemptPreparation::Refused {
                        reason: "selection retry membership changed",
                        scope_error: false,
                    }
                }
            }
        })
    }
}

/// The retry's working set over its `fresh` parts and the overflow it owes,
/// by part index. The source budget sizes chunks, never refuses or drops
/// (Rule 5, L02-38): every original runs; a branch with no thing takes the
/// oldest other sources that fit across its parts; the rest is owed.
fn widen(
    branch: &QueuedBranch,
    fresh: Vec<(usize, Vec<Peer>)>,
    limit: usize,
) -> (QueuedBranch, Vec<(usize, EntityId)>) {
    let original: BTreeSet<EntityId> = fresh
        .iter()
        .flat_map(|(index, _)| branch.parts[*index].turns.iter().copied())
        .collect();
    let mut candidates: Vec<(u64, EntityId, EntityId, usize)> = fresh
        .iter()
        .flat_map(|(index, turns)| {
            turns
                .iter()
                .map(move |(learned_at, key, id)| (*learned_at, *key, *id, *index))
        })
        .collect();
    candidates.sort_unstable();
    let optional = if branch.thing.is_some() {
        0
    } else {
        limit.saturating_sub(original.len())
    };
    let mut kept_optional = 0_usize;
    let mut kept: BTreeMap<usize, Vec<EntityId>> = BTreeMap::new();
    let mut overflow = Vec::new();
    for (_, _, id, index) in candidates {
        let keep = original.contains(&id) || {
            kept_optional += 1;
            kept_optional <= optional
        };
        if keep {
            kept.entry(index).or_default().push(id);
        } else {
            overflow.push((index, id));
        }
    }
    let parts = fresh
        .iter()
        .map(|(index, _)| {
            let part = &branch.parts[*index];
            super::super::ConversationPart {
                conversation_ref: part.conversation_ref,
                turns: kept.remove(index).unwrap_or_default(),
                watermark_last_learned_at: part.watermark_last_learned_at,
                line: part.line,
            }
        })
        .collect();
    (
        QueuedBranch {
            world_ref: branch.world_ref,
            facet_ref: branch.facet_ref,
            thing: branch.thing,
            parts,
        },
        overflow,
    )
}
