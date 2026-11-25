//! The comparison's cohorts (design pass 32 r2, section 4.4). At a two-rule
//! mint the engine draws a 32-byte seed; the period record stores it and its
//! sha256 commit, and no door shows the seed before the period ends. Arms take
//! positions in admission order within (period, track); positions fill blocks
//! of four, and each block holds two arms of each rule in the order the seed
//! picks. The pick reads no ceiling, no room and no request size.
//!
//! Each position taken is one `GPU_LINE_COHORT_POSITION` row, written once:
//! an admission takes the next position of its period and track, and so
//! does an admission refused for budget, so a refusal never moves the
//! cohort of a later arm. An arm still open when the comparison turns on,
//! or of a family that graduated, takes its position at the mint
//! (`experiment_arm::assign_open_arms_in_txn`). A re-run keeps its
//! predecessor's cohort and takes no position; a new idea takes none.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::fold::{GpuLinePeriod, RuleRef, Track};
use crate::entity_id::bytes_to_hex_lower;
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::{EntityId, Vault};

/// The comparison's positions, in (line, period, track, position) order.
const POSITIONS: SideTable<CohortPositionKey, CohortPosition, Named> =
    SideTable::new(&side_table::GPU_LINE_COHORT_POSITION);

/// The arms one cohort block holds: two of each rule.
pub const COHORT_BLOCK_ARMS: u32 = 4;

/// The six orders of a block: 0 is the period's first rule, 1 its second.
const BLOCK_ARRANGEMENTS: [[usize; 4]; 6] = [
    [0, 0, 1, 1],
    [0, 1, 0, 1],
    [0, 1, 1, 0],
    [1, 0, 0, 1],
    [1, 0, 1, 0],
    [1, 1, 0, 0],
];

/// The commit a period record stores for its cohort seed: its sha256, lower
/// hex.
#[must_use]
pub fn cohort_seed_commit(seed: &[u8; 32]) -> String {
    bytes_to_hex_lower(&Sha256::digest(seed))
}

/// The rule of the arm at `position` (0-based, admission order within
/// `period` and `track`) in `period`'s comparison. `None` when the period runs
/// one rule, holds no seed (a preview), or `track` is the new-idea track (a
/// new idea has no cohort).
#[must_use]
pub fn cohort_rule(period: &GpuLinePeriod, track: Track, position: u32) -> Option<RuleRef> {
    if period.tables.len() != 2 {
        return None;
    }
    let seed = period.cohort_seed.as_ref()?;
    let tag: &[u8] = match track {
        Track::Demand => b"demand",
        Track::Interest => b"interest",
        Track::NewIdea => return None,
    };
    let block = position / COHORT_BLOCK_ARMS;
    let mut hasher = blake3::Hasher::new_keyed(seed);
    hasher.update(b"oneiron.gpu_line.cohort_block:v1");
    hasher.update(tag);
    hasher.update(&block.to_le_bytes());
    let digest = hasher.finalize();
    let mut low = [0u8; 8];
    low.copy_from_slice(&digest.as_bytes()[..8]);
    let pick = (u64::from_le_bytes(low) % 6) as usize;
    let arrangement = BLOCK_ARRANGEMENTS.get(pick)?;
    let entry = arrangement.get((position % COHORT_BLOCK_ARMS) as usize)?;
    period.tables.get(*entry).map(|table| table.rule)
}

/// A position's key: the line, its period, the track's tag
/// ([`cohort_track_tag`]) and the 0-based position in admission order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, SideKey)]
pub struct CohortPositionKey {
    /// The lane project the line is set on.
    pub line: EntityId,
    pub period: u32,
    pub track: u8,
    pub position: u32,
}

/// Who took one position, and the rule the period's seed gave it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CohortPosition {
    pub family: EntityId,
    pub rule: RuleRef,
    /// The arm that holds the position; `None` for an admission refused for
    /// budget, whose `GPU_LINE_REFUSAL` row names the same cohort.
    pub arm: Option<EntityId>,
    pub at_ms: u64,
}

/// The tag of `track` in a position's key: 0 demand, 1 interest. `None`
/// for the new-idea track, which takes no position.
#[must_use]
pub fn cohort_track_tag(track: Track) -> Option<u8> {
    match track {
        Track::Demand => Some(0),
        Track::Interest => Some(1),
        Track::NewIdea => None,
    }
}

/// The next position of one period and track, and the rule it gives:
/// read in a door's write transaction, then written with
/// [`CohortAssignment::record_in_txn`] in that same transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CohortAssignment {
    key: CohortPositionKey,
    rule: RuleRef,
}

impl CohortAssignment {
    /// The arm's cohort.
    pub(crate) fn rule(&self) -> RuleRef {
        self.rule
    }

    /// The arm's `cohort_block`: (period, position).
    pub(crate) fn block(&self) -> (u32, u32) {
        (self.key.period, self.key.position)
    }

    /// Writes the position, taken by `family`'s arm `arm` (`None` for an
    /// admission refused for budget) at `at_ms`.
    ///
    /// # Errors
    ///
    /// A store failure.
    pub(crate) fn record_in_txn(
        &self,
        vault: &Vault,
        wtxn: &mut heed::RwTxn<'_>,
        family: EntityId,
        arm: Option<EntityId>,
        at_ms: u64,
    ) -> crate::Result<()> {
        POSITIONS.put(
            &vault.store,
            wtxn,
            &self.key,
            &CohortPosition {
                family,
                rule: self.rule,
                arm,
                at_ms,
            },
        )
    }
}

/// The position an ask of `track` takes next in `period` of the line
/// `line`, and its rule. `None` when the period runs one rule or `track` is
/// the new-idea track: the ask takes no position and no cohort.
///
/// # Errors
///
/// A store read failure.
pub(crate) fn next_cohort_assignment_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    line: &EntityId,
    period: &GpuLinePeriod,
    track: Track,
) -> crate::Result<Option<CohortAssignment>> {
    let Some(tag) = cohort_track_tag(track) else {
        return Ok(None);
    };
    let mut prefix = Vec::new();
    line.encode_into(&mut prefix);
    period.index.encode_into(&mut prefix);
    tag.encode_into(&mut prefix);
    let position = POSITIONS
        .scan_keys(&vault.store, txn, &prefix)?
        .last()
        .map_or(0, |key| key.position.saturating_add(1));
    Ok(
        cohort_rule(period, track, position).map(|rule| CohortAssignment {
            key: CohortPositionKey {
                line: *line,
                period: period.index,
                track: tag,
                position,
            },
            rule,
        }),
    )
}

/// Every position of period `period` of the line `line`, by track, then in
/// admission order.
///
/// # Errors
///
/// A store failure.
pub fn cohort_positions_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    line: &EntityId,
    period: u32,
) -> crate::Result<Vec<(CohortPositionKey, CohortPosition)>> {
    let mut prefix = Vec::new();
    line.encode_into(&mut prefix);
    period.encode_into(&mut prefix);
    POSITIONS.scan_from(&vault.store, txn, &prefix)
}
