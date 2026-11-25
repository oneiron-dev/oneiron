//! The comparison's cohorts (design pass 32 r2, section 4.4). At a two-rule
//! mint the engine draws a 32-byte seed; the period record stores it and its
//! sha256 commit, and no door shows the seed before the period ends. Arms take
//! positions in admission order within (period, track); positions fill blocks
//! of four, and each block holds two arms of each rule in the order the seed
//! picks. The pick reads no ceiling, no room and no request size.
use sha2::{Digest, Sha256};

use super::fold::{GpuLinePeriod, RuleRef, Track};
use crate::entity_id::bytes_to_hex_lower;

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
