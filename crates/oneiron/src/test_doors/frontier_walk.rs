//! The frontier walk doors (Setting stage 7b-1): one walk serves every read of an authority
//! register's frontier (`authority::world_strength::frontier_walk`).
//! Compiled only under `--cfg oneiron_test_support`; never API.

/// The walk's parts over a fixed frontier, each named by its edit's label or `default`. Edits
/// (label: what it replaced, whether it counts at full strength): a: nothing, no; g: nothing, no;
/// b: a and g, yes; c: a, no; d: b and c, no; e: c, no, and two copies of it disagreed;
/// f: nothing, no. Live: d, e, f.
pub fn walk_order() -> Vec<String> {
    crate::authority::frontier_walk_door::walk_order()
}

/// Reads `cases` seeded world frontiers, from `seed`, through the world privacy meet over the walk
/// and through the meet as it stood before the walk. Answers how many cases agreed, or the first
/// that did not.
///
/// # Errors
///
/// The first case whose two reads differ, with both reads and the frontier.
pub fn world_reads_match_before(seed: u64, cases: usize) -> Result<usize, String> {
    crate::authority::frontier_walk_door::world_reads_match_before(seed, cases)
}

/// Reads `cases` seeded grant frontiers, from `seed`, through a grant's travel meet over the walk
/// and through the meet as it stood before the walk. Answers how many cases agreed, or the first
/// that did not.
///
/// # Errors
///
/// The first case whose two reads differ, with both reads and the frontier.
pub fn travel_reads_match_before(seed: u64, cases: usize) -> Result<usize, String> {
    crate::authority::frontier_walk_door::travel_reads_match_before(seed, cases)
}
