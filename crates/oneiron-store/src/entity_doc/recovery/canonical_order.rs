//! The canonical index of each captured version. Two concurrent versions with
//! the same parents, text and metadata stay two versions (FIX 9850): the rows
//! that name each one (its pins, receipts, fork bases and purges, by their
//! own ids) tell them apart, as every capture of those rows does again.

use std::collections::BTreeMap;

use loro::VersionVector;

use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// A pin naming a version.
pub const PIN: u8 = 0;
/// A settlement receipt naming its before (role 0) or after (role 1) version.
pub const RECEIPT: u8 = 1;
/// A fork naming its base.
pub const FORK: u8 = 2;
/// A purge receipt naming its requested (role 0) or applied (role 1) version.
pub const PURGE: u8 = 3;

/// The rows naming one captured version, in order: each by its kind, its own
/// id and the role it names the version in. No two versions share one: a row
/// names one version in each role.
pub type Names = Vec<(u8, [u8; 16], u8)>;

/// Each version's direct predecessors among the captured versions: the
/// maximal ones its version vector includes. A strictly later version holds
/// strictly more operations, so walking down by size meets every cover first.
pub fn hasse(vvs: &[VersionVector]) -> Vec<Vec<usize>> {
    let size = |vv: &VersionVector| vv.values().map(|&end| i64::from(end)).sum::<i64>();
    let mut by_size: Vec<usize> = (0..vvs.len()).collect();
    by_size.sort_by_key(|&node| size(&vvs[node]));
    let mut below = vec![vec![false; vvs.len()]; vvs.len()];
    let mut parents = vec![Vec::new(); vvs.len()];
    for (rank, &node) in by_size.iter().enumerate() {
        let mut covered = vec![false; vvs.len()];
        for &earlier in by_size[..rank].iter().rev() {
            if covered[earlier] || !vvs[node].includes_vv(&vvs[earlier]) {
                continue;
            }
            parents[node].push(earlier);
            covered[earlier] = true;
            for (other, &held) in below[earlier].iter().enumerate() {
                covered[other] |= held;
            }
        }
        let mut reach = vec![false; vvs.len()];
        for &parent in &parents[node] {
            reach[parent] = true;
            for (other, &held) in below[parent].iter().enumerate() {
                reach[other] |= held;
            }
        }
        below[node] = reach;
    }
    parents
}
