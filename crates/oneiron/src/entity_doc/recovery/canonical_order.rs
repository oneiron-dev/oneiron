//! The canonical index of each captured version. Two concurrent versions with
//! the same parents, text and metadata stay two versions (FIX 9850): the rows
//! that name each one (its pins, receipts, fork bases and purges, by their
//! own ids) tell them apart, as every capture of those rows does again.

use std::collections::BTreeMap;

use loro::VersionVector;

use super::super::forks::TextReceipt;
use super::super::pins::{CitationPin, PurgeReceipt};
use super::{ForkAt, invalid, raw};
use crate::{Error, Result};

/// A pin naming a version.
const PIN: u8 = 0;
/// A settlement receipt naming its before (role 0) or after (role 1) version.
const RECEIPT: u8 = 1;
/// A fork naming its base.
const FORK: u8 = 2;
/// A purge receipt naming its requested (role 0) or applied (role 1) version.
const PURGE: u8 = 3;

/// The rows naming one captured version, in order: each by its kind, its own
/// id and the role it names the version in. No two versions share one: a row
/// names one version in each role.
pub(super) type Names = Vec<(u8, [u8; 16], u8)>;

/// The rows naming each of `len` captured versions. The live head and a purge
/// floor may have none: neither is ever concurrent with another version.
pub(super) fn names(
    len: usize,
    pins: &[(CitationPin, usize, usize, usize)],
    receipts: &[(TextReceipt, usize, usize)],
    forks: &[ForkAt],
    purges: &[(PurgeReceipt, usize, usize)],
) -> Result<Vec<Names>> {
    let mut names = vec![Names::new(); len];
    for (pin, node, _, _) in pins {
        names[*node].push((PIN, raw(&pin.citation)?, 0));
    }
    for (receipt, before, after) in receipts {
        let id = raw(&receipt.receipt)?;
        names[*before].push((RECEIPT, id, 0));
        names[*after].push((RECEIPT, id, 1));
    }
    for fork in forks {
        if let Some(base) = fork.base {
            names[base].push((FORK, raw(&fork.record.fork)?, 0));
        }
    }
    for (purge, requested, applied) in purges {
        let id = raw(&purge.receipt)?;
        names[*requested].push((PURGE, id, 0));
        names[*applied].push((PURGE, id, 1));
    }
    for named in &mut names {
        named.sort_unstable();
    }
    Ok(names)
}

/// Each version's direct predecessors among the captured versions: the
/// maximal ones its version vector includes. A strictly later version holds
/// strictly more operations, so walking down by size meets every cover first.
pub(super) fn hasse(vvs: &[VersionVector]) -> Vec<Vec<usize>> {
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

/// The canonical index of every version: a topological order that takes,
/// among the ready versions, the least by (parent indices, text, metadata,
/// the rows naming it). The same causal shape, texts and naming rows give
/// the same order on every capture, including the recapture of a replayed
/// document, so two versions equal in all but their naming rows keep each
/// row on its own version (FIX 9850).
pub(super) fn canonical_order(
    parents: &[Vec<usize>],
    texts: &[String],
    metadata: &[BTreeMap<String, Vec<u8>>],
    names: &[Names],
) -> Result<Vec<usize>> {
    let mut order = vec![usize::MAX; parents.len()];
    for index in 0..parents.len() {
        let mut best: Option<(Vec<usize>, usize)> = None;
        let mut tied = false;
        for node in 0..parents.len() {
            if order[node] != usize::MAX || parents[node].iter().any(|&p| order[p] == usize::MAX) {
                continue;
            }
            let mut key: Vec<usize> = parents[node].iter().map(|&p| order[p]).collect();
            key.sort_unstable();
            let ordering = best.as_ref().map(|(known, other)| {
                (&key, &texts[node], &metadata[node], &names[node]).cmp(&(
                    known,
                    &texts[*other],
                    &metadata[*other],
                    &names[*other],
                ))
            });
            match ordering {
                None | Some(std::cmp::Ordering::Less) => {
                    best = Some((key, node));
                    tied = false;
                }
                Some(std::cmp::Ordering::Equal) => tied = true,
                Some(std::cmp::Ordering::Greater) => {}
            }
        }
        // Distinct versions differ at least in their naming rows; an equal
        // pair is no capture of one document.
        if tied {
            return Err(invalid("entity document versions are indistinguishable"));
        }
        let (_, node) = best.ok_or(Error::InvariantViolation("cyclic document versions"))?;
        order[node] = index;
    }
    Ok(order)
}
