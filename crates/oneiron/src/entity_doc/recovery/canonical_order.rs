//! Core half of `entity_doc::recovery::canonical_order`: its store-layer items live in `oneiron_store::entity_doc::recovery::canonical_order` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::entity_doc::recovery::canonical_order::*;

use super::super::forks::TextReceipt;
use super::super::pins::{CitationPin, PurgeReceipt};
use super::{ForkAt, invalid, raw};
use crate::{Error, Result};
use loro::VersionVector;
use std::collections::BTreeMap;

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
