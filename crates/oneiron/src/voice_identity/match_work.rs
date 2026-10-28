//! Residual clustering in bounded pair tiles over one union-find (FIX 10216).
//! Entry: cluster_residual_tiles.
//!
//! A match of any size is clustered whole: no segment count refuses it. The
//! pairs are compared one bounded tile at a time, and every tile joins the
//! same union-find over all the residual segments, so a link found in any
//! tile joins its two clusters however far apart their segments sit, and the
//! clusters are the connected components of the whole "cosine at or above
//! threshold" graph. Each component's root is its earliest member, whatever
//! order the tiles ran in, so the labels are the ones a single pass gives.
//! No clock is read here: a caller that paces its work steps the tiles.

use std::collections::BTreeMap;

use super::math_keys::cosine_similarity;
use crate::error::Result;

/// Segments per side of one tile: one tile compares at most this many
/// squared pairs.
const TILE: usize = 256;

/// One residual clustering in progress: the one union-find over every
/// residual segment, and the next tile to compare.
pub(super) struct VoiceMatchWork<'a> {
    vectors: &'a [&'a [f32]],
    threshold: f32,
    parent: Vec<usize>,
    /// The next tile's row block and column block starts.
    next: (usize, usize),
}

impl<'a> VoiceMatchWork<'a> {
    pub(super) fn new(vectors: &'a [&'a [f32]], threshold: f32) -> Self {
        Self {
            vectors,
            threshold,
            parent: (0..vectors.len()).collect(),
            next: (0, 0),
        }
    }

    /// Compares one tile of pairs and joins each linked pair; `false` once
    /// every pair has been compared.
    pub(super) fn step(&mut self) -> Result<bool> {
        let count = self.vectors.len();
        let (rows, columns) = self.next;
        if rows >= count {
            return Ok(false);
        }
        for left in rows..(rows + TILE).min(count) {
            for right in columns.max(left + 1)..(columns + TILE).min(count) {
                if cosine_similarity(self.vectors[left], self.vectors[right])? >= self.threshold {
                    self.join(left, right);
                }
            }
        }
        self.next = if columns + TILE < count {
            (rows, columns + TILE)
        } else {
            (rows + TILE, rows + TILE)
        };
        Ok(self.next.0 < count)
    }

    fn find(&mut self, mut node: usize) -> usize {
        while self.parent[node] != node {
            self.parent[node] = self.parent[self.parent[node]];
            node = self.parent[node];
        }
        node
    }

    /// Joins two clusters under the lower root, so a root is always its
    /// component's earliest member.
    fn join(&mut self, left: usize, right: usize) {
        let (root_left, root_right) = (self.find(left), self.find(right));
        if root_left != root_right {
            let (low, high) = if root_left < root_right {
                (root_left, root_right)
            } else {
                (root_right, root_left)
            };
            self.parent[high] = low;
        }
    }

    /// The clusters, each in segment order, ordered by earliest member.
    pub(super) fn clusters(mut self) -> Vec<Vec<usize>> {
        let mut clusters: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for index in 0..self.vectors.len() {
            let root = self.find(index);
            clusters.entry(root).or_default().push(index);
        }
        clusters.into_values().collect()
    }
}

/// Law 6 over every residual segment: single-linkage clusters at
/// `residual_threshold`, computed tile by tile.
pub(super) fn cluster_residual_tiles(
    vectors: &[&[f32]],
    residual_threshold: f32,
) -> Result<Vec<Vec<usize>>> {
    let mut work = VoiceMatchWork::new(vectors, residual_threshold);
    while work.step()? {}
    Ok(work.clusters())
}
