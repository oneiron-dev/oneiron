//! A base view's main-log heads, anchor heads, scope heads and next
//! sequences, carried past the tail (FIX 12307). A fold past the base
//! updates them from its new rows alone, wherever every base row counts in
//! them as it counted in the base's view; otherwise ([`recomputes`]) it
//! computes them over every row, as a full fold does
//! ([`finish_install_fold_of`]).
//!
//! [`finish_install_fold_of`]: crate::authority::install_fold::finish_install_fold_of

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::authority::world_privacy::{side_world, unpinned_anchor_of};

/// What [`finish_install_fold_of`] set on a base's view, and what it read of
/// the base's rows beside their summaries.
///
/// [`finish_install_fold_of`]: crate::authority::install_fold::finish_install_fold_of
pub(super) struct LogHeads {
    append_heads: BTreeSet<AuthorityEntryHash>,
    anchor_heads: BTreeMap<[u8; 32], BTreeSet<AuthorityEntryHash>>,
    append_sequences: BTreeMap<AuthorityKey, u64>,
    scope_heads: BTreeMap<(AuthorityKey, EntityId), (u64, AuthorityEntryHash)>,
    /// The anchor of the view's pin: its rows count as main-log rows.
    pinned_anchor: Option<[u8; 32]>,
    /// The view's anchor rows.
    anchored: BTreeSet<AuthorityEntryHash>,
    /// The rows the base's once fold holds valid and its view does not: the
    /// approvals its stale-roster window expired.
    expired: BTreeSet<AuthorityEntryHash>,
}

impl LogHeads {
    /// What `view` holds, with `expired` the valid entries of its once fold
    /// its stale-roster window took out.
    pub(super) fn of(view: &AuthorityFold, expired: BTreeSet<AuthorityEntryHash>) -> Self {
        Self {
            append_heads: view.append_heads.clone(),
            anchor_heads: view.anchor_heads.clone(),
            append_sequences: view.append_sequences.clone(),
            scope_heads: view.scope_heads.clone(),
            pinned_anchor: view.pinned_root.map(|pin| pin.anchor_key),
            anchored: view.anchor_entries.clone(),
            expired,
        }
    }

    /// The heads of `view`, the view of a fold past the base these are of,
    /// with `new_rows` its new rows and `expired` the approvals its window
    /// expired: these, updated from the new rows alone. Each new row counts
    /// as [`finish_install_fold_of`] counts it, and each head a new row
    /// names drops. None where [`recomputes`] holds.
    ///
    /// [`finish_install_fold_of`]: crate::authority::install_fold::finish_install_fold_of
    pub(super) fn past(
        &self,
        view: &AuthorityFold,
        expired: &BTreeSet<AuthorityEntryHash>,
        new_rows: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
    ) -> Option<Self> {
        if recomputes(self, view, expired, new_rows) {
            return None;
        }
        let mut next = Self {
            append_heads: self.append_heads.clone(),
            anchor_heads: self.anchor_heads.clone(),
            append_sequences: self.append_sequences.clone(),
            scope_heads: self.scope_heads.clone(),
            pinned_anchor: self.pinned_anchor,
            anchored: view.anchor_entries.clone(),
            expired: expired.clone(),
        };
        let mut named = BTreeSet::new();
        let mut own_named = BTreeMap::<[u8; 32], BTreeSet<AuthorityEntryHash>>::new();
        for (hash, entry) in new_rows {
            let signer = entry.signer_key();
            // Every row moves its signer's next sequence, a rejected one too.
            next.append_sequences
                .entry(signer.clone())
                .and_modify(|seq| *seq = (*seq).max(entry.seq))
                .or_insert(entry.seq);
            if !view.valid_entries.contains(hash) {
                continue;
            }
            if let Some(world) = side_world(&entry.op) {
                // The highest sequence, and on a tie the row first in hash
                // order, as the full fold reads the rows.
                let head = next
                    .scope_heads
                    .entry((signer.clone(), world))
                    .or_insert((entry.seq, *hash));
                if entry.seq > head.0 || (entry.seq == head.0 && *hash < head.1) {
                    *head = (entry.seq, *hash);
                }
                continue;
            }
            let parents = entry.parent_hashes.iter().copied();
            match unpinned_anchor_of(signer, hash, &view.anchor_entries, self.pinned_anchor) {
                Some(anchor) => {
                    next.anchor_heads.entry(anchor).or_default().insert(*hash);
                    own_named.entry(anchor).or_default().extend(parents);
                }
                None => {
                    next.append_heads.insert(*hash);
                    named.extend(parents);
                }
            }
        }
        for hash in &named {
            next.append_heads.remove(hash);
        }
        next.anchor_heads.retain(|anchor, heads| {
            let own = own_named.get(anchor);
            heads
                .retain(|hash| !named.contains(hash) && !own.is_some_and(|own| own.contains(hash)));
            !heads.is_empty()
        });
        Some(next)
    }

    /// Sets `view`'s heads, scope heads and next sequences to these.
    pub(super) fn set_on(&self, view: &mut AuthorityFold) {
        view.append_heads = self.append_heads.clone();
        view.anchor_heads = self.anchor_heads.clone();
        view.append_sequences = self.append_sequences.clone();
        view.scope_heads = self.scope_heads.clone();
    }
}

/// Whether a fold past a base computes its view's heads, scope heads and
/// next sequences over every row, as a full fold does, rather than update
/// the base's from its new rows. It does wherever a base row might count in
/// them otherwise than in the base's view:
///
/// - the view's pin names another anchor than the base's view did (or one
///   where it named none, or none where it named one), so another anchor's
///   rows count as main-log rows;
/// - the view holds another set of base rows as anchor rows;
/// - its stale-roster window expired another set of base rows than the base
///   view's did. The base rows its once fold holds valid are the base once
///   fold's, so another set of them would be valid.
///
/// Nothing else of a base row is read: its signer, sequence, parents and
/// world are its summary's, and no base row names a new row (a fold past
/// the base declines a new row a judged row names,
/// [`side_tail::fold_tail`](super::side_tail::fold_tail)).
fn recomputes(
    base: &LogHeads,
    view: &AuthorityFold,
    expired: &BTreeSet<AuthorityEntryHash>,
    new_rows: &BTreeMap<AuthorityEntryHash, &AuthorityLogEntry>,
) -> bool {
    let of_base = |hash: &&AuthorityEntryHash| !new_rows.contains_key(*hash);
    view.pinned_root.map(|pin| pin.anchor_key) != base.pinned_anchor
        || !view
            .anchor_entries
            .iter()
            .filter(of_base)
            .eq(base.anchored.iter())
        || !expired.iter().filter(of_base).eq(base.expired.iter())
}
