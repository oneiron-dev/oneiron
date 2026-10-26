//! A fold's lineages judged from the oldest up (rule 5, FIX 9436). A signed
//! state's judgement asks its parent's verdict first, so a long lineage once
//! nested one native frame per state, and a depth guard quarantined a deep
//! one. Before a verdict is judged, its chain of parents is found the way
//! `judge` reaches them, each state only while every check its judgement
//! makes before it asks its parent passes, and judged from the oldest up:
//! each meets its parent's verdict already kept, and the verdict asked for
//! nests one state deep. Nothing else changes: the same states are judged,
//! with the same checks, results, errors and visits, and a state no
//! judgement would reach is never judged. The lineage's depth is counted
//! against [`EngineScan::ProjectFoldDepth`] for the project; a crossing
//! raises a check and the fold reads on.
use super::*;
use crate::scan_check::{EngineScan, ScanCount};

impl FoldCx<'_, '_, '_> {
    /// Judges `hash`'s chain of parents, oldest first, before `hash` itself
    /// is judged. A judgement that fails ends the settling; the verdict
    /// asked for meets that failure where it always did.
    pub(super) fn settle_lineage(&self, hash: ProjectRevisionHash) {
        let mut chain = Vec::new();
        let mut seen = BTreeSet::new();
        let mut next = Some(hash);
        while let Some(at) = next {
            if self.verdicts.borrow().contains_key(&at) || !seen.insert(at) {
                break;
            }
            chain.push(at);
            next = self.parent_asked(at);
        }
        self.count_depth(chain.len().saturating_sub(1));
        for at in chain.iter().skip(1).rev() {
            if self.verdict_once(*at, false).is_err() {
                break;
            }
        }
    }

    /// The parent the judgement of the signed state `hash` asks for first:
    /// `None` when the row is not a signed state over a parent, or a check
    /// its judgement makes before that ask ends it, as `judge` and `signed`
    /// make them.
    fn parent_asked(&self, hash: ProjectRevisionHash) -> Option<ProjectRevisionHash> {
        let row = self.row(&hash)?;
        let ProjectRevision::Signed {
            authority,
            parent: Some(parent),
            ..
        } = row
        else {
            return None;
        };
        if self.sealed_off(hash, row).ok()?
            || self.origin(hash).ok()? != RevisionOrigin::Authenticated
            || !well_formed(self.id, authority)
            || (authority.parents.is_empty() && Some(self.id) != self.reader.root())
        {
            return None;
        }
        Some(*parent)
    }

    /// Counts a lineage `depth` states below the verdict asked for, once it
    /// is the deepest this fold met.
    fn count_depth(&self, depth: usize) {
        if depth <= self.deepest.get() {
            return;
        }
        self.deepest.set(depth);
        let store = self.reader.store();
        match ScanCount::start(
            store,
            self.reader.txn(),
            EngineScan::ProjectFoldDepth,
            self.id.as_bytes(),
        ) {
            Ok(mut count) => {
                count.rows(depth);
                count.defer(store);
            }
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "project fold depth was not counted");
            }
        }
    }
}
