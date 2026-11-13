//! `vault.revisions.read`'s lane read: each ref's entity view with its
//! live revision, in one snapshot under one receipt.

use super::*;
use crate::vault::RevisionRef;

/// The verb a Grant lists to name a revisions read: the row's own name. This
/// method exists only for that row, so the check names it directly.
const REVISIONS_READ_VERB: &str = "vault.revisions.read";

impl Memory<'_> {
    /// Reads each ref as its entity view with its live revision, in the
    /// lane's snapshot: what `vault.get` shows of the row, plus the LIVE
    /// revision of its record there, so a later reader can tell whether those
    /// words still stand. The caller's live owner Grant naming the verb is
    /// checked in the same snapshot; without one the read is refused. A ref
    /// may pin its row as `<ref>@<revision>` like `vault.hydrate`; the row is
    /// read at the pin but the revision is always the live one, never the
    /// pin. A ref that resolves to nothing, a row the lane withholds, and a
    /// deleted shell answer `None`, exactly like a missing target; the receipt
    /// counts only rows the key could read. Record verbs serve every claim
    /// status, so the lane is `Recorded` as `vault.get` opens it; there is no
    /// status setter.
    pub(crate) fn revisions_read(
        &self,
        refs: &[String],
    ) -> MemoryResult<ScopedReadResult<Vec<Option<(EntityView, Option<RevisionRef>)>>>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let targets = refs
            .iter()
            .map(|reference| match reference.rsplit_once('@') {
                Some((reference, revision)) => self.read_target(
                    reference,
                    ReadMode::Pinned(crate::vault::RevisionRef::from_hex(revision)?),
                ),
                None => self.read_target(reference, ReadMode::Live),
            })
            .collect::<MemoryResult<Vec<_>>>()?;
        lane.read_revisions_projected(&point_reads(&targets), None, |txn, rows| {
            let standing = crate::authority::principal_standing_in_txn(
                self.vault(),
                txn,
                self.actor(),
                self.actor_class(),
                REVISIONS_READ_VERB,
            )?;
            if standing.is_none() {
                return Err(refused());
            }
            let mut slots = rows.into_iter();
            let mut out = Vec::with_capacity(targets.len());
            for target in &targets {
                let slot = match target.map(|(_, mode)| (mode, slots.next())) {
                    Some((mode, Some(Some((row, revision))))) => {
                        match self.slot_view_in(&lane, txn, row, mode, false)? {
                            Some(view) => Some((view, revision)),
                            None => None,
                        }
                    }
                    _ => None,
                };
                out.push(slot);
            }
            Ok::<_, MemoryError>(out)
        })
    }
}

/// The read's refusal of a caller with no live Grant naming the verb.
fn refused() -> MemoryError {
    MemoryError::new(
        crate::memory::MEMORY_CODE_FORBIDDEN,
        format!(
            "{REVISIONS_READ_VERB} takes a live Grant naming the verb: no live Grant from a live owner names this caller and lists the verb"
        ),
        &["Have the owner grant this caller the verb by name."],
    )
}
