//! The sweep that re-tags turns saved under an older tagger (ARCH-0036, a
//! named follow-up of serving the tagger). A saved tag set names the tagger
//! that made it in its envelope (ARCH-0035), so once the vault arms another
//! checkpoint, or pins another stack, each turn whose set an earlier tagger
//! made is marked again: the worker tags it with the tagger armed now, and
//! the save replaces the set under the new envelope.

use std::sync::PoisonError;
use std::sync::atomic::Ordering;

use super::coordinator::TaggingReconciler;
use crate::attempt_queue::AttemptQueue;
use crate::error::Result;
use crate::memory::extraction::ExtractionWork;
use crate::ports::EntityStoreRead;
use crate::tagging::marker::{TAGGING_MARKER_KIND, TaggingMode, dedupe_key};
use crate::tagging::tags::made_by_other_tagger_page_in_txn;

/// How many saved tag sets one upkeep reads for the sweep.
const OLDER_SET_SCAN_ROWS: usize = 4096;
/// How many turns one write of the sweep marks.
const OLDER_SET_MARK_BUDGET: usize = 256;

impl TaggingReconciler {
    /// Marks at the bulk class each turn whose readable tag set the armed
    /// tagger did not make, one bounded read a pass until a read reaches the
    /// end, once per reconciler: the armed tagger changes only across a
    /// reopen. A turn already owed a pass by the armed tagger is left as it
    /// is, so a read that finds nothing new commits nothing; the marks go in
    /// bounded writes. A vault in shadow mode saves no tag set, so it has
    /// none to re-tag. `Ok(true)` when `paused` cut it short: the read it did
    /// not finish marking from is read again.
    pub(super) fn mark_older_tag_sets(&self, paused: &dyn Fn() -> bool) -> Result<bool> {
        if self.older_sets_marked.load(Ordering::Acquire) {
            return Ok(false);
        }
        if self.config.mode != TaggingMode::Save {
            self.older_sets_marked.store(true, Ordering::Release);
            return Ok(false);
        }
        if paused() {
            return Ok(true);
        }
        let mut from = self
            .older_sets_from
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (older, next) = {
            let txn = self.vault.store.env.read_txn()?;
            let (found, next) = made_by_other_tagger_page_in_txn(
                &self.vault.store,
                &txn,
                from.as_ref(),
                OLDER_SET_SCAN_ROWS,
                &self.config,
            )?;
            let queue = AttemptQueue::from_store(&self.vault.store);
            let mut older = Vec::with_capacity(found.len());
            for turn in found {
                let owed = queue
                    .pending_dedupe_in_txn(
                        &txn,
                        TAGGING_MARKER_KIND,
                        &dedupe_key(&turn, &self.config),
                    )?
                    .is_some();
                if !owed {
                    older.push(turn);
                }
            }
            (older, next)
        };
        for chunk in older.chunks(OLDER_SET_MARK_BUDGET) {
            if paused() {
                return Ok(true);
            }
            self.vault.with_write_txn_grouped(|txn| {
                for turn in chunk {
                    // A turn erased since the read is not marked.
                    if self.vault.store.port_entity_present(txn, turn)? {
                        crate::tagging::mark_turn_in_txn(
                            &self.vault,
                            txn,
                            *turn,
                            ExtractionWork::Bulk,
                        )?;
                    }
                }
                Ok(())
            })?;
        }
        match next {
            Some(turn) => *from = Some(turn),
            None => self.older_sets_marked.store(true, Ordering::Release),
        }
        Ok(false)
    }
}
