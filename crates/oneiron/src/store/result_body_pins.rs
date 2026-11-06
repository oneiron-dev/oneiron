//! Core half of `store::result_body_pins`: its store-layer items live in `oneiron_store::result_body_pins` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::result_body_pins::*;

use std::collections::HashMap;
use std::collections::VecDeque;
use std::collections::hash_map::Entry;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

impl crate::Vault {
    /// Pins the result body `digest`: until the pin drops, the collector
    /// leaves its row and file alone. A reader takes it before the read
    /// transaction that finds the body's row and holds it until the file is
    /// closed.
    pub(crate) fn pin_result_body(&self, digest: [u8; 32]) -> ResultBodyPin {
        self.result_body_pins.pin(Some(digest))
    }

    /// [`Self::pin_result_body`] for a body an off-record promotion brought
    /// in as the vault instance `instance`, before the save transaction
    /// that names it opened: that transaction reads the instance while the
    /// pin is held (KS-2A).
    pub(crate) fn pin_promoted_result_body(
        &self,
        digest: [u8; 32],
        instance: [u8; 16],
    ) -> ResultBodyPin {
        let pin = self.result_body_pins.pin(Some(digest));
        lock(&self.result_body_pins.counts)
            .promoted
            .insert(digest, instance);
        pin
    }

    /// Pins every result body at once, for a reader that finds its bodies
    /// inside its read transaction (a checkpoint snapshot, an export). Taken
    /// before that transaction opens, held until its last file is closed.
    pub(crate) fn pin_all_result_bodies(&self) -> ResultBodyPin {
        self.result_body_pins.pin(None)
    }

    /// Notes the scan-bound search credit issued for the window (`digest`,
    /// `base`, `len`): the exact emitted (`offset`, `line`, `credit`), kept
    /// in memory on this handle only (FIX 1189 discount, #4311 P1-B).
    pub(crate) fn note_search_credit(
        &self,
        digest: [u8; 32],
        base: u64,
        len: u64,
        offset: u64,
        line: u64,
        credit: u64,
    ) {
        self.result_body_pins
            .note_search_credit(digest, base, len, offset, line, credit);
    }

    /// Whether (`offset`, `line`, `credit`) is the credit this handle last
    /// issued for the window (`digest`, `base`, `len`): the full tuple must
    /// match, else the resume takes no discount.
    pub(crate) fn valid_search_credit(
        &self,
        digest: [u8; 32],
        base: u64,
        len: u64,
        offset: u64,
        line: u64,
        credit: u64,
    ) -> bool {
        self.result_body_pins
            .valid_search_credit(digest, base, len, offset, line, credit)
    }
}

impl crate::Vault {
    /// Notes a detached line-index rebuild for the body `digest`, `len` bytes
    /// long (FIX 1186b): a read whose lookup found no index calls this and
    /// scans as today. Insert-if-absent, whether queued or in flight, so a
    /// read during an in-flight rebuild is a no-op; only the sweep requeues
    /// a failure.
    pub(crate) fn note_body_line_index_rebuild(&self, digest: [u8; 32], len: u64) {
        lock(&self.result_body_pins.counts)
            .rebuild
            .entry(digest)
            .or_insert(RebuildEntry {
                len,
                in_flight: false,
            });
    }

    /// Begins up to `limit` queued rebuilds, marking them in flight without
    /// removing them: the sweep's in-flight set, one per body per handle.
    /// Entries already in flight stay out, so concurrent notes never double
    /// a body.
    pub(crate) fn begin_body_line_index_rebuilds(&self, limit: usize) -> Vec<([u8; 32], u64)> {
        let mut counts = lock(&self.result_body_pins.counts);
        let mut begun = Vec::new();
        for (digest, entry) in counts.rebuild.iter_mut() {
            if begun.len() >= limit {
                break;
            }
            if !entry.in_flight {
                entry.in_flight = true;
                begun.push((*digest, entry.len));
            }
        }
        begun
    }

    /// Finishes the rebuild for `digest`, after a rebuilt index or a terminal
    /// drop (already fixed, inline, gone): removes it, whether queued or in
    /// flight.
    pub(crate) fn finish_body_line_index_rebuild(&self, digest: &[u8; 32]) {
        lock(&self.result_body_pins.counts).rebuild.remove(digest);
    }

    /// Requeues the rebuild for `digest` after a failure, marking it queued
    /// again for the next sweep. A digest already finished stays finished.
    pub(crate) fn retry_body_line_index_rebuild(&self, digest: &[u8; 32]) {
        if let Some(entry) = lock(&self.result_body_pins.counts).rebuild.get_mut(digest) {
            entry.in_flight = false;
        }
    }

    /// Whether any rebuild waits queued (not in flight).
    pub(crate) fn has_queued_body_line_index_rebuilds(&self) -> bool {
        lock(&self.result_body_pins.counts)
            .rebuild
            .values()
            .any(|entry| !entry.in_flight)
    }
}
