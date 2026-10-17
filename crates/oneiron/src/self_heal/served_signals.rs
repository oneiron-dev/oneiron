//! The served degradation signals (ARCH-0066 §4, OF-298): every tier-1
//! tripwire whose facts a serving vault already records, run as one bounded
//! signed pass. Retrieval misses and windowed retrieval regressions read
//! the stored ARCH-0037 run rows; MCP boundary refusals read the lasting
//! call receipts. Nothing here repairs: the pass emits diagnostics, and
//! `Vault::propose_tier1_repairs` files the bounded proposed-only repairs.

use super::tripwires::{McpActionRejectedDetector, RetrievalRegressionDetector};
use super::{DiagnosticObservation, MAX_EVENTS_PER_RUN, TIER1_SWEEP_SCOPE};
use crate::receipt::CallReceipt;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// Working-set scope of the retrieval-signal detectors, matching the
/// read-hardening pass so both sign the same runs.
pub const SERVED_RETRIEVAL_SCOPE: &str = "retrieval";
/// Retrieval runs one pass reads, newest first.
const SERVED_RUNS: usize = MAX_EVENTS_PER_RUN;
/// Call receipts one pass scans at most.
const CALL_SCAN: usize = 8_192;
/// How far back one pass reads the call receipts: the nightly cadence.
const SERVED_SPAN_SECS: u64 = 86_400;

/// The call receipt ledger, read in place.
const CALL_RECEIPTS: SideTable<EntityId, CallReceipt, Named> =
    SideTable::new(&side_table::CALL_RECEIPT);

impl Vault {
    /// One bounded pass of the served tier-1 detectors the nightly receipt
    /// sweep does not cover: retrieval misses, the windowed retrieval
    /// regression over degraded runs, and refused MCP calls. A manifest
    /// that forces tripwires closed silences the regression leg; the miss
    /// and MCP legs keep their own doors. Returns every diagnostic stored,
    /// sorted and deduplicated.
    pub fn run_served_signal_detectors(&self, now: u64) -> Result<Vec<EntityId>> {
        let mut ids = self.run_retrieval_miss_detector(SERVED_RETRIEVAL_SCOPE, SERVED_RUNS)?;
        let runs = self.retrieval_runs(SERVED_RUNS)?;
        if let Some(bounds) = self.tripwire_bounds()? {
            let degraded = runs
                .iter()
                .filter_map(DiagnosticObservation::from_retrieval_degradation)
                .collect();
            ids.extend(super::tripwires::run(
                self,
                SERVED_RETRIEVAL_SCOPE,
                degraded,
                &[&RetrievalRegressionDetector {
                    bounds,
                    window_end: now,
                }],
            )?);
        }
        let since = now.saturating_sub(SERVED_SPAN_SECS);
        let mut rejected: Vec<DiagnosticObservation> = Vec::new();
        {
            let txn = self.store.env.read_txn()?;
            for row in CALL_RECEIPTS
                .iter_rev_from(&self.store, &txn, &[])?
                .take(CALL_SCAN)
            {
                let Ok((id, receipt)) = row else {
                    continue;
                };
                if receipt.at <= since || receipt.at > now {
                    continue;
                }
                if let Some(observation) =
                    DiagnosticObservation::from_mcp_call_receipt(id, &receipt)
                {
                    rejected.push(observation);
                }
            }
        }
        if rejected.len() > MAX_EVENTS_PER_RUN {
            rejected.sort_by_key(DiagnosticObservation::order_key);
            rejected.dedup();
            let excess = rejected.len().saturating_sub(MAX_EVENTS_PER_RUN);
            rejected.drain(..excess);
        }
        ids.extend(super::tripwires::run(
            self,
            TIER1_SWEEP_SCOPE,
            rejected,
            &[&McpActionRejectedDetector],
        )?);
        ids.sort();
        ids.dedup();
        Ok(ids)
    }
}
