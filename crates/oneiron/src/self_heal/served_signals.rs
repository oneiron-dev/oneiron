//! The served degradation signals (ARCH-0066 §4, OF-298): every tier-1
//! tripwire whose facts a serving vault already records, run as one signed
//! pass. Retrieval misses and windowed retrieval regressions read every
//! stored ARCH-0037 run row; MCP boundary refusals read the lasting call
//! receipts. Nothing here repairs: the pass emits diagnostics, and
//! `Vault::propose_tier1_repairs` files every proposed-only repair. Each
//! regression and refusal it stores becomes a failure-signal witness once
//! its rows read again from base (FIX 2449); one that does not stays a
//! diagnostic only.

use super::tripwires::{McpActionRejectedDetector, RetrievalRegressionDetector};
use super::{DiagnosticObservation, TIER1_SWEEP_SCOPE};
use crate::limit_ask::EngineLimit;
use crate::receipt::CallReceipt;
use crate::scan_check::{EngineScan, ScanCount};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// Working-set scope of the retrieval-signal detectors, matching the
/// read-hardening pass so both sign the same runs.
pub const SERVED_RETRIEVAL_SCOPE: &str = "retrieval";
/// How far back one pass reads the call receipts: the nightly cadence.
const SERVED_SPAN_SECS: u64 = 86_400;

/// The call receipt ledger, read in place.
const CALL_RECEIPTS: SideTable<EntityId, CallReceipt, Named> =
    SideTable::new(&side_table::CALL_RECEIPT);

impl Vault {
    /// One pass of the served tier-1 detectors the nightly receipt sweep
    /// does not cover: retrieval misses, the windowed retrieval regression
    /// over degraded runs, and refused MCP calls. Each leg reads its whole
    /// ledger: past a scan's threshold row it raises one check and reads on.
    /// A manifest that forces tripwires closed silences the regression leg;
    /// the miss and MCP legs keep their own doors. Returns every diagnostic
    /// stored, sorted and deduplicated.
    pub fn run_served_signal_detectors(&self, now: u64) -> Result<Vec<EntityId>> {
        let mut ids = self.run_retrieval_miss_detector(SERVED_RETRIEVAL_SCOPE, usize::MAX)?;
        let runs = self.retrieval_runs(usize::MAX)?;
        if let Some(bounds) = self.tripwire_bounds()? {
            let degraded = runs
                .iter()
                .filter_map(DiagnosticObservation::from_retrieval_degradation)
                .collect();
            let regressions = super::tripwires::run(
                self,
                SERVED_RETRIEVAL_SCOPE,
                degraded,
                &[&RetrievalRegressionDetector {
                    bounds,
                    window_end: now,
                }],
            )?;
            self.capture_tier1_served_regression(&regressions, &runs, bounds, now)?;
            ids.extend(regressions);
        }
        let since = now.saturating_sub(SERVED_SPAN_SECS);
        let mut rejected: Vec<DiagnosticObservation> = Vec::new();
        {
            let txn = self.store.env.read_txn()?;
            let mut count = ScanCount::start(&self.store, &txn, EngineScan::CallReceiptRows, &[])?;
            for row in CALL_RECEIPTS.iter_rev_from(&self.store, &txn, &[])? {
                count.row();
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
            count.finish(self);
        }
        let _ = self.measure_limit(EngineLimit::DetectorObservations, rejected.len() as u64);
        let refused = super::tripwires::run(
            self,
            TIER1_SWEEP_SCOPE,
            rejected,
            &[&McpActionRejectedDetector],
        )?;
        self.capture_tier1_point_producer(&refused)?;
        ids.extend(refused);
        ids.sort();
        ids.dedup();
        Ok(ids)
    }
}
