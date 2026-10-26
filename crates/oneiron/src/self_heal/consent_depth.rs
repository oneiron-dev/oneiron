//! Whole-tray consent queue depth (ARCH-0066 §4, "consent-storm queue
//! depth"; OF-298). The arrival-window storm detector counts the consents
//! proposed inside one tripwire window; this counts every consent the tray
//! still holds, however long ago it was proposed. Its finding goes to the
//! Coach and the owner: it never answers a consent, never limits a proposal
//! and files no repair.

use super::tripwires::{ResolvedTripwireBounds, TripwireBounds, draft, observation};
use super::{
    DeterministicDetector, DiagnosticEvent, DiagnosticEventClass, DiagnosticObservation,
    DiagnosticSourceKind, DiagnosticWorkingSet,
};
use crate::limit_ask::EngineLimit;
use crate::store::PendingGateConsentRecord;
use crate::{EntityId, Result, Vault};
use rmpv::Value;

/// Tray rows one page reads: a traversal unit, never a cut.
const TRAY_PAGE: usize = 256;

/// The observation kind one queued consent reads as.
const QUEUED: &str = "consent_queued";

/// Every pending gate consent the tray held at one read, in tray order.
pub(crate) struct ConsentQueueSnapshot {
    /// When the tray was read.
    pub(crate) snapshot_at: u64,
    /// Every row the tray held then.
    pub(crate) rows: Vec<PendingGateConsentRecord>,
}

impl ConsentQueueSnapshot {
    /// Reads every current tray row in one read transaction, page by page
    /// to the tray's high-water mark at that read.
    pub(crate) fn read(vault: &Vault, snapshot_at: u64) -> Result<Self> {
        let txn = vault.store.env.read_txn()?;
        let fence = vault.store.pending_gate_consents_high_water_in_txn(&txn)?;
        let mut cursor = None;
        let mut rows = Vec::new();
        loop {
            let page = vault
                .store
                .pending_gate_consents_page_in_txn(&txn, cursor, fence, TRAY_PAGE)?;
            let Some((last, _)) = page.last() else {
                break;
            };
            cursor = Some(*last);
            rows.extend(page.into_iter().map(|(_, row)| row));
        }
        Ok(Self { snapshot_at, rows })
    }

    /// One observation per row, by its pending decision, at the time the
    /// row was proposed, in the pinned order. A row whose decision names no
    /// entity, or whose bytes do not encode, makes none.
    pub(crate) fn observations(&self) -> Vec<DiagnosticObservation> {
        let mut observations: Vec<DiagnosticObservation> = self
            .rows
            .iter()
            .filter_map(|row| {
                let decision = EntityId::from_bytes(row.decision_id.as_bytes()).ok()?;
                observation(decision, QUEUED, row.created_at, row)
            })
            .collect();
        observations.sort_by_key(DiagnosticObservation::order_key);
        observations.dedup();
        observations
    }
}

/// Fires once the tray holds at least the policy's `consent_depth` pending
/// consents: one event per snapshot, valid from the snapshot time, carrying
/// the depth and a digest of every row read. Its evidence is the newest row
/// in the pinned order, as the storm detector's is.
pub(crate) struct ConsentQueueDepthDetector {
    /// The resolved tripwire policy; `consent_depth` is the threshold.
    pub(crate) bounds: TripwireBounds,
    /// When the tray was read.
    pub(crate) snapshot_at: u64,
}

impl DeterministicDetector for ConsentQueueDepthDetector {
    fn detector_id(&self) -> &'static str {
        "consent.queue_depth.v1"
    }

    fn detect(&self, input: &DiagnosticWorkingSet<'_>) -> Vec<DiagnosticEvent> {
        if !self.bounds.valid() {
            return vec![];
        }
        let queued: Vec<&DiagnosticObservation> = input
            .observations
            .iter()
            .filter(|o| o.kind == QUEUED)
            .collect();
        let threshold = self.bounds.consent_depth;
        let depth = queued.len() as u64;
        if depth < threshold {
            return vec![];
        }
        let Some(last) = queued.last() else {
            return vec![];
        };
        let mut event = draft(
            self.detector_id(),
            DiagnosticEventClass::ConsentDenied,
            DiagnosticSourceKind::Receipt,
            last,
        );
        event.expected = Value::from(threshold);
        event.actual = Value::from(depth);
        event.delta = Value::from(depth - threshold);
        event.valid_from = self.snapshot_at;
        let mut hash = blake3::Hasher::new();
        for o in &queued {
            hash.update(&o.payload_digest);
        }
        hash.update(&self.snapshot_at.to_be_bytes());
        hash.update(&threshold.to_be_bytes());
        event.replay.content_hash = *hash.finalize().as_bytes();
        vec![event]
    }
}

impl Vault {
    /// Counts the whole current consent tray once against the policy's
    /// consent depth: every pending consent, however long ago it was
    /// proposed, read page by page to the last row, as the signed tier-1
    /// instance. A manifest that forces tripwires closed silences it. Each
    /// finding stored becomes a failure-signal witness once its rows read
    /// again from base; one that does not stays a diagnostic only. Returns
    /// the diagnostics stored.
    pub fn run_pending_consent_depth(&self, scope: &str, now: u64) -> Result<Vec<EntityId>> {
        let Some(policy) = self.resolved_tripwire_bounds()? else {
            return Ok(vec![]);
        };
        self.run_pending_consent_depth_under(scope, now, &policy)
    }

    /// [`Self::run_pending_consent_depth`] under a pass's one resolved
    /// tripwire policy, whose receipt the run signs.
    pub(crate) fn run_pending_consent_depth_under(
        &self,
        scope: &str,
        now: u64,
        policy: &ResolvedTripwireBounds,
    ) -> Result<Vec<EntityId>> {
        let bounds = policy.bounds;
        let snapshot = ConsentQueueSnapshot::read(self, now)?;
        let observations = snapshot.observations();
        let _ = self.measure_limit(EngineLimit::DetectorObservations, observations.len() as u64);
        let ids = super::tripwires::run(
            self,
            scope,
            observations,
            &[&ConsentQueueDepthDetector {
                bounds,
                snapshot_at: snapshot.snapshot_at,
            }],
            Some(&policy.receipt),
        )?;
        self.capture_tier1_consent_queue(&ids, scope, &snapshot, bounds)?;
        Ok(ids)
    }
}
