//! The host's scheduled T2/T3 pass (ARCH-0066 #tiers, OF-418): which
//! telemetry windows a detector has graded, and the raised T3 findings the
//! owner labels. A window is graded once per detector wording, so a pass that
//! sees it again spends nothing, and a changed prompt or rubric grades it
//! afresh.
use super::tiered::{DetectorPolicy, ProposedTier};
use super::{
    DiagnosticEvent, DiagnosticSourceKind, ENTITY_TYPE_DIAGNOSTIC, decode_diagnostic_event_body,
    validate_token,
};
use crate::side_table::{self, Raw, SideTable};
use crate::store::RetrievalRunRecord;
use crate::{EntityId, Result, Vault};

/// When a detector graded one window. Key: [`detector_window_key`].
const GRADED: SideTable<[u8; 32], u64, Raw> =
    SideTable::new(&side_table::SELF_HEAL_DETECTOR_WINDOW);

/// Diagnostic bodies, and timeline rows, one findings read scans at most.
const FINDINGS_BODIES: usize = 4_096;
const FINDINGS_SCAN: usize = 16_384;
/// Most findings one read returns.
pub const MAX_T3_FINDINGS: usize = 256;

/// One raised T3 finding, newest first, with the owner's label.
#[derive(Clone, Debug)]
pub struct T3Finding {
    pub event_id: EntityId,
    pub learned_at: u64,
    pub event: DiagnosticEvent,
    /// `Some(true)` confirmed, `Some(false)` rejected, `None` not yet labeled.
    pub label: Option<bool>,
}

/// The key of one oldest-first window under one detector wording at one tier.
#[must_use]
pub fn detector_window_key(
    policy: &DetectorPolicy,
    tier: ProposedTier,
    runs: impl IntoIterator<Item = &RetrievalRunRecord>,
) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    for part in [
        tier.token(),
        policy.family.as_str(),
        policy.class.as_str(),
        policy.prompt.as_str(),
        policy.rubric.as_str(),
    ] {
        hash.update(&(part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    hash.update(&(policy.consecutive as u64).to_be_bytes());
    for run in runs {
        hash.update(&run.run_id.as_bytes());
    }
    *hash.finalize().as_bytes()
}

impl Vault {
    /// Whether a detector already graded this window.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn detector_window_graded(&self, key: &[u8; 32]) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        GRADED.contains(&self.store, &txn, key)
    }

    /// Records that a detector graded this window, raised or not. A grade
    /// that failed is not recorded, so the next pass asks again.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn mark_detector_window_graded(&self, key: &[u8; 32], at: u64) -> Result<()> {
        self.with_write_txn_grouped(|txn| GRADED.put(&self.store, txn, key, &at))
    }

    /// Up to `limit` raised `t3.<family>` findings, newest first, each with
    /// the owner's label: the list the owner labels from.
    ///
    /// # Errors
    ///
    /// A family that is not a token, or storage errors.
    pub fn t3_findings(&self, family: &str, limit: usize) -> Result<Vec<T3Finding>> {
        validate_token(family, "detector family is not a token")?;
        let limit = limit.clamp(1, MAX_T3_FINDINGS);
        let detector = format!("t3.{family}");
        let mut findings = Vec::new();
        for (event_id, learned_at, body) in self.latest_entity_bodies_by_type(
            ENTITY_TYPE_DIAGNOSTIC,
            FINDINGS_BODIES,
            FINDINGS_SCAN,
        )? {
            let Ok(event) = decode_diagnostic_event_body(&body) else {
                continue;
            };
            if event.source != DiagnosticSourceKind::RetrievalTelemetry
                || event.detector_id != detector
            {
                continue;
            }
            let label = self.t3_label(family, &event_id)?;
            findings.push(T3Finding {
                event_id,
                learned_at,
                event,
                label,
            });
            if findings.len() == limit {
                break;
            }
        }
        Ok(findings)
    }
}
