//! The host's scheduled T2/T3 pass (ARCH-0066 #tiers, OF-418): which
//! telemetry windows a detector has graded, and the raised T3 findings the
//! owner labels. A window is graded once per detector wording, so a pass that
//! sees it again spends nothing, and a changed prompt or rubric grades it
//! afresh.
use super::tiered::{DetectorPolicy, ProposedTier};
use super::{
    CentroidCorpus, DiagnosticEvent, DiagnosticSourceKind, ENTITY_TYPE_DIAGNOSTIC,
    decode_diagnostic_event_body, validate_token,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::side_table::{self, Raw, SideTable};
use crate::store::RetrievalRunRecord;
use crate::{EntityId, Result, Vault};
use oneiron_contracts::fingerprint::{LegacyDigest, purposes};

/// When a detector graded one window. Key: [`detector_window_key`].
const GRADED: SideTable<[u8; 32], u64, Raw> =
    SideTable::new(&side_table::SELF_HEAL_DETECTOR_WINDOW);

/// Diagnostic ids one page of a findings read reads; the read pages on to
/// the last diagnostic (OF-418 L5).
const FINDINGS_PAGE: usize = 256;
/// Findings one read returns when its caller names no count: every one.
pub const MAX_T3_FINDINGS: usize = usize::MAX;

/// One raised T3 finding, newest first, with the owner's label.
#[derive(Clone, Debug)]
pub struct T3Finding {
    pub event_id: EntityId,
    pub learned_at: u64,
    pub event: DiagnosticEvent,
    /// `Some(true)` confirmed, `Some(false)` rejected, `None` not yet labeled.
    pub label: Option<bool>,
}

/// The key of one oldest-first window under one detector wording at one tier
/// (`purposes::self_heal::DETECTOR_WINDOW`).
#[must_use]
pub fn detector_window_key(
    policy: &DetectorPolicy,
    tier: ProposedTier,
    runs: &[&RetrievalRunRecord],
) -> [u8; 32] {
    let mut hash = LegacyDigest::new(purposes::self_heal::DETECTOR_WINDOW);
    for part in [
        tier.token(),
        policy.family.as_str(),
        policy.class.as_str(),
        policy.prompt.as_str(),
        policy.rubric.as_str(),
    ] {
        hash.len_u64_be(part.len()).raw(part.as_bytes());
    }
    hash.raw(&(policy.consecutive as u64).to_be_bytes());
    for run in runs {
        hash.raw(&run.run_id.as_bytes());
    }
    hash.finish()
}

/// The key of one window under a registered T2: its seed's wording at T2b and
/// the corpus revision it asks with, so a new revision grades it afresh
/// (`purposes::self_heal::MINTED_WINDOW`).
#[must_use]
pub fn minted_window_key(
    policy: &DetectorPolicy,
    revision: &[u8; 32],
    runs: &[&RetrievalRunRecord],
) -> [u8; 32] {
    LegacyDigest::new(purposes::self_heal::MINTED_WINDOW)
        .raw(&detector_window_key(
            policy,
            ProposedTier::PromptClassifier,
            runs,
        ))
        .raw(revision)
        .finish()
}

/// The key of one T2 window once a T2a corpus is in force (FIX 2078): its
/// T2b key with the corpus's revision, which folds in the labels, their
/// vectors and the threshold, so a window graded before a label or vector
/// existed is graded afresh. An empty corpus runs no T2a and keeps the key.
#[must_use]
pub fn centroid_window_key(key: &[u8; 32], corpus: &CentroidCorpus) -> [u8; 32] {
    let Some(revision) = corpus.revision() else {
        return *key;
    };
    centroid_revision_key(key, revision)
}

/// [`centroid_window_key`] once the corpus has a revision
/// (`purposes::self_heal::CENTROID_WINDOW`).
fn centroid_revision_key(key: &[u8; 32], revision: &[u8; 32]) -> [u8; 32] {
    LegacyDigest::new(purposes::self_heal::CENTROID_WINDOW)
        .raw(ProposedTier::Centroid.token().as_bytes())
        .raw(key)
        .raw(revision)
        .finish()
}

/// [`centroid_revision_key`] for the K door
/// (`test_doors::fingerprint_keep_self_heal_digests`). Not API.
#[cfg(oneiron_test_support)]
pub(crate) fn centroid_revision_key_for_test(key: &[u8; 32], revision: &[u8; 32]) -> [u8; 32] {
    centroid_revision_key(key, revision)
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

    /// The newest `limit` raised `t3.<family>` findings, each with the
    /// owner's label: the list the owner labels from. Every diagnostic is
    /// read, a page at a time to the last, so an old finding is never out of
    /// reach; [`MAX_T3_FINDINGS`] returns them all, newest first.
    ///
    /// # Errors
    ///
    /// A family that is not a token, or storage errors.
    pub fn t3_findings(&self, family: &str, limit: usize) -> Result<Vec<T3Finding>> {
        validate_token(family, "detector family is not a token")?;
        let detector = format!("t3.{family}");
        let mut findings = Vec::new();
        let mut after = None;
        loop {
            let page =
                self.entities_by_type_page(ENTITY_TYPE_DIAGNOSTIC, after.as_ref(), FINDINGS_PAGE)?;
            for event_id in &page {
                let Some(raw) = self.get_raw(event_id)? else {
                    continue;
                };
                let Some(header) = EntityMetadataHeader::parse(&raw) else {
                    continue;
                };
                if header.entity_type != ENTITY_TYPE_DIAGNOSTIC
                    || raw.len() <= ENTITY_METADATA_HEADER_LEN
                {
                    continue;
                }
                let Ok(event) = decode_diagnostic_event_body(&raw[ENTITY_METADATA_HEADER_LEN..])
                else {
                    continue;
                };
                if event.source != DiagnosticSourceKind::RetrievalTelemetry
                    || event.detector_id != detector
                {
                    continue;
                }
                let label = self.t3_label(family, event_id)?;
                findings.push(T3Finding {
                    event_id: *event_id,
                    learned_at: header.learned_at,
                    event,
                    label,
                });
            }
            if page.len() < FINDINGS_PAGE {
                break;
            }
            after = page.last().copied();
        }
        findings.sort_by_key(|finding| std::cmp::Reverse((finding.learned_at, finding.event_id)));
        findings.truncate(limit.max(1));
        Ok(findings)
    }
}
