//! What an engine commit export stands on (FIX 6869, G4 PR3): the shared
//! load the exporter and the exact preview both read, so the preview can
//! never drift from the export's own eligibility.
//!
//! The load rechecks the finalized fold trace, the promotion, the canonical
//! authorship and message, the active provenance and the live author, in
//! the order the exporter always judged them. The exporter reads the
//! immutable stored promotion and refuses at the first gap, as before. The
//! preview reads readiness instead: the stored receipt when it holds, else
//! the queue's own read-only gap, and it names each gap rather than
//! refusing. Nothing here writes a promotion or any other row.
use crate::code_commit_metadata::CodeCommitMetadata;
use crate::code_promotion_gap::QueuePromotionGap;
use crate::repo_provenance_trailer::REPO_PROVENANCE_TRAILER_KEY;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::claim::ClaimLifecycleStatus;
use oneiron_contracts::entity_id::EntityId;

/// How a load judges the revision's promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportPromotion {
    /// The export: the immutable stored receipt, judged again; a missing
    /// or differing one refuses.
    Stored,
    /// The preview: the stored receipt when it holds, otherwise whether
    /// the chain can be promoted now, read only. A gap is named.
    Readiness,
}

/// A source the preview's load found missing; the export refuses on each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportGap {
    /// The chain's root holds untouched bytes no reviewed import admits now.
    UntouchedBytes(String),
    /// A change lacks its admitted reviewed operation, or an ordinary
    /// revision its promotion.
    Unreviewed(String),
    /// The provenance claim is gone or no longer active.
    Provenance(EntityId),
    /// The author's record is gone; `None` when the author was erased
    /// before the seal (FIX 7348).
    Author(Option<EntityId>),
}

/// The exported commit's message: the canonical message with the
/// revision's provenance trailer, which the message must not supply itself.
///
/// # Errors
/// A message that already carries a provenance trailer.
pub fn export_message(metadata: &CodeCommitMetadata, provenance: EntityId) -> Result<String> {
    if crate::repo_provenance_trailer::parse_repo_provenance_trailer(&metadata.message)?.is_some() {
        return Err(Error::InvariantViolation(
            "export message must not supply its own provenance trailer",
        ));
    }
    Ok(format!(
        "{}\n\n{REPO_PROVENANCE_TRAILER_KEY}: {}\n",
        metadata.message.trim_end(),
        provenance.to_hex()
    ))
}
