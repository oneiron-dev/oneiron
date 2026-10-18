//! Typed claim-citing brief authoring over the existing NOTE pin and write doors.

use crate::EntityId;
use crate::claim::{ClaimReadStatus, PointRead};
use crate::memory::{EntityRefReceipt, Memory, MemoryError, MemoryResult};
use serde::{Deserialize, Serialize};

/// A source span for a load-bearing sentence in the authored markdown.
/// Offsets are half-open Unicode scalar indices in the source NOTE's live text.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BriefClaimCitation {
    /// The supporting CLAIM's 32-hex id.
    pub claim_ref: String,
    /// The quoted source NOTE's 32-hex id.
    pub document_ref: String,
    pub start: usize,
    pub end: usize,
}

/// Authored markdown, with supporting claim citations for each load-bearing
/// sentence. The engine captures the source frontier, cursors and quote hash;
/// no caller-supplied quote or rendered HTML is stored.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorBriefRequest {
    pub markdown: String,
    pub citations: Vec<BriefClaimCitation>,
}

/// The person-stamped policy seed. It grants no sharing or extraction authority.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BriefKindStamp {
    pub person_ref: String,
    pub extraction: super::NoteExtractionDefault,
    pub context: super::NoteContextDefault,
    pub retention: super::NoteRetentionDefault,
}

impl From<super::BriefKindContract> for BriefKindStamp {
    fn from(contract: super::BriefKindContract) -> Self {
        Self {
            person_ref: contract.person().to_hex(),
            extraction: contract.extraction,
            context: contract.context,
            retention: contract.retention,
        }
    }
}

impl Memory<'_> {
    /// Capture pins in the caller's scoped read snapshot, then let the existing
    /// brief writer recheck their source versions and live read authority in
    /// the transaction that writes the brief.
    pub fn author_citing_brief(&self, input: &AuthorBriefRequest) -> MemoryResult<EntityRefReceipt> {
        let id = |value: &str| {
            EntityId::from_hex(value)
                .map_err(|_| MemoryError::bad_request("brief citations require 32-hex entity ids"))
        };
        let sources = input
            .citations
            .iter()
            .map(|citation| Ok((id(&citation.claim_ref)?, id(&citation.document_ref)?)))
            .collect::<MemoryResult<Vec<_>>>()?;
        let reads: Vec<_> = sources
            .iter()
            .flat_map(|(claim, document)| [PointRead::id(*claim), PointRead::id(*document)])
            .collect();
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let pins = lane.read_projected(&reads, None, |txn, rows| {
            if rows
                .iter()
                .any(|row| row.as_ref().is_none_or(|row| row.body.is_none()))
            {
                return Err(MemoryError::not_found(
                    "brief citation source does not resolve",
                ));
            }
            sources
                .iter()
                .zip(&input.citations)
                .map(|((claim, document), citation)| {
                    Ok(self.vault().pin_note_span_in_txn(
                        txn,
                        *document,
                        *claim,
                        citation.start,
                        citation.end,
                    )?)
                })
                .collect::<MemoryResult<Vec<_>>>()
        })?;
        self.author_brief(input.markdown.clone(), &pins.value)
    }
}
