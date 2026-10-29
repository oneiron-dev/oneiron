//! The one endpoint ref every lane writes: the retained document an end of a
//! measured window lives in, and the version there (FIX 7819, 9799).
//!
//! Each kind also names how the measured content is read there, so a
//! measurement recomputes from its refs alone. An entity end always names a
//! retained revision: without one there is no endpoint, and the capture is
//! unavailable rather than versionless.

use serde::{Deserialize, Serialize};

use crate::edit_distance::{LoroOpRef, ProposalArtifactRef};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::vault::entity_revision::{ReadMode, RevisionRef, revision_for_mode_in_txn};

/// The retained source one end of a measured window lives in, and how its
/// content is read there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointDocument {
    /// A finalized proposal artifact's retained Loro document (ED-00): the
    /// body text at a frontier. By artifact id hex.
    ProposalArtifact(String),
    /// The proposed text an endpoint-only settlement retained under its own
    /// record. By record id hex.
    ImportedProposed(String),
    /// The final text an endpoint-only settlement retained under its own
    /// record. By record id hex.
    ImportedFinal(String),
    /// A claim's body at a retained revision, read with its approval set to
    /// Approved and re-encoded: the inbox measures the decider's edit, not
    /// the approval flip it performs. By claim id hex.
    ApprovedClaim(String),
    /// An identity-topology event at a retained revision, its applied op
    /// encoded as an amendment body. By event id hex.
    IdentityOpProposal(String),
    /// A proposal-outcome receipt's `amended_body` field. By receipt id.
    ReceiptAmendedBody(String),
}

/// One end of a measured window: the document it lives in and the version
/// there, so the measurement recomputes from the refs alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRef {
    /// The retained document this end lives in.
    pub document: EndpointDocument,
    /// The version there: encoded Loro `Frontiers` hex in a proposal
    /// artifact, a [`RevisionRef`] hex in an entity. `None` for a retained
    /// imported text or a receipt field, each of which holds one version.
    pub frontier: Option<String>,
    /// blake3 hex of the content the lane measured at this end: a check
    /// value beside the pointer, never the pointer.
    pub content_hash: Option<String>,
}

impl EndpointRef {
    /// An end inside a finalized proposal artifact's document.
    #[must_use]
    pub fn proposal(artifact: ProposalArtifactRef, frontier: &LoroOpRef) -> Self {
        Self::at(
            EndpointDocument::ProposalArtifact(artifact.entity_id().to_hex()),
            Some(bytes_to_hex_lower(frontier.as_bytes())),
        )
    }

    /// The proposed end an endpoint-only settlement retained under `record`.
    #[must_use]
    pub fn imported_proposed(record: ProposalArtifactRef) -> Self {
        Self::at(
            EndpointDocument::ImportedProposed(record.entity_id().to_hex()),
            None,
        )
    }

    /// The final end an endpoint-only settlement retained under `record`.
    #[must_use]
    pub fn imported_final(record: ProposalArtifactRef) -> Self {
        Self::at(
            EndpointDocument::ImportedFinal(record.entity_id().to_hex()),
            None,
        )
    }

    /// A claim's Approved-normalized body at `revision`.
    #[must_use]
    pub fn approved_claim(claim: EntityId, revision: RevisionRef) -> Self {
        Self::at(
            EndpointDocument::ApprovedClaim(claim.to_hex()),
            Some(revision.to_hex()),
        )
    }

    /// An identity-topology event's applied op at `revision`.
    #[must_use]
    pub fn identity_op_proposal(event: EntityId, revision: RevisionRef) -> Self {
        Self::at(
            EndpointDocument::IdentityOpProposal(event.to_hex()),
            Some(revision.to_hex()),
        )
    }

    /// A proposal-outcome receipt's `amended_body`.
    #[must_use]
    pub fn receipt_amended_body(receipt_id: &str) -> Self {
        Self::at(
            EndpointDocument::ReceiptAmendedBody(receipt_id.to_owned()),
            None,
        )
    }

    const fn at(document: EndpointDocument, frontier: Option<String>) -> Self {
        Self {
            document,
            frontier,
            content_hash: None,
        }
    }

    /// This ref with the blake3 of the content measured at it.
    #[must_use]
    pub fn with_content(mut self, content: &[u8]) -> Self {
        self.content_hash = Some(bytes_to_hex_lower(blake3::hash(content).as_bytes()));
        self
    }

    /// The proposal-artifact row this end is retained in, when it is one.
    #[must_use]
    pub fn proposal_artifact(&self) -> Option<ProposalArtifactRef> {
        match &self.document {
            EndpointDocument::ProposalArtifact(hex)
            | EndpointDocument::ImportedProposed(hex)
            | EndpointDocument::ImportedFinal(hex) => {
                EntityId::from_hex(hex).ok().map(ProposalArtifactRef::new)
            }
            EndpointDocument::ApprovedClaim(_)
            | EndpointDocument::IdentityOpProposal(_)
            | EndpointDocument::ReceiptAmendedBody(_) => None,
        }
    }

    /// One string spelling of the ref, `kind:id@frontier`, for surfaces that
    /// carry a ref as text.
    #[must_use]
    pub fn token(&self) -> String {
        let (kind, id) = match &self.document {
            EndpointDocument::ProposalArtifact(id) => ("proposal_artifact", id),
            EndpointDocument::ImportedProposed(id) => ("imported_proposed", id),
            EndpointDocument::ImportedFinal(id) => ("imported_final", id),
            EndpointDocument::ApprovedClaim(id) => ("approved_claim", id),
            EndpointDocument::IdentityOpProposal(id) => ("identity_op_proposal", id),
            EndpointDocument::ReceiptAmendedBody(id) => ("receipt_amended_body", id),
        };
        match &self.frontier {
            Some(frontier) => format!("{kind}:{id}@{frontier}"),
            None => format!("{kind}:{id}"),
        }
    }
}

/// An entity's live revision, read in the caller's transaction: the revision
/// an entity write retains beside the body it replaces. `None` when the
/// entity's revision history holds no state, so no versioned endpoint exists.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn live_revision_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> crate::Result<Option<RevisionRef>> {
    revision_for_mode_in_txn(store, txn, &id, ReadMode::Live)
}

/// One end of a window as a lane measures it: where it is retained, and its
/// content as read there.
#[derive(Debug)]
pub struct MeasuredEnd<'a, T: ?Sized> {
    /// The retained source this content was read from.
    pub at: EndpointRef,
    /// The content at that end.
    pub content: &'a T,
}
