//! The one endpoint ref every lane writes: the retained document an end of a
//! measured window lives in, and the version there (FIX 7819, 9799).

use serde::{Deserialize, Serialize};

use crate::edit_distance::{LoroOpRef, ProposalArtifactRef};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::vault::entity_revision::{ReadMode, RevisionRef, revision_for_mode_in_txn};

/// The retained source one end of a measured window lives in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointDocument {
    /// A finalized proposal artifact's retained Loro document (ED-00), by
    /// artifact id hex.
    ProposalArtifact(String),
    /// An entity's retained revision history, by entity id hex.
    Entity(String),
    /// A receipt's recorded fields, by receipt id.
    Receipt(String),
}

/// One end of a measured window: the document it lives in and the version
/// there, so the measurement recomputes from the refs alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRef {
    /// The retained document this end lives in.
    pub document: EndpointDocument,
    /// The version there: encoded Loro `Frontiers` hex in a proposal
    /// artifact, a [`RevisionRef`] hex in an entity. `None` for a receipt,
    /// which holds one version only.
    pub frontier: Option<String>,
    /// blake3 hex of the content the lane measured at this end: a check
    /// value beside the pointer, never the pointer.
    pub content_hash: Option<String>,
}

impl EndpointRef {
    /// An end inside a finalized proposal artifact's document.
    #[must_use]
    pub fn proposal(artifact: ProposalArtifactRef, frontier: &LoroOpRef) -> Self {
        Self {
            document: EndpointDocument::ProposalArtifact(artifact.entity_id().to_hex()),
            frontier: Some(bytes_to_hex_lower(frontier.as_bytes())),
            content_hash: None,
        }
    }

    /// An end at one retained revision of an entity; `None` names an entity
    /// whose revision history holds no state.
    #[must_use]
    pub fn entity(id: EntityId, revision: Option<RevisionRef>) -> Self {
        Self {
            document: EndpointDocument::Entity(id.to_hex()),
            frontier: revision.map(RevisionRef::to_hex),
            content_hash: None,
        }
    }

    /// An end recorded on a receipt.
    #[must_use]
    pub fn receipt(receipt_id: &str) -> Self {
        Self {
            document: EndpointDocument::Receipt(receipt_id.to_owned()),
            frontier: None,
            content_hash: None,
        }
    }

    /// This ref with the blake3 of the content measured at it.
    #[must_use]
    pub fn with_content(mut self, content: &[u8]) -> Self {
        self.content_hash = Some(bytes_to_hex_lower(blake3::hash(content).as_bytes()));
        self
    }

    /// The proposal artifact this end lives in, when it lives in one.
    #[must_use]
    pub fn proposal_artifact(&self) -> Option<ProposalArtifactRef> {
        match &self.document {
            EndpointDocument::ProposalArtifact(hex) => {
                EntityId::from_hex(hex).ok().map(ProposalArtifactRef::new)
            }
            EndpointDocument::Entity(_) | EndpointDocument::Receipt(_) => None,
        }
    }

    /// One string spelling of the ref, `kind:id@frontier`, for surfaces that
    /// carry a ref as text.
    #[must_use]
    pub fn token(&self) -> String {
        let (kind, id) = match &self.document {
            EndpointDocument::ProposalArtifact(id) => ("proposal_artifact", id),
            EndpointDocument::Entity(id) => ("entity", id),
            EndpointDocument::Receipt(id) => ("receipt", id),
        };
        match &self.frontier {
            Some(frontier) => format!("{kind}:{id}@{frontier}"),
            None => format!("{kind}:{id}"),
        }
    }
}

/// An entity's live revision as an endpoint, read in the caller's
/// transaction: the revision an entity write retains beside the body it
/// replaces.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn entity_endpoint_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> crate::Result<EndpointRef> {
    Ok(EndpointRef::entity(
        id,
        revision_for_mode_in_txn(store, txn, &id, ReadMode::Live)?,
    ))
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
