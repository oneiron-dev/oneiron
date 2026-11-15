//! Moved from `crates/oneiron/src/edit_distance/delta/endpoint.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The retained source one end of a measured window lives in, and how its
/// content is read there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointDocument {
    /// A finalized proposal artifact's retained Loro document (ED-00), its
    /// own headed document on the entity-document plane (FIX 11535): the
    /// body text at a frontier. By artifact id hex, its head's key.
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
