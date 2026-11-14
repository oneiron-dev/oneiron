//! Moved from `crates/oneiron/src/blob_artifact/esign/model.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::blob_artifact::esign::model::*;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignDocument {
    pub schema_version: u8,
    pub kind: DocumentKind,
    pub title: String,
    pub sequential: bool,
    pub expires_at: u64,
    /// Optional owner-selected deadline for signing and delivery links: when
    /// set, capabilities expire at `min(token_expires_at, expires_at)`; when
    /// unset, they expire at `expires_at`. Set on the draft alongside the
    /// document deadline; it never moves recipient signing windows.
    #[serde(default)]
    pub token_expires_at: Option<u64>,
    pub items: Vec<EsignItem>,
    pub recipients: Vec<EsignRecipient>,
    pub fields: Vec<EsignField>,
    pub full_trail_appendix: bool,
    /// Frozen pack timing and per-document notice switches, carried by the draft claim.
    #[serde(default)]
    pub lifecycle: Option<super::EsignLifecycleRules>,
    /// The project the document is sent for: a held sign act's ask climbs
    /// its boards before the vault owners. Only its members or a live vault
    /// owner bind it ([`super::PROJECT_MEMBERS_ONLY`]).
    #[serde(default)]
    pub project: Option<EntityId>,
    /// The obligations the document names (ARCH-0064 §3). Each is born an
    /// inert commitment with the draft, at
    /// [`super::esign_document_commitment_id`] of its index. An uploaded
    /// paper names none unless its drafter declares them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commitments: Vec<EsignCommitmentTerm>,
}

/// One obligation a draft names (ARCH-0064 §3, OF-187): an inert commitment
/// until the document completes, which opens it with the sealed version as
/// evidence; a decline, void or expiry releases it. A signature binds, so its
/// strength is `commitment`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignCommitmentTerm {
    /// Who owes it.
    pub obligor: crate::memory::commitment_doors::types::CommitmentObligor,
    /// Whom it is owed to.
    pub beneficiary: String,
    /// What is promised.
    pub content: crate::memory::commitment_doors::types::CommitmentContent,
    /// When it falls due, once the document opens it.
    pub schedule: crate::memory::commitment_doors::types::CommitmentSchedule,
    /// How long before each due instant its reminder leads.
    #[serde(default)]
    pub lead_seconds: Option<u64>,
}
