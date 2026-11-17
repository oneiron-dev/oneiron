//! Stored code-operation provenance and exact edit receipts.

use crate::entity_id::EntityId;
use crate::store::code_document_values::{
    CodeDocumentFrontier, CodeFileEdit, CodeFileMetadataEdit,
};
use crate::write_envelope::WriteActor;

#[doc(hidden)]
pub use oneiron_verb_wire::store::code_document_receipt::CodeOpProvenance;

/// Durable per-operation receipt; sequence is ordered within one document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeEditReceipt {
    pub document_id: [u8; 32],
    /// The durable ingress identity; a replay with it appends nothing.
    pub operation: EntityId,
    pub session_id: EntityId,
    /// None once that actor was erased (FIX 3520).
    pub actor: Option<WriteActor>,
    pub provenance: CodeOpProvenance,
    pub sequence: u64,
    pub peer_id: u64,
    pub counter_start: i32,
    pub counter_end: i32,
    pub edit: CodeFileEdit,
    /// The reviewed metadata change the operation made with its text, if
    /// any (G4 PR2); `None` on every ordinary text edit.
    pub metadata_edit: Option<CodeFileMetadataEdit>,
    pub before: CodeDocumentFrontier,
    pub after: CodeDocumentFrontier,
}
