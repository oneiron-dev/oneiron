//! Stored code-operation provenance and exact edit receipts.

use crate::entity_id::EntityId;
use crate::store::code_document_values::{CodeDocumentFrontier, CodeFileEdit, CodeFileMetadataEdit};
use crate::write_envelope::WriteActor;
use serde::{Deserialize, Serialize};

/// Who and why behind one operation: the turn and activity that made it, the
/// intent it serves and the model that ran. The actor itself is on the receipt.
/// Absent fields are unrecorded, never inferred.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeOpProvenance {
    /// The TURN (a Dreamer or agent turn) that made the operation.
    pub turn: Option<EntityId>,
    /// The activity the turn worked under: its TASK, run or work session.
    pub activity: Option<EntityId>,
    /// The intent the operation serves: the ask, TASK or NOTE it answers.
    pub intent: Option<EntityId>,
    /// The MODEL entity that produced the operation.
    pub substrate_ref: Option<EntityId>,
    pub reasoning_effort: Option<String>,
}

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
