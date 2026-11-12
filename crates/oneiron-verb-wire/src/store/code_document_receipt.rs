//! Moved from `crates/oneiron/src/store/code_document_receipt.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::code_document_values::CodeDocumentFrontier;
use oneiron_store::code_document_values::CodeFileEdit;
use oneiron_store::code_document_values::CodeFileMetadataEdit;
use oneiron_store::write_envelope::WriteActor;
use serde::Deserialize;
use serde::Serialize;

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
