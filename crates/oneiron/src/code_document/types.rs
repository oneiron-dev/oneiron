//! File edit verbs, cursor spans, operation receipts and tested frontiers.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::write_envelope::WriteActor;

pub use crate::store::code_document_values::{CodeDocumentFrontier, CodeFileEdit};

pub use crate::store::code_document_values::CodeSpanAnchor;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeSpanResolution {
    Mapped {
        start: usize,
        end: usize,
    },
    /// The original span was deleted or changed. Never silently select new text.
    Drifted,
}

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

impl CodeOpProvenance {
    /// A recorded reasoning effort is a short non-empty scalar.
    pub(crate) fn validate(&self) -> crate::error::Result<()> {
        if self.reasoning_effort.as_ref().is_some_and(|effort| {
            effort.is_empty() || effort.len() > crate::provenance::REASONING_EFFORT_MAX_BYTES
        }) {
            return Err(super::codec::invalid());
        }
        Ok(())
    }
}

/// One operation as blame and diff name it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeOpAttribution {
    pub operation: EntityId,
    pub session_id: EntityId,
    /// None once that actor was erased (FIX 3520).
    pub actor: Option<WriteActor>,
    pub sequence: u64,
    pub provenance: CodeOpProvenance,
}

impl CodeOpAttribution {
    /// The symbol-manifest chain entry, once turn, activity and intent are all
    /// recorded. An erased actor's operation keeps its place in the chain and
    /// names no one: no actor is made up (FIX 4476).
    #[must_use]
    pub fn producing_operation(&self) -> Option<crate::code_symbol::CodeProducingOperation> {
        Some(crate::code_symbol::CodeProducingOperation {
            operation: self.operation,
            actor: self.actor.map(WriteActor::entity_ref),
            turn: self.provenance.turn?,
            activity: self.provenance.activity?,
            intent: self.provenance.intent?,
        })
    }

    /// How a view names the actor: its hex id, or [`ERASED_CALL_IDENTITY`]
    /// once that actor was erased.
    #[must_use]
    pub fn actor_ref(&self) -> String {
        self.actor.map_or_else(
            || ERASED_CALL_IDENTITY.to_owned(),
            |actor| actor.entity_ref().to_hex(),
        )
    }
}

/// A run of characters in one tested file state written by one operation.
/// `op` is `None` for the birth text the document was first opened with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeSpanBlame {
    pub start: usize,
    pub end: usize,
    pub op: Option<CodeOpAttribution>,
}

/// The operations between two tested states of one document that changed one
/// character range: those whose text survives in the newer range, and those
/// that deleted text of the older range. Each list is in sequence order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeRangeChange {
    pub inserted_by: Vec<CodeOpAttribution>,
    pub deleted_by: Vec<CodeOpAttribution>,
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
    pub metadata_edit: Option<super::CodeFileMetadataEdit>,
    pub before: CodeDocumentFrontier,
    pub after: CodeDocumentFrontier,
}
