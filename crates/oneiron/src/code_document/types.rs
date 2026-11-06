//! File edit verbs, cursor spans, operation receipts and tested frontiers.

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

pub use crate::store::code_document_receipt::{CodeEditReceipt, CodeOpProvenance};

pub(crate) trait CodeOpProvenanceValidation {
    fn validate(&self) -> crate::error::Result<()>;
}

impl CodeOpProvenanceValidation for CodeOpProvenance {
    /// A recorded reasoning effort is a short non-empty scalar.
    fn validate(&self) -> crate::error::Result<()> {
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
