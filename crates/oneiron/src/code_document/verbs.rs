//! The code views' agent verbs (OF-323): `vault.code.diff`, a semantic diff
//! between two tested states of one file, and `vault.code.blame`, blame by op
//! over one. Every unit names the operations that wrote it, and every
//! operation its actor, session, turn, activity, intent, model and effort.
//! Text diff stays a derived rendering (`rendered`); birth text, which no
//! operation wrote, carries no operation.

use serde::{Deserialize, Serialize};

use super::{CodeDocumentFrontier, CodeOpAttribution};
use crate::blob_artifact::hash_hex;
use crate::code_symbol::{
    CodeAttributedChange, CodeContentVersion, CodeUnitBlame, render_attributed_semantic_diff,
};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error};
use crate::memory::{Memory, MemoryResult};

/// One tested state of a file: as the code revision `revision_ref` tested
/// it, or, with no revision, the document's live head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeStateRequest {
    pub repo: String,
    pub path: String,
    #[serde(default)]
    pub revision_ref: Option<String>,
}

/// Two tested states of one document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeDiffRequest {
    pub before: CodeStateRequest,
    pub after: CodeStateRequest,
}

/// One tested state of a document, as a view names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeStateView {
    pub document_ref: String,
    pub repo: String,
    pub path: String,
    pub revision_ref: Option<String>,
    pub text_hash: String,
}

/// One operation on a code document, with who made it and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeOperationView {
    pub operation_ref: String,
    /// Its order within the document.
    pub sequence: u64,
    pub session_ref: String,
    pub actor_ref: String,
    pub actor_class: String,
    pub turn_ref: Option<String>,
    pub activity_ref: Option<String>,
    pub intent_ref: Option<String>,
    pub model_ref: Option<String>,
    pub reasoning_effort: Option<String>,
}

/// One unit's text at one state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeUnitVersionView {
    pub content_hash: String,
    pub text: String,
    pub start_line: u32,
    pub end_line: u32,
}

/// One semantic change, with the operations made between the two states
/// that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeChangeView {
    pub path: String,
    pub symbol: String,
    pub before: Option<CodeUnitVersionView>,
    pub after: Option<CodeUnitVersionView>,
    /// Operations whose text survives in the newer unit.
    pub inserted_by: Vec<CodeOperationView>,
    /// Operations that deleted text of the older unit.
    pub deleted_by: Vec<CodeOperationView>,
}

/// `vault.code.diff`: the changes between two states, unit by unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeDiffView {
    pub before: CodeStateView,
    pub after: CodeStateView,
    pub changes: Vec<CodeChangeView>,
    /// The changes as text: each unit's operations, then its hunk.
    pub rendered: String,
}

/// A run of characters one operation wrote; `op` is absent for birth text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeSpanView {
    pub start: usize,
    pub end: usize,
    pub op: Option<CodeOperationView>,
}

/// One unit of the file and the runs that wrote it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeUnitBlameView {
    pub path: String,
    pub symbol: String,
    pub version: CodeUnitVersionView,
    pub spans: Vec<CodeSpanView>,
}

/// `vault.code.blame`: every unit of one state, blamed by op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeBlameView {
    pub at: CodeStateView,
    pub units: Vec<CodeUnitBlameView>,
}

impl Memory<'_> {
    /// The tested state a request names; `None` when the file or the
    /// revision is not there, or the revision did not test the file.
    fn code_state(
        &self,
        request: &CodeStateRequest,
    ) -> MemoryResult<Option<(CodeDocumentFrontier, CodeStateView)>> {
        let vault = self.vault();
        let frontier = match &request.revision_ref {
            Some(revision) => vault
                .get_code_revision(&EntityId::from_hex(revision)?)?
                .and_then(|revision| {
                    revision.file_frontiers.into_values().find(|frontier| {
                        frontier.repo == request.repo && frontier.path == request.path
                    })
                }),
            None => vault.code_document_frontier(&request.repo, &request.path)?,
        };
        Ok(frontier.map(|frontier| {
            let view = state_view(&frontier, request.revision_ref.clone());
            (frontier, view)
        }))
    }

    /// `vault.code.diff`: the semantic changes between two tested states of
    /// one document, each with the operations that made it.
    pub fn code_diff(&self, input: &CodeDiffRequest) -> MemoryResult<Option<CodeDiffView>> {
        let (Some((before, before_view)), Some((after, after_view))) = (
            self.code_state(&input.before)?,
            self.code_state(&input.after)?,
        ) else {
            return Ok(None);
        };
        if before.document_id != after.document_id {
            return Err(Error::Artifact(ArtifactError::InvalidCodeArtifactBody(
                "a code diff compares two states of one document",
            ))
            .into());
        }
        let changes = self.vault().code_document_semantic_diff(&before, &after)?;
        Ok(Some(CodeDiffView {
            before: before_view,
            after: after_view,
            rendered: render_attributed_semantic_diff(&changes),
            changes: changes.into_iter().map(change_view).collect(),
        }))
    }

    /// `vault.code.blame`: every unit of one tested state, with the
    /// operation runs that wrote it.
    pub fn code_blame(&self, input: &CodeStateRequest) -> MemoryResult<Option<CodeBlameView>> {
        let Some((at, view)) = self.code_state(input)? else {
            return Ok(None);
        };
        let units = self.vault().code_document_symbol_blame(&at)?;
        Ok(Some(CodeBlameView {
            at: view,
            units: units.into_iter().map(unit_view).collect(),
        }))
    }
}

/// One tested state as a view names it.
pub(super) fn state_view(
    frontier: &CodeDocumentFrontier,
    revision_ref: Option<String>,
) -> CodeStateView {
    CodeStateView {
        document_ref: hash_hex(&frontier.document_id),
        repo: frontier.repo.clone(),
        path: frontier.path.clone(),
        revision_ref,
        text_hash: hash_hex(&frontier.text_hash),
    }
}

pub(super) fn operation_view(op: &CodeOpAttribution) -> CodeOperationView {
    let id = |id: Option<EntityId>| id.map(|id| id.to_hex());
    CodeOperationView {
        operation_ref: op.operation.to_hex(),
        sequence: op.sequence,
        session_ref: op.session_id.to_hex(),
        actor_ref: op.actor.entity_ref().to_hex(),
        actor_class: op.actor.actor_class().gate_actor_class().to_owned(),
        turn_ref: id(op.provenance.turn),
        activity_ref: id(op.provenance.activity),
        intent_ref: id(op.provenance.intent),
        model_ref: id(op.provenance.substrate_ref),
        reasoning_effort: op.provenance.reasoning_effort.clone(),
    }
}

fn version_view(version: CodeContentVersion) -> CodeUnitVersionView {
    CodeUnitVersionView {
        content_hash: hash_hex(&version.content_hash),
        text: version.text,
        start_line: version.start_line,
        end_line: version.end_line,
    }
}

pub(super) fn change_view(change: CodeAttributedChange) -> CodeChangeView {
    CodeChangeView {
        path: change.change.path,
        symbol: change.change.symbol,
        before: change.change.before.map(version_view),
        after: change.change.after.map(version_view),
        inserted_by: change.inserted_by.iter().map(operation_view).collect(),
        deleted_by: change.deleted_by.iter().map(operation_view).collect(),
    }
}

fn unit_view(unit: CodeUnitBlame) -> CodeUnitBlameView {
    CodeUnitBlameView {
        path: unit.path,
        symbol: unit.symbol,
        version: version_view(unit.version),
        spans: unit
            .spans
            .into_iter()
            .map(|span| CodeSpanView {
                start: span.start,
                end: span.end,
                op: span.op.as_ref().map(operation_view),
            })
            .collect(),
    }
}
