//! The code views' agent verbs (OF-323): `vault.code.diff`, a semantic diff
//! between two tested states of one file, and `vault.code.blame`, blame by op
//! over one. Every unit names the operations that wrote it, and every
//! operation its actor, session, turn, activity, intent, model and effort,
//! each ref as the caller reads it ([`OpRefs`]). An erased actor is no ref,
//! of class `erased` (FIX 3520). Text diff stays a derived rendering
//! (`rendered`); birth text, which no operation wrote, carries no operation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{CodeDocumentFrontier, CodeOpAttribution};
use crate::blob_artifact::hash_hex;
use crate::code_symbol::{
    CodeAttributedChange, CodeContentVersion, CodeUnitBlame, render_code_semantic_diff,
};
use crate::codebase::snapshot_asset_entity_id;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error};
use crate::memory::{Memory, MemoryResult};
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::secret_custody::SecretSight;

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

/// One operation on a code document, with who made it and why. Each ref is
/// one the caller reads: a session, actor, turn, activity, intent or model it
/// cannot read is `None`, and renders as `-`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeOperationView {
    pub operation_ref: String,
    /// Its order within the document.
    pub sequence: u64,
    pub session_ref: Option<String>,
    pub actor_ref: Option<String>,
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
    /// revision is not there or withheld, or the revision did not test the
    /// file.
    fn code_state(
        &self,
        request: &CodeStateRequest,
    ) -> MemoryResult<Option<(CodeDocumentFrontier, CodeStateView)>> {
        let vault = self.vault();
        let frontier = match &request.revision_ref {
            Some(revision) => {
                let id = EntityId::from_hex(revision)?;
                let Some(revision) = vault.get_code_revision(&id)? else {
                    return Ok(None);
                };
                // The revision is read through the caller's credential, so a
                // withheld revision answers as an absent one (FIX 4344).
                if self.get_entity_tolerant(&id.to_hex())?.value.is_none() {
                    return Ok(None);
                }
                self.produced_from([id]);
                revision
                    .file_frontiers
                    .into_values()
                    .find(|frontier| frontier.repo == request.repo && frontier.path == request.path)
            }
            None => {
                let Some(frontier) = vault.code_document_frontier(&request.repo, &request.path)?
                else {
                    return Ok(None);
                };
                // The live head is judged here, under the bound caller's
                // own authority, not only at the outer doors (FIX 9687).
                if !self.reads_live_code_head(&frontier)? {
                    return Ok(None);
                }
                Some(frontier)
            }
        };
        Ok(frontier.map(|frontier| {
            let view = state_view(&frontier, request.revision_ref.clone());
            (frontier, view)
        }))
    }

    /// Whether the bound caller reads the live head `frontier`: the vault
    /// owner's own key does; any other caller only when it reads the head
    /// text's repo ASSET, as `vault.code.repo_diff` admits a snapshot's
    /// file, and that ASSET is then listed as a producer. A withheld head
    /// answers as an absent one.
    fn reads_live_code_head(&self, frontier: &CodeDocumentFrontier) -> MemoryResult<bool> {
        if self.secret_sight()? == SecretSight::Owner {
            return Ok(true);
        }
        let text = self.vault().code_document_at(frontier)?;
        let asset = snapshot_asset_entity_id(blake3::hash(text.as_bytes()).as_bytes())?;
        if self.get_entity_tolerant(&asset.to_hex())?.value.is_none() {
            return Ok(false);
        }
        self.produced_from([asset]);
        Ok(true)
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
        let (changes, rendered) = OpRefs::new(self).changes(changes)?;
        let view = CodeDiffView {
            before: before_view,
            after: after_view,
            changes,
            rendered,
        };
        // A lifted key reads as its handle to all but the owner (OF-067).
        self.lifted_view(view, || {
            self.vault().code_document_lifted_keys(&[&before, &after])
        })
        .map(Some)
    }

    /// `vault.code.blame`: every unit of one tested state, with the
    /// operation runs that wrote it.
    pub fn code_blame(&self, input: &CodeStateRequest) -> MemoryResult<Option<CodeBlameView>> {
        let Some((at, view)) = self.code_state(input)? else {
            return Ok(None);
        };
        let units = self.vault().code_document_symbol_blame(&at)?;
        let mut refs = OpRefs::new(self);
        let units = units
            .into_iter()
            .map(|unit| refs.unit(unit))
            .collect::<MemoryResult<Vec<_>>>()?;
        let view = CodeBlameView { at: view, units };
        self.lifted_view(view, || self.vault().code_document_lifted_keys(&[&at]))
            .map(Some)
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

/// The refs a code view's operations name, each read through the caller's
/// credential once a view: a session, actor, turn, activity, intent or model
/// the caller cannot read projects as `None` and renders as `-`, and one it
/// reads is listed as a producer.
pub(super) struct OpRefs<'a, 'v> {
    memory: &'a Memory<'v>,
    readable: BTreeMap<EntityId, bool>,
}

impl<'a, 'v> OpRefs<'a, 'v> {
    pub(super) fn new(memory: &'a Memory<'v>) -> Self {
        Self {
            memory,
            readable: BTreeMap::new(),
        }
    }

    /// `id` as a view names it: its hex when the caller reads it.
    pub(super) fn admitted(&mut self, id: Option<EntityId>) -> MemoryResult<Option<String>> {
        let Some(id) = id else {
            return Ok(None);
        };
        let readable = match self.readable.get(&id).copied() {
            Some(readable) => readable,
            None => {
                let readable = self
                    .memory
                    .get_entity_tolerant(&id.to_hex())?
                    .value
                    .is_some();
                if readable {
                    self.memory.produced_from([id]);
                }
                self.readable.insert(id, readable);
                readable
            }
        };
        Ok(readable.then(|| id.to_hex()))
    }

    /// One operation, with who made it and why as the caller reads them.
    pub(super) fn operation(&mut self, op: &CodeOpAttribution) -> MemoryResult<CodeOperationView> {
        Ok(CodeOperationView {
            operation_ref: op.operation.to_hex(),
            sequence: op.sequence,
            session_ref: self.admitted(Some(op.session_id))?,
            actor_ref: self.admitted(op.actor.map(|actor| actor.entity_ref()))?,
            actor_class: op
                .actor
                .map_or(ERASED_CALL_IDENTITY, |actor| {
                    actor.actor_class().gate_actor_class()
                })
                .to_owned(),
            turn_ref: self.admitted(op.provenance.turn)?,
            activity_ref: self.admitted(op.provenance.activity)?,
            intent_ref: self.admitted(op.provenance.intent)?,
            model_ref: self.admitted(op.provenance.substrate_ref)?,
            reasoning_effort: op.provenance.reasoning_effort.clone(),
        })
    }

    fn operations(&mut self, ops: &[CodeOpAttribution]) -> MemoryResult<Vec<CodeOperationView>> {
        ops.iter().map(|op| self.operation(op)).collect()
    }

    /// The changes as a view shows them, and their text: each change's
    /// operations, one line each, then its hunk.
    pub(super) fn changes(
        &mut self,
        changes: Vec<CodeAttributedChange>,
    ) -> MemoryResult<(Vec<CodeChangeView>, String)> {
        let mut views = Vec::with_capacity(changes.len());
        let mut rendered = String::new();
        for change in changes {
            let inserted_by = self.operations(&change.inserted_by)?;
            let deleted_by = self.operations(&change.deleted_by)?;
            for (sign, ops) in [("+", &inserted_by), ("-", &deleted_by)] {
                for op in ops {
                    rendered.push_str(&format!("# {sign}op {}\n", op_line(op)));
                }
            }
            rendered.push_str(&render_code_semantic_diff(std::slice::from_ref(
                &change.change,
            )));
            let unit = change.change;
            views.push(CodeChangeView {
                path: unit.path,
                symbol: unit.symbol,
                before: unit.before.map(version_view),
                after: unit.after.map(version_view),
                inserted_by,
                deleted_by,
            });
        }
        Ok((views, rendered))
    }

    /// One unit of a blame, each run's operation as the caller reads it.
    fn unit(&mut self, unit: CodeUnitBlame) -> MemoryResult<CodeUnitBlameView> {
        let mut spans = Vec::with_capacity(unit.spans.len());
        for span in unit.spans {
            spans.push(CodeSpanView {
                start: span.start,
                end: span.end,
                op: span.op.as_ref().map(|op| self.operation(op)).transpose()?,
            });
        }
        Ok(CodeUnitBlameView {
            path: unit.path,
            symbol: unit.symbol,
            version: version_view(unit.version),
            spans,
        })
    }
}

/// One operation's line of a rendered diff, as
/// [`crate::code_symbol::render_op`] writes one: a ref the caller cannot read
/// shows as `-`.
fn op_line(op: &CodeOperationView) -> String {
    format!(
        "{} seq:{} session:{} actor:{} turn:{} activity:{} intent:{} model:{} effort:{}",
        op.operation_ref,
        op.sequence,
        shown(op.session_ref.as_deref()),
        shown(op.actor_ref.as_deref()),
        shown(op.turn_ref.as_deref()),
        shown(op.activity_ref.as_deref()),
        shown(op.intent_ref.as_deref()),
        shown(op.model_ref.as_deref()),
        shown(op.reasoning_effort.as_deref()),
    )
}

fn shown(text: Option<&str>) -> &str {
    text.unwrap_or("-")
}

fn version_view(version: CodeContentVersion) -> CodeUnitVersionView {
    CodeUnitVersionView {
        content_hash: hash_hex(&version.content_hash),
        text: version.text,
        start_line: version.start_line,
        end_line: version.end_line,
    }
}
