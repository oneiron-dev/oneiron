//! Semantic diff and blame over tested code documents, named per operation.
//! Each unit points at the operations that wrote it; each operation names its
//! actor, turn, activity, intent and model.

use super::semantic_code_diff;
use super::semantic_diff::{CodeContentVersion, CodeSemanticChange, render_code_semantic_diff};
use crate::Vault;
use crate::code_document::{CodeDocumentFrontier, CodeOpAttribution, CodeSpanBlame};
use crate::entity_id::EntityId;
use crate::error::Result;

/// One semantic change between two tested states of a file, with the
/// operations made between them that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeAttributedChange {
    pub change: CodeSemanticChange,
    /// Operations whose text survives in the newer unit.
    pub inserted_by: Vec<CodeOpAttribution>,
    /// Operations that deleted text of the older unit.
    pub deleted_by: Vec<CodeOpAttribution>,
}

/// One unit of a tested file and the operation runs that wrote its span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeUnitBlame {
    pub path: String,
    /// Qualified syntax identity; non-Rust sources use the file as the unit.
    pub symbol: String,
    pub version: CodeContentVersion,
    pub spans: Vec<CodeSpanBlame>,
}

impl CodeUnitBlame {
    /// Each distinct operation that wrote part of the unit, in sequence order.
    #[must_use]
    pub fn operations(&self) -> Vec<&CodeOpAttribution> {
        let mut ops: Vec<_> = self
            .spans
            .iter()
            .filter_map(|span| span.op.as_ref())
            .collect();
        ops.sort_by_key(|op| op.sequence);
        ops.dedup_by_key(|op| op.sequence);
        ops
    }
}

impl Vault {
    /// Semantic diff of two tested states of one document. Text is only a
    /// rendering of this list; see [`render_attributed_semantic_diff`].
    pub fn code_document_semantic_diff(
        &self,
        before: &CodeDocumentFrontier,
        after: &CodeDocumentFrontier,
    ) -> Result<Vec<CodeAttributedChange>> {
        let old = self.code_document_at(before)?;
        let new = self.code_document_at(after)?;
        let changes = semantic_code_diff(&after.path, &old, &new)?;
        let ranges: Vec<_> = changes
            .iter()
            .map(|change| {
                (
                    change.before.as_ref().map(|v| unit_chars(&old, v)),
                    change.after.as_ref().map(|v| unit_chars(&new, v)),
                )
            })
            .collect();
        let ops = self.code_document_range_changes(before, after, &ranges)?;
        Ok(changes
            .into_iter()
            .zip(ops)
            .map(|(change, ops)| CodeAttributedChange {
                change,
                inserted_by: ops.inserted_by,
                deleted_by: ops.deleted_by,
            })
            .collect())
    }

    /// Blame by op for every unit of one tested file state.
    pub fn code_document_symbol_blame(
        &self,
        tested: &CodeDocumentFrontier,
    ) -> Result<Vec<CodeUnitBlame>> {
        let text = self.code_document_at(tested)?;
        semantic_code_diff(&tested.path, "", &text)?
            .into_iter()
            .filter_map(|change| {
                change
                    .after
                    .map(|version| (change.path, change.symbol, version))
            })
            .map(|(path, symbol, version)| {
                let (start, end) = unit_chars(&text, &version);
                Ok(CodeUnitBlame {
                    spans: self.code_document_blame(tested, start, end)?,
                    path,
                    symbol,
                    version,
                })
            })
            .collect()
    }
}

/// Render attributed changes: each unit's operations, then its semantic hunk.
pub fn render_attributed_semantic_diff(changes: &[CodeAttributedChange]) -> String {
    let mut out = String::new();
    for change in changes {
        for (sign, ops) in [("+", &change.inserted_by), ("-", &change.deleted_by)] {
            for op in ops {
                out.push_str(&format!("# {sign}op {}\n", render_op(op)));
            }
        }
        out.push_str(&render_code_semantic_diff(std::slice::from_ref(
            &change.change,
        )));
    }
    out
}

/// One line naming an operation's identity, actor and provenance.
pub fn render_op(op: &CodeOpAttribution) -> String {
    let id = |id: Option<EntityId>| id.map_or_else(|| "-".to_owned(), |id| id.to_hex());
    format!(
        "{} seq:{} session:{} actor:{} turn:{} activity:{} intent:{} model:{} effort:{}",
        op.operation.to_hex(),
        op.sequence,
        op.session_id.to_hex(),
        op.actor_ref(),
        id(op.provenance.turn),
        id(op.provenance.activity),
        id(op.provenance.intent),
        id(op.provenance.substrate_ref),
        op.provenance.reasoning_effort.as_deref().unwrap_or("-"),
    )
}

/// The unit's exact Unicode scalar span when its text sits at its first line,
/// else the whole lines it covers (impl blocks joined from several places).
fn unit_chars(text: &str, version: &CodeContentVersion) -> (usize, usize) {
    let mut line = 1;
    let mut start_byte = if version.start_line <= 1 {
        Some(0)
    } else {
        None
    };
    let mut end_byte = text.len();
    for (index, byte) in text.bytes().enumerate() {
        if byte != b'\n' {
            continue;
        }
        if line >= version.end_line {
            end_byte = index;
            break;
        }
        line += 1;
        if line == version.start_line {
            start_byte = Some(index + 1);
        }
    }
    let start_byte = start_byte.unwrap_or(end_byte).min(end_byte);
    let chars = |byte: usize| text[..byte].chars().count();
    if text[start_byte..].starts_with(&version.text) {
        let start = chars(start_byte);
        return (start, start + version.text.chars().count());
    }
    (chars(start_byte), chars(end_byte))
}
