//! Folds by kind (ARCH-0067 §2.2; owner 2026-11-03 20:33, ledger
//! engine-20261103-log-fold-by-kind): the agent folds one kind of content
//! over a span of its own log, such as
//! `self.fold({kind: "repl_output", before: "t40"})`. Oneiron agents run in
//! code mode, so the main kind is old REPL cell output. Each folded step
//! keeps its program text, and with it every say() it made; its console
//! shows one stub that keeps the output's result handles, so the agent
//! re-reads any of it by handle.
//!
//! The engine writes each stub from the step's own typed output, with no
//! model call, so a fold by kind keeps no summary and no record's words
//! reach it. Its marks wait and land in one batch with every other mark of
//! that batch, and unfolding appends the raw content at the end of the log,
//! as for every fold.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::folds::{
    FoldLedger, FoldMark, FoldMarkInput, FoldRecord, STUB_IDS, escape_compacted_text, fold_handle,
};
use crate::entity_id::EntityId;
use oneiron_contracts::claim::ClaimSource;

/// The kind of content one fold by kind folds in each step of its span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FoldKind {
    /// A step's REPL cell output: the console its sandbox returned. The
    /// program text and its say() messages stay.
    ReplOutput,
}

impl FoldKind {
    /// The kind as the agent writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReplOutput => "repl_output",
        }
    }
}

/// One step a fold by kind folded: what its stub keeps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FoldedOutput {
    pub step: u64,
    /// The folded content's own handle first, then each stored result it
    /// names: `describe(handle)` or `sandbox.fs.read_file` reads it back.
    pub handles: Vec<String>,
    /// Every id the folded content names.
    pub ids: Vec<String>,
}

/// The bound of a fold by kind that names none: past every step, and the
/// largest a JavaScript number names exactly, so a hook's rewrite of the
/// call keeps it.
const UNBOUNDED_THROUGH: u64 = (1 << 53) - 1;

/// `self.fold`'s object spelling, a fold by kind: `before` (exclusive) or
/// `through` (inclusive) bounds its span, `from` starts it (default the
/// first step), and with no bound it reaches the current step.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FoldByKind {
    kind: FoldKind,
    #[serde(default)]
    from: Option<FoldStepRef>,
    #[serde(default)]
    through: Option<FoldStepRef>,
    #[serde(default)]
    before: Option<FoldStepRef>,
    #[serde(default)]
    note: Option<String>,
}

/// A step as the agent names it: `40`, or its label `"t40"`.
#[derive(Deserialize)]
#[serde(untagged)]
enum FoldStepRef {
    Seq(u64),
    Label(String),
}

impl FoldStepRef {
    fn seq(&self) -> Result<u64, String> {
        match self {
            Self::Seq(seq) => Ok(*seq),
            Self::Label(label) => {
                let text = label.trim();
                text.strip_prefix('t')
                    .unwrap_or(text)
                    .parse::<u64>()
                    .map_err(|_| format!("`{label}` names no step; write 40 or \"t40\""))
            }
        }
    }
}

impl FoldByKind {
    pub(super) fn normalize(self) -> Result<FoldMarkInput, String> {
        let from = self
            .from
            .as_ref()
            .map(FoldStepRef::seq)
            .transpose()?
            .unwrap_or(0);
        let through = match (&self.through, &self.before) {
            (Some(_), Some(_)) => {
                return Err("a fold by kind names `through` or `before`, not both".to_owned());
            }
            (Some(through), None) => through.seq()?,
            (None, Some(before)) => before
                .seq()?
                .checked_sub(1)
                .ok_or_else(|| "no step runs before t0".to_owned())?,
            // Every step that has run: the ledger cuts it to the current step.
            (None, None) => UNBOUNDED_THROUGH,
        };
        Ok(FoldMarkInput {
            from,
            through,
            note: self.note,
            kind: Some(self.kind),
        })
    }
}

impl FoldLedger {
    /// The fold by `kind` whose stub step `seq` shows: the first one made
    /// that folded it. Later folds of the same kind over the step keep it
    /// too, and unfolding one of them appends without changing this stub.
    #[must_use]
    pub fn kind_covering(&self, kind: FoldKind, seq: u64) -> Option<&FoldRecord> {
        self.folds.iter().find(|fold| {
            fold.kind == Some(kind) && fold.outputs.iter().any(|output| output.step == seq)
        })
    }

    /// Every step whose `kind` content some fold folds.
    #[must_use]
    pub fn kind_folded_steps(&self, kind: FoldKind) -> BTreeSet<u64> {
        self.folds
            .iter()
            .filter(|fold| fold.kind == Some(kind))
            .flat_map(|fold| fold.outputs.iter().map(|output| output.step))
            .collect()
    }
}

impl FoldRecord {
    /// A fold by kind as its batch lands: the mark's span and note, what
    /// each folded step's stub keeps, and the host's byline. The stubs are
    /// the steps' own output references, so the record is stamped
    /// [`ClaimSource::ToolOutput`] and has no sources to withdraw.
    #[must_use]
    pub fn of_kind(
        mark: &FoldMark,
        kind: FoldKind,
        actor: EntityId,
        outputs: Vec<FoldedOutput>,
    ) -> Self {
        let mut ids: Vec<String> = Vec::new();
        let mut handles = Vec::new();
        for output in &outputs {
            for id in &output.ids {
                if !ids.contains(id) {
                    ids.push(id.clone());
                }
            }
            handles.extend(output.handles.iter().cloned());
        }
        Self {
            fold: mark.fold,
            from: mark.from,
            through: mark.through,
            summary: None,
            source: ClaimSource::ToolOutput,
            actor,
            sources: Vec::new(),
            ids,
            handles,
            execution: None,
            kind: Some(kind),
            note: mark.note.clone(),
            outputs,
            marked_at: mark.marked_at,
        }
    }

    /// A fold by kind's head line, which `describe({fold})` shows: its
    /// handle, kind and span, how many steps it folded, and the agent's note.
    pub(super) fn kind_head(&self, kind: FoldKind) -> String {
        let count = self.outputs.len();
        let mut head = format!(
            "⟨{} · {} · t{}–t{}⟩ {count} {} folded",
            fold_handle(self.fold),
            kind.as_str(),
            self.from,
            self.through,
            if count == 1 { "step" } else { "steps" }
        );
        if let Some(note) = &self.note {
            head.push_str("\nnote: ");
            head.push_str(&escape_compacted_text(note));
        }
        head
    }

    /// What step `seq` shows in place of its folded content: the fold's
    /// handle and kind, the agent's note where `with_note` asks for it (the
    /// first step of the fold the log shows), each handle the content keeps
    /// and the ids it names. The same bytes at every render, so the cached
    /// log holds. `None` when this fold did not fold the step.
    #[must_use]
    pub fn output_stub(&self, seq: u64, with_note: bool) -> Option<String> {
        let kind = self.kind?;
        let output = self.outputs.iter().find(|output| output.step == seq)?;
        let mut stub = format!("⟨{} · {} folded⟩", fold_handle(self.fold), kind.as_str());
        if with_note && let Some(note) = &self.note {
            stub.push_str("\nnote: ");
            stub.push_str(&escape_compacted_text(note));
        }
        for handle in &output.handles {
            stub.push('\n');
            stub.push_str(handle);
        }
        if !output.ids.is_empty() {
            stub.push_str("\nids: ");
            stub.push_str(&output.ids[..output.ids.len().min(STUB_IDS)].join(", "));
            if output.ids.len() > STUB_IDS {
                stub.push_str(&format!(
                    " and {} more (describe({{fold: \"{}\"}}))",
                    output.ids.len() - STUB_IDS,
                    fold_handle(self.fold)
                ));
            }
        }
        Some(stub)
    }
}
