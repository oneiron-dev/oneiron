//! Folds by kind (ARCH-0067 §2.2; owner 2026-11-03 20:33, ledger
//! engine-20261103-log-fold-by-kind): the agent folds one kind of content
//! over a span of its own log, such as
//! `self.fold({kind: "repl_output", before: "t40"})`. Oneiron agents run in
//! code mode, so the main kind is old REPL cell output. Each folded step
//! keeps its program text, and with it every say() it made; its console
//! shows one stub that keeps the output's result handles, so the agent
//! re-reads any of it by handle.
//!
//! A `program` fold folds the other half: each folded step's program text
//! shows one stub, as comment lines inside its exec frame, that keeps every
//! speech call the step made (`self.speak`, `self.think`, `self.express`)
//! with its text and the ids the program names; its console stays.
//! `self.unfold` brings the programs back.
//!
//! A `connector_result` fold folds what connectors replied (FIX 14541):
//! each step of its span that took a connector's reply shows the stub of a
//! `repl_output` fold in place of its console, with one line per connector
//! call that replied, and the reply a parked connector call resumed with
//! shows as its result card. A step that took no connector's reply keeps its
//! console. Connector replies reach the log only there, so the step is the
//! unit: no reply is told apart from the step's other output.
//!
//! The engine writes each stub from the step's own typed record, with no
//! model call, so a fold by kind keeps no summary and no record's words
//! reach it. Its marks wait and land in one batch with every other mark of
//! that batch, and unfolding appends the raw content at the end of the log,
//! as for every fold.

use std::collections::BTreeSet;

use super::folds::{
    FoldLedger, FoldMark, FoldRecord, STUB_IDS, escape_compacted_text, fold_handle,
};
use crate::entity_id::EntityId;
use oneiron_contracts::claim::ClaimSource;

#[doc(hidden)]
pub use oneiron_verb_wire::compaction::fold_kinds::{
    FoldKind, FoldedConnectorCall, FoldedOutput, FoldedSpeech,
};

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

    /// The fold whose stub step `seq`'s console shows: the first one made,
    /// of the kinds that fold a console (`repl_output`, `connector_result`),
    /// that folded it. A later one of either kind keeps the step too, and the
    /// stub keeps its bytes.
    #[must_use]
    pub fn console_covering(&self, seq: u64) -> Option<&FoldRecord> {
        self.folds.iter().find(|fold| {
            fold.kind.is_some_and(FoldKind::folds_console)
                && fold.outputs.iter().any(|output| output.step == seq)
        })
    }

    /// Every step whose console some fold folds.
    #[must_use]
    pub fn console_folded_steps(&self) -> BTreeSet<u64> {
        self.folds
            .iter()
            .filter(|fold| fold.kind.is_some_and(FoldKind::folds_console))
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
        match kind {
            FoldKind::Program => return self.program_stub(seq, with_note, |_| None),
            FoldKind::ConnectorResult => return self.connector_stub(seq, with_note, |_| None),
            FoldKind::ReplOutput => {}
        }
        let mut stub = format!("⟨{} · {} folded⟩", fold_handle(self.fold), kind.as_str());
        if with_note && let Some(note) = &self.note {
            stub.push_str("\nnote: ");
            stub.push_str(&escape_compacted_text(note));
        }
        push_handles_and_ids(&mut stub, self.fold, output);
        Some(stub)
    }

    /// A folded connector result's stub for step `seq`: the console stub of
    /// a `repl_output` fold, with one line per connector call that replied
    /// after its head (and note). `label_of` reads a call's connector and
    /// tool from the run's record (`name/tool`); a call it cannot read shows
    /// its verb and call. `None` when this fold did not fold the step.
    pub fn connector_stub(
        &self,
        seq: u64,
        with_note: bool,
        label_of: impl Fn(&FoldedConnectorCall) -> Option<String>,
    ) -> Option<String> {
        let output = self.outputs.iter().find(|output| output.step == seq)?;
        let mut stub = format!(
            "⟨{} · {} folded⟩",
            fold_handle(self.fold),
            FoldKind::ConnectorResult.as_str()
        );
        if with_note && let Some(note) = &self.note {
            stub.push_str("\nnote: ");
            stub.push_str(&escape_compacted_text(note));
        }
        for call in &output.connector_calls {
            stub.push('\n');
            match label_of(call) {
                Some(label) => stub.push_str(&format!(
                    "{} {} (call {})",
                    call.verb,
                    escape_compacted_text(&label),
                    call.call
                )),
                None => stub.push_str(&format!("{} (call {})", call.verb, call.call)),
            }
        }
        push_handles_and_ids(&mut stub, self.fold, output);
        Some(stub)
    }

    /// A folded program's stub for step `seq`: comment lines, so the exec
    /// frame it stands in still holds a program. `text_of` reads a speech
    /// call's text (masked) from the run's record; a call it cannot read
    /// shows its verb and call. Every text is JSON-quoted on its own line.
    /// `None` when this fold did not fold the step.
    pub fn program_stub(
        &self,
        seq: u64,
        with_note: bool,
        text_of: impl Fn(&FoldedSpeech) -> Option<String>,
    ) -> Option<String> {
        let output = self.outputs.iter().find(|output| output.step == seq)?;
        let quote = |text: &str| serde_json::to_string(text).unwrap_or_default();
        let mut lines = vec![format!(
            "⟨{} · program folded⟩ self.unfold({{fold: \"{}\"}}) brings it back",
            fold_handle(self.fold),
            fold_handle(self.fold)
        )];
        if with_note && let Some(note) = &self.note {
            lines.push(format!("note: {}", quote(note)));
        }
        for speech in &output.said {
            lines.push(match text_of(speech) {
                Some(text) => format!("{}: {}", speech.verb, quote(&text)),
                None => format!("{} (call {})", speech.verb, speech.call),
            });
        }
        if !output.ids.is_empty() {
            lines.push(format!(
                "ids: {}",
                output.ids[..output.ids.len().min(STUB_IDS)].join(", ")
            ));
        }
        Some(
            lines
                .iter()
                .map(|line| format!("// {line}"))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }
}

/// A console stub's tail: each handle the folded output keeps, one a line,
/// then the ids it names, the first [`STUB_IDS`] of them.
fn push_handles_and_ids(stub: &mut String, fold: u64, output: &FoldedOutput) {
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
                fold_handle(fold)
            ));
        }
    }
}
