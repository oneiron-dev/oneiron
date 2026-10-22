//! A step's type feedback on the executor (FIX 8277): its check started
//! beside its program, its feedback kept as the step ends, whatever way it
//! ends, refreshed on each later turn and handed back with the run's
//! outcome. The model reads it beside the step's console, in a message of
//! the host's own: none of it enters the guest's output, the step's result
//! digests or its state hash.

use std::collections::BTreeMap;
use std::sync::{Arc, PoisonError};

use oneiron_code_check::ProgramLanguage;

use super::code_check::{CheckJob, StepCell, StepCheck};
use super::driver::EngineNativeExecutor;
use super::store::{clean_for_context, script_output_path};
use crate::code_run::{
    CodeRunReplayRecord, DiagnosticCollection, ExecutorStorage, ProgramPreparationNote,
    ProgramStepFeedback, ProgramStepIdentity, StepKey, TYPE_CHECK_NOT_ATTACHED, TYPE_CHECK_OFF,
    TYPE_FEEDBACK_NOT_KEPT, TypeDiagnostic, TypeDiagnostics,
};
use crate::code_sandbox::source::{PreparedSource, SourceLanguage};
use crate::{ContentPart, EntityId, LlmMessage, LlmMessageRole};

impl EngineNativeExecutor<'_> {
    /// Starts the step's check beside its program: the program as its author
    /// wrote it, in the language it was prepared from. Never waits.
    pub(super) fn start_step_check(
        &self,
        record: &CodeRunReplayRecord,
        seq: u64,
        prepared: &PreparedSource<'_>,
    ) -> StepCheck {
        let source = script_output_path(seq);
        let job = CheckJob {
            key: (record.run_id, seq, 0),
            program: prepared.original().to_owned(),
            language: match prepared.language() {
                SourceLanguage::JavaScript => ProgramLanguage::JavaScript,
                SourceLanguage::TypeScript => ProgramLanguage::TypeScript,
            },
            note: prepared.note().map(ProgramPreparationNote::of),
            actor: Some(self.gated_write.actor().entity_ref()),
            source: record
                .outputs
                .iter()
                .find(|output| output.path == source)
                .cloned(),
            vault: match &self.storage {
                ExecutorStorage::Canonical(vault) => Some(vault.vault_id()),
                ExecutorStorage::Session(_) => None,
            },
        };
        match self.code_check {
            Some(feedback) => feedback.start(job),
            None => {
                let unattached = TypeDiagnostics::unavailable(TYPE_CHECK_NOT_ATTACHED, None);
                StepCheck::unavailable(&job, unattached)
            }
        }
    }

    /// Keeps the step's feedback as the step ends, before any way out of it:
    /// the run's rows on the vault's own storage get it, landed or pending,
    /// and every later turn of this attempt reads it. A feedback write that
    /// fails is traced, never the step's failure.
    pub(super) fn keep_step_feedback(&self, check: &StepCheck) {
        let cell = check.cell();
        self.keep_row(&cell);
        self.held_checks().push(cell);
    }

    fn held_checks(&self) -> std::sync::MutexGuard<'_, Vec<Arc<StepCell>>> {
        self.step_checks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes `cell`'s row once landed, or once pending, on the vault's own
    /// storage; a session keeps its steps' feedback with the run alone. A
    /// collection past one reply goes to a body of the run first.
    fn keep_row(&self, cell: &StepCell) {
        cell.finalize(&self.storage);
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return;
        };
        if let Some(row) = cell.claim_row()
            && let Err(error) = vault.put_type_diagnostics(cell.key(), &row)
        {
            tracing::warn!(target: "oneiron::code_check", %error, "type feedback not kept");
        }
    }

    /// Step `seq`'s feedback as it stands now: this attempt's own check, or
    /// the row the run keeps. `None` when no feedback was kept for it.
    pub(super) fn step_feedback(&self, run: EntityId, seq: u64) -> Option<ProgramStepFeedback> {
        let key = (run, seq, 0);
        let held = self
            .held_checks()
            .iter()
            .find(|cell| cell.key() == key)
            .cloned();
        if let Some(cell) = held {
            self.keep_row(&cell);
            return Some(cell.feedback());
        }
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return None;
        };
        match vault.type_diagnostics_row(key) {
            Ok(row) => row.map(|row| row.feedback(key)),
            Err(error) => Some(not_kept(key, &error)),
        }
    }

    /// Every program step's feedback of `run`, for its outcome: each row the
    /// run keeps, and this attempt's checks as they stand now. Never waits
    /// on a check; a row that cannot be read leaves this attempt's own.
    pub(super) fn program_steps(&self, run: EntityId) -> Vec<ProgramStepFeedback> {
        let mut steps: BTreeMap<StepKey, ProgramStepFeedback> = BTreeMap::new();
        if let ExecutorStorage::Canonical(vault) = &self.storage {
            match vault.type_diagnostics_rows(run) {
                Ok(rows) => {
                    steps.extend(rows.into_iter().map(|(key, row)| (key, row.feedback(key))));
                }
                Err(error) => {
                    tracing::warn!(target: "oneiron::code_check", %error, "type feedback not read");
                }
            }
        }
        for cell in self.held_checks().iter().filter(|cell| cell.key().0 == run) {
            self.keep_row(cell);
            steps.insert(cell.key(), cell.feedback());
        }
        steps.into_values().collect()
    }

    /// The host's own message after step `seq`'s console: its preparation
    /// note and its type check as they stand, when there is anything to say.
    /// Diagnostics that quote a program the model may not read are withheld
    /// with it.
    pub(super) fn step_feedback_message(
        &self,
        record: &CodeRunReplayRecord,
        seq: u64,
    ) -> Option<LlmMessage> {
        let feedback = self.step_feedback(record.run_id, seq)?;
        let program = script_output_path(seq);
        let readable = record
            .outputs
            .iter()
            .find(|output| output.path == program)
            .is_none_or(|output| {
                clean_for_context(&self.storage, Some(record.run_id), output).unwrap_or(false)
            });
        let text = feedback_text(seq, &feedback, readable)?;
        Some(LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text { text }],
        })
    }
}

/// The feedback of a step whose row could not be read.
fn not_kept(key: StepKey, error: &crate::Error) -> ProgramStepFeedback {
    let (run, seq, invocation) = key;
    ProgramStepFeedback::new(
        ProgramStepIdentity::of(run, seq, invocation),
        None,
        TypeDiagnostics::unavailable(TYPE_FEEDBACK_NOT_KEPT, Some(error.to_string())),
    )
}

/// Step `seq`'s feedback as the model reads it: every diagnostic, or the
/// result its whole collection is kept as; `None` when there is nothing to
/// say (no note, and no check by configuration).
fn feedback_text(seq: u64, feedback: &ProgramStepFeedback, readable: bool) -> Option<String> {
    let mut lines = vec![format!("Host feedback on step {seq}, not program output:")];
    if let Some(note) = &feedback.preparation_note {
        let detail = note
            .detail
            .as_deref()
            .map_or_else(String::new, |detail| format!(": {detail}"));
        lines.push(format!(
            "It ran as written; its preparation noted {}{detail}.",
            note.code
        ));
    }
    match &feedback.type_diagnostics {
        TypeDiagnostics::Unavailable { reason, .. }
            if reason == TYPE_CHECK_OFF || reason == TYPE_CHECK_NOT_ATTACHED => {}
        TypeDiagnostics::Unavailable { reason, detail } => lines.push(format!(
            "Its type check is unavailable: {reason}{}.",
            detail
                .as_deref()
                .map_or_else(String::new, |detail| format!(" ({detail})"))
        )),
        TypeDiagnostics::Pending { check } => lines.push(format!(
            "Its type check ({}) is still running; its result comes with a later turn \
             ({}).",
            check.file, feedback.check_ref
        )),
        TypeDiagnostics::Complete {
            check,
            measures,
            diagnostics,
        } => {
            lines.push(format!(
                "Its type check ({}, {}) found {} diagnostics, {} bytes.",
                check.file, check.backend, measures.count, measures.bytes
            ));
            lines.extend(collection_lines(diagnostics, readable));
        }
        TypeDiagnostics::Failed {
            check,
            failure,
            measures,
            diagnostics,
        } => {
            lines.push(format!(
                "Its type check ({}, {}) failed: {failure}. It printed {} diagnostics, {} \
                 bytes, first: a partial report.",
                check.file, check.backend, measures.count, measures.bytes
            ));
            lines.extend(collection_lines(diagnostics, readable));
        }
    }
    (lines.len() > 1).then(|| lines.join("\n"))
}

/// A collection's lines: each diagnostic as `tsc --pretty false` prints it,
/// or the result the whole collection is kept as.
fn collection_lines(collection: &DiagnosticCollection, readable: bool) -> Vec<String> {
    match collection {
        DiagnosticCollection::Inline { diagnostics } if diagnostics.is_empty() => Vec::new(),
        DiagnosticCollection::Inline { .. } if !readable => {
            vec!["The diagnostics are withheld with the step's program.".to_owned()]
        }
        DiagnosticCollection::Inline { diagnostics } => {
            diagnostics.iter().map(diagnostic_line).collect()
        }
        DiagnosticCollection::Stored {
            handle, byte_len, ..
        } => vec![format!(
            "Every diagnostic is kept whole as the result {handle} ({byte_len} bytes): \
             describe(\"{handle}\") gives its card."
        )],
    }
}

fn diagnostic_line(diagnostic: &TypeDiagnostic) -> String {
    let place = diagnostic.file.as_ref().map_or_else(String::new, |file| {
        format!("{file}({},{}): ", diagnostic.line, diagnostic.column)
    });
    format!(
        "{place}{} TS{}: {}",
        diagnostic.category, diagnostic.code, diagnostic.message
    )
}
