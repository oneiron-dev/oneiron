//! Moved from `crates/oneiron/src/code_run/type_diagnostics.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_code_source::source::PreparationNote;
use oneiron_contracts::entity_id::EntityId;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

/// The prefix of a step check's public reference.
pub const CHECK_REF_PREFIX: &str = "type_diagnostics:";

/// One program step: its run, its step in the run, and the invocation that
/// ran the program there (0 for the step's own program).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramStepIdentity {
    /// The run's id, hex.
    pub run: String,
    pub program_seq: u64,
    pub invocation: u64,
}

impl ProgramStepIdentity {
    pub fn of(run: EntityId, program_seq: u64, invocation: u64) -> Self {
        Self {
            run: run.to_hex(),
            program_seq,
            invocation,
        }
    }

    /// The step's check reference: the one key its late result lands under
    /// and `vault.code.type_diagnostics` reads.
    #[must_use]
    pub fn check_ref(&self) -> String {
        format!(
            "{CHECK_REF_PREFIX}{}:{}:{}",
            self.run, self.program_seq, self.invocation
        )
    }
}

/// A step's type feedback: the host's own answer beside the step's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramStepFeedback {
    pub step: ProgramStepIdentity,
    /// Where the step's check result lands and is read again.
    pub check_ref: String,
    /// What the program's preparation noted, when it ran as written though
    /// it was not JavaScript Oxc accepts (FIX 8276).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preparation_note: Option<ProgramPreparationNote>,
    pub type_diagnostics: TypeDiagnostics,
}

impl ProgramStepFeedback {
    pub fn new(
        step: ProgramStepIdentity,
        preparation_note: Option<ProgramPreparationNote>,
        type_diagnostics: TypeDiagnostics,
    ) -> Self {
        Self {
            check_ref: step.check_ref(),
            step,
            preparation_note,
            type_diagnostics,
        }
    }
}

/// A preparation note as the step's feedback carries it: its stable code,
/// and Oxc's message for a construct it could not lower.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramPreparationNote {
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ProgramPreparationNote {
    pub fn of(note: &PreparationNote) -> Self {
        let detail = match note {
            PreparationNote::UnsupportedTypeScript(message) => Some(message.clone()),
            _ => None,
        };
        Self {
            code: note.code().to_owned(),
            detail,
        }
    }
}

/// A step's type check, as it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TypeDiagnostics {
    /// The check finished: every diagnostic it found, measured.
    Complete {
        check: TypeCheckFacts,
        measures: DiagnosticMeasures,
        diagnostics: DiagnosticCollection,
    },
    /// The check is still running beside the run, which never waits on it:
    /// its result lands later under the step's `check_ref`.
    Pending { check: TypeCheckFacts },
    /// The check stopped with no complete report: its typed failure, and
    /// every whole diagnostic it printed before it stopped, measured. Never
    /// a clean check.
    Failed {
        check: TypeCheckFacts,
        failure: String,
        measures: DiagnosticMeasures,
        diagnostics: DiagnosticCollection,
    },
    /// No check answers for the step: why.
    Unavailable {
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
}

impl TypeDiagnostics {
    pub fn unavailable(reason: &str, detail: Option<String>) -> Self {
        Self::Unavailable {
            reason: reason.to_owned(),
            detail,
        }
    }

    /// Whether the check may still change: a pending one.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending { .. })
    }
}

/// What checked the program, and how.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TypeCheckFacts {
    /// `javascript` or `typescript`: the language the run was prepared from.
    pub language: String,
    /// The file the program was checked as, `program.js` or `program.ts`.
    pub file: String,
    /// The checker that answered, or the configured one while pending.
    pub backend: String,
    pub pin: String,
    /// The check's action digest over the program, each declaration file,
    /// the language and the checker at its pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elapsed_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_memory_bytes: Option<u64>,
}

/// The size of a step's diagnostics: every occurrence, and the UTF-8 bytes
/// of their JSON array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DiagnosticMeasures {
    pub count: u64,
    pub bytes: u64,
}

/// Every diagnostic of a check: inline, or in a stored body read whole by
/// its handle (`read(handle)` in the run, `read_result` outside it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "form", rename_all = "snake_case")]
pub enum DiagnosticCollection {
    Inline {
        diagnostics: Vec<TypeDiagnostic>,
    },
    Stored {
        /// The body's handle in the run's results.
        handle: String,
        /// The run's occurrence of the body, hex.
        occurrence: String,
        byte_len: u64,
    },
}

/// One TypeScript diagnostic, its message whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TypeDiagnostic {
    /// `program.js` or `program.ts`, a declaration file, or none for a
    /// diagnostic about the whole check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// One-based, in the program as its author wrote it.
    pub line: u32,
    pub column: u32,
    pub category: String,
    pub code: u32,
    pub message: String,
    /// The message's UTF-8 bytes.
    pub message_bytes: u64,
}

impl TypeDiagnostic {
    pub fn of(diagnostic: &oneiron_code_check::Diagnostic) -> Self {
        Self {
            file: diagnostic.file.clone(),
            line: diagnostic.line,
            column: diagnostic.column,
            category: diagnostic.category.clone(),
            code: diagnostic.code,
            message: diagnostic.message.clone(),
            message_bytes: diagnostic.message.len() as u64,
        }
    }
}

/// A step's check state, as its withheld feedback states it: the four states
/// of [`TypeDiagnostics`], no other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TypeCheckState {
    Complete,
    Pending,
    Failed,
    Unavailable,
}

/// A step's type feedback as one destination is given it (FIX 10390, CALLS
/// "feedback released apart from its answer"): whole, or withheld when its
/// own release check holds it. A withheld one keeps the step's identity, its
/// `check_ref`, its check's state, the checker's own facts and codes and the
/// real measures, and drops every text of the feedback: diagnostic messages
/// and files, and preparation, unavailable and error detail. A hold on it
/// changes nothing else in the answer it rides with. The step's row stays
/// whole; the owner reads it by `check_ref` with `vault.code.type_diagnostics`
/// where that destination admits it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "release", rename_all = "snake_case")]
pub enum ProgramStepFeedbackRelease {
    /// The feedback whole, as the step keeps it.
    Released(ProgramStepFeedback),
    /// The feedback withheld from this destination, with none of its text.
    Withheld {
        step: ProgramStepIdentity,
        check_ref: String,
        state: TypeCheckState,
        /// What checked the program; none for an unavailable check.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        check: Option<TypeCheckFacts>,
        /// A failed check's failure code.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure: Option<String>,
        /// Why no check answers for the step: its code.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unavailable: Option<String>,
        /// The diagnostics' measures, when the check measured them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        measures: Option<DiagnosticMeasures>,
        /// The code of the note the preparation left, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preparation_code: Option<String>,
        reason: FeedbackWithheldReason,
    },
}

impl ProgramStepFeedbackRelease {
    /// `feedback` withheld for `reason`: its identity, state, facts, codes
    /// and measures, and none of its text.
    #[must_use]
    pub fn withheld(feedback: &ProgramStepFeedback, reason: FeedbackWithheldReason) -> Self {
        let (state, check, failure, unavailable, measures) = match &feedback.type_diagnostics {
            TypeDiagnostics::Complete {
                check, measures, ..
            } => (
                TypeCheckState::Complete,
                Some(check.clone()),
                None,
                None,
                Some(*measures),
            ),
            TypeDiagnostics::Pending { check } => (
                TypeCheckState::Pending,
                Some(check.clone()),
                None,
                None,
                None,
            ),
            TypeDiagnostics::Failed {
                check,
                failure,
                measures,
                ..
            } => (
                TypeCheckState::Failed,
                Some(check.clone()),
                Some(failure.clone()),
                None,
                Some(*measures),
            ),
            TypeDiagnostics::Unavailable { reason: why, .. } => (
                TypeCheckState::Unavailable,
                None,
                None,
                Some(why.clone()),
                None,
            ),
        };
        Self::Withheld {
            step: feedback.step.clone(),
            check_ref: feedback.check_ref.clone(),
            state,
            check,
            failure,
            unavailable,
            measures,
            preparation_code: feedback
                .preparation_note
                .as_ref()
                .map(|note| note.code.clone()),
            reason,
        }
    }
}

/// Why a destination is not given a step's feedback text, content-free: it
/// names no row, no world and no scan error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackWithheldReason {
    /// The owner's recipient choice for a world a row it names lies in.
    Recipient,
    /// A row it names cannot be placed in its world, or a short ref in it
    /// names no row.
    Placement,
    /// The rows its run was derived from are unknown.
    ProducersUnknown,
    /// The vault root is conflicted, so no world's recipient policy can be
    /// judged.
    ConflictedRoot,
    /// Its release check could not run.
    ReleaseCheckFailed,
}
