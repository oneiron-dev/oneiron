//! A code-mode program step's type feedback (FIX 8277, owner ruling
//! CODE-MODE-TS rule 4): the host's typed answer beside the step's result,
//! never inside the guest's own output or the step's replay record.
//!
//! The program's type check runs beside it and never delays or refuses it.
//! A step answers its check as it stands when the step ends: `complete` with
//! every diagnostic, measured; `pending` while the check runs, its result
//! landing later under the step's `check_ref`; `failed` with the typed
//! failure and whatever whole diagnostics the check printed first, never as
//! complete; or `unavailable`, with why. The note the program's preparation
//! left, if any, rides beside it on every exit of the step.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

use crate::EntityId;
use crate::code_sandbox::source::PreparationNote;

/// The prefix of a step check's public reference.
const CHECK_REF_PREFIX: &str = "type_diagnostics:";

/// Why a step's type feedback is unavailable (CALLS, FIX 8277): the
/// configured mode is off.
pub const TYPE_CHECK_OFF: &str = "type_check_off";
/// The host that ran the step attached no checker.
pub const TYPE_CHECK_NOT_ATTACHED: &str = "type_check_not_attached";
/// The configured checker did not load; the detail names its failure.
pub const TYPE_CHECK_NOT_LOADED: &str = "type_check_not_loaded";
/// The check could not start beside the program.
pub const TYPE_CHECK_NOT_STARTED: &str = "type_check_not_started";
/// The checker that was checking the step is gone (a restart, a restore):
/// its result can never land.
pub const TYPE_CHECK_INTERRUPTED: &str = "type_check_interrupted";
/// The step's feedback could not be kept or read; the detail names why.
pub const TYPE_FEEDBACK_NOT_KEPT: &str = "type_feedback_not_kept";

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
    pub(crate) fn of(run: EntityId, program_seq: u64, invocation: u64) -> Self {
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

/// The run, step and invocation a check reference names; `None` for text
/// that is not one.
pub(crate) fn parse_check_ref(text: &str) -> Option<(EntityId, u64, u64)> {
    let mut parts = text.strip_prefix(CHECK_REF_PREFIX)?.split(':');
    let run = EntityId::from_hex(parts.next()?).ok()?;
    let program_seq = parts.next()?.parse().ok()?;
    let invocation = parts.next()?.parse().ok()?;
    parts
        .next()
        .is_none()
        .then_some((run, program_seq, invocation))
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
    pub(crate) fn new(
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
    pub(crate) fn of(note: &PreparationNote) -> Self {
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
    pub(crate) fn unavailable(reason: &str, detail: Option<String>) -> Self {
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
    pub(crate) fn of(diagnostic: &oneiron_code_check::Diagnostic) -> Self {
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

/// The measures of `diagnostics`: their count, and the bytes of their JSON
/// array.
pub(crate) fn measure(diagnostics: &[TypeDiagnostic]) -> DiagnosticMeasures {
    DiagnosticMeasures {
        count: diagnostics.len() as u64,
        bytes: serde_json::to_vec(diagnostics).map_or(0, |bytes| bytes.len() as u64),
    }
}

/// This process's checker incarnation: a pending check stamped with another
/// one can never land, so it reads as interrupted (FIX 8277).
pub(crate) fn check_incarnation() -> EntityId {
    static INCARNATION: OnceLock<EntityId> = OnceLock::new();
    *INCARNATION.get_or_init(EntityId::now)
}
