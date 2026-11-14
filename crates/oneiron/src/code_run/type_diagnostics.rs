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
//!
//! Off this device the feedback is released apart from the answer it rides
//! with (FIX 10390): a hold on it withholds only its text, as the typed
//! [`ProgramStepFeedbackRelease::Withheld`] projection, and never the answer.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

use crate::EntityId;
use crate::settings::ReleaseHold;

#[doc(hidden)]
use oneiron_verb_wire::code_run::type_diagnostics::CHECK_REF_PREFIX;
#[doc(hidden)]
pub use oneiron_verb_wire::code_run::type_diagnostics::{
    DiagnosticCollection, DiagnosticMeasures, ProgramPreparationNote, ProgramStepFeedback,
    ProgramStepIdentity, TypeCheckFacts, TypeCheckState, TypeDiagnostic, TypeDiagnostics,
};

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

impl From<ReleaseHold> for FeedbackWithheldReason {
    fn from(hold: ReleaseHold) -> Self {
        match hold {
            ReleaseHold::Recipient(_) => Self::Recipient,
            ReleaseHold::Placement => Self::Placement,
            ReleaseHold::ProducersUnknown => Self::ProducersUnknown,
            ReleaseHold::ConflictedRoot => Self::ConflictedRoot,
        }
    }
}

/// A run's kept program-step feedback, as a trusted host lists it (FIX
/// 10389): every step's feedback the run keeps, in step order, or the typed
/// fact that it could not be read. A read that failed is never an empty
/// list, and never the run's own failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeptProgramSteps {
    Kept(Vec<ProgramStepFeedback>),
    /// The run's feedback could not be read ([`TYPE_FEEDBACK_NOT_KEPT`]):
    /// why.
    NotKept {
        detail: String,
    },
}
