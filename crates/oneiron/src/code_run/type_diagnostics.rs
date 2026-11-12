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
use crate::code_sandbox::source::PreparationNote;
use crate::settings::ReleaseHold;

#[doc(hidden)]
use oneiron_verb_wire::code_run::type_diagnostics::CHECK_REF_PREFIX;
#[doc(hidden)]
pub use oneiron_verb_wire::code_run::type_diagnostics::{
    DiagnosticCollection, DiagnosticMeasures, FeedbackWithheldReason, ProgramPreparationNote,
    ProgramStepFeedback, ProgramStepFeedbackRelease, ProgramStepIdentity, TypeCheckFacts,
    TypeCheckState, TypeDiagnostic, TypeDiagnostics,
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
