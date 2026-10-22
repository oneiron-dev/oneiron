//! A captured step prepared for a reader admitted to its capture (FIX
//! 8704): the reader's own admission is asked again before each raw read of
//! the step's source, and once it no longer admits the reader the step is
//! withheld, and nothing more of it is read. The host's own preparation of
//! an arm it runs reads as before.

use super::{
    Outcome, PreparedShadowStep, Reason, ShadowUnavailable, prepare_step_source, unavailable,
};
use crate::code_run::StepReplayCapsule;
use crate::{Result, Vault};

/// A reader's admission to a captured step's source, asked again before
/// each raw read of it.
pub(crate) trait ShadowSourceAdmission {
    /// Whether the reader is still admitted to the step's source now, read
    /// in a snapshot of its own.
    ///
    /// # Errors
    ///
    /// Storage errors.
    fn admits_now(&self, vault: &Vault) -> Result<bool>;
}

/// The step `capsule` captured, read and frozen for an arm as
/// [`super::prepare_shadow_step_source`] reads it, while `admission` still
/// admits its reader: asked again before the request, the start and the
/// record of the step's end, and each body frozen, are read. Once it does
/// not, the step's source is withheld.
///
/// # Errors
///
/// Storage errors, the admission's own among them.
pub(crate) fn prepare_admitted_shadow_step_source(
    vault: &Vault,
    capsule: &StepReplayCapsule,
    admission: &dyn ShadowSourceAdmission,
) -> Result<Outcome<PreparedShadowStep>> {
    prepare_step_source(vault, capsule, &|| admission.admits_now(vault))
}

/// Why a step is withheld once its reader's admission lapsed: its source is
/// withheld from that reader.
pub(super) fn lapsed() -> ShadowUnavailable {
    unavailable(Reason::SourceWithheld, "admission")
}
