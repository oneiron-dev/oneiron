//! A captured step prepared for a reader admitted to its capture (FIX
//! 8704): the reader's own admission is asked again before each raw read of
//! the step's source, and once it no longer admits the reader the step is
//! withheld, and nothing more of it is read. A host's worker that prepares
//! an arm's source again holds that admission as an owned witness (FIX
//! 9446, [`ShadowSourceWitness`]). The host's own preparation of an arm it
//! runs, with no witness, reads as before.

use std::sync::Arc;

use super::{
    Outcome, PreparedShadowStep, Reason, ShadowStepIdentity, ShadowUnavailable,
    prepare_step_source, unavailable,
};
use crate::code_run::StepReplayCapsule;
use crate::{Result, Vault};

/// A reader's admission to a captured step's source, asked again before
/// each raw read of it, and before each release of an arm's body to a model
/// (FIX 9468).
pub trait ShadowSourceAdmission {
    /// Whether the reader is still admitted to the step's source now, read
    /// in a snapshot of its own.
    ///
    /// # Errors
    ///
    /// Storage errors.
    fn admits_now(&self, vault: &Vault) -> Result<bool>;
}

/// A reader's admission to one captured step's source, owned, so a host's
/// worker can hold it while it prepares an arm's source again (FIX 9446):
/// the step it admits, and the proof the reader holds, asked before each raw
/// read. Only the engine makes one, from a proof it holds. A host cannot
/// make one, so no grant id a request names stands in for it.
#[derive(Clone)]
pub struct ShadowSourceWitness {
    step: ShadowStepIdentity,
    admission: Arc<dyn ShadowSourceAdmission + Send + Sync>,
}

impl ShadowSourceWitness {
    /// The witness of `admission`, a reader's admission to the step `step`.
    pub(crate) fn new(
        step: ShadowStepIdentity,
        admission: Arc<dyn ShadowSourceAdmission + Send + Sync>,
    ) -> Self {
        Self { step, admission }
    }

    /// Whether it admits its reader to the source of `step` now. A step
    /// other than the one it admits is withheld (`SourceWithheld`), and so
    /// is its own step once the reader's admission lapsed.
    ///
    /// # Errors
    ///
    /// Storage errors, the admission's own among them.
    pub fn check(&self, vault: &Vault, step: ShadowStepIdentity) -> Result<Outcome<()>> {
        if step != self.step || !self.admission.admits_now(vault)? {
            return Ok(Err(lapsed()));
        }
        Ok(Ok(()))
    }
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

/// The step `capsule` captured, read and frozen for an arm under `witness`
/// (FIX 9446): as a reader admitted to its capture has it read, the
/// witness's admission asked before each raw read. A capsule of a step
/// other than the one the witness admits is withheld before any of it is
/// read.
///
/// # Errors
///
/// Storage errors, the admission's own among them.
pub fn prepare_witnessed_shadow_step_source(
    vault: &Vault,
    capsule: &StepReplayCapsule,
    witness: &ShadowSourceWitness,
) -> Result<Outcome<PreparedShadowStep>> {
    if ShadowStepIdentity::of(capsule) != witness.step {
        return Ok(Err(lapsed()));
    }
    prepare_admitted_shadow_step_source(vault, capsule, &*witness.admission)
}

/// Why a step is withheld once its reader's admission lapsed: its source is
/// withheld from that reader. An arm's body released to a model meets the
/// same lapse (FIX 9468).
pub(in crate::code_run::shadow_runner) fn lapsed() -> ShadowUnavailable {
    unavailable(Reason::SourceWithheld, "admission")
}
