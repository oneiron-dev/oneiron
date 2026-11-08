//! A captured step prepared for a reader admitted to its capture (FIX
//! 8704): the reader's own admission is asked again before each raw read of
//! the step's source, and once it no longer admits the reader the step is
//! withheld, and nothing more of it is read. A host's worker that prepares
//! an arm's source again holds that admission as an owned witness (FIX
//! 9446, [`ShadowSourceWitness`]). The host's own preparation of an arm it
//! runs, with no witness, reads as before. A worker that reads an arm's
//! bodies back for a model under a witness releases them through it (FIX
//! 20607, [`WitnessedRelease`]).

use std::sync::Arc;

use super::{
    Outcome, PreparedShadowStep, Reason, ShadowBodyRef, ShadowStepIdentity, ShadowUnavailable,
    prepare_step_source, unavailable,
};
use crate::code_run::StepReplayCapsule;
use crate::code_run::shadow_runner::{ShadowBodyStore, read_for_model};
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

/// The release of an arm's bodies to a model under a witness (FIX 20607):
/// the vault the witness's admission is asked in, and the witness of the
/// step the arm ran from. A contribution fork's program run reads its
/// bodies back through it.
#[derive(Clone, Copy)]
pub struct WitnessedRelease<'a> {
    vault: &'a Vault,
    witness: &'a ShadowSourceWitness,
}

impl<'a> WitnessedRelease<'a> {
    /// The release `witness` admits, asked in `vault`.
    #[must_use]
    pub const fn new(vault: &'a Vault, witness: &'a ShadowSourceWitness) -> Self {
        Self { vault, witness }
    }

    /// The whole body `body` of an arm run from `step`, whose store is
    /// `store`, released to a model (FIX 20607). A step other than the one
    /// the witness admits is withheld, and nothing is read. Otherwise the
    /// body is released by [`read_for_model`], under the witness's own
    /// admission and `step`'s release source.
    ///
    /// # Errors
    ///
    /// Storage errors, the admission's own among them, and a body that is
    /// not its digest.
    pub fn read_for_model(
        &self,
        store: &ShadowBodyStore,
        step: &PreparedShadowStep,
        body: &ShadowBodyRef,
    ) -> Result<Outcome<Vec<u8>>> {
        if *step.step() != self.witness.step {
            return Ok(Err(lapsed()));
        }
        let source = step.release_source();
        read_for_model(self.vault, store, &source, body, &*self.witness.admission)
    }
}

/// Why a step is withheld once its reader's admission lapsed: its source is
/// withheld from that reader. An arm's body released to a model meets the
/// same lapse (FIX 9468).
pub(in crate::code_run::shadow_runner) fn lapsed() -> ShadowUnavailable {
    unavailable(Reason::SourceWithheld, "admission")
}

/// Whether `unavailable` is a lapsed admission (FIX 20607): its reader is
/// not admitted to the step's source now. A Grant given later may change
/// that, so it is never an outcome to keep.
#[must_use]
pub(crate) fn admission_lapsed(unavailable: &ShadowUnavailable) -> bool {
    *unavailable == lapsed()
}
