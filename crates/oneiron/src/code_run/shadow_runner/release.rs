//! A shadow arm's bodies as a model reads them (FIX 9468, extends FIX
//! 6649). An arm write with a secret the wall cannot place is stored as it
//! came and marked (FIX 6649): the mark is storage, not a release. The raw
//! store read ([`ShadowBodyStore::read`]) stays the byte read of the arm's
//! owner. A model reads a body of the arm only through [`read_for_model`].
//!
//! Before each release, the release reads these again: the arm's own mark
//! on the body (its scan's reason, or the taint it inherited), its source
//! actor's hold, the reader's Grant to the step's capture, and the taint
//! and secret state of each source occurrence the arm was seeded with
//! ([`ShadowReleaseSource`]). Any body of the arm can quote any of those
//! occurrences, so one that reads tainted now withholds each body. Each
//! refusal is `SourceWithheld`. The bytes released are the arm's snapshot,
//! as written: no live body takes their place.
//!
//! An arm's own reads of a result frozen from its source take the taint
//! the source occurrence reads under now, at its worst with the frozen one
//! ([`live_taint`]). A read of a result that reads tainted is withheld, as
//! a run's read of one is.

use super::bridge::Taint;
use super::source::{PreparedShadowStep, ShadowSourceAdmission, lapsed};
use super::store::ShadowBodyStore;
use super::types::{ShadowBodyRef, ShadowUnavailable, ShadowUnavailableReason as Reason};
use crate::code_run::result_read::taint_word;
use crate::code_run::{CodeRunRawOutput, RESPONSE_ERASED};
use crate::secret_rotation::ArtifactTaintState;
use crate::{EntityId, Result, Vault};

/// A body a model may read, or why it may not read it now.
type Outcome<T> = std::result::Result<T, ShadowUnavailable>;

/// One occurrence an arm was seeded with clean: the run that holds it, and
/// its manifest in that run.
#[derive(Debug, Clone)]
struct SourceOccurrence {
    owner: EntityId,
    output: CodeRunRawOutput,
}

/// What a release of an arm's bodies reads again (FIX 9468): each
/// occurrence the arm was seeded with clean. These are the bodies of its
/// source run before the step, the stored replies of the step, and the
/// bodies of other runs its read context names (FIX 6352).
#[derive(Debug, Clone)]
pub struct ShadowReleaseSource {
    occurrences: Vec<SourceOccurrence>,
}

impl PreparedShadowStep {
    /// What a release of the bodies of an arm run from this step reads
    /// again (FIX 9468): each body frozen clean for the arm.
    #[must_use]
    pub fn release_source(&self) -> ShadowReleaseSource {
        let run = self.step.run;
        let own = self
            .frozen
            .iter()
            .chain(self.replies.iter().map(|reply| &reply.body))
            .map(|body| (run, body));
        let foreign = self.foreign.iter().map(|held| (held.owner, &held.body));
        let occurrences = own
            .chain(foreign)
            .filter(|(_, body)| body.bytes.is_some())
            .map(|(owner, body)| SourceOccurrence {
                owner,
                output: body.output.clone(),
            })
            .collect();
        ShadowReleaseSource { occurrences }
    }
}

impl ShadowReleaseSource {
    /// Why each body of the arm is withheld from a model now (FIX 9468):
    /// the first source occurrence that reads tainted in `vault`, by its
    /// secret's reason, else by its taint. `None` while each reads clean.
    fn withheld_now(&self, vault: &Vault) -> Result<Option<ShadowUnavailable>> {
        for occurrence in &self.occurrences {
            let (state, secret) = taint_now(vault, occurrence.owner, &occurrence.output)?;
            if state.is_tainted() {
                let cause = secret.as_deref().unwrap_or_else(|| taint_word(state));
                return Ok(Some(ShadowUnavailable::new(Reason::SourceWithheld, cause)));
            }
        }
        Ok(None)
    }
}

/// The whole body `body` of the arm whose store is `store`, released to a
/// model (FIX 9468). It is withheld while the arm marked it (its scan's
/// reason, or the taint it inherited), once the arm's source actor is gone,
/// once `admission` no longer admits its reader to the step's capture, and
/// while an occurrence of `source` reads tainted in `vault`. It is
/// `SourceMissing` when the store does not hold it. Its bytes are read from
/// the store as they were written, after each check.
///
/// # Errors
///
/// Storage errors, the admission's own among them, and a body that is not
/// its digest.
pub fn read_for_model(
    vault: &Vault,
    store: &ShadowBodyStore,
    source: &ShadowReleaseSource,
    body: &ShadowBodyRef,
    admission: &dyn ShadowSourceAdmission,
) -> Result<Outcome<Vec<u8>>> {
    if let Some(reason) = body.secret.as_deref() {
        return Ok(Err(ShadowUnavailable::new(Reason::SourceWithheld, reason)));
    }
    if let Some(withheld) = store.source_withheld() {
        return Ok(Err(withheld));
    }
    if !admission.admits_now(vault)? {
        return Ok(Err(lapsed()));
    }
    if let Some(withheld) = source.withheld_now(vault)? {
        return Ok(Err(withheld));
    }
    Ok(store
        .read(body.body)?
        .ok_or_else(|| ShadowUnavailable::new(Reason::SourceMissing, "body")))
}

/// The taint an arm's read of `output` reads under now (FIX 9468), for run
/// `owner`'s occurrence of it, frozen under `frozen` for the arm. This is
/// `frozen` when it is tainted, or while the occurrence reads clean in the
/// vault the arm's store is bound to; else the taint it reads under there
/// now. A store that no source binds reads under `frozen`, as its writes are
/// stored as they come. A store whose source vault is gone reads
/// `response_erased`.
///
/// # Errors
///
/// Storage errors.
pub(super) fn live_taint(
    store: &ShadowBodyStore,
    owner: EntityId,
    output: &CodeRunRawOutput,
    frozen: Taint,
) -> Result<Taint> {
    if frozen.0.is_tainted() {
        return Ok(frozen);
    }
    let Some(binding) = store.binding() else {
        return Ok(frozen);
    };
    let Some(vault) = binding.vault() else {
        return Ok((
            ArtifactTaintState::TaintedLive,
            Some(RESPONSE_ERASED.to_owned()),
        ));
    };
    let now = taint_now(&vault, owner, output)?;
    Ok(if now.0.is_tainted() { now } else { frozen })
}

/// The taint run `owner`'s occurrence of `output` reads under in `vault`
/// now, read as the step's freeze read it: its state, and its secret's
/// reason.
fn taint_now(vault: &Vault, owner: EntityId, output: &CodeRunRawOutput) -> Result<Taint> {
    Ok((
        vault.code_run_raw_output_taint_state(Some(owner), output)?,
        vault.code_run_raw_output_secret(Some(owner), output)?,
    ))
}
