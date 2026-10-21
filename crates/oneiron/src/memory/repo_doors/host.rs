//! The run binding of a public `vault.repo.*` call (FIX 6867, G1 PR3b): an
//! external agent's credential-bound host door on its own attached live run.
//!
//! The host resolved the attachment, verified the same credential and holds
//! the run's guard (`hold_live_run`); it hands the sealed lease proof it
//! holds here, never anything decoded from the request. The binding keeps
//! the proof's executor run, reads the TASK the leased try realizes, and
//! reads on the credential's own lane. Each door then judges the run
//! against its Grant in every snapshot and writer, as it judges a native
//! run's call.

use super::{REPO_PROVENANCE_REQUIRED, RepoRunBinding, refusal_error};
use crate::claim::ScopedReadActorKey;
use crate::federation::RepoAccessRefusal;
use crate::memory::{MemoryError, MemoryResult};
use crate::task_verb::HostBinding;
use crate::{EntityId, Vault, WriteActor};

impl RepoRunBinding {
    /// The binding of the live run `lease` seals, as `actor`, reading on
    /// `reader`: the host's held proof, read live. A lease that no longer
    /// holds, a try that realizes no TASK and a proof sealed with no
    /// executor run are a stale lease.
    ///
    /// # Errors
    /// The typed `repo_stale_lease` refusal, or a store failure.
    pub fn for_live_host(
        vault: &Vault,
        actor: WriteActor,
        lease: &HostBinding,
        reader: ScopedReadActorKey,
    ) -> MemoryResult<Self> {
        let stale = || refusal_error(RepoAccessRefusal::StaleLease);
        let record = match lease.leased_record(vault) {
            Ok(record) => record,
            Err(crate::Error::InvalidClaimBody(_)) => return Err(stale()),
            Err(error) => return Err(error.into()),
        };
        let task = record
            .task_ref
            .as_deref()
            .and_then(|hex| EntityId::from_hex(hex).ok())
            .ok_or_else(stale)?;
        Self::new(actor, lease.clone(), task, reader).ok_or_else(stale)
    }
}

/// A public run's proposal while its host holds no witness of the model
/// request the run serves: the typed `repo_provenance_required` hold. An
/// external agent's model call is its own; no author is made up for it.
#[must_use]
pub fn repo_provenance_unwitnessed() -> MemoryError {
    MemoryError::new(
        REPO_PROVENANCE_REQUIRED,
        "this run's host holds no witness of the model request it serves",
        &["A public run's proposal needs a request witness its host bound; the work is kept."],
    )
}
