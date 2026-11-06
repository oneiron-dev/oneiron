//! A queued measurement's original source reader, owned by its question.

use std::cell::RefCell;

use super::EvalMeasurementRequest;
use super::doors::{bind_source_in_txn, source_in_txn};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::memory::stored_read::StoredReadContext;
use crate::memory::{Memory, MemoryResult};
use crate::skill_optimize::eval_set::EvalTaskRead;
use crate::skill_optimize::eval_set::released_task::attempt_read;
use crate::skill_optimize::eval_set::replay_input::{hydrate, released_case_in_txn};
use crate::{EntityId, Error, Vault};

/// The canonical question a measurement request queued, without serving
/// its sealed membership, task content or stored answers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalMeasurementRef {
    pub digest: String,
}

/// A leased measurement's source reader. The retained context permits only
/// the ordinary scoped task read; it exposes no general restored Memory.
pub struct EvalMeasurementSource<'v> {
    vault: &'v Vault,
    digest: [u8; 32],
    context: Option<StoredReadContext>,
    reader: RefCell<Option<Memory<'v>>>,
}

impl EvalMeasurementSource<'_> {
    /// Read a claimed case. A request with no bound source keeps its old
    /// kept-attempt path; it acquires no Coach or actor-wide source grant.
    pub fn released_eval_task(&self, case: &EntityId) -> MemoryResult<EvalTaskRead> {
        {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            let (_, member) = match released_case_in_txn(self.vault, &txn, &self.digest, case)? {
                Ok(released) => released,
                Err(reason) => return Ok(attempt_read(Err(reason))),
            };
            if member.repair_task.is_none() || self.context.is_none() {
                return Ok(attempt_read(hydrate(self.vault, &txn, member)?));
            }
        }
        let mut reader = self.reader.borrow_mut();
        if reader.is_none() {
            if let Some(context) = &self.context {
                *reader = Some(context.restore(self.vault)?);
            }
        }
        match reader.as_ref() {
            Some(reader) => reader.released_eval_task(&self.digest, case),
            None => unreachable!("a Repair source was bound above"),
        }
    }
}

impl Memory<'_> {
    /// Queue a paired measurement with this handle's original source read
    /// context. The owner authorizes the request write, never its reads.
    /// A pending unbound question binds its first source; repeated requests
    /// keep that source, and claimed or settled questions never change it.
    /// Every source read still checks current credential and room standing.
    pub fn request_eval_measurement(
        &self,
        owner: &AuthenticatedOwner,
        request: &EvalMeasurementRequest,
        now: u64,
    ) -> MemoryResult<[u8; 32]> {
        let source = StoredReadContext::of(self);
        self.vault().try_with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self.vault(), txn)?;
            self.recheck_host_action_in_txn(txn)?;
            let digest = self
                .vault()
                .request_eval_measurement_in_txn(txn, request, now)?;
            bind_source_in_txn(self.vault(), txn, &digest, source)?;
            Ok(digest)
        })
    }
}

impl Vault {
    /// Open the source reader for this leased Coach measurement, not an
    /// arbitrary caller-supplied digest. Restored facts are checked by the
    /// usual read lane; a missing or lapsed source is never an actor fallback.
    pub fn coach_eval_measurement_source(
        &self,
        attempt: &DreamerAdmittedAttempt,
    ) -> MemoryResult<EvalMeasurementSource<'_>> {
        let digest = self.coach_eval_measurement_target(attempt)?;
        let source = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            source_in_txn(self, &txn, &digest)?
        };
        Ok(EvalMeasurementSource {
            vault: self,
            digest,
            context: source,
            reader: RefCell::new(None),
        })
    }
}
