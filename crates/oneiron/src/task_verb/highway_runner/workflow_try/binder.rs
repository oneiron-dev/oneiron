//! Who binds a saved workflow's run to a TASK, as the door that took the
//! request proved them (FIX 5316): the owner by his owner proof, or an agent
//! by the live lease its host proved on the try it runs as. Neither comes
//! from the request, and an agent is never relabelled as the owner.

use crate::Vault;
use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, agent_dispatch_actor, decode_agent_dispatch_input,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::edge::EdgeActorClass;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Error;
use crate::memory::{MemoryError, MemoryResult};
use crate::task_verb::HostBinding;
use crate::write_envelope::WriteActor;

/// The binding caller, with the proof its door checked.
pub(crate) enum WorkflowBinder<'a> {
    /// The owner, by the proof his door verified. His run is a root.
    Owner(&'a AuthenticatedOwner),
    /// An agent, by the lease its host proved on the try it runs as. That
    /// try is the run's real parent, and the run spends under its lease
    /// tree.
    Agent {
        actor: WriteActor,
        lease: &'a HostBinding,
    },
}

impl WorkflowBinder<'_> {
    /// The binder's actor under its real class, proved in its own read
    /// transaction before the writer opens.
    pub(super) fn actor(&self, vault: &Vault) -> MemoryResult<WriteActor> {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        self.revalidate_in_txn(vault, &txn)
    }

    /// The same proof in `txn`: the owner's proof still his and still the
    /// owner's, or the agent's lease still held on its own try.
    pub(super) fn revalidate_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> MemoryResult<WriteActor> {
        match self {
            Self::Owner(owner) => Ok(WriteActor::new(
                owner.revalidate_in_txn(vault, txn)?,
                EdgeActorClass::Human,
            )),
            Self::Agent { actor, lease } => {
                if lease_holds_in(vault, txn, *actor, lease)? {
                    Ok(*actor)
                } else {
                    Err(MemoryError::from(Error::Refused(
                        "self.workflows.dispatch_bound needs a live leased run; bind from an \
                         agent run that still holds its try's lease"
                            .to_owned(),
                    )))
                }
            }
        }
    }

    /// The run's real parent: none for the owner's root run, the leased try
    /// for an agent's.
    pub(super) fn parent(&self) -> Option<AttemptId> {
        match self {
            Self::Owner(_) => None,
            Self::Agent { lease, .. } => Some(lease.parent()),
        }
    }

    /// The refusal when the intent key `key` already names `first` with
    /// another TASK, no TASK or another request: the owner's as it always
    /// read, an agent's naming the run it started first.
    pub(super) fn retry_refusal(&self, key: &str, first: AttemptId) -> Error {
        Error::Refused(match self {
            Self::Owner(_) => format!(
                "{key} already names a run with another TASK, no TASK or another request; \
                 repeat that request or use a new intent key"
            ),
            Self::Agent { .. } => format!(
                "{key} already names run {}, started with another request; repeat that \
                 request or use a new intent key",
                bytes_to_hex_lower(first.as_bytes())
            ),
        })
    }
}

/// Whether `lease` still holds in `txn`: its try is leased to that owner at
/// that count, and is `actor`'s own agent dispatch.
fn lease_holds_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    lease: &HostBinding,
) -> MemoryResult<bool> {
    let Some(record) = AttemptQueue::new(vault).get_in_txn(txn, lease.parent())? else {
        return Ok(false);
    };
    if record.state != AttemptState::Leased
        || record.lease_owner.as_deref() != Some(lease.lease_owner())
        || record.attempt_count != lease.attempt_count()
    {
        return Ok(false);
    }
    Ok(decode_dreamer_attempt_payload(&record.payload)
        .ok()
        .filter(|payload| payload.attempt_type == AGENT_DISPATCH_ATTEMPT_TYPE)
        .and_then(|payload| decode_agent_dispatch_input(&payload.input).ok())
        .and_then(|input| agent_dispatch_actor(&input).ok())
        == Some(actor))
}
