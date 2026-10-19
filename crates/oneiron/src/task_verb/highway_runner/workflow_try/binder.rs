//! Who binds a saved workflow's run to a TASK, as the door that took the
//! request proved them (FIX 5316): the owner by his owner proof, an agent by
//! the live lease its host proved on the try it runs as, or a member by the
//! proof their door bound to their own verified slip. None comes from the
//! request, and no one is relabelled as the owner.

use crate::Vault;
use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatcher, SpendPayer, SpendScopeId, agent_dispatch_actor,
    decode_agent_dispatch_input,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::llm::run_admission::{DeclaredMaximum, MaximumShown};
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
    /// A member, by the proof their door bound to their own verified slip,
    /// rechecked as a person and never as the owner. Their run is a root
    /// they pay for under `funding`, the terms they accepted.
    Person {
        person: &'a AuthenticatedOwner,
        funding: &'a WorkflowFunding,
    },
}

/// The terms a member accepted for their bound run (FIX 5316): the cap they
/// set and were shown, when, and the root spend scope those terms name.
pub(crate) struct WorkflowFunding {
    pub(crate) scope: SpendScopeId,
    pub(crate) maximum: DeclaredMaximum,
    pub(crate) shown_at_ms: u64,
}

/// One run's binding to the TASK it realizes, as its intent stores it: the
/// TASK, its binder under that binder's class, and whether every step's
/// model calls must read a payer, as a member's run's must (FIX 5316).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkflowTaskBind {
    pub(crate) task: EntityId,
    pub(crate) bound_by: WriteActor,
    pub(crate) payer_required: bool,
}

impl WorkflowTaskBind {
    /// Whether the run settles its TASK on the right its bind recorded, with
    /// no fresh proof of its binder (FIX 5349): every binder but the owner
    /// at his own door, whose run settles as it always did.
    pub(crate) fn settles_on_bind(&self) -> bool {
        self.payer_required || self.bound_by.actor_class() != EdgeActorClass::Human
    }
}

impl WorkflowBinder<'_> {
    /// The binder's actor under its real class, proved in its own read
    /// transaction before the writer opens.
    pub(super) fn actor(&self, vault: &Vault) -> MemoryResult<WriteActor> {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        self.revalidate_in_txn(vault, &txn)
    }

    /// The same proof in `txn`: the owner's proof still his and still the
    /// owner's, the agent's lease still held on its own try, or the member
    /// still a live person on a slip still live.
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
            Self::Person { person, .. } => Ok(WriteActor::new(
                person.revalidate_person_in_txn(vault, txn)?,
                EdgeActorClass::Human,
            )),
        }
    }

    /// The run's real parent: none for an owner's or a member's root run,
    /// the leased try for an agent's.
    pub(super) fn parent(&self) -> Option<AttemptId> {
        match self {
            Self::Owner(_) | Self::Person { .. } => None,
            Self::Agent { lease, .. } => Some(lease.parent()),
        }
    }

    /// The binding `actor` makes of `task`: a member's requires a payer.
    pub(super) fn bind(&self, task: EntityId, actor: WriteActor) -> WorkflowTaskBind {
        WorkflowTaskBind {
            task,
            bound_by: actor,
            payer_required: matches!(self, Self::Person { .. }),
        }
    }

    /// Opens a member's root spend scope in the admitting writer, before the
    /// launch reserves under it: their accepted cap, shown when they say, with
    /// them as its payer and the one who took that yes. The same terms
    /// reopen the same root. The owner's and an agent's runs open none.
    pub(super) fn fund_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        actor: WriteActor,
    ) -> MemoryResult<()> {
        let Self::Person { funding, .. } = self else {
            return Ok(());
        };
        let payer = actor.entity_ref();
        AgentDispatcher::new(vault)
            .open_root_spend_scope_for_payer_in_txn(
                txn,
                funding.scope.clone(),
                funding.maximum.clone(),
                Some(MaximumShown {
                    at_ms: funding.shown_at_ms,
                }),
                SpendPayer {
                    party: payer,
                    granted_by: payer,
                    at_ms: funding.shown_at_ms,
                },
                crate::unix_seconds_now(),
            )
            .map_err(Error::from)?;
        Ok(())
    }

    /// The refusal when the intent key `key` already names `first` with
    /// another TASK, no TASK or another request: the owner's as it always
    /// read, an agent's or a member's naming the run it started first.
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
            Self::Person { .. } => format!(
                "{key} already names run {}, started with another request or other funding \
                 terms; repeat that request with its terms or use a new intent key",
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
