//! Who may act on one TASK (OF-220): the authority rule the task highway asks
//! before a verb moves a task. It reads only the TASK's immutable facts
//! (Owner, Assigned, HumanAssigned, Accepted) through `task_standing_in`,
//! never the body's display assignee.

use crate::error::{ClaimError, Error, Result};
use crate::task_authority::TaskStanding;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// The task verbs whose actor [`Vault::prove_task_actor_in_txn`] judges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskActorVerb {
    /// `tasks.accept`, and an agent's take of work addressed to it: the
    /// actor the TASK is assigned to, and only it. Being the assignee
    /// confers this verb and no other.
    Accept,
    /// `tasks.report`: the assignee, or the actor whose acceptance holds it.
    Report,
    /// `tasks.status`: the owner, the assignee or the taker. A cancelled
    /// TASK stays readable.
    Status,
    /// The owner's verbs (revising the brief, cancelling): the TASK's owner.
    Owner,
}

impl TaskActorVerb {
    /// Whether `actor` holds this verb's standing on the TASK.
    fn admits(self, standing: &TaskStanding, actor: EntityId) -> bool {
        let assignee = standing.assignee == Some(actor);
        let taker = standing.taker.is_some_and(|taker| taker.actor == actor);
        match self {
            Self::Accept => assignee,
            Self::Report => assignee || taker,
            Self::Status => standing.owner == actor || assignee || taker,
            Self::Owner => standing.owner == actor,
        }
    }

    fn refusal(self) -> &'static str {
        match self {
            Self::Accept => "only the actor this task is assigned to takes it",
            Self::Report => "only the task's assignee or taker reports on it",
            Self::Status => "only the task's parties read its status",
            Self::Owner => "only the task's owner runs this verb",
        }
    }
}

fn refused(reason: &'static str) -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority { reason })
}

impl Vault {
    /// Proves `actor` may run `verb` on `task` in the caller's transaction:
    /// the writer's live binding (`verify_write_actor_in_txn`), then the
    /// TASK's facts. A TASK no Owner fact proves, or one the actor is no
    /// party to, is not found; a party the verb does not admit, or any verb
    /// but [`TaskActorVerb::Status`] on a cancelled TASK, is refused.
    pub(crate) fn prove_task_actor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        task: EntityId,
        actor: &WriteActor,
        verb: TaskActorVerb,
    ) -> Result<TaskStanding> {
        self.verify_write_actor_in_txn(txn, actor)?;
        let standing = self
            .task_standing_in(txn, task)?
            .ok_or(Error::EntityNotFound)?;
        let actor = actor.entity_ref();
        if !TaskActorVerb::Status.admits(&standing, actor) {
            return Err(Error::EntityNotFound);
        }
        if !verb.admits(&standing, actor) {
            return Err(refused(verb.refusal()));
        }
        if standing.cancelled && verb != TaskActorVerb::Status {
            return Err(refused("a cancelled task takes no more work"));
        }
        Ok(standing)
    }
}
