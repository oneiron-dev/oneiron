//! Who may act on one TASK (OF-220): the authority rule the task highway asks
//! before a verb moves a task. It first proves the caller is the actor it
//! names ([`TaskActorProof`]): by a live authority binding, or, for a caller
//! no binding names (the owner on a hosted root, an ask guest), by its own
//! slip or grant, or, for the in-process host's own caller, by store truth.
//! Then it reads only the TASK's immutable facts (Owner, Assigned,
//! HumanAssigned, Accepted) through `task_standing_in`, never the body's
//! display assignee. An engine runner's first take, which no fact names, is
//! proven by its live lease on the TASK's try instead
//! ([`TaskActorVerb::RunnerTake`]).

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::authority::VerifiedSlip;
use crate::error::{ClaimError, Error, Result};
use crate::task_authority::TaskStanding;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// What proves the caller of a task verb is the actor it names.
#[derive(Debug, Clone, Copy)]
pub(crate) enum TaskActorProof<'a> {
    /// A writer with a live authority binding in this vault
    /// (`verify_write_actor_in_txn`).
    Bound(&'a WriteActor),
    /// A caller no binding names, by the verified slip its request was
    /// admitted on: still live in this snapshot (a grant-bound slip's grant
    /// with it), and held by `actor` itself, or the host's own slip
    /// (`holder_ref` "host") when `actor` is the vault's embedded owner, as a
    /// hosted root's owner calls.
    Slip {
        actor: EntityId,
        slip: &'a VerifiedSlip,
    },
    /// An ask guest no slip names, by its own FEDERATION_GRANT: live, not
    /// withdrawn, an ask guest's grant whose member is `actor`, and
    /// conferring now. A host binds it as an [`AdmittedTaskGrant`]
    /// (`Memory::presented_task_grant`).
    Grant { actor: EntityId, grant: EntityId },
    /// The in-process host's own caller (`Memory::native_invocation`: no
    /// transport reached it, no slip or read proof is bound to it), such as
    /// the embedded SDK's owner or `as_actor`, an engine runner, or a host
    /// acting as an ask guest: the writer's store truth, and on a rooted
    /// vault no binding asked of an actor the log never bound
    /// ([`Vault::verify_native_write_actor_in_txn`]). Only a native surface
    /// builds it, and never after a slip or grant it presented failed.
    Native(&'a WriteActor),
}

/// A runner's lease on the try realizing one TASK, as its host binding
/// names it: the attempt, the lease owner and the attempt count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RunnerLease<'a> {
    pub(crate) attempt: AttemptId,
    pub(crate) lease_owner: &'a str,
    pub(crate) attempt_count: u32,
}

/// The FEDERATION_GRANT an ask minted for one guest, admitted for the
/// companion it names as member: what a host binds to that companion's
/// surface (`Memory::with_task_grant`) so its task verbs prove it by
/// [`TaskActorProof::Grant`], checked again on every verb. Only
/// [`Vault::admit_ask_guest_grant`] builds one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmittedTaskGrant {
    grant: EntityId,
    member: EntityId,
}

impl AdmittedTaskGrant {
    /// The FEDERATION_GRANT's id.
    #[must_use]
    pub const fn grant(&self) -> EntityId {
        self.grant
    }

    /// The companion the grant names as its member.
    #[must_use]
    pub const fn member(&self) -> EntityId {
        self.member
    }
}

impl Vault {
    /// Admits the guest grant the ask `ask` recorded for guest `person`, for
    /// that guest's companion `member`: only that ask's own grant, never
    /// another grant the companion holds, and only while it is live, not
    /// withdrawn, names `member` and confers now. An ask that recorded no
    /// grant for `person`, or one that no longer holds, is refused.
    pub fn admit_ask_guest_grant(
        &self,
        ask: crate::task_verb::TaskAskHandle,
        person: EntityId,
        member: EntityId,
    ) -> Result<AdmittedTaskGrant> {
        let txn = self.store.env.read_txn()?;
        let grant = crate::task_verb::ask_guest_grant_in(self, &txn, ask.group_ref, person)?
            .ok_or_else(|| refused("the ask recorded no grant for this guest"))?;
        let now = self.instant_in_txn(&txn)?.secs();
        self.require_live_guest_grant_in_txn(&txn, grant, &member.to_hex(), now)
            .map_err(|_| refused("the guest's grant does not prove this actor"))?;
        Ok(AdmittedTaskGrant { grant, member })
    }
}

/// The task verbs whose actor [`Vault::prove_task_actor_in_txn`] judges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskActorVerb<'a> {
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
    /// An engine runner's take of the TASK its leased try realizes: the
    /// Dreamer's, which no Assigned fact names, or an agent definition's,
    /// while `lease` still holds that try in this snapshot. The lease makes
    /// the runner a party; a TASK assigned to another actor is not its to
    /// take. The take's Accepted fact then makes it the taker, so its
    /// Report and Status prove as any taker's.
    RunnerTake(RunnerLease<'a>),
}

impl TaskActorVerb<'_> {
    /// Whether `actor` holds this verb's standing on the TASK.
    fn admits(self, standing: &TaskStanding, actor: EntityId) -> bool {
        let assignee = standing.assignee == Some(actor);
        let taker = standing.taker.is_some_and(|taker| taker.actor == actor);
        match self {
            Self::Accept => assignee,
            Self::Report => assignee || taker,
            Self::Status => standing.owner == actor || assignee || taker,
            Self::Owner => standing.owner == actor,
            Self::RunnerTake(_) => standing.assignee.is_none_or(|assignee| assignee == actor),
        }
    }

    fn refusal(self) -> &'static str {
        match self {
            Self::Accept => "only the actor this task is assigned to takes it",
            Self::Report => "only the task's assignee or taker reports on it",
            Self::Status => "only the task's parties read its status",
            Self::Owner => "only the task's owner runs this verb",
            Self::RunnerTake(_) => "a runner takes no task assigned to another actor",
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
    /// party to (for [`TaskActorVerb::RunnerTake`], one its lease does not
    /// hold), is not found; a party the verb does not admit, or any verb but
    /// [`TaskActorVerb::Status`] on a cancelled TASK, is refused.
    pub(crate) fn prove_task_actor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        task: EntityId,
        actor: &WriteActor,
        verb: TaskActorVerb<'_>,
    ) -> Result<TaskStanding> {
        self.prove_task_actor_by_in_txn(txn, task, TaskActorProof::Bound(actor), verb)
    }

    /// [`Vault::prove_task_actor_in_txn`] for any caller: `proof` proves the
    /// actor (a live binding, the caller's own slip or grant, or a native
    /// caller's store truth), then the TASK's facts judge it as there.
    pub(crate) fn prove_task_actor_by_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        task: EntityId,
        proof: TaskActorProof<'_>,
        verb: TaskActorVerb<'_>,
    ) -> Result<TaskStanding> {
        let actor = self.task_actor_proven_in_txn(txn, proof)?;
        let standing = self
            .task_standing_in(txn, task)?
            .ok_or(Error::EntityNotFound)?;
        let party = match verb {
            TaskActorVerb::RunnerTake(lease) => self.runner_lease_holds_in_txn(txn, task, lease)?,
            _ => TaskActorVerb::Status.admits(&standing, actor),
        };
        if !party {
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

    /// Whether `lease` still holds the try realizing `task` in this
    /// snapshot: the attempt realizes it, is running, and is leased to that
    /// owner at that attempt count.
    fn runner_lease_holds_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        task: EntityId,
        lease: RunnerLease<'_>,
    ) -> Result<bool> {
        let Some(record) = AttemptQueue::new(self).get_in_txn(txn, lease.attempt)? else {
            return Ok(false);
        };
        Ok(record.task_ref.as_deref() == Some(task.to_hex().as_str())
            && record.state.is_running()
            && record.lease_owner.as_deref() == Some(lease.lease_owner)
            && record.attempt_count == lease.attempt_count)
    }

    /// The actor `proof` proves in this snapshot.
    fn task_actor_proven_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        proof: TaskActorProof<'_>,
    ) -> Result<EntityId> {
        match proof {
            TaskActorProof::Bound(writer) => {
                self.verify_write_actor_in_txn(txn, writer)?;
                Ok(writer.entity_ref())
            }
            TaskActorProof::Slip { actor, slip } => {
                let claims = slip.claims();
                let holder = claims.holder_ref == actor.to_hex()
                    || (claims.holder_ref == "host"
                        && actor == crate::vault::embedded_owner_actor_id()?);
                let now = self.instant_in_txn(txn)?.secs();
                if !holder
                    || !self.capability_slip_is_live_in_txn(txn, slip)?
                    || self
                        .require_live_slip_grant_in_txn(txn, claims, now)
                        .is_err()
                {
                    return Err(refused("the caller's slip does not prove this actor"));
                }
                Ok(actor)
            }
            TaskActorProof::Grant { actor, grant } => {
                let now = self.instant_in_txn(txn)?.secs();
                self.require_live_guest_grant_in_txn(txn, grant, &actor.to_hex(), now)
                    .map_err(|_| refused("the caller's grant does not prove this actor"))?;
                Ok(actor)
            }
            TaskActorProof::Native(writer) => {
                self.verify_native_write_actor_in_txn(txn, writer)?;
                Ok(writer.entity_ref())
            }
        }
    }
}
