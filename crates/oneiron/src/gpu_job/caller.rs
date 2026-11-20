//! Who may call the `vault.gpu.jobs.*` verbs (substrate behind grants, 9 Nov;
//! RULING L10-31-STARTER = B). Quoting a job, reading its status and listing
//! jobs are reads: the vault owner under their own proof, or an agent whose
//! own live Grant from a live owner names the verb. Starting, resuming and
//! cancelling spend or end the owner's money: the owner under their own proof
//! (pressing start on the quote that shows the maximum is C2 01's showing),
//! or an agent whose Grant names the verb, judged again by the act itself in
//! its own write: a start fits the per-job maximum the owner set beside that
//! Grant ([`GpuJobAllowance`](super::GpuJobAllowance)), and a resume or cancel
//! touches only a job the agent started. Setting that maximum is the owner's
//! own act.
use crate::EdgeActorClass;
use crate::authority::{
    NoStanding, PACT_STANDING_LAPSED, VerifiedSlip, principal_standing_or_lapse_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{EntityId, Vault};

/// The `vault.gpu.jobs.*` verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuJobVerb {
    Quote,
    Start,
    Status,
    List,
    Cancel,
    Allow,
}

impl GpuJobVerb {
    /// Every verb, in the order the verb table lists them.
    pub const ALL: [Self; 6] = [
        Self::Quote,
        Self::Start,
        Self::Status,
        Self::List,
        Self::Cancel,
        Self::Allow,
    ];

    /// The verb's registered name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Quote => "vault.gpu.jobs.quote",
            Self::Start => "vault.gpu.jobs.start",
            Self::Status => "vault.gpu.jobs.status",
            Self::List => "vault.gpu.jobs.list",
            Self::Cancel => "vault.gpu.jobs.cancel",
            Self::Allow => "vault.gpu.jobs.allow",
        }
    }

    /// The verb named `name`, if it is one of these.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|verb| verb.name() == name)
    }

    /// Whether only the owner's own proof admits it: setting the per-job
    /// maximum an agent's Grant carries.
    #[must_use]
    pub const fn is_owner_act(self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Whether it spends or ends the owner's money, so an agent's call is
    /// judged again by the act itself.
    #[must_use]
    pub const fn is_paid_act(self) -> bool {
        matches!(self, Self::Start | Self::Cancel)
    }
}

/// Who presses start, resume or cancel on a GPU job.
#[derive(Debug, Clone, Copy)]
pub enum GpuJobActor<'a> {
    /// The vault owner under their own proof.
    Owner(&'a AuthenticatedOwner),
    /// An agent under its own Grant (RULING L10-31-STARTER = B).
    Agent(&'a GpuJobAgent),
}

/// An agent caller of a paid GPU job act, as its own handle bound it. Only
/// [`Memory::gpu_job_agent`] makes one; the act judges its Grant again in its
/// own write.
#[derive(Debug, Clone)]
pub struct GpuJobAgent {
    actor: EntityId,
    class: EdgeActorClass,
    credential: Option<VerifiedSlip>,
}

impl GpuJobAgent {
    /// The agent's actor id.
    #[must_use]
    pub fn actor(&self) -> EntityId {
        self.actor
    }

    /// The live Grant that admits this agent to `verb` now, as the standing
    /// rule picks it (one Grant answers alone, never a union): its actor
    /// binding holds, its presented credential is still live, and one live
    /// Grant from a live owner names it and lists the verb.
    ///
    /// # Errors
    ///
    /// `forbidden` naming why; a store read failure.
    pub(super) fn grant_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        verb: GpuJobVerb,
    ) -> MemoryResult<EntityId> {
        crate::memory::verify_actor_binding_in_txn(vault, txn, self.actor, self.class)?;
        if let Some(slip) = &self.credential
            && !vault.capability_slip_is_live_in_txn(txn, slip)?
        {
            return Err(refused(verb, "the caller's credential is no longer live"));
        }
        let standing = match self.class {
            EdgeActorClass::Agent | EdgeActorClass::System => {
                principal_standing_or_lapse_in_txn(vault, txn, self.actor, self.class, verb.name())?
            }
            EdgeActorClass::Human => Err(NoStanding::NotStanding),
        };
        match standing.map(|standing| standing.grant) {
            Ok(Some(grant)) => Ok(grant),
            Err(NoStanding::PactStandingLapsed) => Err(refused(verb, PACT_STANDING_LAPSED)),
            Ok(None) | Err(NoStanding::NotStanding) => Err(refused(
                verb,
                "no live Grant from a live owner names this agent and lists the verb",
            )),
        }
    }
}

impl Memory<'_> {
    /// Admits this handle's caller to `verb`. With `owner`, the caller's own
    /// proof decides: revalidated as a live owner of this vault and this
    /// handle's own human actor. Without one, `verb` must not be the owner's
    /// own act, the caller is this handle's agent, its presented credential
    /// still live, and one live Grant a live owner gave it must confer now
    /// and name the verb. A start, resume or cancel is judged again by the
    /// act ([`GpuJobAgent`]).
    ///
    /// # Errors
    ///
    /// `forbidden` for a caller it does not admit; a store read failure.
    pub fn gpu_job_admits(
        &self,
        owner: Option<&AuthenticatedOwner>,
        verb: GpuJobVerb,
    ) -> MemoryResult<()> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        crate::memory::verify_actor_binding_in_txn(vault, &txn, self.actor(), self.actor_class())?;
        if let Some(owner) = owner {
            if owner.revalidate_in_txn(vault, &txn)? != self.actor()
                || self.actor_class() != EdgeActorClass::Human
            {
                return Err(refused(
                    verb,
                    "the owner proof does not belong to this caller",
                ));
            }
            return Ok(());
        }
        if verb.is_owner_act() {
            return Err(refused(
                verb,
                "setting the GPU job maximum an agent's Grant carries is the owner's own act",
            ));
        }
        self.gpu_job_agent()
            .grant_in_txn(vault, &txn, verb)
            .map(drop)
    }

    /// This handle's caller as an agent of a paid GPU job act.
    #[must_use]
    pub fn gpu_job_agent(&self) -> GpuJobAgent {
        GpuJobAgent {
            actor: self.actor(),
            class: self.actor_class(),
            credential: self.presented_credential().cloned(),
        }
    }
}

/// The refusal of a caller `verb` does not admit.
pub(super) fn refused(verb: GpuJobVerb, why: &str) -> MemoryError {
    let takes = if verb.is_owner_act() {
        "the vault owner's own proof"
    } else {
        "the vault owner's own proof or an agent's own Grant that names it"
    };
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{} takes {takes}: {why}", verb.name()),
        &["Call it as the vault owner, or name the verb in the agent's Grant."],
    )
}
