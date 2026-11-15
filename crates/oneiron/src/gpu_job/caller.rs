//! Who may call the `vault.gpu.jobs.*` verbs (substrate behind grants, 9 Nov;
//! ASK L10-31-STARTER). Quoting a job, reading its status and listing jobs
//! are reads: the vault owner under their own proof, or an agent whose own
//! live Grant from a live owner names the verb. Starting a job, resuming it
//! and cancelling it spend or end the owner's money, so they take the owner's
//! own proof: the owner presses start on the quote that shows the maximum
//! (C2 01).
use crate::EdgeActorClass;
use crate::authority::{NoStanding, PACT_STANDING_LAPSED, principal_standing_or_lapse_in_txn};
use crate::consent::AuthenticatedOwner;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

/// The `vault.gpu.jobs.*` verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuJobVerb {
    Quote,
    Start,
    Status,
    List,
    Cancel,
}

impl GpuJobVerb {
    /// Every verb, in the order the verb table lists them.
    pub const ALL: [Self; 5] = [
        Self::Quote,
        Self::Start,
        Self::Status,
        Self::List,
        Self::Cancel,
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
        }
    }

    /// The verb named `name`, if it is one of these.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|verb| verb.name() == name)
    }

    /// Whether only the owner's own proof admits it.
    #[must_use]
    pub const fn is_owner_act(self) -> bool {
        matches!(self, Self::Start | Self::Cancel)
    }
}

impl Memory<'_> {
    /// Admits this handle's caller to `verb`. With `owner`, the caller's own
    /// proof decides: revalidated as a live owner of this vault and this
    /// handle's own human actor. Without one, `verb` must be a read, the
    /// caller this handle's agent, its presented credential still live, and
    /// one live Grant a live owner gave it must confer now and name the verb.
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
                "starting, resuming and cancelling a GPU job are the owner's own acts",
            ));
        }
        if let Some(slip) = self.presented_credential()
            && !vault.capability_slip_is_live_in_txn(&txn, slip)?
        {
            return Err(refused(verb, "the caller's credential is no longer live"));
        }
        let standing = match self.actor_class() {
            EdgeActorClass::Agent | EdgeActorClass::System => principal_standing_or_lapse_in_txn(
                vault,
                &txn,
                self.actor(),
                self.actor_class(),
                verb.name(),
            )?,
            EdgeActorClass::Human => Err(NoStanding::NotStanding),
        };
        match standing.map(|standing| standing.grant) {
            Ok(Some(_)) => Ok(()),
            Err(NoStanding::PactStandingLapsed) => Err(refused(verb, PACT_STANDING_LAPSED)),
            Ok(None) | Err(NoStanding::NotStanding) => Err(refused(
                verb,
                "no live Grant from a live owner names this agent and lists the verb",
            )),
        }
    }
}

/// The refusal of a caller `verb` does not admit.
fn refused(verb: GpuJobVerb, why: &str) -> MemoryError {
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
