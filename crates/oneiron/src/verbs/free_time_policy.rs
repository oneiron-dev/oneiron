//! `vault.free_time.policy.set_as` (FIX 11424): an agent sets or clears one
//! agent's free-time policy under its own live Grant naming the act.
//!
//! The owner twin is `vault.free_time.policy.set`. This row's caller is the
//! handle's own agent, never the owner: its live Grant naming
//! `free_time_policy_set` builds [`ActAuthority::Agent`] through
//! `Vault::granted_act`, as the clustering judgments build theirs
//! (`memory::clustering::doors`, FIX 4650), and the engine door
//! ([`crate::dreamer_runner::free_time_policy_set_as`]) checks that Grant
//! again in its own write. Only an explicit verb listing names the act: a
//! Grant over every verb names none, as the sibling's Grant rule holds.

use crate::authority::{
    ActAuthority, NoStanding, OwnerActKind, PACT_STANDING_LAPSED,
    principal_standing_or_lapse_in_txn,
};
use crate::dreamer_runner::{FreeTimePolicySetRequest, FreeTimePolicyView};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::EdgeActorClass;

/// The verb a Grant lists to name an agent's free-time policy act: the
/// `OwnerActKind::FreeTimePolicy` grant verb L02's door judges by
/// (`FREE_TIME_POLICY_SET_VERB`), a set or a clear of any agent's policy.
const GRANT_VERB: &str = "free_time_policy_set";

/// `vault.free_time.policy.set_as` as the handle's own agent: the agent's
/// live Grant naming [`GRANT_VERB`] carries the set or clear, its Grant
/// checked again in the engine door's write. A caller that is no agent, an
/// agent with no standing Grant, and a Grant lapsed on its pact alone are
/// refused, and nothing is written.
pub fn free_time_policy_set_as_agent(
    memory: &Memory<'_>,
    input: FreeTimePolicySetRequest,
) -> MemoryResult<FreeTimePolicyView> {
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(refused("the caller is no agent"));
    }
    let agent = memory.actor();
    let vault = memory.vault();
    let grant = {
        let txn = vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        match principal_standing_or_lapse_in_txn(
            vault,
            &txn,
            agent,
            EdgeActorClass::Agent,
            GRANT_VERB,
        )
        .map_err(MemoryError::from)?
        {
            Ok(standing) => standing.grant.ok_or_else(|| refused("no live Grant names the act"))?,
            Err(NoStanding::PactStandingLapsed) => return Err(refused(PACT_STANDING_LAPSED)),
            Err(NoStanding::NotStanding) => {
                return Err(refused(
                    "no live Grant from a live owner names this agent and lists the verb",
                ));
            }
        }
    };
    let authority = ActAuthority::Agent(
        vault
            .granted_act(agent, grant, OwnerActKind::FreeTimePolicy)
            .map_err(MemoryError::from)?,
    );
    crate::dreamer_runner::free_time_policy_set_as(vault, &authority, &input)
        .map_err(MemoryError::from)
}

/// The row's refusal of a caller it does not admit.
fn refused(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "vault.free_time.policy.set_as takes an agent's own live Grant naming \
             {GRANT_VERB}: {why}"
        ),
        &[
            "Call vault.free_time.policy.set with the owner's own credential, or have \
             the owner grant this agent the verb by name.",
        ],
    )
}
