//! Agent-binding fixture for the warm authority-view Grant regression.

use crate::authority::HostSlipIssuer;
use crate::{EdgeActorClass, EntityId, Result, Vault, WriteActor};

/// Binds the fixture's agent under the host key and observes its write frontier.
///
/// This rebinds the host key away from the embedded owner. Complete the
/// owner's world creation and Grant mint before calling it.
///
/// # Errors
///
/// The existing fixture binder's or write-actor verifier's refusal.
pub fn bind_agent(vault: &Vault, issuer: &HostSlipIssuer, agent: EntityId) -> Result<WriteActor> {
    vault.bind_host_actor_for_test(issuer, agent, "agent")?;
    vault.observed_write_actor(WriteActor::new(agent, EdgeActorClass::Agent))
}

/// How many times this thread has loaded the stored authority history to
/// judge a refused agent world edit's past Grant standing (FIX 4703): the
/// warm reads of one authority generation load it once, not on every read
/// (FIX 22382, review P2-1 of #7078).
#[must_use]
pub fn past_standing_history_loads() -> usize {
    crate::authority::past_standing_history_loads_for_test()
}
