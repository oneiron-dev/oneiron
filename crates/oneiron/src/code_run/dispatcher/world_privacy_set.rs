//! `vault.worlds.privacy.set` (FIX 4480): the run's agent asks to change a
//! world's settings through the vault's world-privacy door, as itself. Within
//! a Grant line naming a tighten of the world the change applies; otherwise a
//! tighten waits as a proposal and a widen as an ask to the world's holders.
//! A run of the owner himself, whose host bound his proof, changes them as
//! his own say-so. An agent is never relabelled as the owner. A request the
//! run opens carries the credential lineage its host admitted it under (FIX
//! 4705), so no answer from that lineage settles it.

use crate::EdgeActorClass;
use crate::authority::{ActAuthority, ActSurface};
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{
    AGENT_VERB_SESSION_BOUND, AgentVerbAnswer, SelfDeniedResult, SelfDispatchOutcome, SelfEffect,
};
use crate::error::{Error, Result};
use crate::policy_model::{WorldPrivacySetInput, WorldPrivacySetOutput};

use super::HostSelfDispatcher;

/// A run whose actor is neither an agent nor the owner its host proved.
const WORLD_PRIVACY_NEEDS_AGENT: &str = "world_privacy_needs_agent_or_owner";

impl HostSelfDispatcher<'_> {
    /// The run's world-settings request, answered with what it came to: the
    /// receipt, the proposal or the ask. The world-privacy door checks the
    /// agent, its Grant and the holders in its own transaction. A run bound
    /// to a session is refused: the door writes the canonical vault.
    pub(super) fn dispatch_world_privacy_set(
        &self,
        input: &WorldPrivacySetInput,
    ) -> Result<SelfDispatchOutcome> {
        let refused = |code: &str| {
            SelfDispatchOutcome::Denied(SelfDeniedResult {
                effect: SelfEffect::WorldPrivacySet,
                outcome: code.to_owned(),
                reason_codes: Vec::new(),
            })
        };
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Ok(refused(AGENT_VERB_SESSION_BOUND));
        };
        let (world, settings, seen) = input.parse()?;
        let outcome = match (self.actor.actor_class(), self.owner_proof) {
            (EdgeActorClass::Agent, _) => vault.agent_world_privacy(
                &self.actor,
                self.opener_lineage.clone(),
                world,
                settings,
                seen,
            )?,
            (EdgeActorClass::Human, Some(owner))
                if owner.actor_for_read(vault)? == self.actor.entity_ref() =>
            {
                let surface = self.owner_surface.unwrap_or(ActSurface::ThisInstall);
                vault.set_world_privacy_by(
                    &ActAuthority::Owner(owner.clone(), surface),
                    world,
                    settings,
                    seen,
                )?
            }
            _ => return Ok(refused(WORLD_PRIVACY_NEEDS_AGENT)),
        };
        let output = serde_json::to_value(WorldPrivacySetOutput::from(&outcome))
            .map_err(|_| Error::InvariantViolation("world privacy answer encode"))?;
        // The answer names ids only, and serves no vault rows.
        Ok(SelfDispatchOutcome::AgentVerb(AgentVerbAnswer {
            output,
            rows: Some(Vec::new()),
        }))
    }
}
