//! The press policy the vault's standing action grants set for a run's
//! browser and desktop sends, and its live read at each classified send.
//! `browser_send_policy` and `VaultPressGrants` are its call surface.

use super::*;
use oneiron::consent::BrowserSendScope;
use oneiron_browser::PressGrants;

/// The press policy the vault's standing action grants set for one run's
/// browser: a grant naming a browser effect class covers it (no press),
/// and a budgeted grant covers that many sends as one reviewed batch.
/// No grant leaves the floor: a press per send.
pub(super) fn browser_send_policy(server: &SyncServer) -> SendPolicy {
    grants_policy(&server.vault, None)
}

/// The press policy `vault`'s standing action grants set now, as
/// [`browser_send_policy`] reads it; the floor where they cannot be read.
/// Where the sends' `scope` is known, a grant counts only when it covers a
/// send from it (FIX 10422).
fn grants_policy(vault: &oneiron::Vault, scope: Option<&BrowserSendScope>) -> SendPolicy {
    let mut policy = SendPolicy::default();
    let Ok(grants) = vault.active_standing_consent_grants() else {
        return policy;
    };
    for grant in &grants {
        let StandingConsentGrant::Action(_) = grant else {
            continue;
        };
        let bound = grant.bound();
        let BoundClass::Action(class) = bound.class() else {
            continue;
        };
        let class = class.as_str();
        if !EFFECT_CLASSES.contains(&class) || SendPolicy::person_only(class) {
            continue;
        }
        // A grant covers only the sends inside the scope its owner gave it:
        // its actor, the project and the audience it names (FIX 10422).
        if scope.is_some_and(|scope| !scope.covered_by(grant, class)) {
            continue;
        }
        let budget = match bound.envelope() {
            BoundEnvelope::Action(envelope) => envelope.budget(),
            BoundEnvelope::Disclosure(_) => None,
        };
        match budget {
            Some(count) => {
                policy.modes.insert(class.to_owned(), PressMode::PerBatch);
                policy
                    .batch
                    .insert(class.to_owned(), u32::try_from(count).unwrap_or(u32::MAX));
            }
            None => {
                policy.modes.insert(class.to_owned(), PressMode::None);
            }
        }
    }
    policy
}

/// The vault's grants, read again at each classified browser send (FIX
/// 4613): a grant revoked during the run covers no later send, and only a
/// grant whose scope covers the call's sends covers any (FIX 10422).
pub(super) struct VaultPressGrants {
    vault: Arc<oneiron::Vault>,
    scope: BrowserSendScope,
}

impl VaultPressGrants {
    /// The live read for the sends `caller` makes from run `run`'s browser:
    /// its verified actor, in the project the run sends in. A project the
    /// vault cannot read leaves the sends in none, which a grant naming a
    /// project does not cover.
    pub(super) fn new(
        vault: &Arc<oneiron::Vault>,
        caller: &VerdictAsker,
        run: oneiron::EntityId,
    ) -> Self {
        let (actor, actor_class) = super::super::secret_custody::caller_actor(caller);
        let project = vault
            .browser_run_project(run)
            .inspect_err(|error| {
                tracing::warn!(%error, "a browser run's project did not read; its sends name none");
            })
            .ok()
            .flatten();
        Self {
            vault: Arc::clone(vault),
            scope: BrowserSendScope {
                actor,
                actor_class,
                project,
                // A send reports its own counterparty as it is classified
                // (FIX 11907); the call's scope itself names none.
                audience: None,
            },
        }
    }
}

impl PressGrants for VaultPressGrants {
    fn current(&self) -> SendPolicy {
        grants_policy(&self.vault, Some(&self.scope))
    }

    /// The same live read for a send that reports `audience` - the origin
    /// of the page it acted on (FIX 11907): only a grant whose audience
    /// names it covers the send. A send that reports none reads as
    /// [`Self::current`], keeping today's cover on that axis.
    fn current_for(&self, audience: Option<&str>) -> SendPolicy {
        let Some(audience) = audience else {
            return self.current();
        };
        let mut scope = self.scope.clone();
        scope.audience = Some(audience.to_owned());
        grants_policy(&self.vault, Some(&scope))
    }
}
