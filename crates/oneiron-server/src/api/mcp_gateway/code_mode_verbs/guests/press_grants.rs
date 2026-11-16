//! The press policy the vault's send grant and standing action grants set
//! for a run's browser and desktop sends (`Vault::browser_send_policy`,
//! PLAN L4-03), and its live read at each classified send.
//! `browser_send_policy` and `VaultPressGrants` are its call surface.

use super::*;
use oneiron::consent::BrowserSendScope;
use oneiron_browser::PressGrants;

/// The press policy the vault's grants set for one run's browser before its
/// first call names its caller: a standing grant naming a browser effect
/// class covers it (no press), and a budgeted grant covers that many sends
/// as one reviewed batch. No grant leaves the floor: a press per send.
pub(super) fn browser_send_policy(server: &SyncServer) -> SendPolicy {
    vault_send_policy(&server.vault, None)
}

/// The press policy `vault`'s grants set now for the sends in `scope`
/// (`Vault::browser_send_policy`); the floor where they cannot be read.
fn vault_send_policy(vault: &oneiron::Vault, scope: Option<&BrowserSendScope>) -> SendPolicy {
    vault.browser_send_policy(scope).unwrap_or_else(|error| {
        tracing::warn!(%error, "the vault's browser press policy did not read; its sends take a press each");
        SendPolicy::default()
    })
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
            .flatten()
            .or_else(|| caller_project(caller));
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
        vault_send_policy(&self.vault, Some(&self.scope))
    }

    /// The same live read for a send that reports `audience` - the origin
    /// of the page it acted on, or for a mailto:/tel: link its href's
    /// protocol-level recipient (FIX 11907, 12395): only a grant whose
    /// audience names it covers the send. A send that reports none reads
    /// as [`Self::current`], keeping today's cover on that axis.
    fn current_for(&self, audience: Option<&str>) -> SendPolicy {
        let Some(audience) = audience else {
            return self.current();
        };
        let mut scope = self.scope.clone();
        scope.audience = Some(audience.to_owned());
        vault_send_policy(&self.vault, Some(&scope))
    }
}

/// The one project a credential caller's verified slip scopes it to (FIX
/// 11906): a slip whose audience names exactly one project acts in that
/// project, so the sends of a run with no host-known project are in it. A
/// pumped run's agent, a caller with no slip, and a slip whose audience is
/// every project, none or several name none.
fn caller_project(caller: &VerdictAsker) -> Option<oneiron::EntityId> {
    let auth = match caller {
        VerdictAsker::Connector(context) => context.auth.as_ref()?,
        VerdictAsker::Credential(auth, _) => auth,
        VerdictAsker::Agent(..) => return None,
    };
    match &auth.verified_slip()?.scope().audience {
        oneiron::federation::ScopeAxis::Some(projects) if projects.len() == 1 => {
            projects.first().map(|project| project.0)
        }
        _ => None,
    }
}
