//! Host-bound UI and agent action executor over the engine's one verb registry.
use std::sync::LazyLock;

use oneiron::code_run::actions::{
    ActionDispatch, ActionHostBinding, ActionRegistry, ActionVerbDefinition, AgentActionCall,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::lens::{GeneratedUiValidatedAction, LensPrincipalBinding};
use oneiron::{Error, Result, Vault, WriteActor};

/// Authentication binds the actor before entering this service. Neither a UI
/// event nor an agent's call body can choose the acting principal or ceiling.
pub struct SharedActionExecutor {
    registry: ActionRegistry,
}
impl SharedActionExecutor {
    pub fn new(registry: ActionRegistry) -> Self {
        Self { registry }
    }
    /// The app's one table ([`ActionRegistry::app`]), built once per process:
    /// the server's buttons and its agents' calls are served from it alike.
    pub fn app() -> Result<&'static Self> {
        static APP: LazyLock<std::result::Result<SharedActionExecutor, String>> =
            LazyLock::new(|| {
                ActionRegistry::app()
                    .map(SharedActionExecutor::new)
                    .map_err(|error| error.to_string())
            });
        APP.as_ref()
            .map_err(|error| Error::InvalidConfig(error.clone()))
    }
    pub fn definitions(&self) -> impl Iterator<Item = &ActionVerbDefinition> {
        self.registry.definitions()
    }
    pub fn execute_ui(
        &self,
        vault: &Vault,
        actor: WriteActor,
        event: &GeneratedUiValidatedAction,
        key: &str,
    ) -> Result<ActionDispatch> {
        self.registry.execute_ui(vault, actor, event, key)
    }
    /// [`Self::execute_ui`] under the host's verb door and owner proof.
    pub fn execute_ui_bound(
        &self,
        vault: &Vault,
        actor: WriteActor,
        event: &GeneratedUiValidatedAction,
        key: &str,
        binding: ActionHostBinding<'_>,
    ) -> Result<ActionDispatch> {
        self.registry
            .execute_ui_bound(vault, actor, event, key, binding)
    }
    pub fn execute_agent(
        &self,
        vault: &Vault,
        actor: WriteActor,
        principal: &LensPrincipalBinding,
        call: &AgentActionCall,
    ) -> Result<ActionDispatch> {
        self.registry.execute_agent(vault, actor, principal, call)
    }
    /// An agent's call under an owner proof the host authenticated on its own.
    pub fn execute_agent_with_owner(
        &self,
        vault: &Vault,
        actor: WriteActor,
        principal: &LensPrincipalBinding,
        call: &AgentActionCall,
        owner: &AuthenticatedOwner,
    ) -> Result<ActionDispatch> {
        self.registry
            .execute_agent_with_owner(vault, actor, principal, call, owner)
    }
    /// One call from either caller, a person's app button or an agent's call,
    /// as the host's credential binds it.
    pub fn execute_call(
        &self,
        vault: &Vault,
        actor: WriteActor,
        principal: &LensPrincipalBinding,
        call: &AgentActionCall,
        binding: ActionHostBinding<'_>,
    ) -> Result<ActionDispatch> {
        self.registry
            .execute_call(vault, actor, principal, call, binding)
    }
}
