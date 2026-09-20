//! Host-bound UI and agent action executor over the engine's one verb registry.
use oneiron::code_run::{
    SelfDispatchOutcome,
    actions::{ActionRegistry, ActionVerbDefinition, AgentActionCall},
};
use oneiron::lens::{GeneratedUiValidatedAction, LensPrincipalBinding};
use oneiron::{Result, Vault, WriteActor};

/// Authentication binds the actor before entering this service. Neither a UI
/// event nor an agent's call body can choose the acting principal or ceiling.
pub struct SharedActionExecutor {
    registry: ActionRegistry,
}
impl SharedActionExecutor {
    pub fn new(registry: ActionRegistry) -> Self {
        Self { registry }
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
    ) -> Result<SelfDispatchOutcome> {
        self.registry.execute_ui(vault, actor, event, key)
    }
    pub fn execute_agent(
        &self,
        vault: &Vault,
        actor: WriteActor,
        principal: &LensPrincipalBinding,
        call: &AgentActionCall,
    ) -> Result<SelfDispatchOutcome> {
        self.registry.execute_agent(vault, actor, principal, call)
    }
}
