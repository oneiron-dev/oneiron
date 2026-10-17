//! The host doors of the app's policy actions (OF-181):
//! `vault.settings.wake_policy.set`, `vault.settings.inference_defaults` and
//! `.replace`. `host_doors` re-exports them, so the generated HTTP facade
//! handler and the MCP dispatcher call them by the name every host door has.
//! Each runs the app's one action table ([`SharedActionExecutor::app`]) as
//! `POST /v1/core/actions/{verb}` does: as the credential's own principal,
//! reading under its read key. The wake policy also takes the owner's proof,
//! as `/v1/owner` takes it; the inference defaults leave the caller's Auto
//! ceiling to the table.
use std::sync::Arc;

use oneiron::WriteActor;
use oneiron::code_run::actions::{ActionHostBinding, AgentActionCall};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::policy_setting_doors::{
    self, InferenceDefaultsReplaceRequest, PolicyActionOutcome, WakePolicySetRequest,
};
use oneiron::task_verb::sdk::EmptyRequest;

use super::FacadeApiError;
use super::host_doors::internal;
use crate::actions::SharedActionExecutor;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Runs `call` from the app's table as the credential's principal, under
/// the owner's proof when `needs_owner`.
async fn run_action(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    call: AgentActionCall,
    needs_owner: bool,
) -> MemoryResult<PolicyActionOutcome> {
    let (actor, class) = super::facade_actor(auth).map_err(FacadeApiError::into_memory_error)?;
    let unbound = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} runs under the credential's own read key"),
            &["Present a verified slip paired to this principal."],
        )
    };
    let proof = auth.verified_slip().ok_or_else(unbound)?;
    let key = server
        .vault
        .credential_read_key(proof)?
        .ok_or_else(unbound)?
        .at(auth.locality());
    let owner = if needs_owner {
        Some(crate::api::owner_routes::owner(auth, server).map_err(|_| {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!("{verb} is the vault owner's"),
                &["Present the owner's own verified, unattenuated credential."],
            )
        })?)
    } else {
        None
    };
    let vault = Arc::clone(&server.vault);
    tokio::task::spawn_blocking(move || {
        let actor = WriteActor::new(actor, class);
        let principal = policy_setting_doors::action_principal(actor, key)?;
        let dispatch = SharedActionExecutor::app()?.execute_call(
            &vault,
            actor,
            &principal,
            &call,
            ActionHostBinding {
                verb_door: None,
                owner: owner.as_ref(),
                live_run: None,
            },
        )?;
        PolicyActionOutcome::from_dispatch(&dispatch)
    })
    .await
    .map_err(|_| internal(verb))?
    .map_err(MemoryError::from)
}

/// `vault.settings.wake_policy.set`: the owner sets the dreamer's wake
/// policy through `dreamer.wake_policy.set`.
pub(crate) async fn vault_settings_wake_policy_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WakePolicySetRequest,
) -> MemoryResult<PolicyActionOutcome> {
    let call = input.into_action()?;
    run_action(server, auth, "vault.settings.wake_policy.set", call, true).await
}

/// `vault.settings.inference_defaults`: the per-purpose inference defaults,
/// through `inference.defaults.read`.
pub(crate) async fn vault_settings_inference_defaults(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> MemoryResult<PolicyActionOutcome> {
    let call = policy_setting_doors::inference_defaults_read_action()?;
    run_action(
        server,
        auth,
        "vault.settings.inference_defaults",
        call,
        false,
    )
    .await
}

/// `vault.settings.inference_defaults.replace`: the whole table replaced,
/// through `inference.defaults.replace`.
pub(crate) async fn vault_settings_inference_defaults_replace(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: InferenceDefaultsReplaceRequest,
) -> MemoryResult<PolicyActionOutcome> {
    let call = input.into_action()?;
    run_action(
        server,
        auth,
        "vault.settings.inference_defaults.replace",
        call,
        false,
    )
    .await
}
