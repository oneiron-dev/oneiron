//! The configured owner-policy snapshot on one authenticated private call.

use std::sync::Arc;

use oneiron::llm::decision::ProviderPin;
use oneiron::policy_model::PolicyModelConfig;

use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Called after the anonymous door's Read check. Its queue uses this same
/// server's live recipient hub, including the recipient's state projection.
/// No responder or Checker meter is borrowed, and no shared ladder is changed.
pub(super) fn owner_policy_config(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    human_pin: ProviderPin,
) -> PolicyModelConfig {
    let mut config = server
        .decision_host()
        .policy_model_config(&server.policy_doors.owner);
    let Some(decisions) = config.owner_decisions.as_deref() else {
        return config;
    };
    let recipients = crate::livequery::connection::Hub::for_server(server).private_human();
    let human = Arc::new(crate::api::private_human::RequestHumanQueue::new(
        server, auth, recipients,
    ));
    let vault = Arc::clone(server.vault());
    let auth = auth.clone();
    let run = crate::models::unrecorded_run(
        "anonymous-chat-owner-decisions",
        super::private_budget(server.ai.chat_settings().turn_budget_units),
        Some(server.host_account()),
        None,
    )
    .with_send_guard(Arc::new(move || auth.credential_is_live(&vault)));
    config.owner_decisions = Some(Arc::new(
        decisions.for_run_with_human(run, human, human_pin),
    ));
    config
}
