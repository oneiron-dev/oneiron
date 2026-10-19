//! The owner's first-hub and bootstrap reads and explicit defaults re-import.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::skill_hub::{DefaultSkillHub, HubImportReceipt};
use oneiron::task_verb::sdk::{self, BootstrapSkillView, EmptyRequest};

use super::host_doors::Listed;
use super::hub_doors::owner_call;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_skills_bootstrap(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmptyRequest,
) -> Listed<Vec<BootstrapSkillView>> {
    owner_call(server, auth, "vault.skills.bootstrap", move |server, owner| {
        let answer = sdk::skill_bootstrap_as_owner(server.vault(), owner, &input)?;
        let rows = answer.iter().flat_map(BootstrapSkillView::rows).collect();
        Ok((answer, rows))
    })
    .await
}

pub(crate) async fn vault_skill_hubs_default_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmptyRequest,
) -> Listed<DefaultSkillHub> {
    owner_call(
        server,
        auth,
        "vault.skill_hubs.default.get",
        move |server, owner| {
            let answer = sdk::default_skill_hub_as_owner(server.vault(), owner, &input)?;
            let rows = vec![answer.hub];
            Ok((answer, rows))
        },
    )
    .await
}

// The public verb preserves the canon SDK spelling.
pub(crate) use vault_skills_restore_defaults as vault_skills_restoreDefaults;

pub(crate) async fn vault_skills_restore_defaults(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmptyRequest,
) -> Listed<Vec<HubImportReceipt>> {
    owner_call(
        server,
        auth,
        "vault.skills.restoreDefaults",
        move |server, owner| {
            let answer = sdk::skill_restore_defaults_as_owner(server.vault(), owner, &input)?;
            let rows = std::iter::once(oneiron::skill_hub::default_skill_hub_id()?)
                .chain(answer.iter().filter_map(|receipt| {
                    EntityId::from_hex(&receipt.entity).ok()
                }))
                .collect();
            Ok((answer, rows))
        },
    )
    .await
}
