//! Owner-proof facade doors for configured hubs and pinned foreign imports.
//! The generated HTTP and MCP dispatchers both enter here; an agent never
//! borrows the owner's authority to admit a publisher or consent to an update.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{self, *};
use oneiron::EntityId;

use super::host_doors::{Listed, internal, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

async fn owner_call<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &AuthenticatedOwner) -> MemoryResult<(T, Vec<EntityId>)>
        + Send + 'static,
) -> Listed<T> {
    let owner = match crate::api::owner_routes::owner(auth, server) {
        Ok(owner) => owner,
        Err(_) => return refused(MemoryError::new(
            oneiron::memory::MEMORY_CODE_FORBIDDEN,
            format!("{verb} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )),
    };
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || match act(&server, &owner) {
        Ok((answer, rows)) => (Ok(answer), rows),
        Err(error) => refused(error),
    })
    .await
    .unwrap_or_else(|_| refused(internal(verb)))
}

fn pack_rows(receipt: &PackPutReceipt) -> Vec<EntityId> {
    receipt.receipt.as_ref().map_or_else(Vec::new, |receipt| {
        [&receipt.source_id, &receipt.hub_id].into_iter()
            .filter_map(|id| EntityId::from_hex(id).ok()).collect()
    })
}

/// `vault.skill_hubs.put`: The owner registers or revises a hub source; hub trust never grants activation authority.
pub(crate) async fn vault_skill_hubs_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillHubPutRequest,
) -> Listed<SkillHubConfigured> {
    owner_call(server, auth, "vault.skill_hubs.put", move |server, owner| {
        let answer = sdk::skill_hub_put_as_owner(server.vault(), owner, &input)?;
        let rows = vec![input.hub];
        Ok((answer, rows))
    }).await
}

/// `vault.skill_hubs.get`: Reads one configured hub as the owner.
pub(crate) async fn vault_skill_hubs_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillHubRequest,
) -> Listed<oneiron::skill_hub::SkillHubRecord> {
    owner_call(server, auth, "vault.skill_hubs.get", move |server, owner| {
        let answer = sdk::skill_hub_get_as_owner(server.vault(), owner, &input)?;
        let rows = vec![input.hub];
        Ok((answer, rows))
    }).await
}

/// `vault.skill_hubs.publishers.admit`: The owner admits a foreign publisher to offer candidates from one configured hub, and nothing else.
pub(crate) async fn vault_skill_hubs_publishers_admit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillPublisherRequest,
) -> Listed<SkillPublisherAdmission> {
    owner_call(server, auth, "vault.skill_hubs.publishers.admit", move |server, owner| {
        let answer = sdk::skill_publisher_admit_as_owner(server.vault(), owner, &input)?;
        let rows = vec![input.hub];
        Ok((answer, rows))
    }).await
}

/// `vault.skill_hubs.publishers.revoke`: The owner revokes the exact offer-only publisher grant; foreign hooks recheck it before running.
pub(crate) async fn vault_skill_hubs_publishers_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SkillPublisherRequest,
) -> Listed<HubConsentReceipt> {
    owner_call(server, auth, "vault.skill_hubs.publishers.revoke", move |server, owner| {
        let answer = sdk::skill_publisher_revoke_as_owner(server.vault(), owner, &input)?;
        let rows = vec![input.hub];
        Ok((answer, rows))
    }).await
}

/// `vault.skill_hubs.refs.get`: Reads one hub ref policy, pin and separate seen and trusted revisions as the owner.
pub(crate) async fn vault_skill_hubs_refs_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HubRefRequest,
) -> Listed<Option<oneiron::skill_hub::TrackedHubRef>> {
    owner_call(server, auth, "vault.skill_hubs.refs.get", move |server, owner| {
        let answer = sdk::hub_ref_get_as_owner(server.vault(), owner, &input)?;
        let rows = vec![input.hub];
        Ok((answer, rows))
    }).await
}

/// `vault.skill_hubs.refs.set`: The owner changes one hub ref policy and pin without fetching or trusting new bytes.
pub(crate) async fn vault_skill_hubs_refs_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HubRefSetRequest,
) -> Listed<oneiron::skill_hub::TrackedHubRef> {
    owner_call(server, auth, "vault.skill_hubs.refs.set", move |server, owner| {
        let answer = sdk::hub_ref_set_as_owner(server.vault(), owner, &input)?;
        let rows = vec![input.hub_ref.hub_id];
        Ok((answer, rows))
    }).await
}

/// `vault.packs.install`: The owner fetches a pinned hub pack as its foreign publisher; code stays Candidate and hooks wait for consent.
pub(crate) async fn vault_packs_install(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HubImportRequest,
) -> Listed<PackPutReceipt> {
    owner_call(server, auth, "vault.packs.install", move |server, owner| {
        let answer = sdk::hub_pack_install_as_owner(server.vault(), owner, &input)?;
        let rows = { let mut rows = pack_rows(&answer); rows.push(input.hub_ref.hub_id); rows };
        Ok((answer, rows))
    }).await
}

/// `vault.packs.sync`: The owner syncs a hub pack at its stored ref policy; wider hooks keep their old bindings until re-consent.
pub(crate) async fn vault_packs_sync(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HubPackRequest,
) -> Listed<PackPutReceipt> {
    owner_call(server, auth, "vault.packs.sync", move |server, owner| {
        let answer = sdk::hub_pack_sync_as_owner(server.vault(), owner, &input)?;
        let rows = pack_rows(&answer);
        Ok((answer, rows))
    }).await
}

/// `vault.packs.get`: Reads an installed pack and its exact source, pin, publisher and requested powers as the owner.
pub(crate) async fn vault_packs_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HubPackRequest,
) -> Listed<Option<oneiron::skill_hub::pack_catalog::PackInstallReceipt>> {
    owner_call(server, auth, "vault.packs.get", move |server, owner| {
        let answer = sdk::hub_pack_get_as_owner(server.vault(), owner, &input)?;
        let rows = answer.as_ref().map_or_else(Vec::new, |receipt| {
            [&receipt.source_id, &receipt.hub_id].into_iter()
                .filter_map(|id| EntityId::from_hex(id).ok()).collect()
        });
        Ok((answer, rows))
    }).await
}

/// `vault.skills.import`: The owner imports a pinned hub skill through scanning and publisher admission, pending its permission ask.
pub(crate) async fn vault_skills_import(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HubImportRequest,
) -> Listed<HubSkillImported> {
    owner_call(server, auth, "vault.skills.import", move |server, owner| {
        let answer = sdk::hub_skill_import_as_owner(server.vault(), owner, &input)?;
        let rows = vec![input.hub_ref.hub_id, answer.entity];
        Ok((answer, rows))
    }).await
}

/// `vault.skills.sync`: The owner syncs a hub skill under its ref policy; widening proposes without changing trusted capabilities.
pub(crate) async fn vault_skills_sync(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HubSkillRequest,
) -> Listed<HubSkillSyncReceipt> {
    owner_call(server, auth, "vault.skills.sync", move |server, owner| {
        let answer = sdk::hub_skill_sync_as_owner(server.vault(), owner, &input)?;
        let rows = std::iter::once(input.entity).chain(answer.proposal).collect();
        Ok((answer, rows))
    }).await
}

/// `vault.skills.receipts`: Reads every hub source and import receipt of a skill, and its held-out admission ruling, as the owner.
pub(crate) async fn vault_skills_receipts(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HubSkillRequest,
) -> Listed<HubSkillReceipts> {
    owner_call(server, auth, "vault.skills.receipts", move |server, owner| {
        let answer = sdk::hub_skill_receipts_as_owner(server.vault(), owner, &input)?;
        let rows = std::iter::once(input.entity).chain(answer.sources.iter().map(|source| source.hub_id)).collect();
        Ok((answer, rows))
    }).await
}

/// `vault.skills.permissions.approve`: The owner answers one imported skill permission ask at its exact hub source.
pub(crate) async fn vault_skills_permissions_approve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HubSkillPermissionRequest,
) -> Listed<HubConsentReceipt> {
    owner_call(server, auth, "vault.skills.permissions.approve", move |server, owner| {
        let answer = sdk::hub_skill_permissions_as_owner(server.vault(), owner, &input)?;
        let rows = vec![input.entity, input.hub_ref.hub_id];
        Ok((answer, rows))
    }).await
}

/// `vault.packs.hooks.bind`: The owner consents to the installed pack hook capabilities, including a widening update; publisher identity stays foreign.
pub(crate) async fn vault_packs_hooks_bind(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HubHookBindRequest,
) -> Listed<Vec<oneiron::EntityId>> {
    owner_call(server, auth, "vault.packs.hooks.bind", move |server, owner| {
        let answer = sdk::hub_hooks_bind_as_owner(server.vault(), owner, &input)?;
        let rows = answer.clone();
        Ok((answer, rows))
    }).await
}

/// `vault.packs.hooks.list`: Reads live pack hook bindings as the owner, excluding revoked foreign publisher grants.
pub(crate) async fn vault_packs_hooks_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmptyRequest,
) -> Listed<Vec<oneiron::task_verb::sdk::HubHookBindingRow>> {
    owner_call(server, auth, "vault.packs.hooks.list", move |server, owner| {
        let answer = sdk::hub_hooks_list_as_owner(server.vault(), owner, &input)?;
        let rows = answer.iter().flat_map(|row| [row.id, row.binding.code, row.binding.source]).collect();
        Ok((answer, rows))
    }).await
}

/// Qualification runs the server's real hook sandbox and preserves each replay.
/// Like `vault.hooks.replay`, it does not claim a complete list of replay reads.
pub(crate) async fn vault_packs_hooks_qualify(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HubHookQualifyRequest,
) -> MemoryResult<HubHookQualificationReceipt> {
    let (answer, _) = owner_call(
        server, auth, "vault.packs.hooks.qualify", move |server, owner| {
            let runtime = server.hook_runtime.get().cloned().ok_or_else(|| MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                "no hook sandbox runs on this server",
                &["Serve with fact hooks enabled on a build with the code sandbox."],
            ))?;
            let answer = sdk::hub_hooks_qualify_as_owner(
                server.vault(), owner, runtime.as_ref(), &input,
            )?;
            Ok((answer, Vec::new()))
        },
    ).await;
    answer
}
