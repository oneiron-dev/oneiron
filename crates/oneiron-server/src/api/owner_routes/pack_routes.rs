//! `/v1/owner/packs`: the served `vault.packs.put` (ARCH-0080 §8, slice 1).
//! The owner installs a pack from a folder on this host or from its files,
//! lists what is installed, activates a held hub Candidate, and binds or
//! dials its hooks. Hub refs sync at their stored policy, and hub skills
//! import, sync, restore and read their receipts here (OF-213). The organ
//! inventory and the owner's organ build upload live here too (OF-575), and
//! so do the Slack app's manifest and install link (OF-519).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use oneiron::EntityId;
use oneiron::skill_hub::pack_catalog::{
    PackInstallDisposition, PackInstallReceipt, PackOrganBuild, PackOrganEntry, hub_pin,
};
use oneiron::skill_hub::{HubFile, HubPin, HubRef, HubSyncPolicy, MODEL_PACK_NAME, TrackedHubRef};
use oneiron::task_verb::sdk::{HubHookBindingRow, PackFileInput, decode_pack_files};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::OwnerError;
use crate::server::SyncServer;

mod line_chats;
pub(crate) mod schema;
mod setup_routes;
mod skill_routes;

use setup_routes::{
    PackSetupAnswerRequest, PackSetupKey, PackSetupReply, PackSetupVerifyRequest,
    SlackInstallRequest, setup_answer, setup_prepare, setup_verify, setup_view, slack_install,
    slack_manifest,
};
use skill_routes::{
    ActivationAskView, ActivationRequest, ConsentRow, ImportSkill, RestoreSkill, SkillRow,
    SkillSync, approve_skill_activation, approve_skill_permissions, import_skill,
    prepare_skill_activation, restore_default_skills, restore_skill, skill_receipts, sync_skill,
};

mod table;
pub(super) use self::table::owner_table;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct PutPack {
    /// An absolute folder on this host.
    #[serde(default)]
    path: Option<PathBuf>,
    /// The folder's files, when the caller sends them instead: each as text
    /// or as standard base64 bytes, the input `vault.packs.put` takes.
    #[serde(default)]
    files: Option<Vec<PackFileInput>>,
}

/// What one put did.
#[derive(Serialize, schemars::JsonSchema)]
struct PackPut {
    /// `installed`, `candidate` or `blocked`.
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt: Option<Box<PackInstallReceipt>>,
}

/// `GET /v1/owner/packs`: every active installation.
async fn installed(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<PackInstallReceipt>> {
    owner(&auth, &server)?;
    let packs = blocking(move || Ok(server.vault().installed_packs()?)).await?;
    Ok(Json(packs))
}

/// `POST /v1/owner/packs`: install a pack folder, or replace the one under
/// its name. The owner's put is the consent for the pack's hooks.
async fn put(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<PutPack>,
) -> OwnerReply<PackPut> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let host = Arc::clone(&server);
    let put = blocking(move || {
        let files = match (request.path, request.files) {
            (Some(path), None) => read_folder(&path)?,
            (None, Some(files)) => {
                decode_pack_files(files).map_err(|error| OwnerError::Invalid(error.to_string()))?
            }
            _ => {
                return Err(OwnerError::Invalid(
                    "send exactly one of path or files".to_owned(),
                ));
            }
        };
        Ok(PackPut::from(server.vault().put_pack(&owner, files)?))
    })
    .await?;
    measure_catalog_token_ratios(&host, &put);
    Ok(Json(put))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct InstallFromHub {
    /// A configured hub, as 32 hex.
    hub: String,
    /// The pack's folder in the hub.
    folder: String,
    /// `semver`, `tag`, `commit` or `content_hash`.
    pin_type: String,
    pin_value: String,
    /// The publisher admitted as a foreign actor for this hub.
    publisher: String,
}

/// `POST /v1/owner/packs/install`: fetch a pack from a configured hub at a
/// pin and install it. Code lands Candidate; hooks wait for
/// `/packs/hooks/bind`.
async fn install_from_hub(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<InstallFromHub>,
) -> OwnerReply<PackPut> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let host = Arc::clone(&server);
    let put = blocking(move || {
        let hub = oneiron::EntityId::from_hex(&request.hub)
            .map_err(|_| OwnerError::Invalid("hub is not an entity id".to_owned()))?;
        let pin = hub_pin(&request.pin_type, &request.pin_value)?;
        let disposition = server.vault().install_pack_from_hub(
            &owner,
            hub,
            &request.folder,
            pin,
            &request.publisher,
        )?;
        Ok(PackPut::from(disposition))
    })
    .await?;
    measure_catalog_token_ratios(&host, &put);
    Ok(Json(put))
}

impl From<PackInstallDisposition> for PackPut {
    fn from(disposition: PackInstallDisposition) -> Self {
        match disposition {
            PackInstallDisposition::Installed(receipt) => Self {
                outcome: "installed",
                reason: None,
                receipt: Some(receipt),
            },
            PackInstallDisposition::Candidate(receipt) => Self {
                outcome: "candidate",
                reason: None,
                receipt: Some(receipt),
            },
            PackInstallDisposition::Blocked { reason } => Self {
                outcome: "blocked",
                reason: Some(reason),
                receipt: None,
            },
        }
    }
}

/// Each row an install of the first-party model catalog brought in or
/// changed is counted on the fixed passage, in the background, as
/// `/v1/owner/model-catalog/sync` counts them (OF-577).
fn measure_catalog_token_ratios(server: &SyncServer, put: &PackPut) {
    if put.outcome == "installed"
        && put
            .receipt
            .as_ref()
            .is_some_and(|receipt| receipt.pack_name == MODEL_PACK_NAME)
        && let Some(ratios) = server.ai.model_runtime().token_ratios()
    {
        let vault = Arc::clone(server.vault());
        tokio::task::spawn_blocking(move || {
            if let Err(error) = ratios.measure_missing_blocking(&vault) {
                tracing::warn!(%error, "catalog token ratios were not measured");
            }
        });
    }
}

/// A pack folder's files, relative and `/`-separated, every one of them
/// whatever the folder's size (FIX 8202, Rule 5). Dot entries such as
/// `.git` are skipped.
pub(super) fn read_folder(root: &Path) -> Result<Vec<HubFile>, OwnerError> {
    if !root.is_absolute() {
        return Err(OwnerError::Invalid(
            "a pack path must be absolute".to_owned(),
        ));
    }
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|error| OwnerError::Host(error.into()))?;
        for entry in entries {
            let entry = entry.map_err(|error| OwnerError::Host(error.into()))?;
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            let kind = entry
                .file_type()
                .map_err(|error| OwnerError::Host(error.into()))?;
            let path = entry.path();
            if kind.is_dir() {
                pending.push(path);
                continue;
            }
            if !kind.is_file() {
                return Err(OwnerError::Invalid(
                    "a pack folder holds plain files only".to_owned(),
                ));
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|error| OwnerError::Host(error.into()))?
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let content = std::fs::read(&path).map_err(|error| OwnerError::Host(error.into()))?;
            files.push(HubFile::new(relative, content));
        }
    }
    Ok(files)
}

/// `GET /v1/owner/packs/hooks`: every live binding, enabled or not,
/// with the effective grant it reads under.
async fn hook_bindings(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<HubHookBindingRow>> {
    owner(&auth, &server)?;
    let rows = blocking(move || {
        Ok(server
            .vault()
            .pack_hook_bindings_with_grants()?
            .into_iter()
            .map(|(id, binding, grant)| HubHookBindingRow { id, binding, grant })
            .collect())
    })
    .await?;
    Ok(Json(rows))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct BindHooks {
    pack: String,
}

/// `POST /v1/owner/packs/hooks/bind`: the owner's consent binds an installed
/// pack's hooks; a hub install never does by itself.
async fn bind_hooks(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<BindHooks>,
) -> OwnerReply<Vec<String>> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let bound = blocking(move || {
        Ok(server
            .vault()
            .bind_pack_hooks(&owner, &request.pack)?
            .into_iter()
            .map(|id| id.to_hex())
            .collect())
    })
    .await?;
    Ok(Json(bound))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct QualifyHooks {
    /// The Candidate pack's source, as 32 hex (its receipt's `source_id`).
    source: String,
}

#[derive(Serialize, schemars::JsonSchema)]
struct HookQualification {
    #[serde(flatten)]
    put: PackPut,
    replays: Vec<oneiron::skill_hub::pack_catalog::PackHookReplay>,
}

/// `POST /v1/owner/packs/hooks/qualify`: a Candidate hub pack's hooks take
/// their test, a replay over past entries that lands nothing. A clean replay
/// installs the pack; the replays come back either way.
async fn qualify_hooks(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<QualifyHooks>,
) -> OwnerReply<HookQualification> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let qualified = blocking(move || {
        // The one sandbox, taken here when no runner took it: `--no-hooks`
        // stops the runner, not an explicit qualification (FIX 1122).
        let runtime = crate::commands::hook_sandbox(&server).map_err(|reason| {
            OwnerError::Refused(format!("no hook sandbox runs on this server: {reason}"))
        })?;
        let source = EntityId::from_hex(&request.source)
            .map_err(|_| OwnerError::Invalid("source is not an entity id".to_owned()))?;
        let qualified = server
            .vault()
            .qualify_pack_hooks(&owner, runtime.as_ref(), source)?;
        Ok(HookQualification {
            put: PackPut::from(qualified.disposition),
            replays: qualified.replays,
        })
    })
    .await?;
    Ok(Json(qualified))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct AgentWorld {
    /// The Candidate pack's source, as 32 hex (its receipt's `source_id`).
    source: String,
    /// The local world its agent runs in, as 32 hex; unset, the world its
    /// scope names, once the owner has created it.
    #[serde(default)]
    world: Option<String>,
}

/// `POST /v1/owner/packs/agent/world`: the owner's answer to a travelling
/// AgentPack held for its world (`needs_world`). The pack then installs and
/// its agent runs in that world.
async fn place_agent_world(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<AgentWorld>,
) -> OwnerReply<PackPut> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let placed = blocking(move || {
        let id = |hex: &str, what: &str| {
            EntityId::from_hex(hex)
                .map_err(|_| OwnerError::Invalid(format!("{what} is not an entity id")))
        };
        let source = id(&request.source, "source")?;
        let world = request
            .world
            .as_deref()
            .map(|world| id(world, "world"))
            .transpose()?;
        Ok(PackPut::from(
            server
                .vault()
                .place_pack_agent_world(&owner, source, world)?,
        ))
    })
    .await?;
    Ok(Json(placed))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ActivateCandidate {
    /// The Candidate pack's source, as 32 hex (its receipt's `source_id`).
    source: String,
}

/// `POST /v1/owner/packs/activate`: the owner activates a hub Candidate held
/// for its advisories, or for code that is organs only. The pack installs
/// unless another hold or a rule keeps it; its receipt's `owner_activated`
/// names the holds the owner lifted.
async fn activate_candidate(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ActivateCandidate>,
) -> OwnerReply<PackPut> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let host = Arc::clone(&server);
    let put = blocking(move || {
        let source = entity_id(&request.source, "source")?;
        Ok(PackPut::from(
            server.vault().activate_pack_candidate(&owner, source)?,
        ))
    })
    .await?;
    measure_catalog_token_ratios(&host, &put);
    Ok(Json(put))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct HookEnabled {
    /// The binding claim, as 32 hex.
    binding: String,
    enabled: bool,
}

/// `POST /v1/owner/packs/hooks/enabled`: the owner's dial on one binding.
async fn set_hook_enabled(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<HookEnabled>,
) -> OwnerReply<()> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    blocking(move || {
        let binding = oneiron::EntityId::from_hex(&request.binding)
            .map_err(|_| OwnerError::Invalid("binding is not an entity id".to_owned()))?;
        Ok(server
            .vault()
            .set_pack_hook_enabled(&owner, binding, request.enabled)?)
    })
    .await?;
    Ok(Json(()))
}

/// `POST /v1/owner/packs/remove`: the owner removes an installed pack. Its
/// receipt leaves the Active catalog and every hook binding of it stops; a
/// built-in goes back to its Candidate. Replies with the removed receipt.
async fn remove_pack(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<BindHooks>,
) -> OwnerReply<PackInstallReceipt> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let removed = blocking(move || Ok(server.vault().remove_pack(&owner, &request.pack)?)).await?;
    Ok(Json(removed))
}

/// `GET /v1/owner/packs/organs`: every organ of an Active installation, with
/// the platforms this vault holds a build for.
async fn pack_organs(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<PackOrganEntry>> {
    owner(&auth, &server)?;
    let organs = blocking(move || Ok(server.vault().pack_organs()?)).await?;
    Ok(Json(organs))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct PutOrganBuild {
    /// The staged pack source, as 32 hex.
    source: String,
    organ: String,
    platform: String,
    /// An absolute path to the build on this host.
    path: PathBuf,
}

/// `POST /v1/owner/packs/organs/build`: hold one organ build for a staged
/// pack source. The bytes must match the source's pin; holding grants nothing.
async fn put_organ_build(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<PutOrganBuild>,
) -> OwnerReply<PackOrganBuild> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let build = blocking(move || {
        let source = entity_id(&request.source, "source")?;
        if !request.path.is_absolute() {
            return Err(OwnerError::Invalid(
                "a build path must be absolute".to_owned(),
            ));
        }
        let bytes = std::fs::read(&request.path).map_err(|error| OwnerError::Host(error.into()))?;
        Ok(server.vault().put_pack_organ_build(
            &owner,
            source,
            &request.organ,
            &request.platform,
            &bytes,
        )?)
    })
    .await?;
    Ok(Json(build))
}

fn entity_id(hex: &str, what: &str) -> Result<EntityId, OwnerError> {
    EntityId::from_hex(hex).map_err(|_| OwnerError::Invalid(format!("{what} is not an entity id")))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefKey {
    /// A configured hub, as 32 hex.
    hub: String,
    /// The folder the ref names in that hub.
    r#ref: String,
}

/// One hub ref's policy, pin and the revisions seen and trusted.
#[derive(Serialize, schemars::JsonSchema)]
struct RefSyncView {
    hub: String,
    r#ref: String,
    sync_policy: &'static str,
    pin_type: &'static str,
    pin_value: Option<String>,
    latest_seen: Option<String>,
    latest_trusted: Option<String>,
}

impl From<TrackedHubRef> for RefSyncView {
    fn from(tracked: TrackedHubRef) -> Self {
        let pin_type = tracked.hub_ref.pin.pin_type();
        let pin_value = match tracked.hub_ref.pin {
            HubPin::Semver(value)
            | HubPin::Tag(value)
            | HubPin::Commit(value)
            | HubPin::ContentHash(value) => Some(value),
            HubPin::None => None,
        };
        Self {
            hub: tracked.hub_ref.hub_id.to_hex(),
            r#ref: tracked.hub_ref.ref_string,
            sync_policy: tracked.sync_policy.as_str(),
            pin_type,
            pin_value,
            latest_seen: tracked.latest_seen,
            latest_trusted: tracked.latest_trusted,
        }
    }
}

/// `GET /v1/owner/packs/ref-sync?hub=&ref=`: the ref's stored policy, or
/// null when it follows its installed pin.
async fn ref_sync(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<RefKey>, QueryRejection>,
) -> OwnerReply<Option<RefSyncView>> {
    owner(&auth, &server)?;
    let key = query_params(query)?;
    let view = blocking(move || {
        let hub = entity_id(&key.hub, "hub")?;
        Ok(server
            .vault()
            .hub_ref_sync(&hub, &key.r#ref)?
            .map(RefSyncView::from))
    })
    .await?;
    Ok(Json(view))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct SetRefSync {
    hub: String,
    r#ref: String,
    /// `pinned-commit`, `pinned-ref` or `content-hash-frozen`.
    sync_policy: String,
    /// `commit`, `tag`, `semver` or `content_hash`, fitting the policy.
    pin_type: String,
    pin_value: String,
}

/// `PUT /v1/owner/packs/ref-sync`: set one ref's policy and pin. Nothing is
/// fetched until the next sync.
async fn set_ref_sync(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<SetRefSync>,
) -> OwnerReply<RefSyncView> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let view = blocking(move || {
        let hub = entity_id(&request.hub, "hub")?;
        let policy = HubSyncPolicy::parse(&request.sync_policy)
            .ok_or_else(|| OwnerError::Invalid("unknown sync_policy".to_owned()))?;
        let pin = hub_pin(&request.pin_type, &request.pin_value)?;
        let reference = HubRef::new(hub, request.r#ref, pin)?;
        Ok(RefSyncView::from(
            server.vault().set_hub_ref_sync(&owner, reference, policy)?,
        ))
    })
    .await?;
    Ok(Json(view))
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct SyncPack {
    /// The installed pack's name.
    name: String,
}

/// `POST /v1/owner/packs/sync`: refetch an installed hub pack at its ref's
/// policy and install it. A source with advisories lands Candidate.
async fn sync_pack(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<SyncPack>,
) -> OwnerReply<PackPut> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let host = Arc::clone(&server);
    let put = blocking(move || {
        Ok(PackPut::from(
            server.vault().sync_pack_from_hub(&owner, &request.name)?,
        ))
    })
    .await?;
    measure_catalog_token_ratios(&host, &put);
    Ok(Json(put))
}
