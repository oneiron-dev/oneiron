//! `/v1/owner/packs`: the served `vault.packs.put` (ARCH-0080 §8, slice 1).
//! The owner installs a pack from a folder on this host or from its files,
//! lists what is installed, and binds or dials its hooks. Hub refs sync at
//! their stored policy, and hub skills import, sync, restore and read their
//! receipts here (OF-213). The organ inventory and the owner's organ build
//! upload live here too (OF-575), and so do the Slack app's manifest and
//! install link (OF-519).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path as UrlPath, Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::EntityId;
use oneiron::consent::ConsentReceipt;
use oneiron::skill_hub::pack_catalog::{
    MAX_ORGAN_BUILD_BYTES, PackHookBinding, PackInstallDisposition, PackInstallReceipt,
    PackOrganBuild, PackOrganEntry, hub_pin,
};
use oneiron::skill_hub::{
    HubAdmissionReceipt, HubAskSurface, HubFile, HubImportReceipt, HubPin, HubRef,
    HubSyncDisposition, HubSyncPolicy, TrackedHubRef,
};
use serde::{Deserialize, Serialize};

use oneiron::lens::{GeneratedUiCard, GeneratedUiStateSnapshot};
use oneiron::skill_hub::pack_catalog::{PackSetupAnswer, PackSetupCardAction, PackSetupView};

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::builtin_host::{
    HostConnectionChecks, ProviderSetup, public_origin, slack_app_manifest, start_slack_install,
};
use crate::owner::OwnerError;
use crate::server::SyncServer;

/// A folder read from disk stops here; the pack source applies its own,
/// tighter bounds after.
const MAX_FOLDER_FILES: usize = 1024;
/// Organ builds ride in the folder and leave the source as blob assets.
const MAX_FOLDER_BYTES: u64 = 256 * 1024 * 1024;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/packs", get(installed).post(put))
        .route("/packs/install", post(install_from_hub))
        .route("/packs/setup", get(setup_view))
        .route("/packs/setup/prepare", post(setup_prepare))
        .route("/packs/setup/answer", post(setup_answer))
        .route("/packs/setup/verify", post(setup_verify))
        .route("/packs/slack/manifest", get(slack_manifest))
        .route("/packs/slack/install", post(slack_install))
        .route("/packs/hooks", get(hook_bindings))
        .route("/packs/hooks/bind", post(bind_hooks))
        .route("/packs/hooks/enabled", post(set_hook_enabled))
        .route("/packs/remove", post(remove_pack))
        .route("/packs/ref-sync", get(ref_sync).put(set_ref_sync))
        .route("/packs/sync", post(sync_pack))
        .route("/packs/organs", get(pack_organs))
        .route("/packs/organs/build", post(put_organ_build))
        .route("/packs/skills/import", post(import_skill))
        .route("/packs/skills/restore", post(restore_skill))
        .route(
            "/packs/skills/restore-defaults",
            post(restore_default_skills),
        )
        .route("/packs/skills/{entity}/sync", post(sync_skill))
        .route(
            "/packs/skills/{entity}/permissions/approve",
            post(approve_skill_permissions),
        )
        .route("/packs/skills/{entity}/receipts", get(skill_receipts))
        .route(
            "/packs/skills/{entity}/activation/prepare",
            post(prepare_skill_activation),
        )
        .route(
            "/packs/skills/{entity}/activation/approve",
            post(approve_skill_activation),
        )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackFile {
    /// Relative to the pack folder, `/`-separated.
    path: String,
    text: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PutPack {
    /// An absolute folder on this host.
    #[serde(default)]
    path: Option<PathBuf>,
    /// The folder's files, when the caller sends them instead.
    #[serde(default)]
    files: Option<Vec<PackFile>>,
}

/// What one put did.
#[derive(Serialize)]
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
    payload: Result<Json<PutPack>, JsonRejection>,
) -> OwnerReply<PackPut> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let put = blocking(move || {
        let files = match (request.path, request.files) {
            (Some(path), None) => read_folder(&path)?,
            (None, Some(files)) => files
                .into_iter()
                .map(|file| HubFile::new(file.path, file.text.into_bytes()))
                .collect(),
            _ => {
                return Err(OwnerError::Invalid(
                    "send exactly one of path or files".to_owned(),
                ));
            }
        };
        Ok(PackPut::from(server.vault().put_pack(&owner, files)?))
    })
    .await?;
    Ok(Json(put))
}

#[derive(Debug, Deserialize)]
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
    payload: Result<Json<InstallFromHub>, JsonRejection>,
) -> OwnerReply<PackPut> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
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

/// A pack folder's files, relative and `/`-separated. Dot entries such as
/// `.git` are skipped.
fn read_folder(root: &Path) -> Result<Vec<HubFile>, OwnerError> {
    if !root.is_absolute() {
        return Err(OwnerError::Invalid(
            "a pack path must be absolute".to_owned(),
        ));
    }
    let mut files = Vec::new();
    let mut total = 0_u64;
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
            total += entry
                .metadata()
                .map_err(|error| OwnerError::Host(error.into()))?
                .len();
            if files.len() >= MAX_FOLDER_FILES || total > MAX_FOLDER_BYTES {
                return Err(OwnerError::Invalid(
                    "the pack folder is too large".to_owned(),
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

/// `GET /v1/owner/packs/hooks`: every hook binding, enabled or not.
async fn hook_bindings(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<HookBindingRow>> {
    owner(&auth, &server)?;
    let rows = blocking(move || {
        Ok(server
            .vault()
            .pack_hook_bindings()?
            .into_iter()
            .map(|(id, binding)| HookBindingRow {
                id: id.to_hex(),
                binding,
            })
            .collect())
    })
    .await?;
    Ok(Json(rows))
}

#[derive(Serialize)]
struct HookBindingRow {
    /// The binding claim, as 32 hex.
    id: String,
    binding: PackHookBinding,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindHooks {
    pack: String,
}

/// `POST /v1/owner/packs/hooks/bind`: the owner's consent binds an installed
/// pack's hooks; a hub install never does by itself.
async fn bind_hooks(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<BindHooks>, JsonRejection>,
) -> OwnerReply<Vec<String>> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
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

#[derive(Debug, Deserialize)]
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
    payload: Result<Json<HookEnabled>, JsonRejection>,
) -> OwnerReply<()> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
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
    payload: Result<Json<BindHooks>, JsonRejection>,
) -> OwnerReply<PackInstallReceipt> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
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

#[derive(Debug, Deserialize)]
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
    payload: Result<Json<PutOrganBuild>, JsonRejection>,
) -> OwnerReply<PackOrganBuild> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let build = blocking(move || {
        let source = entity_id(&request.source, "source")?;
        if !request.path.is_absolute() {
            return Err(OwnerError::Invalid(
                "a build path must be absolute".to_owned(),
            ));
        }
        let length = std::fs::metadata(&request.path)
            .map_err(|error| OwnerError::Host(error.into()))?
            .len();
        if length > MAX_ORGAN_BUILD_BYTES {
            return Err(OwnerError::Invalid(
                "the organ build is too large".to_owned(),
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
#[derive(Serialize)]
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

#[derive(Debug, Deserialize)]
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
    payload: Result<Json<SetRefSync>, JsonRejection>,
) -> OwnerReply<RefSyncView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
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

#[derive(Debug, Deserialize)]
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
    payload: Result<Json<SyncPack>, JsonRejection>,
) -> OwnerReply<PackPut> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let put = blocking(move || {
        Ok(PackPut::from(
            server.vault().sync_pack_from_hub(&owner, &request.name)?,
        ))
    })
    .await?;
    Ok(Json(put))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportSkill {
    /// A shipped library subtree, imported at the released commit.
    #[serde(default)]
    subtree: Option<String>,
    /// Else a configured hub, as 32 hex, with the fields below.
    #[serde(default)]
    hub: Option<String>,
    #[serde(default)]
    folder: Option<String>,
    #[serde(default)]
    pin_type: Option<String>,
    #[serde(default)]
    pin_value: Option<String>,
    #[serde(default)]
    publisher: Option<String>,
}

#[derive(Serialize)]
struct SkillRow {
    /// The skill, as 32 hex.
    entity: String,
}

fn skill_row(entity: EntityId) -> SkillRow {
    SkillRow {
        entity: entity.to_hex(),
    }
}

/// `POST /v1/owner/packs/skills/import`: import a shipped library skill, or
/// a hub skill at a pin. A hub skill lands Candidate behind one permission
/// ask; its dependency advisories land with it.
async fn import_skill(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ImportSkill>, JsonRejection>,
) -> OwnerReply<SkillRow> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let row = blocking(move || {
        let vault = server.vault();
        let at = vault.now_recorded_at();
        let occurred = oneiron::TimeRange { start: at, end: at };
        let entity = match request {
            ImportSkill {
                subtree: Some(subtree),
                hub: None,
                folder: None,
                pin_type: None,
                pin_value: None,
                publisher: None,
            } => vault.import_default_hub_skill(&subtree, occurred, at)?,
            ImportSkill {
                subtree: None,
                hub: Some(hub),
                folder: Some(folder),
                pin_type: Some(pin_type),
                pin_value: Some(pin_value),
                publisher: Some(publisher),
            } => vault.import_skill_from_hub_ref(
                &owner,
                entity_id(&hub, "hub")?,
                &folder,
                hub_pin(&pin_type, &pin_value)?,
                &publisher,
            )?,
            _ => {
                return Err(OwnerError::Invalid(
                    "send a subtree, or hub, folder, pin_type, pin_value and publisher".to_owned(),
                ));
            }
        };
        Ok(skill_row(entity))
    })
    .await?;
    Ok(Json(row))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreSkill {
    subtree: String,
}

/// `POST /v1/owner/packs/skills/restore`: re-import a deleted or retired
/// library skill as a fresh Candidate; an unchanged one is left alone.
async fn restore_skill(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RestoreSkill>, JsonRejection>,
) -> OwnerReply<SkillRow> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let row = blocking(move || {
        let at = server.vault().now_recorded_at();
        let occurred = oneiron::TimeRange { start: at, end: at };
        Ok(skill_row(server.vault().restore_default_hub_skill(
            &owner,
            &request.subtree,
            occurred,
            at,
        )?))
    })
    .await?;
    Ok(Json(row))
}

/// `POST /v1/owner/packs/skills/restore-defaults`: restore every missing or
/// retired embedded default as a fresh Candidate.
async fn restore_default_skills(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<SkillRow>> {
    let owner = owner(&auth, &server)?;
    let rows = blocking(move || {
        let at = server.vault().now_recorded_at();
        let occurred = oneiron::TimeRange { start: at, end: at };
        Ok(server
            .vault()
            .restore_default_skills(&owner, occurred, at)?
            .into_iter()
            .map(skill_row)
            .collect())
    })
    .await?;
    Ok(Json(rows))
}

/// What one skill sync did.
#[derive(Serialize)]
struct SkillSync {
    /// `applied`, `proposed` or `refused_by_policy`.
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    proposal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval: Option<&'static str>,
}

/// `POST /v1/owner/packs/skills/{entity}/sync`: refetch a hub skill at its
/// ref's stored policy. Same or narrower bytes apply; widening proposes.
async fn sync_skill(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(entity): UrlPath<String>,
) -> OwnerReply<SkillSync> {
    let owner = owner(&auth, &server)?;
    let sync = blocking(move || {
        let entity = entity_id(&entity, "entity")?;
        Ok(
            match server.vault().sync_skill_from_hub_ref(&owner, &entity)? {
                HubSyncDisposition::Applied => SkillSync {
                    outcome: "applied",
                    proposal: None,
                    approval: None,
                },
                HubSyncDisposition::Proposed {
                    proposal_id,
                    approval,
                } => SkillSync {
                    outcome: "proposed",
                    proposal: Some(proposal_id.to_hex()),
                    approval: Some(approval.as_str()),
                },
                HubSyncDisposition::RefusedByPolicy => SkillSync {
                    outcome: "refused_by_policy",
                    proposal: None,
                    approval: None,
                },
            },
        )
    })
    .await?;
    Ok(Json(sync))
}

/// The owner's consent as it landed.
#[derive(Serialize)]
struct ConsentRow {
    outcome: &'static str,
    /// The gate decision, as 32 hex.
    decision: String,
}

impl From<ConsentReceipt> for ConsentRow {
    fn from(receipt: ConsentReceipt) -> Self {
        Self {
            outcome: receipt.gate_outcome(),
            decision: receipt
                .decision_id()
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        }
    }
}

/// The skill's first hub source: the ref its import or sync named.
fn skill_source(vault: &oneiron::Vault, entity: &EntityId) -> Result<HubRef, OwnerError> {
    vault
        .skill_hub_sources(entity)?
        .into_iter()
        .next()
        .ok_or_else(|| OwnerError::Invalid("the skill has no hub source".to_owned()))
}

/// `POST /v1/owner/packs/skills/{entity}/permissions/approve`: the owner's
/// answer to a hub skill's permission ask; it activates the Candidate.
async fn approve_skill_permissions(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(entity): UrlPath<String>,
) -> OwnerReply<ConsentRow> {
    let owner = owner(&auth, &server)?;
    let row = blocking(move || {
        let vault = server.vault();
        let entity = entity_id(&entity, "entity")?;
        let source = skill_source(vault, &entity)?;
        let at = vault.now_recorded_at();
        let occurred = oneiron::TimeRange { start: at, end: at };
        Ok(ConsentRow::from(vault.approve_marketplace_permission_ask(
            &owner, &entity, &source, occurred, at,
        )?))
    })
    .await?;
    Ok(Json(row))
}

/// A hub skill's receipts: one import receipt per hub source, and the
/// held-out activation ruling once one landed.
#[derive(Serialize)]
struct SkillReceipts {
    imports: Vec<HubImportReceipt>,
    admission: Option<HubAdmissionReceipt>,
}

/// `GET /v1/owner/packs/skills/{entity}/receipts`
async fn skill_receipts(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(entity): UrlPath<String>,
) -> OwnerReply<SkillReceipts> {
    owner(&auth, &server)?;
    let receipts = blocking(move || {
        let vault = server.vault();
        let entity = entity_id(&entity, "entity")?;
        let mut imports = Vec::new();
        for source in vault.skill_hub_sources(&entity)? {
            if let Some(receipt) = vault.hub_import_receipt(&entity, &source)? {
                imports.push(receipt);
            }
        }
        Ok(SkillReceipts {
            imports,
            admission: vault.hub_admission_receipt(&entity)?,
        })
    })
    .await?;
    Ok(Json(receipts))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationRequest {
    /// The publisher admitted for the skill's hub.
    publisher: String,
    /// An active local skill whose attributed outcomes are the baseline.
    evidence_skill: String,
    /// On approve: the digest the owner was shown.
    #[serde(default)]
    effect_digest: Option<String>,
}

/// The activation ask as the owner reads it.
#[derive(Serialize)]
struct ActivationAskView {
    candidate: String,
    content_hash: String,
    effect_digest: String,
    /// `one_tap`, `summarized_review` or `full_review`.
    surface: &'static str,
}

fn prepare_activation(
    server: &SyncServer,
    owner: &oneiron::consent::AuthenticatedOwner,
    entity: &str,
    request: &ActivationRequest,
) -> Result<oneiron::skill_hub::HubActivationAsk, OwnerError> {
    let vault = server.vault();
    let candidate = entity_id(entity, "entity")?;
    let evidence = entity_id(&request.evidence_skill, "evidence_skill")?;
    let source = skill_source(vault, &candidate)?;
    let publisher = vault.admit_skill_publisher(owner, &request.publisher, source.hub_id)?;
    Ok(vault.prepare_marketplace_activation(candidate, &source, &publisher, evidence)?)
}

/// `POST /v1/owner/packs/skills/{entity}/activation/prepare`: the immutable
/// held-out activation ask for a hub Candidate.
async fn prepare_skill_activation(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(entity): UrlPath<String>,
    payload: Result<Json<ActivationRequest>, JsonRejection>,
) -> OwnerReply<ActivationAskView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let view = blocking(move || {
        let ask = prepare_activation(&server, &owner, &entity, &request)?;
        Ok(ActivationAskView {
            candidate: ask.candidate().to_hex(),
            content_hash: ask.content_hash().to_hex(),
            effect_digest: ask.effect_digest().to_hex(),
            surface: match ask.surface() {
                HubAskSurface::OneTap => "one_tap",
                HubAskSurface::SummarizedReview => "summarized_review",
                HubAskSurface::FullReview => "full_review",
            },
        })
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/packs/skills/{entity}/activation/approve`: the owner's
/// consent to the ask they were shown. The ask is rebuilt and must carry
/// the same digest. Admission itself needs the host's held-out scorer.
async fn approve_skill_activation(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(entity): UrlPath<String>,
    payload: Result<Json<ActivationRequest>, JsonRejection>,
) -> OwnerReply<ConsentRow> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let row = blocking(move || {
        let shown = request
            .effect_digest
            .clone()
            .ok_or_else(|| OwnerError::Invalid("send the effect_digest shown".to_owned()))?;
        let ask = prepare_activation(&server, &owner, &entity, &request)?;
        if ask.effect_digest().to_hex() != shown {
            return Err(OwnerError::Invalid(
                "the activation ask moved; prepare it again".to_owned(),
            ));
        }
        Ok(ConsentRow::from(
            server
                .vault()
                .approve_marketplace_activation(&ask, &owner)?,
        ))
    })
    .await?;
    Ok(Json(row))
}

/// One pack's setup: by name, and by content hash when several sources wait.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackSetupKey {
    pack: String,
    /// One exact source; else the Active one, or the pack's one Candidate.
    #[serde(default)]
    source: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackSetupAnswerRequest {
    pack: String,
    #[serde(default)]
    source: Option<String>,
    /// A typed answer.
    #[serde(default)]
    answer: Option<PackSetupAnswer>,
    /// Or one action from the setup's cards, with the card's `$state`.
    #[serde(default)]
    card_action: Option<PackSetupCardActionRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackSetupCardActionRequest {
    action_id: String,
    #[serde(default)]
    state: GeneratedUiStateSnapshot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackSetupVerifyRequest {
    pack: String,
    #[serde(default)]
    source: Option<String>,
    connection: String,
}

/// The setup, its GenUI cards and its plain text.
#[derive(Serialize)]
struct PackSetupReply {
    setup: PackSetupView,
    cards: Vec<GeneratedUiCard>,
    text: String,
    /// A built-in channel's provider URLs at this host, and Slack's manifest.
    #[serde(flatten)]
    provider: ProviderSetup,
    /// Set when a card asked to store a credential: the owner secrets door
    /// takes the value, then a `secret_stored` answer pins its record.
    #[serde(skip_serializing_if = "Option::is_none")]
    store_secret: Option<PackSetupStoreSecret>,
}

#[derive(Serialize)]
struct PackSetupStoreSecret {
    door: &'static str,
    connection: String,
    name: String,
    /// The binding the stored credential needs, with the read scope.
    effector: String,
}

impl PackSetupReply {
    fn new(setup: PackSetupView, server: &SyncServer) -> Result<Self, OwnerError> {
        let provider = ProviderSetup::for_pack(
            &setup.pack_name,
            server.config.oauth_resource_indicator.as_deref(),
        )?;
        Ok(Self {
            cards: setup.cards()?,
            text: setup.text() + &provider.text(),
            setup,
            provider,
            store_secret: None,
        })
    }
}

/// `GET /v1/owner/packs/setup?pack=&source=`: the owner's guided setup of one
/// pack (OF-378), readable while the pack is still a Candidate.
async fn setup_view(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<PackSetupKey>, QueryRejection>,
) -> OwnerReply<PackSetupReply> {
    let owner = owner(&auth, &server)?;
    let key = query_params(query)?;
    let reply = blocking(move || {
        PackSetupReply::new(
            server
                .vault()
                .pack_setup(&owner, &key.pack, key.source.as_deref())?,
            &server,
        )
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/packs/setup/prepare`: open, or resume, the setup. Opening
/// grants nothing.
async fn setup_prepare(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<PackSetupKey>, JsonRejection>,
) -> OwnerReply<PackSetupReply> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let reply = blocking(move || {
        PackSetupReply::new(
            server
                .vault()
                .prepare_pack_setup(&owner, &request.pack, request.source.as_deref())?,
            &server,
        )
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/packs/setup/answer`: one typed answer, or one card action.
/// A credential value never comes here: a card's store button answers with
/// the owner secrets door to open.
async fn setup_answer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<PackSetupAnswerRequest>, JsonRejection>,
) -> OwnerReply<PackSetupReply> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let reply = blocking(move || {
        let vault = server.vault();
        let source = request.source.as_deref();
        let answer = match (request.answer, request.card_action) {
            (Some(answer), None) => answer,
            (None, Some(card)) => {
                let view = vault.pack_setup(&owner, &request.pack, source)?;
                match view.card_action(&card.action_id, &card.state)? {
                    PackSetupCardAction::Answer(answer) => answer,
                    PackSetupCardAction::Verify { connection } => {
                        let checks = HostConnectionChecks::new(&server)?;
                        return PackSetupReply::new(
                            vault.verify_pack_connection(
                                &owner,
                                &request.pack,
                                source,
                                &connection,
                                &checks,
                            )?,
                            &server,
                        );
                    }
                    PackSetupCardAction::StoreSecret {
                        connection,
                        secret,
                        effector,
                    } => {
                        let mut reply = PackSetupReply::new(view, &server)?;
                        reply.store_secret = Some(PackSetupStoreSecret {
                            door: "/v1/owner/secrets/register",
                            connection,
                            name: secret,
                            effector,
                        });
                        return Ok(reply);
                    }
                }
            }
            _ => {
                return Err(OwnerError::Invalid(
                    "send exactly one of answer or card_action".to_owned(),
                ));
            }
        };
        PackSetupReply::new(
            vault.answer_pack_setup(&owner, &request.pack, source, &answer)?,
            &server,
        )
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/packs/setup/verify`: check one connection before the pack
/// uses it. The check is the engine's fixed read-only provider call for the
/// declared check name; a pack never names a URL.
async fn setup_verify(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<PackSetupVerifyRequest>, JsonRejection>,
) -> OwnerReply<PackSetupReply> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let reply = blocking(move || {
        let checks = HostConnectionChecks::new(&server)?;
        PackSetupReply::new(
            server.vault().verify_pack_connection(
                &owner,
                &request.pack,
                request.source.as_deref(),
                &request.connection,
                &checks,
            )?,
            &server,
        )
    })
    .await?;
    Ok(Json(reply))
}

/// `GET /v1/owner/packs/slack/manifest`: the Slack app manifest at this
/// host's public origin, to paste at api.slack.com/apps (OF-519). It needs
/// no checked connection, since the app is made first.
async fn slack_manifest(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<serde_json::Value> {
    owner(&auth, &server)?;
    let manifest = blocking(move || {
        let origin =
            public_origin(server.config.oauth_resource_indicator.as_deref()).ok_or_else(|| {
                OwnerError::Invalid(
                    "this host has no public https origin; set oauth_resource_indicator to it first"
                        .to_owned(),
                )
            })?;
        Ok(slack_app_manifest(&origin)?)
    })
    .await?;
    Ok(Json(manifest))
}

/// The Slack setup to install for: by content hash when several wait.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SlackInstallRequest {
    #[serde(default)]
    source: Option<String>,
}

/// `POST /v1/owner/packs/slack/install`: one link that installs the Slack
/// app to the owner's workspace (OF-519). Slack's redirect redeems it once,
/// within ten minutes, and the host stores and checks the bot token under
/// this owner's proof.
async fn slack_install(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SlackInstallRequest>, JsonRejection>,
) -> OwnerReply<crate::builtin_host::SlackInstallLink> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let link = blocking(move || start_slack_install(&server, owner, request.source)).await?;
    Ok(Json(link))
}
