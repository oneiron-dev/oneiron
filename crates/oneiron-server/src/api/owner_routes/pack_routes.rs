//! `/v1/owner/packs`: the served `vault.packs.put` (ARCH-0080 §8, slice 1).
//! The owner installs a pack from a folder on this host or from its files,
//! lists what is installed, and binds or dials its hooks.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::{
    PackHookBinding, PackInstallDisposition, PackInstallReceipt,
};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::OwnerError;
use crate::server::SyncServer;

/// A folder read from disk stops here; the pack source applies its own,
/// tighter bounds after.
const MAX_FOLDER_FILES: usize = 1024;
const MAX_FOLDER_BYTES: u64 = 64 * 1024 * 1024;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/packs", get(installed).post(put))
        .route("/packs/install", post(install_from_hub))
        .route("/packs/hooks", get(hook_bindings))
        .route("/packs/hooks/bind", post(bind_hooks))
        .route("/packs/hooks/enabled", post(set_hook_enabled))
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
        let pin = oneiron::skill_hub::pack_catalog::hub_pin(&request.pin_type, &request.pin_value)?;
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
