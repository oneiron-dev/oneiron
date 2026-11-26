//! The PROJECT an attached agent session's folder selects (rows RECALL-SESSION-PROJECT and
//! RECALL-SESSION-PROJECT-ALL-READS; Engine ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov: Q1 = A,
//! Q2 = A, Q3 = A, a hash plus a label; Engine NOTE 22:5x: the id keyed by the vault).
//!
//! A client names a folder by its folder digest: the SHA-256 of a domain tag and the folder's
//! canonical checkout path, in lower-case hex (`oneiron_server::workspace_identity`). The vault
//! keys it again with its own store id into the folder's workspace id ([`Vault::workspace_id`]),
//! so one folder's ids do not correlate across vaults. The vault never receives the path; a
//! reader of the vault who guesses a path and knows the vault's store id can still test the
//! guess. The store id is the random one the vault's store took at its first open: it holds
//! before and after a rooting, and a replica, or a store a backup is restored into, has its own,
//! so a binding binds the folder on the store that bound it. A binding does not follow the vault
//! to a restored store or a replica: there the folder reads as unbound, and the start hook's
//! vault line gives the bind command (Q2 = A).
//!
//! The owner binds a folder to a PROJECT with `vault.projects.workspace.bind`, which writes the
//! family Setting key `workspace.project`: one item per folder, named by its workspace id. The
//! row holds the project and a label, the folder's name, shown to the owner and never matched.
//! `vault.projects.workspace.unbind` clears it; `vault.settings.list` lists the rows.
//!
//! An attached session names its folder's digests, its own first. The first whose row names a
//! project decides: [`workspace_project_in_txn`] answers that project while it is a live
//! PROJECT, and nothing otherwise. That project is the session's default: what its reads select
//! when they name no project. Selection only narrows; the reader's credential still decides
//! what it reads.
//!
//! Binding is the owner's act: the two doors take the owner's proof, and an agent's own change
//! of the key waits on the owner's answer, as a change to every owner key does. An agent may
//! tell the owner the command (`oneiron project bind <project-ref>`, run in the folder). A set
//! must name a live PROJECT.

pub(crate) mod setting_keys;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::authority::ActSurface;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryResult};
use crate::setting::{
    Kind, SetSetting, SetSettingOutcome, SettingCaller, SettingChange, SettingValue,
};
use crate::{EntityId, Vault};

/// The key's catalogue name.
pub const WORKSPACE_PROJECT_KEY: &str = "workspace.project";

/// The bind verb's name, as a refusal names it.
const BIND_VERB: &str = "vault.projects.workspace.bind";

/// The unbind verb's name, as a refusal names it.
const UNBIND_VERB: &str = "vault.projects.workspace.unbind";

/// What a workspace id's digest covers before the vault's id and the folder digest.
const WORKSPACE_ID_DOMAIN: &[u8] = b"oneiron.workspace-id.v1\0";

/// The length of a folder digest and of a workspace id: a SHA-256 digest in hex.
pub const SHA256_HEX_LEN: usize = 64;

/// The longest label a binding keeps, in bytes.
pub const WORKSPACE_LABEL_MAX: usize = 128;

/// One folder's binding: the `workspace.project` row's value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceProject {
    /// The PROJECT the folder's sessions read by default, as 32 hex. Absent: no project is
    /// bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<EntityId>,
    /// The folder's name, for display. Never matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl WorkspaceProject {
    /// No project bound: the default, and what an unreadable row reads as.
    #[must_use]
    pub fn unbound() -> Self {
        Self::default()
    }
}

impl SettingValue for WorkspaceProject {
    /// A label is trimmed, and at most [`WORKSPACE_LABEL_MAX`] bytes with no control character;
    /// an empty one is dropped.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for a label that is too long or holds a control character.
    fn check(mut self) -> Result<Self> {
        if let Some(label) = self.label.take() {
            let label = label.trim();
            if label.len() > WORKSPACE_LABEL_MAX || label.chars().any(char::is_control) {
                return Err(Error::InvalidConfig(format!(
                    "{WORKSPACE_PROJECT_KEY}: a label is at most {WORKSPACE_LABEL_MAX} bytes with \
                     no control character"
                )));
            }
            if !label.is_empty() {
                self.label = Some(label.to_owned());
            }
        }
        Ok(self)
    }
}

/// Whether `text` is a SHA-256 digest in lower-case hex: the one spelling of a folder digest and
/// of a workspace id, so no row sits under another spelling of the same folder.
#[must_use]
pub fn is_sha256_hex(text: &str) -> bool {
    text.len() == SHA256_HEX_LEN
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Refuses a binding that names anything but a live PROJECT. A clear, or a row that names no
/// project, binds nothing and passes.
fn refuse_unless_live_project(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &SettingChange,
) -> Result<()> {
    let Some(value) = change.value.as_ref() else {
        return Ok(());
    };
    // A row another machine's signed act projects here may arrive before its PROJECT does:
    // the reader judges the project live at each read, so the projection is not refused.
    if change.standing.is_some() {
        return Ok(());
    }
    let binding = Kind::<WorkspaceProject>::decode(value).ok_or_else(|| {
        Error::InvalidConfig(format!("{WORKSPACE_PROJECT_KEY}: the row does not decode"))
    })?;
    let Some(project) = binding.project else {
        return Ok(());
    };
    if !crate::workspace_roster::project::is_project_entity(&vault.store, txn, project)? {
        return Err(Error::InvalidConfig(format!(
            "{WORKSPACE_PROJECT_KEY}: {} is not a live PROJECT",
            project.to_hex()
        )));
    }
    Ok(())
}

/// The binding with `erased` taken out: unbound when it named that project.
fn erase_bound_project(binding: &WorkspaceProject, erased: EntityId) -> Option<WorkspaceProject> {
    (binding.project == Some(erased)).then(|| WorkspaceProject {
        project: None,
        label: binding.label.clone(),
    })
}

/// The workspace id of the folder `folder_digest` names in `vault`: the SHA-256, in lower-case
/// hex, of [`WORKSPACE_ID_DOMAIN`], the vault's store id and the digest's bytes. `None` for a
/// digest that is not one.
#[must_use]
pub fn workspace_id_of(vault: &Vault, folder_digest: &str) -> Option<String> {
    if !is_sha256_hex(folder_digest) {
        return None;
    }
    let mut digest = Sha256::new();
    digest.update(WORKSPACE_ID_DOMAIN);
    digest.update(vault.vault_id().as_bytes());
    digest.update(folder_digest.as_bytes());
    Some(oneiron_hex::encode(&digest.finalize()))
}

/// The project a session in the folder `folder_digests` names (its own digest first, then its
/// main checkout's) reads by default, in `txn`: the project of the first folder whose row names
/// one, while that project is a live PROJECT. `None`: no folder is bound, or the first bound one
/// names a project that is gone.
///
/// # Errors
///
/// Storage errors.
pub fn workspace_project_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    folder_digests: &[String],
) -> Result<Option<EntityId>> {
    for folder_digest in folder_digests {
        let Some(id) = workspace_id_of(vault, folder_digest) else {
            continue;
        };
        let bound = setting_keys::WORKSPACE_PROJECT
            .read_in_txn(vault, txn, &[], Some(&id))?
            .value;
        if let Some(project) = bound.project {
            let live =
                crate::workspace_roster::project::is_project_entity(&vault.store, txn, project)?;
            return Ok(live.then_some(project));
        }
    }
    Ok(None)
}

/// `vault.projects.workspace.bind`'s input: the folder, the PROJECT, and the folder's label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceBindRequest {
    /// The folder's digest, 64 lower-case hex: the SHA-256 of `oneiron.workspace.v1\0` and its
    /// canonical checkout path, as `oneiron project bind` computes it.
    pub folder_digest: String,
    /// The PROJECT the folder's sessions read by default, as 32 hex.
    pub project: EntityId,
    /// The folder's name, for display.
    #[serde(default)]
    pub label: Option<String>,
}

/// `vault.projects.workspace.unbind`'s input: the folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceUnbindRequest {
    /// The folder's digest, as [`WorkspaceBindRequest::folder_digest`].
    pub folder_digest: String,
}

/// A folder's binding as the two doors answer it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceBinding {
    /// The folder's workspace id in this vault: the `workspace.project` row's item.
    pub workspace_id: String,
    /// The bound PROJECT; absent once unbound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<EntityId>,
    /// The folder's label; absent once unbound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Vault {
    /// The workspace id of the folder `folder_digest` names in this vault
    /// ([`workspace_id_of`]); `None` for a digest that is not one.
    #[must_use]
    pub fn workspace_id(&self, folder_digest: &str) -> Option<String> {
        workspace_id_of(self, folder_digest)
    }

    /// [`workspace_project_in_txn`] in a snapshot of its own.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn workspace_project(&self, folder_digests: &[String]) -> Result<Option<EntityId>> {
        let txn = self.store.env.read_txn()?;
        workspace_project_in_txn(self, &txn, folder_digests)
    }

    /// The owner binds the folder `request.folder_digest` names to `request.project`: the
    /// owner's change of the folder's `workspace.project` row, under the owner's proof, recorded
    /// as every owner setting change is, with `surface` as where the owner said so. The project
    /// must be a live PROJECT.
    ///
    /// # Errors
    ///
    /// A folder digest that is not one, a project that is not a live PROJECT, a label the key
    /// refuses, a proof that no longer holds, and storage errors.
    pub fn bind_workspace_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        surface: Option<ActSurface>,
        request: WorkspaceBindRequest,
    ) -> Result<WorkspaceBinding> {
        let value = serde_json::to_value(WorkspaceProject {
            project: Some(request.project),
            label: request.label,
        })
        .map_err(|error| Error::InvalidConfig(format!("{WORKSPACE_PROJECT_KEY}: {error}")))?;
        self.set_workspace_row_as_owner(owner, surface, &request.folder_digest, Some(value))
    }

    /// The owner clears the folder `request.folder_digest` names: its sessions then read no
    /// project by default.
    ///
    /// # Errors
    ///
    /// A folder digest that is not one, a proof that no longer holds, and storage errors.
    pub fn unbind_workspace_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        surface: Option<ActSurface>,
        request: &WorkspaceUnbindRequest,
    ) -> Result<WorkspaceBinding> {
        self.set_workspace_row_as_owner(owner, surface, &request.folder_digest, None)
    }

    /// The owner's change of the folder's `workspace.project` row to `value` (`None` clears it).
    fn set_workspace_row_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        surface: Option<ActSurface>,
        folder_digest: &str,
        value: Option<serde_json::Value>,
    ) -> Result<WorkspaceBinding> {
        let workspace_id = self.workspace_id(folder_digest).ok_or_else(|| {
            Error::InvalidConfig(format!(
                "{WORKSPACE_PROJECT_KEY}: a folder digest is 64 lower-case hex"
            ))
        })?;
        let mut change = SetSetting::vault_value(WORKSPACE_PROJECT_KEY, serde_json::Value::Null);
        change.item = Some(workspace_id.clone());
        change.value = value;
        change.surface = surface;
        match self.set_setting(SettingCaller::Owner(owner), change)? {
            SetSettingOutcome::Applied { .. } => {}
            SetSettingOutcome::Pending { check_in } => {
                return Err(Error::InvalidConfig(format!(
                    "{WORKSPACE_PROJECT_KEY}: the owner's change waits on check-in {check_in}"
                )));
            }
        }
        let txn = self.store.env.read_txn()?;
        let bound = setting_keys::WORKSPACE_PROJECT
            .read_in_txn(self, &txn, &[], Some(&workspace_id))?
            .value;
        Ok(WorkspaceBinding {
            workspace_id,
            project: bound.project,
            label: bound.label,
        })
    }
}

/// `vault.projects.workspace.bind` on the embedded owner's handle. The owner's act records this
/// install as where the owner said so.
///
/// # Errors
///
/// A handle that is not the vault owner's, and every refusal of
/// [`Vault::bind_workspace_as_owner`].
pub fn bind_workspace_embedded(
    memory: &Memory<'_>,
    input: WorkspaceBindRequest,
) -> MemoryResult<WorkspaceBinding> {
    Ok(memory.vault().bind_workspace_as_owner(
        &memory.embedded_owner(BIND_VERB)?,
        Some(ActSurface::ThisInstall),
        input,
    )?)
}

/// `vault.projects.workspace.unbind` on the embedded owner's handle.
///
/// # Errors
///
/// A handle that is not the vault owner's, and every refusal of
/// [`Vault::unbind_workspace_as_owner`].
pub fn unbind_workspace_embedded(
    memory: &Memory<'_>,
    input: WorkspaceUnbindRequest,
) -> MemoryResult<WorkspaceBinding> {
    Ok(memory.vault().unbind_workspace_as_owner(
        &memory.embedded_owner(UNBIND_VERB)?,
        Some(ActSurface::ThisInstall),
        &input,
    )?)
}
