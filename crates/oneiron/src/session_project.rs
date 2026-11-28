//! The PROJECT an attached agent session's folder selects (rows RECALL-SESSION-PROJECT and
//! RECALL-SESSION-PROJECT-ALL-READS; Engine ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov: Q1 = A,
//! Q2 = A, Q3 = A, a hash plus a label; Engine NOTE 22:5x: the id keyed by the vault).
//!
//! A client names a folder by its folder digest: the fingerprint (BLAKE3, the engine's
//! fingerprint door) of the folder's canonical checkout path under the purpose
//! `oneiron.workspace.v1`, as `blake3:` and lower-case hex (`oneiron_server::workspace_identity`).
//! The vault keys it again with its store id into the folder's workspace id
//! ([`Vault::workspace_id`]), so one folder's ids do not correlate across vaults. The vault never
//! receives the path; a reader of the vault who guesses a path and knows the vault's store id
//! can still test the guess.
//!
//! The owner binds a folder to a PROJECT with `vault.projects.workspace.bind`, which writes the
//! family Setting key `workspace.project`: one item per folder, named by its workspace id. The
//! row holds the project and a label, the folder's name, shown to the owner and never matched.
//! `vault.projects.workspace.unbind` clears it; `vault.settings.list` lists the rows. Each row is
//! one folder's own value: a row with no item, which would bind every folder, and a pinned row,
//! which the two verbs could not replace, are refused.
//!
//! A binding is a choice about this install (`SettingSync::Install`), as the folder's path is a
//! fact about the machine it is on: it never leaves the install that holds it, another machine of
//! the vault never receives it, and a restore drops it. So on a replica, and after a restore, the
//! folder reads as unbound, and the start hook's vault line gives the bind command (Q2 = A); a
//! restore that has not joined its vault yet can bind it again.
//!
//! An attached session names its folder's digests, its own first. The first whose row names a
//! project decides: [`workspace_project_in_txn`] answers that project while the project fold
//! shows it (a quarantined or erased PROJECT does not), and nothing otherwise. That project is the session's default: what its reads select
//! when they name no project. Selection only narrows; the reader's credential still decides
//! what it reads.
//!
//! Binding is the owner's act: the two doors take the owner's proof, and an agent's own change
//! of the key waits on the owner's answer, as a change to every owner key does. An agent may
//! tell the owner the command (`oneiron project bind <project-ref>`, run in the folder). A set
//! must name a live PROJECT.

pub(crate) mod setting_keys;

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron_contracts::fingerprint::Fingerprint;
use oneiron_contracts::fingerprint::purposes::session_project::WORKSPACE_ID;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::authority::ActSurface;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryResult};
use crate::setting::{
    Kind, SetSetting, SetSettingOutcome, SettingCaller, SettingChange, SettingMode, SettingValue,
};
use crate::{EntityId, Vault};

/// The key's catalogue name.
pub const WORKSPACE_PROJECT_KEY: &str = "workspace.project";

/// The bind verb's name, as a refusal names it.
const BIND_VERB: &str = "vault.projects.workspace.bind";

/// The unbind verb's name, as a refusal names it.
const UNBIND_VERB: &str = "vault.projects.workspace.unbind";

/// What a folder digest's and a workspace id's text starts with: the hash that made it.
pub const DIGEST_TEXT_PREFIX: &str = "blake3:";

/// The length of a folder digest's and of a workspace id's text: [`DIGEST_TEXT_PREFIX`] and a
/// 32-byte fingerprint in hex.
pub const DIGEST_TEXT_LEN: usize = DIGEST_TEXT_PREFIX.len() + 64;

/// The longest label a binding keeps, in bytes.
pub const WORKSPACE_LABEL_MAX: usize = 128;

/// The receipt axis a read names when an attached session's project narrowed it: CLAIM, NOTE,
/// MESSAGE and TURN rows placed outside the session's project were not read.
pub const SESSION_PROJECT_AXIS: &str = "session_project";

/// The receipt axis when an attached session's folder has no project bound: it read no CLAIM,
/// NOTE, MESSAGE or TURN row. The owner binds one with `oneiron project bind <project-ref>`
/// in the folder; a call that names its projects (`project_refs`) reads those.
pub const NO_PROJECT_BOUND_AXIS: &str = "no_project_bound";

/// A session folder's default when a read names no project: a request, never authority.
/// Only CLAIM (body project) and NOTE, MESSAGE or TURN (birth stamp) rows are narrowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionProjects {
    /// The folder's project and every PROJECT below it.
    Bound {
        /// The project the owner bound to the folder: the one a project's settings are read
        /// at for the session (RECALL-CARRIER-THRESHOLD).
        project: EntityId,
        /// It and every PROJECT below it.
        closure: Arc<BTreeSet<EntityId>>,
    },
    /// No live project is bound to the folder: such a read reads no CLAIM row.
    Unbound,
}

impl SessionProjects {
    /// Whether a CLAIM stamped with `project` is read.
    #[must_use]
    pub fn admits(&self, project: EntityId) -> bool {
        match self {
            Self::Bound { closure, .. } => closure.contains(&project),
            Self::Unbound => false,
        }
    }

    /// The project the owner bound to the folder, `None` when none is.
    #[must_use]
    pub fn project(&self) -> Option<EntityId> {
        match self {
            Self::Bound { project, .. } => Some(*project),
            Self::Unbound => None,
        }
    }

    /// The axis a read's receipt names.
    #[must_use]
    pub fn receipt_axis(&self) -> &'static str {
        match self {
            Self::Bound { .. } => SESSION_PROJECT_AXIS,
            Self::Unbound => NO_PROJECT_BOUND_AXIS,
        }
    }
}

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

/// The text of a folder digest or a workspace id: [`DIGEST_TEXT_PREFIX`] and the fingerprint's
/// lower-case hex.
#[must_use]
pub fn digest_text(fingerprint: &Fingerprint) -> String {
    format!("{DIGEST_TEXT_PREFIX}{}", fingerprint.to_hex())
}

/// Whether `text` is a digest's text ([`digest_text`]): the one spelling of a folder digest and
/// of a workspace id, so no row sits under another spelling of the same folder.
#[must_use]
pub fn is_digest_text(text: &str) -> bool {
    text.len() == DIGEST_TEXT_LEN
        && text.strip_prefix(DIGEST_TEXT_PREFIX).is_some_and(|hex| {
            hex.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// Refuses a `workspace.project` row that is not one folder's own value, and a binding that
/// names a PROJECT the project fold does not show. A row with no item would bind every folder,
/// and a pinned row would outlast the bind and unbind verbs, which write the value. A clear, or
/// a row that names no project, binds nothing and passes.
fn check_workspace_binding(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &SettingChange,
) -> Result<()> {
    if change.item.is_none() || !matches!(change.mode, SettingMode::Value) {
        return Err(Error::InvalidConfig(format!(
            "{WORKSPACE_PROJECT_KEY}: a binding is one folder's own value: name its workspace id \
             as the item, and do not pin it"
        )));
    }
    let Some(value) = change.value.as_ref() else {
        return Ok(());
    };
    let binding = Kind::<WorkspaceProject>::decode(value).ok_or_else(|| {
        Error::InvalidConfig(format!("{WORKSPACE_PROJECT_KEY}: the row does not decode"))
    })?;
    let Some(project) = binding.project else {
        return Ok(());
    };
    if vault.visible_project_in_txn(txn, project)?.is_none() {
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

/// The workspace id of the folder `folder_digest` names in `vault`: the fingerprint under
/// [`WORKSPACE_ID`] (`oneiron.workspace-id.v1`) of the vault's store id and the digest's text,
/// as [`digest_text`]. `None` for a digest that is not one.
#[must_use]
pub fn workspace_id_of(vault: &Vault, folder_digest: &str) -> Option<String> {
    if !is_digest_text(folder_digest) {
        return None;
    }
    let vault_id = vault.vault_id();
    let parts: [&[u8]; 2] = [vault_id.as_bytes(), folder_digest.as_bytes()];
    Some(digest_text(&Fingerprint::of_parts(WORKSPACE_ID, &parts)))
}

/// The project a session in the folder `folder_digests` names (its own digest first, then its
/// main checkout's) reads by default, in `txn`: the project of the first folder whose row names
/// one, while the project fold shows that PROJECT. `None`: no folder is bound, or the first bound
/// one names a project that is gone or quarantined.
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
            let live = vault.visible_project_in_txn(txn, project)?.is_some();
            return Ok(live.then_some(project));
        }
    }
    Ok(None)
}

/// `vault.projects.workspace.bind`'s input: the folder, the PROJECT, and the folder's label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceBindRequest {
    /// The folder's digest, `blake3:` and 64 lower-case hex: the fingerprint of its canonical
    /// checkout path under `oneiron.workspace.v1`, as `oneiron project bind` computes it.
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
    /// What an attached session in the folder `folder_digests` (its own digest first) reads by
    /// default: the folder's bound project with every PROJECT below it, or
    /// [`SessionProjects::Unbound`] when no live project is bound.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn session_projects(&self, folder_digests: &[String]) -> Result<SessionProjects> {
        Ok(match self.workspace_project(folder_digests)? {
            Some(project) => SessionProjects::Bound {
                project,
                closure: Arc::new(
                    crate::memory::project_descendant_closure_of(self, vec![project])?
                        .into_iter()
                        .collect(),
                ),
            },
            None => SessionProjects::Unbound,
        })
    }

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

    /// Whether `proof`, the credential `actor` presented (`None`: none), admits placing
    /// `actor`'s records under `project` (PR A Q2, SESSION-PROJECT-NOTE-MESSAGE-PLACEMENT): with
    /// no credential, only in process (`transport` false); else the slip must be live, held by
    /// `actor`, bounded by no record or channel, grant a write, and have an audience that covers
    /// `project`. Both a session-folder write's writer and a hook transcript's hand-over judge
    /// placement by it.
    pub(crate) fn credential_admits_project_placement_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
        proof: Option<&crate::authority::VerifiedSlip>,
        transport: bool,
        project: EntityId,
    ) -> MemoryResult<bool> {
        let Some(proof) = proof else {
            return if transport { Ok(false) } else { Ok(true) };
        };
        if proof.claims().holder_ref != actor.to_hex()
            || !proof.claims().records.is_empty()
            || !proof.claims().channels.is_empty()
            || !self.capability_slip_is_live_in_txn(txn, proof)?
        {
            return Ok(false);
        }
        if !["core:write", "write", "core:propose"]
            .into_iter()
            .any(|verb| proof.allows_verb(verb))
        {
            return Ok(false);
        }
        if !proof
            .scope()
            .audience
            .contains(&crate::federation::ScopeId(project))
        {
            return Ok(false);
        }
        Ok(true)
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
                "{WORKSPACE_PROJECT_KEY}: a folder digest is `blake3:` and 64 lower-case hex"
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
