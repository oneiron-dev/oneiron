//! The PROJECT an attached agent session's folder selects (rows RECALL-SESSION-PROJECT and
//! RECALL-SESSION-PROJECT-ALL-READS; Engine ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov: Q1 = A,
//! Q2 = A, Q3 = A, a hash plus a label).
//!
//! The owner binds a folder to a PROJECT with the family Setting key `workspace.project`: one
//! item per folder, named by its workspace id, never by its path. A workspace id is the SHA-256,
//! in lower-case hex, of the folder's canonical checkout path (the client computes it; see
//! `oneiron project bind`), so a hosted vault holds no local path. The row holds the project and
//! a label, the folder's name, shown to the owner and never matched.
//!
//! An attached session names its folder's workspace ids, its own first. The first id with a row
//! that names a project decides: [`workspace_project_in_txn`] answers that project while it is a
//! live PROJECT, and nothing otherwise. That project is the session's default: what its reads
//! select when they name no project. Selection only narrows; the reader's credential still
//! decides what it reads.
//!
//! Binding is the owner's act (`vault.settings.set` on the key, which `oneiron project bind`
//! sends from the folder). An agent may tell the owner the command; its own change waits on the
//! owner's answer, as a change to every owner key does. A set must name a live PROJECT.

pub(crate) mod setting_keys;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::setting::{Kind, SettingChange, SettingValue};
use crate::{EntityId, Vault};

/// The key's catalogue name.
pub const WORKSPACE_PROJECT_KEY: &str = "workspace.project";

/// A workspace id's length: a SHA-256 digest in hex.
pub const WORKSPACE_ID_HEX_LEN: usize = 64;

/// The longest label a binding keeps, in bytes.
pub const WORKSPACE_LABEL_MAX: usize = 128;

/// The receipt axis a read names when an attached session's project narrowed it: CLAIM rows
/// stamped outside the session's project were not read.
pub const SESSION_PROJECT_AXIS: &str = "session_project";

/// The receipt axis a read names when its attached session's folder has no project bound: it
/// read no CLAIM row. The owner binds one with `oneiron project bind <project-ref>` in the
/// folder; a call that names its projects (`project_refs`) reads those.
pub const NO_PROJECT_BOUND_AXIS: &str = "no_project_bound";

/// What an attached session's folder selects for the reads that name no project: a request,
/// never authority. Only CLAIM rows carry a project stamp, so only they are narrowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionProjects {
    /// The folder's project and every PROJECT below it.
    Bound(Arc<BTreeSet<EntityId>>),
    /// No live project is bound to the folder: such a read reads no CLAIM row.
    Unbound,
}

impl SessionProjects {
    /// Whether a CLAIM stamped with `project` is read.
    #[must_use]
    pub fn admits(&self, project: EntityId) -> bool {
        match self {
            Self::Bound(projects) => projects.contains(&project),
            Self::Unbound => false,
        }
    }

    /// The axis a read's receipt names.
    #[must_use]
    pub fn receipt_axis(&self) -> &'static str {
        match self {
            Self::Bound(_) => SESSION_PROJECT_AXIS,
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

/// Whether `item` is a workspace id: [`WORKSPACE_ID_HEX_LEN`] lower-case hex digits, the one
/// spelling, so no row sits under another spelling of the same folder.
#[must_use]
pub fn is_workspace_id(item: &str) -> bool {
    item.len() == WORKSPACE_ID_HEX_LEN
        && item
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

/// The project a session in the folder `workspace_ids` names (its own id first, then its main
/// checkout's) reads by default, in `txn`: the project of the first id whose row names one,
/// while that project is a live PROJECT. `None`: no id is bound, or the first bound one names a
/// project that is gone. An id that is not a workspace id is skipped.
///
/// # Errors
///
/// Storage errors.
pub fn workspace_project_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    workspace_ids: &[String],
) -> Result<Option<EntityId>> {
    for id in workspace_ids.iter().filter(|id| is_workspace_id(id)) {
        let bound = setting_keys::WORKSPACE_PROJECT
            .read_in_txn(vault, txn, &[], Some(id))?
            .value;
        if let Some(project) = bound.project {
            let live =
                crate::workspace_roster::project::is_project_entity(&vault.store, txn, project)?;
            return Ok(live.then_some(project));
        }
    }
    Ok(None)
}

impl Vault {
    /// What an attached session in the folder `workspace_ids` (its own id first) reads by
    /// default: the folder's bound project with every PROJECT below it, or
    /// [`SessionProjects::Unbound`] when no live project is bound.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn session_projects(&self, workspace_ids: &[String]) -> Result<SessionProjects> {
        Ok(match self.workspace_project(workspace_ids)? {
            Some(project) => SessionProjects::Bound(Arc::new(
                crate::memory::project_descendant_closure_of(self, vec![project])?
                    .into_iter()
                    .collect(),
            )),
            None => SessionProjects::Unbound,
        })
    }

    /// [`workspace_project_in_txn`] in a snapshot of its own.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn workspace_project(&self, workspace_ids: &[String]) -> Result<Option<EntityId>> {
        let txn = self.store.env.read_txn()?;
        workspace_project_in_txn(self, &txn, workspace_ids)
    }
}
