//! `oneiron project …`: the owner binds the folder it runs in to the PROJECT its attached agent
//! sessions read by default, unbinds it, or lists the bindings (RECALL-SESSION-PROJECT; Engine
//! ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov: Q3 = A, the owner's act only).
//!
//! Each subcommand is one `vault.settings.*` call on the `workspace.project` key, sent as
//! `oneiron api call` sends a verb, under the credential that command takes: binding is the
//! owner's act, so an agent's credential gets a check-in for the owner, never a binding. The
//! folder's path never leaves this machine: the row is keyed by its workspace id
//! ([`crate::workspace_identity`]) and labelled with its name.

use std::path::Path;
use std::time::Instant;

use anyhow::Context as _;
use oneiron::EntityId;
use oneiron::session_project::WORKSPACE_PROJECT_KEY;
use serde_json::{Value, json};

use crate::cli::{ApiArgs, ApiCommand, ProjectArgs, ProjectCommand};
use crate::workspace_identity::{GIT_TIMEOUT, WorkspaceIdentity};

/// Runs one `oneiron project` subcommand.
///
/// # Errors
///
/// A folder that does not resolve, a project ref that is not 32 hex, and every error
/// `oneiron api` gives.
pub async fn project(args: ProjectArgs) -> anyhow::Result<()> {
    let (verb, data) = match &args.command {
        ProjectCommand::Bind { project_ref } => {
            let identity = folder_identity(args.folder.as_deref())?;
            (
                "vault.settings.set",
                workspace_bind_request(&identity, project_ref)?,
            )
        }
        ProjectCommand::Unbind => {
            let identity = folder_identity(args.folder.as_deref())?;
            ("vault.settings.set", workspace_unbind_request(&identity))
        }
        ProjectCommand::Bindings => (
            "vault.settings.list",
            json!({ "prefix": WORKSPACE_PROJECT_KEY }),
        ),
    };
    super::api(ApiArgs {
        base_url: args.base_url,
        secret_env: args.secret_env,
        binding_key_env: args.binding_key_env,
        resolve_address: args.resolve_address,
        max_time: args.max_time,
        command: ApiCommand::Call {
            verb: verb.to_owned(),
            data: data.to_string(),
        },
    })
    .await
}

/// The identity of `folder`, else of this process's working directory.
fn folder_identity(folder: Option<&Path>) -> anyhow::Result<WorkspaceIdentity> {
    let folder = match folder {
        Some(folder) => folder.to_path_buf(),
        None => std::env::current_dir().context("this process has no working directory")?,
    };
    WorkspaceIdentity::of_session_folder(&folder, Instant::now() + GIT_TIMEOUT).with_context(|| {
        format!(
            "{} is no workspace: it does not resolve, or its checkout root is the filesystem \
             root or the home directory",
            folder.display()
        )
    })
}

/// The `vault.settings.set` request that binds the folder `identity` names (its own id, never
/// its main checkout's) to the PROJECT `project_ref`, labelled with the folder's name.
///
/// # Errors
///
/// A project ref that is not 32 hex.
pub fn workspace_bind_request(
    identity: &WorkspaceIdentity,
    project_ref: &str,
) -> anyhow::Result<Value> {
    let project = EntityId::from_hex(project_ref.trim())
        .map_err(|_| anyhow::anyhow!("a project ref is the PROJECT's id, 32 hex"))?;
    Ok(json!({
        "key": WORKSPACE_PROJECT_KEY,
        "item": identity.own_id(),
        "scope": { "kind": "vault" },
        "value": { "project": project.to_hex(), "label": identity.label },
    }))
}

/// The `vault.settings.set` request that clears the folder `identity` names.
#[must_use]
pub fn workspace_unbind_request(identity: &WorkspaceIdentity) -> Value {
    json!({
        "key": WORKSPACE_PROJECT_KEY,
        "item": identity.own_id(),
        "scope": { "kind": "vault" },
    })
}
