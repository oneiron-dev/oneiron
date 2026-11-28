//! `oneiron project …`: the owner binds the folder it runs in to the PROJECT its attached agent
//! sessions read by default, unbinds it, or lists the bindings (RECALL-SESSION-PROJECT; Engine
//! ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov: Q3 = A, the owner's act only).
//!
//! Bind and unbind are the owner's verbs `vault.projects.workspace.bind` and `.unbind`;
//! bindings is one `vault.settings.list` call on the `workspace.project` key. Each is sent as
//! `oneiron api call` sends a verb, under the credential that command takes: binding is the
//! owner's act, so only the owner's proof binds. The folder's path never leaves this machine:
//! the request names the folder by its digest ([`crate::workspace_identity`]) and its name, and
//! the vault keys the digest with its own id.

use std::path::Path;

use anyhow::Context as _;
use oneiron::EntityId;
use oneiron::session_project::WORKSPACE_PROJECT_KEY;
use serde_json::{Value, json};

use crate::cli::{ApiArgs, ApiCommand, ProjectArgs, ProjectCommand};
use crate::workspace_identity::WorkspaceIdentity;

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
                "vault.projects.workspace.bind",
                workspace_bind_request(&identity, project_ref)?,
            )
        }
        ProjectCommand::Unbind => {
            let identity = folder_identity(args.folder.as_deref())?;
            (
                "vault.projects.workspace.unbind",
                workspace_unbind_request(&identity),
            )
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
    WorkspaceIdentity::of_session_folder(&folder).with_context(|| {
        format!(
            "{} is no workspace: it does not resolve to a directory, or it or its checkout root \
             is the filesystem root or the home directory",
            folder.display()
        )
    })
}

/// The `vault.projects.workspace.bind` request that binds the folder `identity` names (its own
/// digest, never its main checkout's) to the PROJECT `project_ref`, labelled with the folder's
/// name.
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
        "folder_digest": identity.own_digest(),
        "project": project.to_hex(),
        "label": identity.label,
    }))
}

/// The `vault.projects.workspace.unbind` request that clears the folder `identity` names.
#[must_use]
pub fn workspace_unbind_request(identity: &WorkspaceIdentity) -> Value {
    json!({ "folder_digest": identity.own_digest() })
}
