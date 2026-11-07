//! `oneiron import folder attach|rescan|detach|list`: a folder of markdown
//! notes and PDFs that stays attached to the vault (OF-554, ARCH-0027).
//!
//! `attach` is the owner's one act: it records the folder and lands its notes
//! as `import notes` would. From then on `oneiron serve` rescans every
//! attached folder every few minutes, starting when it starts, and `rescan`
//! does one by hand. A rescan reads the folder the way `import notes` reads
//! it, lands the new files, supersedes what changed files landed and
//! retracts (archives) the notes of files that left. Nothing is ever written
//! to the folder. `detach` stops the rescans; the notes stay. The reading
//! and the rescan are the host's intake (`crate::files_intake`).
//!
//! With the vault stopped, these open it directly as before. When its writer
//! lease is held, they ask that same vault's running serve through its owner
//! folder routes (FIX 11929). `ONEIRON_SECRET` supplies the owner credential
//! and, for a slip bearer, `ONEIRON_BINDING_KEY` signs its holder proof. The
//! attach route's object is printed as the direct command's tuple array;
//! every other answer keeps its existing JSON shape.
//!
//! Stdout carries counts, never note text, titles or link targets.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use oneiron::note::{FolderFileState, FolderSource};
use reqwest::Method;
use serde::Serialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::cli::{ImportFolderAttachArgs, ImportFolderCommand};
use crate::commands::api::{normalized_base, signed_binding};
use crate::commands::local_servers;
use crate::config::{ServeConfig, resolve_serve_config};
use crate::files_intake::{canonical_folder, rescanned};
use oneiron_vault_contract::BINDING_HEADER;

/// One live folder call's whole request/response deadline. Large scans get
/// room; a stalled running serve still ends the CLI instead of holding it forever.
const LIVE_FOLDER_REQUEST_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Serialize)]
struct Listed {
    #[serde(flatten)]
    source: FolderSource,
    files: usize,
    retracted: usize,
    proposed: usize,
}

/// The live runtime entry holding this vault, and the owner credential its
/// routes need. Only a typed writer-lease hold constructs one.
struct HeldServer {
    base: String,
    secret: Option<Zeroizing<String>>,
}

impl HeldServer {
    fn for_vault(config: &ServeConfig) -> anyhow::Result<Self> {
        let wanted = absolute(&config.vault_path);
        let server = local_servers::listed()
            .into_iter()
            .map(|(_, server)| server)
            .filter(|server| local_servers::alive(server.pid))
            .filter(|server| absolute(&server.state_dir) == wanted)
            .max_by_key(|server| server.started_at_ms)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "vault {} is held by a running serve this user cannot find (no live runtime                      entry); stop it, then import — or call its /v1/owner/imports/folders routes                      with `oneiron api raw`",
                    config.vault_path.display()
                )
            })?;
        let secret = match std::env::var("ONEIRON_SECRET") {
            Ok(secret) => Some(Zeroizing::new(secret)),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                anyhow::bail!("ONEIRON_SECRET is not valid UTF-8; nothing was sent")
            }
        };
        Ok(Self {
            base: normalized_base(&server.url)?,
            secret,
        })
    }

    /// One owner-route call. Once the vault is known held, an HTTP or
    /// transport failure is final: no direct-open retry can succeed or
    /// disguise it as "server absent".
    fn call(&self, method: Method, path: &str, body: Option<Value>) -> anyhow::Result<Value> {
        let binding = self
            .secret
            .as_deref()
            .filter(|token| token.starts_with("v2.slip."))
            .map(|token| signed_binding(token, "ONEIRON_BINDING_KEY"))
            .transpose()?;
        let url = format!("{}{path}", self.base);
        let secret = self.secret.clone();
        std::thread::scope(|scope| {
            crate::engine_thread("history-import-folder".into())
                .spawn_scoped(scope, move || -> anyhow::Result<Value> {
                    let client = reqwest::blocking::Client::builder()
                        // The bearer and holder proof stay off every environment proxy.
                        .no_proxy()
                        .redirect(reqwest::redirect::Policy::none())
                        .timeout(LIVE_FOLDER_REQUEST_TIMEOUT)
                        .build()?;
                    let mut request = client.request(method, &url);
                    if let Some(secret) = &secret {
                        request = request.bearer_auth(secret.as_str());
                    }
                    if let Some(binding) = &binding {
                        request = request.header(BINDING_HEADER, binding.as_str());
                    }
                    if let Some(body) = body {
                        request = request
                            .header(reqwest::header::CONTENT_TYPE, "application/json")
                            .body(serde_json::to_vec(&body)?);
                    }
                    let response = request.send().map_err(|error| {
                        anyhow::anyhow!(
                            "vault is held, but its running server is unreachable at {url}: {error}"
                        )
                    })?;
                    let status = response.status();
                    let text = response.text().unwrap_or_default();
                    if !status.is_success() {
                        eprintln!("{text}");
                        anyhow::bail!("{url} answered {status}");
                    }
                    serde_json::from_str(&text)
                        .map_err(|_| anyhow::anyhow!("{url} answered {status} with no JSON"))
                })
                .expect("failed to spawn thread")
                .join()
                .map_err(|_| anyhow::anyhow!("the call to {path} stopped"))?
        })
    }
}

/// An absolute comparison path, with symbolic links resolved where the path
/// exists. Runtime entries store absolute vault paths.
fn absolute(path: &Path) -> PathBuf {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    std::fs::canonicalize(&absolute).unwrap_or(absolute)
}

/// `oneiron import folder <attach|rescan|detach|list>`.
pub(in crate::commands) fn import_folder(command: ImportFolderCommand) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    match command {
        ImportFolderCommand::Attach(args) => {
            let ImportFolderAttachArgs {
                path,
                include,
                kind,
                serve,
            } = *args;
            let folder = canonical_folder(&path)?;
            let config = resolve_serve_config(&serve)?;
            match super::super::try_open_vault(&config)? {
                super::super::VaultOpen::Open(vault) => {
                    let owner = crate::owner::local_owner(&vault)?;
                    let source = vault.attach_folder_source(&owner, &folder, include, &kind)?;
                    let rescanned = rescanned(&vault, &owner, &source);
                    serde_json::to_writer_pretty(&mut stdout, &(&source, &rescanned))?;
                }
                super::super::VaultOpen::Held => {
                    let answer = HeldServer::for_vault(&config)?.call(
                        Method::POST,
                        "/v1/owner/imports/folders/attach",
                        Some(json!({ "path": folder, "include": include, "kind": kind })),
                    )?;
                    let source = answer
                        .get("source")
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("the attach answer has no source field"))?;
                    let rescan = answer
                        .get("rescan")
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("the attach answer has no rescan field"))?;
                    serde_json::to_writer_pretty(&mut stdout, &(source, rescan))?;
                }
            }
        }
        ImportFolderCommand::Rescan(args) => {
            let config = resolve_serve_config(&args.serve)?;
            match super::super::try_open_vault(&config)? {
                super::super::VaultOpen::Open(vault) => {
                    let owner = crate::owner::local_owner(&vault)?;
                    let sources = match &args.path {
                        Some(path) => {
                            let folder = canonical_folder(path)?;
                            vec![vault.folder_source(&folder)?.ok_or_else(|| {
                                anyhow::anyhow!(
                                    "{folder} is not attached; `import folder attach` it"
                                )
                            })?]
                        }
                        None => vault.folder_sources()?,
                    };
                    let rescanned = sources
                        .iter()
                        .map(|source| rescanned(&vault, &owner, source))
                        .collect::<Vec<_>>();
                    serde_json::to_writer_pretty(&mut stdout, &rescanned)?;
                }
                super::super::VaultOpen::Held => {
                    let body = match &args.path {
                        Some(path) => json!({ "path": canonical_folder(path)? }),
                        None => json!({}),
                    };
                    let answer = HeldServer::for_vault(&config)?.call(
                        Method::POST,
                        "/v1/owner/imports/folders/rescan",
                        Some(body),
                    )?;
                    serde_json::to_writer_pretty(&mut stdout, &answer)?;
                }
            }
        }
        ImportFolderCommand::Detach(args) => {
            // A folder that is gone is detached by the name it was attached by.
            let folder = canonical_folder(&args.path)
                .unwrap_or_else(|_| args.path.to_string_lossy().into_owned());
            let config = resolve_serve_config(&args.serve)?;
            match super::super::try_open_vault(&config)? {
                super::super::VaultOpen::Open(vault) => {
                    let owner = crate::owner::local_owner(&vault)?;
                    let detached = vault.detach_folder_source(&owner, &folder)?;
                    anyhow::ensure!(detached, "{folder} is not attached");
                    serde_json::to_writer_pretty(
                        &mut stdout,
                        &serde_json::json!({ "folder": folder, "detached": true }),
                    )?;
                }
                super::super::VaultOpen::Held => {
                    let answer = HeldServer::for_vault(&config)?.call(
                        Method::POST,
                        "/v1/owner/imports/folders/detach",
                        Some(json!({ "path": folder })),
                    )?;
                    serde_json::to_writer_pretty(&mut stdout, &answer)?;
                }
            }
        }
        ImportFolderCommand::List(args) => {
            let config = resolve_serve_config(&args.serve)?;
            match super::super::try_open_vault(&config)? {
                super::super::VaultOpen::Open(vault) => {
                    let listed = vault
                        .folder_sources()?
                        .into_iter()
                        .map(|source| {
                            let files = vault.folder_source_files(&source.folder)?;
                            let count = |wanted: fn(&FolderFileState) -> bool| {
                                files.iter().filter(|file| wanted(&file.state)).count()
                            };
                            Ok(Listed {
                                retracted: count(|state| *state == FolderFileState::Retracted),
                                proposed: count(|state| {
                                    matches!(state, FolderFileState::Proposed { .. })
                                }),
                                files: files.len(),
                                source,
                            })
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?;
                    serde_json::to_writer_pretty(&mut stdout, &listed)?;
                }
                super::super::VaultOpen::Held => {
                    let answer = HeldServer::for_vault(&config)?.call(
                        Method::GET,
                        "/v1/owner/imports/folders",
                        None,
                    )?;
                    serde_json::to_writer_pretty(&mut stdout, &answer)?;
                }
            }
        }
    }
    writeln!(stdout)?;
    Ok(())
}
