use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::entity_id::bytes_to_hex_lower;
use crate::llm::{ContentPart, LlmMessage, LlmMessageRole, LlmRequest};

pub const DEFAULT_PROMPT_PACKAGE_RELATIVE_PATH: &str = "packages/prompts";
pub const EIRI_V3_PROMPT_RELATIVE_PATH: &str = "eiri/v3.md";
pub const PROMPT_RECOMPILE_STAMP_SCHEMA_VERSION: &str = "oneiron.prompt_recompile.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptRecompileStamp {
    pub schema_version: String,
    pub prompt_path: String,
    pub compiled_at_secs: u64,
    pub source_fingerprint: String,
    pub resolved_fingerprint: String,
    pub source_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPrompt {
    pub text: String,
    pub stamp: PromptRecompileStamp,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionPromptParts {
    pub activated_memory: Vec<String>,
    pub history: Vec<LlmMessage>,
    /// Host-supplied off-record marker rendered as its own system-prompt
    /// section. The engine never authors this text.
    pub off_record_marker: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionPromptAssembly {
    pub system_prompt: String,
    pub messages: Vec<LlmMessage>,
    pub stamp: PromptRecompileStamp,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StampedLlmRequest {
    pub request: LlmRequest,
    pub stamp: PromptRecompileStamp,
}

pub fn workspace_prompt_package_root() -> Result<PathBuf, io::Error> {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = crate_root.parent().and_then(Path::parent).ok_or_else(|| {
        io::Error::other(format!(
            "failed to locate workspace root from {}",
            crate_root.display()
        ))
    })?;
    let package_root = workspace_root.join(DEFAULT_PROMPT_PACKAGE_RELATIVE_PATH);
    if package_root.is_dir() {
        Ok(package_root)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "expected monorepo prompt package at {}",
                package_root.display()
            ),
        ))
    }
}

pub fn resolve_eiri_v3_prompt(package_root: impl AsRef<Path>) -> Result<ResolvedPrompt, io::Error> {
    let package_root = package_root.as_ref();
    resolve_prompt(
        package_root.join(EIRI_V3_PROMPT_RELATIVE_PATH),
        package_root,
    )
}

pub fn resolve_prompt(
    path: impl AsRef<Path>,
    package_root: impl AsRef<Path>,
) -> Result<ResolvedPrompt, io::Error> {
    let package_root = fs::canonicalize(package_root)?;
    let path = canonical_prompt_path(path.as_ref(), &package_root)?;
    let mut state = ResolveState::default();
    let text = resolve_prompt_inner(&path, &package_root, &mut state)?;
    let stamp = recompile_stamp(&text, &path, &package_root, &state.source_hashes);
    Ok(ResolvedPrompt { text, stamp })
}

pub fn assemble_eiri_session_prompt(
    package_root: impl AsRef<Path>,
    parts: SessionPromptParts,
) -> Result<SessionPromptAssembly, io::Error> {
    let resolved = resolve_eiri_v3_prompt(package_root)?;
    let system_prompt = assemble_system_prompt(
        &resolved.text,
        parts.off_record_marker.as_deref(),
        &parts.activated_memory,
    );
    let mut messages = Vec::with_capacity(parts.history.len() + 1);
    messages.push(LlmMessage {
        role: LlmMessageRole::System,
        content: vec![ContentPart::Text {
            text: system_prompt.clone(),
        }],
    });
    messages.extend(parts.history);

    Ok(SessionPromptAssembly {
        system_prompt,
        messages,
        stamp: resolved.stamp,
    })
}

pub fn build_eiri_session_request(
    mut request: LlmRequest,
    package_root: impl AsRef<Path>,
    parts: SessionPromptParts,
) -> Result<StampedLlmRequest, io::Error> {
    let assembly = assemble_eiri_session_prompt(package_root, parts)?;
    request.messages = assembly.messages;
    Ok(StampedLlmRequest {
        request,
        stamp: assembly.stamp,
    })
}

#[derive(Default)]
struct ResolveState {
    stack: BTreeSet<PathBuf>,
    source_hashes: BTreeMap<PathBuf, String>,
}

fn resolve_prompt_inner(
    path: &Path,
    package_root: &Path,
    state: &mut ResolveState,
) -> Result<String, io::Error> {
    let canonical_path = fs::canonicalize(path)?;
    if !state.stack.insert(canonical_path.clone()) {
        return Err(io::Error::other(format!(
            "cyclic prompt include: {}",
            canonical_path.display()
        )));
    }

    let source = fs::read_to_string(&canonical_path)?;
    state
        .source_hashes
        .insert(canonical_path.clone(), hash_hex(source.as_bytes()));

    let mut resolved = String::new();
    for line in source.lines() {
        if let Some(include_path) = include_path(line) {
            let include_path = Path::new(include_path);
            if include_path.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "absolute prompt include is not allowed: {}",
                        include_path.display()
                    ),
                ));
            }

            let include_target =
                if include_path.starts_with("./") || include_path.starts_with("../") {
                    canonical_path
                        .parent()
                        .ok_or_else(|| io::Error::other("prompt path has no parent"))?
                        .join(include_path)
                } else {
                    package_root.join(include_path)
                };
            let include_target = canonical_prompt_path(&include_target, package_root)?;
            resolved.push_str(&resolve_prompt_inner(&include_target, package_root, state)?);
        } else {
            resolved.push_str(line);
            resolved.push('\n');
        }
    }

    state.stack.remove(&canonical_path);
    Ok(resolved)
}

fn canonical_prompt_path(path: &Path, package_root: &Path) -> Result<PathBuf, io::Error> {
    let canonical_path = fs::canonicalize(path)?;
    if canonical_path.starts_with(package_root) {
        Ok(canonical_path)
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "prompt include escapes package root: {}",
                canonical_path.display()
            ),
        ))
    }
}

fn include_path(line: &str) -> Option<&str> {
    line.trim()
        .strip_prefix("@include ")
        .map(str::trim)
        .filter(|path| !path.is_empty())
}

fn assemble_system_prompt(
    soul_prompt: &str,
    off_record_marker: Option<&str>,
    activated_memory: &[String],
) -> String {
    let mut prompt = String::new();
    prompt.push_str(soul_prompt.trim_end());
    prompt.push('\n');

    if let Some(marker) = off_record_marker.map(str::trim).filter(|m| !m.is_empty()) {
        prompt.push_str("\n# Off-Record Session\n\n");
        prompt.push_str(marker);
        prompt.push('\n');
    }

    let activated_memory = activated_memory
        .iter()
        .map(|memory| memory.trim())
        .filter(|memory| !memory.is_empty());

    let mut wrote_header = false;
    for memory in activated_memory {
        if !wrote_header {
            prompt.push_str("\n# Activated Memory\n\n");
            wrote_header = true;
        }
        prompt.push_str(memory);
        prompt.push('\n');
    }

    prompt
}

fn recompile_stamp(
    resolved: &str,
    prompt_path: &Path,
    package_root: &Path,
    source_hashes: &BTreeMap<PathBuf, String>,
) -> PromptRecompileStamp {
    let prompt_path = package_relative_path(prompt_path, package_root);
    let source_paths = source_hashes
        .keys()
        .map(|path| package_relative_path(path, package_root))
        .collect::<Vec<_>>();
    PromptRecompileStamp {
        schema_version: PROMPT_RECOMPILE_STAMP_SCHEMA_VERSION.to_owned(),
        prompt_path,
        compiled_at_secs: crate::unix_seconds_now(),
        source_fingerprint: source_fingerprint(source_hashes, package_root),
        resolved_fingerprint: hash_hex(resolved.as_bytes()),
        source_paths,
    }
}

fn source_fingerprint(source_hashes: &BTreeMap<PathBuf, String>, package_root: &Path) -> String {
    let mut bytes = Vec::new();
    for (path, hash) in source_hashes {
        bytes.extend_from_slice(package_relative_path(path, package_root).as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(hash.as_bytes());
        bytes.push(b'\n');
    }
    hash_hex(&bytes)
}

fn package_relative_path(path: &Path, package_root: &Path) -> String {
    path.strip_prefix(package_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn hash_hex(bytes: &[u8]) -> String {
    bytes_to_hex_lower(blake3::hash(bytes).as_bytes())
}
