use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::code_run::{CACHE_BOUNDARIES_KEY, CacheBoundary, HOST_PROVIDER_OPTIONS};
use crate::entity_id::bytes_to_hex_lower;
use crate::llm::{
    ByteSpan, ContentPart, LlmMessage, LlmMessageRole, LlmRequest, Segment, SegmentClass,
    SegmentClock, SegmentKind,
};

/// Where a turn's request puts the context read for that turn (FIX 6676).
/// Every assembler that builds a turn's request reads
/// [`session_prompt_layout`]: this module's session builder, the `ai.reply`
/// board door and a chat answer's craft.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptLayout {
    /// The order before FIX 6676: the turn's context joins the early system
    /// text, before the history.
    EarlySystem,
    /// ARCH-0067 v5's order: the stable system, then the append-only
    /// history, then the turn's context as one request-only user message
    /// right before the latest real user turn ([`place_turn_context`]).
    StableHistoryThenTurnContext,
}

/// The layout a host uses when its operator names none: today's order
/// (Engine 10-22 11:35, rubric 1). The answer-quality screen decides whether
/// the stable-prefix layout becomes the default (FIX 9430).
pub const DEFAULT_PROMPT_LAYOUT: PromptLayout = PromptLayout::EarlySystem;

/// The environment variable an operator sets to choose the layout:
/// `stable_history_then_turn_context` for ARCH-0067 v5's order, or
/// `early_system` for today's. Unset or any other value keeps
/// [`DEFAULT_PROMPT_LAYOUT`].
pub const PROMPT_LAYOUT_ENV: &str = "ONEIRON_PROMPT_LAYOUT";

/// The one layout every assembler of a turn's request reads (FIX 6676), as
/// [`PROMPT_LAYOUT_ENV`] names it when the turn is assembled. Both arms are
/// policy alternatives, not a compatibility path.
#[must_use]
pub fn session_prompt_layout() -> PromptLayout {
    match std::env::var(PROMPT_LAYOUT_ENV).as_deref() {
        Ok("stable_history_then_turn_context") => PromptLayout::StableHistoryThenTurnContext,
        Ok("early_system") => PromptLayout::EarlySystem,
        _ => DEFAULT_PROMPT_LAYOUT,
    }
}

#[cfg(any(test, feature = "test-support"))]
pub const TEST_PROMPT_PACKAGE_RELATIVE_PATH: &str = "crates/oneiron/tests/fixtures/prompts";
pub const ENGINE_EXECUTOR_WIRE_PROMPT_RELATIVE_PATH: &str = "blocks/engine-executor-wire.md";
/// The host prompt an executor run's compaction backend writes summaries
/// under (agent-runtime-v1 §d7), in the same package as the wire prompt.
pub const ENGINE_EXECUTOR_COMPACTION_PROMPT_RELATIVE_PATH: &str =
    "blocks/engine-executor-compaction.md";
pub const PROMPT_RECOMPILE_STAMP_SCHEMA_VERSION: &str = "oneiron.prompt_recompile.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptRecompileStamp {
    pub schema_version: String,
    pub prompt_path: String,
    pub compiled_at_secs: u64,
    pub source_fingerprint: String,
    /// Hash of resolved package files, before host sections or memory assembly.
    pub resolved_fingerprint: String,
    /// Hash of the exact system message sent to the model. `None` for a
    /// resolved file that has not yet been assembled into a session request.
    pub assembled_fingerprint: Option<String>,
    pub source_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPrompt {
    pub text: String,
    pub stamp: PromptRecompileStamp,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionPromptParts {
    /// This turn's activated memory: blocks already admitted and rendered,
    /// fenced and attributed, by the board's renderer. Under
    /// [`session_prompt_layout`] they ride the turn's context message after
    /// the history ([`place_turn_context`]), never the system text.
    pub activated_memory: Vec<String>,
    pub history: Vec<LlmMessage>,
    /// Host-supplied sections (including any off-record disclosure).
    /// The host owns both the wording and its section headings. They stay
    /// in the early system text in either layout: a section that changes
    /// turn by turn belongs in `activated_memory` as a rendered block.
    pub host_sections: Vec<String>,
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

#[cfg(any(test, feature = "test-support"))]
pub fn workspace_test_prompt_package_root() -> Result<PathBuf, io::Error> {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = crate_root.parent().and_then(Path::parent).ok_or_else(|| {
        io::Error::other(format!(
            "failed to locate workspace root from {}",
            crate_root.display()
        ))
    })?;
    let package_root = workspace_root.join(TEST_PROMPT_PACKAGE_RELATIVE_PATH);
    if package_root.is_dir() {
        Ok(package_root)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("expected test prompt package at {}", package_root.display()),
        ))
    }
}

/// Resolves the canonical engine-executor wire prompt through the package
/// resolver used by prompt tooling and parity tests.
pub fn resolve_engine_executor_wire_prompt(
    package_root: impl AsRef<Path>,
) -> Result<ResolvedPrompt, io::Error> {
    let package_root = package_root.as_ref();
    resolve_prompt(
        package_root.join(ENGINE_EXECUTOR_WIRE_PROMPT_RELATIVE_PATH),
        package_root,
    )
}

pub fn resolve_engine_executor_compaction_prompt(
    package_root: impl AsRef<Path>,
) -> Result<ResolvedPrompt, io::Error> {
    let package_root = package_root.as_ref();
    resolve_prompt(
        package_root.join(ENGINE_EXECUTOR_COMPACTION_PROMPT_RELATIVE_PATH),
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

pub fn assemble_session_prompt(
    prompt_path: impl AsRef<Path>,
    package_root: impl AsRef<Path>,
    parts: SessionPromptParts,
) -> Result<SessionPromptAssembly, io::Error> {
    let (assembly, _) = assemble_session(prompt_path, package_root, parts)?;
    Ok(assembly)
}

pub fn build_session_request(
    mut request: LlmRequest,
    prompt_path: impl AsRef<Path>,
    package_root: impl AsRef<Path>,
    parts: SessionPromptParts,
) -> Result<StampedLlmRequest, io::Error> {
    let (assembly, context) = assemble_session(prompt_path, package_root, parts)?;
    request.messages = assembly.messages;
    // Only a placed context message moves the indices today's marks name;
    // with none (today's layout among them) the caller's marks stand.
    if context.is_some() {
        rebuild_cache_boundaries(&mut request, context);
    }
    Ok(StampedLlmRequest {
        request,
        stamp: assembly.stamp,
    })
}

/// Puts a turn's context, its already-rendered `blocks` (each fenced and
/// attributed by its own canonical renderer), in `messages` as one
/// request-only user message: the nonempty blocks, trimmed, joined by a
/// blank line, right before the last user message, the latest real user
/// turn, or after them all when `messages` hold no user message. It adds
/// no delimiter of its own. The message belongs to the outgoing request
/// alone, never to history, a witnessed turn or a compaction span. Returns
/// where it went; `None`, with nothing inserted, when every block is empty.
pub fn place_turn_context<S: AsRef<str>>(
    messages: &mut Vec<LlmMessage>,
    blocks: &[S],
) -> Option<usize> {
    let text = blocks
        .iter()
        .map(|block| block.as_ref().trim())
        .filter(|block| !block.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");
    if text.is_empty() {
        return None;
    }
    let at = messages
        .iter()
        .rposition(|message| message.role == LlmMessageRole::User)
        .unwrap_or(messages.len());
    messages.insert(
        at,
        LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text { text }],
        },
    );
    Some(at)
}

/// [`assemble_session_prompt`], beside where [`session_prompt_layout`] put
/// the turn's context: its message's index, or `None` when it rode the
/// system text or there was none. The stamp's assembled fingerprint is the
/// exact system text sent, in either layout.
fn assemble_session(
    prompt_path: impl AsRef<Path>,
    package_root: impl AsRef<Path>,
    parts: SessionPromptParts,
) -> Result<(SessionPromptAssembly, Option<usize>), io::Error> {
    let mut resolved = resolve_prompt(prompt_path, package_root)?;
    let layout = session_prompt_layout();
    let early_memory: &[String] = match layout {
        PromptLayout::EarlySystem => &parts.activated_memory,
        PromptLayout::StableHistoryThenTurnContext => &[],
    };
    let system_prompt = assemble_system_prompt(&resolved.text, &parts.host_sections, early_memory);
    resolved.stamp.assembled_fingerprint = Some(hash_hex(system_prompt.as_bytes()));
    let mut messages = Vec::with_capacity(parts.history.len() + 2);
    messages.push(LlmMessage {
        role: LlmMessageRole::System,
        content: vec![ContentPart::Text {
            text: system_prompt.clone(),
        }],
    });
    messages.extend(parts.history);
    let context = match layout {
        PromptLayout::EarlySystem => None,
        PromptLayout::StableHistoryThenTurnContext => {
            place_turn_context(&mut messages, parts.activated_memory.as_slice())
        }
    };

    Ok((
        SessionPromptAssembly {
            system_prompt,
            messages,
            stamp: resolved.stamp,
        },
        context,
    ))
}

/// Rebuilds the host's cache-boundary descriptor once assembly replaced
/// `request`'s messages (FIX 6676): a message boundary it carried named a
/// message the request no longer holds, so none is kept. Where it named
/// any, the stable prefix's end is marked in their place: the message
/// before the turn's context (`context`), or the request's last when it
/// sends none. Tool boundaries stay, as the tools do. A descriptor that
/// does not decode stays as it is, for the wire to refuse.
fn rebuild_cache_boundaries(request: &mut LlmRequest, context: Option<usize>) {
    let end = match context {
        Some(at) => at.checked_sub(1),
        None => request.messages.len().checked_sub(1),
    };
    let stable_end = end.and_then(|message| {
        let held = request.messages.get(message)?;
        let part = held.content.len().checked_sub(1)?;
        Some(CacheBoundary::Message { message, part })
    });
    let Some(options) = request
        .provider_options
        .get_mut(HOST_PROVIDER_OPTIONS)
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    let Some(Ok(boundaries)) = options
        .get(CACHE_BOUNDARIES_KEY)
        .map(|value| serde_json::from_value::<Vec<CacheBoundary>>(value.clone()))
    else {
        return;
    };
    let named_message = boundaries
        .iter()
        .any(|boundary| matches!(boundary, CacheBoundary::Message { .. }));
    let mut rebuilt: Vec<CacheBoundary> = boundaries
        .into_iter()
        .filter(|boundary| matches!(boundary, CacheBoundary::Tool { .. }))
        .collect();
    if named_message {
        rebuilt.extend(stable_end);
    }
    match serde_json::to_value(&rebuilt) {
        Ok(value) => {
            options.insert(CACHE_BOUNDARIES_KEY.to_owned(), value);
        }
        Err(_) => {
            options.remove(CACHE_BOUNDARIES_KEY);
        }
    }
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
    host_sections: &[String],
    activated_memory: &[String],
) -> String {
    system_prompt_pieces(soul_prompt, host_sections, activated_memory).0
}

/// One piece of an assembled system prompt and where its bytes lie in it
/// (DESIGN-V2 R2): the soul, each host section, each activated memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemPromptPiece {
    pub kind: SegmentKind,
    pub bytes: ByteSpan,
}

/// The system prompt [`assemble_session_prompt`] sends for these parts,
/// byte for byte, with each piece's place in it. The `# Activated Memory`
/// heading and the separators belong to no piece.
pub fn system_prompt_pieces(
    soul_prompt: &str,
    host_sections: &[String],
    activated_memory: &[String],
) -> (String, Vec<SystemPromptPiece>) {
    let mut pieces = Vec::new();
    let mut piece = |kind: SegmentKind, prompt: &mut String, text: &str| {
        let start = prompt.len();
        prompt.push_str(text);
        pieces.push(SystemPromptPiece {
            kind,
            bytes: ByteSpan {
                start,
                end: prompt.len(),
            },
        });
    };
    let mut prompt = String::new();
    piece(SegmentKind::System, &mut prompt, soul_prompt.trim_end());
    prompt.push('\n');

    for section in host_sections
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        prompt.push('\n');
        piece(SegmentKind::HostSection, &mut prompt, section);
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
        piece(SegmentKind::ActivatedMemory, &mut prompt, memory);
        prompt.push('\n');
    }

    (prompt, pieces)
}

/// The segments of a system message at `message` assembled from `pieces`:
/// the soul and the host sections on the epoch clock, canonical; each
/// activated memory live, and so ephemeral wherever it sits.
#[must_use]
pub fn system_prompt_segments(pieces: &[SystemPromptPiece], message: usize) -> Vec<Segment> {
    pieces
        .iter()
        .map(|piece| {
            let memory = piece.kind == SegmentKind::ActivatedMemory;
            let clock = if memory {
                SegmentClock::Live
            } else {
                SegmentClock::Epoch
            };
            let mut segment =
                Segment::whole(piece.kind.clone(), clock, message).within(piece.bytes);
            if memory {
                segment.class = SegmentClass::Ephemeral;
            }
            segment
        })
        .collect()
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
        assembled_fingerprint: None,
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
