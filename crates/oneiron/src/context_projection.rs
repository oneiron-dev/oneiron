//! Typed context projection (`ContextSpec`) and the referenced panel-spec
//! codec/planner a recursive task lead composes over existing primitives.
//!
//! Two generic mechanisms live here, both consumer-neutral despite their
//! EIRI-ARCH-0013 canon source:
//!
//! 1. **`ContextSpec` — a descriptor, not context data.** `self.context(spec)`
//!    returns the descriptor unchanged; RESOLUTION happens later, at agent
//!    dispatch, so a sub-agent reads fresh state rather than a create-time
//!    snapshot. Resolution follows one fixed order — Layers → Memory → Chat →
//!    Briefing — and the dev-only `_annotation` never reaches a resolved
//!    projection.
//!
//! 2. **`LeadPanelSpec` — a typed spec entity, referenced by a consult.** The
//!    consult wire stays exactly `{question_ref, context_refs, correlation_ref}`:
//!    free-form question text, member instructions, judge rubric, and synthesis
//!    instructions live only in referenced durable entities, never inline in a
//!    TASK payload. [`plan_lead_panel_tasks`] returns typed task INPUTS; the
//!    lead mints the actual TASKs with ordinary `tasks.create` calls. This is
//!    not a workflow executor and it pre-allocates no entity ids.
//!
//! ## The narrowing law
//!
//! Context can only narrow, never widen. That is enforced twice, on two
//! different axes, because they answer different questions:
//!
//! * [`validate_spec_narrows`] compares two DECLARED bounds — the parent's
//!   stored spec against the child's requested one. A child cannot ask for a
//!   domain its parent did not scope, nor raise a limit.
//! * [`validate_context_narrows`] compares the child's request against what the
//!   parent ACTUALLY RESOLVED. A child cannot name a layer the parent did not
//!   project, and an explicit `Scoped`/`Recent` request against an empty parent
//!   projection is the "excluded → included" widening the law forbids.
//!   `Default` inherits and is therefore always admissible.
//!
//! Resolution additionally INTERSECTS a child's sections with its parent's, so
//! narrowing holds structurally even where neither declarative check bites.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::WorldScope;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::task_verb::{ConsultPayload, ConsultPayloadRef, TaskAssignee, TaskTerminalDisposition};
use crate::temporal::TimeRange;

/// Most layer names one projection may name.
pub const CONTEXT_SPEC_MAX_LAYERS: usize = 32;
/// Most memory domains one scoped projection may name.
pub const CONTEXT_SPEC_MAX_DOMAINS: usize = 32;
/// Byte cap on a layer name or memory domain token.
pub const CONTEXT_SPEC_MAX_LABEL_BYTES: usize = 256;
/// Byte cap on free-form descriptor text (briefing, annotation, instructions).
pub const CONTEXT_SPEC_MAX_TEXT_BYTES: usize = 8192;
/// Hard ceiling on a scoped memory projection's `limit`.
pub const CONTEXT_SPEC_MAX_MEMORY_LIMIT: usize = 256;
/// Hard ceiling on a recent-chat projection's `last_n`.
pub const CONTEXT_SPEC_MAX_CHAT_LAST_N: usize = 256;
/// Sections a `MemoryProjection::Default` resolves to at a root dispatch.
pub const CONTEXT_SPEC_DEFAULT_MEMORY_LIMIT: usize = 32;
/// Sections a `ChatProjection::Default` resolves to at a root dispatch.
pub const CONTEXT_SPEC_DEFAULT_CHAT_LAST_N: usize = 16;
/// Rows a memory resolution may walk before it stops looking.
pub const CONTEXT_SPEC_MEMORY_SCAN_LIMIT: usize = 512;
/// Ancestors the dispatcher folds when rebuilding a parent projection. A
/// structural backstop, not a policy: `depth_remaining` is the real bound.
pub const CONTEXT_PROJECTION_MAX_ANCESTORS: usize = 16;
/// Most members one panel spec may carry.
pub const LEAD_PANEL_MAX_MEMBERS: usize = 16;

/// Pinned schema version of the persisted `LeadPanelSpec` entity body.
pub const LEAD_PANEL_SPEC_SCHEMA_VERSION: u64 = 1;
/// Pinned `role` discriminant of the persisted `LeadPanelSpec` entity body.
pub const LEAD_PANEL_SPEC_ROLE: &str = "lead_panel_spec";

/// A projection DESCRIPTOR. It names what a delegated agent may see; it never
/// carries the content itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextSpec {
    #[serde(default)]
    pub layers: Vec<String>,
    #[serde(default)]
    pub memory: MemoryProjection,
    #[serde(default)]
    pub chat: ChatProjection,
    #[serde(default)]
    pub briefing: Option<String>,
    /// Dev-only authoring note. Stripped at resolution — it never reaches a
    /// [`ResolvedContextProjection`] and therefore never reaches a prompt.
    #[serde(
        rename = "_annotation",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub annotation: Option<String>,
}

impl Default for ContextSpec {
    fn default() -> Self {
        Self {
            layers: Vec::new(),
            memory: MemoryProjection::Default,
            chat: ChatProjection::Default,
            briefing: None,
            annotation: None,
        }
    }
}

impl ContextSpec {
    /// The everything-excluded descriptor: the narrowest legal projection.
    #[must_use]
    pub fn excluded() -> Self {
        Self {
            layers: Vec::new(),
            memory: MemoryProjection::Exclude,
            chat: ChatProjection::Exclude,
            briefing: None,
            annotation: None,
        }
    }

    /// Adds parent-authored delegation text. Briefing grants no read scope.
    #[must_use]
    pub fn with_briefing(mut self, briefing: impl Into<String>) -> Self {
        self.briefing = Some(briefing.into());
        self
    }
}

/// How much of the parent's memory the delegate may project.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum MemoryProjection {
    /// Inherit the parent's projection verbatim (the widest legal request).
    #[default]
    Default,
    Exclude,
    Scoped {
        domains: Vec<String>,
        limit: usize,
    },
}

/// How much of the parent's chat history the delegate may project.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ChatProjection {
    #[default]
    Default,
    Exclude,
    Recent {
        last_n: usize,
    },
}

/// One dispatch-time resolution request.
#[derive(Debug, Clone, PartialEq)]
pub struct ContextResolutionRequest {
    pub spec: ContextSpec,
    /// The parent's already-resolved projection, absent at a root dispatch.
    pub parent: Option<ResolvedContextProjection>,
    /// Settled sibling RESULT refs, injected separately from parent context.
    pub context_from: Vec<EntityId>,
    /// Effective dispatch world boundary; absent preserves the all-world default.
    pub world_scope: Option<WorldScope>,
}

/// What a [`ContextSpec`] resolved to against live vault state.
///
/// A RUNTIME value, deliberately not serde: it is recomputed at every dispatch
/// from live state, never persisted, so a stale copy can never be replayed as
/// if it were fresh.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedContextProjection {
    pub layers: Vec<String>,
    /// `"<domain>:cl_<hex>"` tokens, newest-first.
    pub memory_sections: Vec<String>,
    /// `"tn_<hex>"` tokens, newest-first.
    pub chat_sections: Vec<String>,
    pub briefing: Option<String>,
    pub sibling_result_refs: Vec<EntityId>,
}

impl ResolvedContextProjection {
    /// The distinct memory domains this projection actually reached.
    #[must_use]
    pub fn memory_domains(&self) -> Vec<&str> {
        let mut domains: Vec<&str> = self
            .memory_sections
            .iter()
            .filter_map(|section| section.split_once(':').map(|(domain, _)| domain))
            .collect();
        domains.sort_unstable();
        domains.dedup();
        domains
    }
}

/// `self.context(spec)` — the identity call. It returns the spec as-is because
/// it IS a descriptor: resolution happens at dispatch time so data is fresh,
/// not stale. It reads no memory, consumes no budget, and resolves no text.
#[must_use]
pub fn context(spec: ContextSpec) -> ContextSpec {
    spec
}

/// Canonicalizes a descriptor without changing its meaning: trims tokens, drops
/// blanks, and dedupes while preserving caller order. Idempotent.
#[must_use]
pub fn normalize_context_spec(spec: ContextSpec) -> ContextSpec {
    ContextSpec {
        layers: normalize_tokens(spec.layers),
        memory: match spec.memory {
            MemoryProjection::Scoped { domains, limit } => MemoryProjection::Scoped {
                domains: normalize_tokens(domains),
                limit,
            },
            mode @ (MemoryProjection::Default | MemoryProjection::Exclude) => mode,
        },
        chat: spec.chat,
        briefing: normalize_text(spec.briefing),
        annotation: normalize_text(spec.annotation),
    }
}

/// Structural validation of one descriptor, independent of any parent.
pub fn validate_context_spec(spec: &ContextSpec) -> Result<()> {
    if spec.layers.len() > CONTEXT_SPEC_MAX_LAYERS {
        return Err(Error::InvalidAgentDispatchInput(
            "context spec names too many layers",
        ));
    }
    for layer in &spec.layers {
        validate_label(
            layer,
            "context spec layer name must be non-empty and bounded",
        )?;
    }
    match &spec.memory {
        MemoryProjection::Default | MemoryProjection::Exclude => {}
        MemoryProjection::Scoped { domains, limit } => {
            if domains.is_empty() {
                return Err(Error::InvalidAgentDispatchInput(
                    "scoped memory projection must name at least one domain",
                ));
            }
            if domains.len() > CONTEXT_SPEC_MAX_DOMAINS {
                return Err(Error::InvalidAgentDispatchInput(
                    "scoped memory projection names too many domains",
                ));
            }
            for domain in domains {
                validate_label(
                    domain,
                    "memory domain must be non-empty, bounded, and separator-free",
                )?;
                if domain.contains(':') {
                    return Err(Error::InvalidAgentDispatchInput(
                        "memory domain must be non-empty, bounded, and separator-free",
                    ));
                }
            }
            if *limit == 0 || *limit > CONTEXT_SPEC_MAX_MEMORY_LIMIT {
                return Err(Error::InvalidAgentDispatchInput(
                    "scoped memory projection limit is out of range",
                ));
            }
        }
    }
    match &spec.chat {
        ChatProjection::Default | ChatProjection::Exclude => {}
        ChatProjection::Recent { last_n } => {
            if *last_n == 0 || *last_n > CONTEXT_SPEC_MAX_CHAT_LAST_N {
                return Err(Error::InvalidAgentDispatchInput(
                    "recent chat projection last_n is out of range",
                ));
            }
        }
    }
    validate_optional_text(
        spec.briefing.as_deref(),
        "context spec briefing is too long",
    )?;
    validate_optional_text(
        spec.annotation.as_deref(),
        "context spec annotation is too long",
    )
}

/// DECLARED-bound narrowing: the child's requested scope against the parent's
/// stored scope. `Default` inherits, so it is always admissible.
pub fn validate_spec_narrows(parent: &ContextSpec, child: &ContextSpec) -> Result<()> {
    for layer in &child.layers {
        if !parent.layers.iter().any(|known| known == layer) {
            return Err(Error::InvalidAgentDispatchInput(
                "child context spec requests a layer its parent does not carry",
            ));
        }
    }
    if let MemoryProjection::Scoped { domains, limit } = &child.memory {
        match &parent.memory {
            MemoryProjection::Exclude => {
                return Err(Error::InvalidAgentDispatchInput(
                    "child memory projection cannot widen a parent that excludes memory",
                ));
            }
            MemoryProjection::Default => {}
            MemoryProjection::Scoped {
                domains: parent_domains,
                limit: parent_limit,
            } => {
                for domain in domains {
                    if !parent_domains.iter().any(|known| known == domain) {
                        return Err(Error::InvalidAgentDispatchInput(
                            "child memory projection requests a domain outside its parent scope",
                        ));
                    }
                }
                if limit > parent_limit {
                    return Err(Error::InvalidAgentDispatchInput(
                        "child memory projection raises its parent limit",
                    ));
                }
            }
        }
    }
    if let ChatProjection::Recent { last_n } = &child.chat {
        match &parent.chat {
            ChatProjection::Exclude => {
                return Err(Error::InvalidAgentDispatchInput(
                    "child chat projection cannot widen a parent that excludes chat",
                ));
            }
            ChatProjection::Default => {}
            ChatProjection::Recent {
                last_n: parent_last_n,
            } => {
                if last_n > parent_last_n {
                    return Err(Error::InvalidAgentDispatchInput(
                        "child chat projection raises its parent bound",
                    ));
                }
            }
        }
    }
    Ok(())
}

/// RESOLVED-bound narrowing: the child's request against what the parent
/// actually projected.
pub fn validate_context_narrows(
    parent: &ResolvedContextProjection,
    child: &ContextSpec,
) -> Result<()> {
    for layer in &child.layers {
        if !parent.layers.iter().any(|known| known == layer) {
            return Err(Error::InvalidAgentDispatchInput(
                "child context spec requests a layer the parent did not project",
            ));
        }
    }
    if let MemoryProjection::Scoped { domains, limit } = &child.memory {
        if parent.memory_sections.is_empty() {
            return Err(Error::InvalidAgentDispatchInput(
                "child memory projection cannot widen an empty parent projection",
            ));
        }
        let parent_domains = parent.memory_domains();
        for domain in domains {
            if !parent_domains.iter().any(|known| *known == domain.as_str()) {
                return Err(Error::InvalidAgentDispatchInput(
                    "child memory projection requests a domain the parent did not project",
                ));
            }
        }
        if *limit > parent.memory_sections.len() {
            return Err(Error::InvalidAgentDispatchInput(
                "child memory projection exceeds the parent's projected section count",
            ));
        }
    }
    if let ChatProjection::Recent { last_n } = &child.chat {
        if parent.chat_sections.is_empty() {
            return Err(Error::InvalidAgentDispatchInput(
                "child chat projection cannot widen an empty parent projection",
            ));
        }
        if *last_n > parent.chat_sections.len() {
            return Err(Error::InvalidAgentDispatchInput(
                "child chat projection exceeds the parent's projected section count",
            ));
        }
    }
    Ok(())
}

/// Resolves one descriptor against LIVE vault state in the fixed order
/// Layers → Memory → Chat → Briefing, stripping `_annotation`.
///
/// # Errors
///
/// [`Error::InvalidAgentDispatchInput`] when the descriptor is malformed, when
/// it widens beyond `request.parent`, or when a `context_from` ref does not
/// name a SETTLED sibling TASK with a `Completed` terminal result (missing,
/// unsettled, non-TASK, or non-completed rows all reject).
pub fn resolve_context_spec(
    vault: &Vault,
    request: ContextResolutionRequest,
) -> Result<ResolvedContextProjection> {
    let ContextResolutionRequest {
        spec,
        parent,
        context_from,
        world_scope,
    } = request;
    let spec = normalize_context_spec(spec);
    validate_context_spec(&spec)?;
    if let Some(parent) = parent.as_ref() {
        validate_context_narrows(parent, &spec)?;
    }

    // 1. Layers.
    let layers = spec.layers.clone();
    // 2. Memory.
    let memory_sections =
        resolve_memory_sections(vault, &spec.memory, parent.as_ref(), world_scope)?;
    // 3. Chat.
    let chat_sections = resolve_chat_sections(vault, &spec.chat, parent.as_ref())?;
    // 4. Briefing — parent-authored delegation text, never a read grant. The
    //    dev-only `_annotation` is dropped here and reaches no prompt.
    let briefing = spec.briefing.clone();

    Ok(ResolvedContextProjection {
        layers,
        memory_sections,
        chat_sections,
        briefing,
        sibling_result_refs: resolve_sibling_results(vault, &context_from)?,
    })
}

fn resolve_memory_sections(
    vault: &Vault,
    projection: &MemoryProjection,
    parent: Option<&ResolvedContextProjection>,
    world_scope: Option<WorldScope>,
) -> Result<Vec<String>> {
    match projection {
        MemoryProjection::Exclude => Ok(Vec::new()),
        // Inherit: a `Default` child sees exactly what its parent saw, which is
        // both the widest legal request and the no-context-rot answer.
        MemoryProjection::Default => match parent {
            Some(parent) => Ok(parent.memory_sections.clone()),
            None => {
                scan_memory_sections(vault, None, CONTEXT_SPEC_DEFAULT_MEMORY_LIMIT, world_scope)
            }
        },
        MemoryProjection::Scoped { domains, limit } => {
            let sections = scan_memory_sections(vault, Some(domains), *limit, world_scope)?;
            Ok(intersect_with_parent(
                sections,
                parent.map(|parent| parent.memory_sections.as_slice()),
                *limit,
            ))
        }
    }
}

fn resolve_chat_sections(
    vault: &Vault,
    projection: &ChatProjection,
    parent: Option<&ResolvedContextProjection>,
) -> Result<Vec<String>> {
    match projection {
        ChatProjection::Exclude => Ok(Vec::new()),
        ChatProjection::Default => match parent {
            Some(parent) => Ok(parent.chat_sections.clone()),
            None => scan_chat_sections(vault, CONTEXT_SPEC_DEFAULT_CHAT_LAST_N),
        },
        ChatProjection::Recent { last_n } => {
            let sections = scan_chat_sections(vault, *last_n)?;
            Ok(intersect_with_parent(
                sections,
                parent.map(|parent| parent.chat_sections.as_slice()),
                *last_n,
            ))
        }
    }
}

/// Structural narrowing: a child never sees a section its parent did not.
fn intersect_with_parent(
    sections: Vec<String>,
    parent: Option<&[String]>,
    limit: usize,
) -> Vec<String> {
    let mut kept = match parent {
        Some(parent) => sections
            .into_iter()
            .filter(|section| parent.iter().any(|known| known == section))
            .collect(),
        None => sections,
    };
    kept.truncate(limit);
    kept
}

/// Live read: the newest CLAIM rows whose predicate namespace is in scope.
fn scan_memory_sections(
    vault: &Vault,
    domains: Option<&[String]>,
    limit: usize,
    world_scope: Option<WorldScope>,
) -> Result<Vec<String>> {
    let rows = vault.latest_entity_bodies_by_type(
        ENTITY_TYPE_CLAIM,
        CONTEXT_SPEC_MEMORY_SCAN_LIMIT,
        CONTEXT_SPEC_MEMORY_SCAN_LIMIT,
    )?;
    let mut sections = Vec::with_capacity(limit.min(rows.len()));
    for (id, _learned_at, _body) in rows {
        if sections.len() >= limit {
            break;
        }
        let Some(claim) = vault.get_claim(&id)? else {
            continue;
        };
        // `get_claim` is the deliberately-ungated history door (claim.rs D19):
        // apply the crate's canonical surfacing gate so Proposed/Rejected/
        // Superseded/Retracted/stale claims never reach a memory projection.
        if !crate::claim::claim_surfaceable(&claim) {
            continue;
        }
        let in_world = match world_scope.unwrap_or(WorldScope::All) {
            WorldScope::All => true,
            WorldScope::Base => claim.world.is_none(),
            WorldScope::World(world) => claim.world.is_none() || claim.world == Some(world),
            WorldScope::WorldSet(_) => true, // not used by AgentScope mapping
        };
        if !in_world {
            continue;
        }
        let domain = memory_domain_of(&claim.predicate);
        if domains.is_some_and(|scope| !scope.iter().any(|known| known == domain)) {
            continue;
        }
        sections.push(format!("{domain}:cl_{}", id.to_hex()));
    }
    Ok(sections)
}

/// Live read: the newest CONVERSATIONAL TURN rows, newest-first. Non-
/// conversational artifacts persisted AS TURNs (the panel-spec entity,
/// consult-expiry receipts, marker bodies) are filtered BEFORE `last_n`
/// applies, so they can neither reach a chat projection nor displace real
/// conversational turns under the bounded over-scan.
fn scan_chat_sections(vault: &Vault, last_n: usize) -> Result<Vec<String>> {
    let mut sections = Vec::with_capacity(last_n);
    for (id, _learned_at, body) in vault.latest_entity_bodies_by_type(
        ENTITY_TYPE_TURN,
        CONTEXT_SPEC_MEMORY_SCAN_LIMIT,
        CONTEXT_SPEC_MEMORY_SCAN_LIMIT,
    )? {
        if !is_conversational_turn_body(vault, &id, &body)? {
            continue;
        }
        sections.push(format!("tn_{}", id.to_hex()));
        if sections.len() >= last_n {
            break;
        }
    }
    Ok(sections)
}

/// The chat projection's local shape check for a conversational turn. A row
/// is conversational iff its body map carries a recognized speaker marker
/// (`speaker|role|author`, plus the legacy `spkr`) AND a text-ish payload key
/// (`text`, legacy `txt`) — the same vocabulary the ingest decoder
/// normalizes. A `role == lead_panel_spec` discriminant is a known artifact,
/// never chat. Everything else (undecodable, non-map, marker-only) fails at
/// least one marker and is excluded.
fn is_conversational_turn_body(vault: &Vault, turn: &EntityId, body: &[u8]) -> Result<bool> {
    let mut cursor = body;
    let Ok(rmpv::Value::Map(entries)) = rmpv::decode::read_value(&mut cursor) else {
        return Ok(false);
    };
    let get = |key: &str| {
        entries
            .iter()
            .find(|(candidate, _)| candidate.as_str() == Some(key))
            .map(|(_, value)| value)
    };
    if get("role").and_then(rmpv::Value::as_str) == Some(LEAD_PANEL_SPEC_ROLE) {
        return Ok(false);
    }
    let speaker = ["speaker", "role", "author", "spkr"].iter().any(|key| {
        get(key)
            .and_then(rmpv::Value::as_str)
            .is_some_and(|v| !v.trim().is_empty())
    });
    let text = ["text", "txt"].iter().any(|key| {
        get(key)
            .and_then(rmpv::Value::as_str)
            .is_some_and(|v| !v.is_empty())
    });
    if speaker && text {
        return Ok(true);
    }
    if !entries.is_empty() {
        return Ok(false);
    }
    // Witnessed conversations use an empty TURN container with MESSAGE children.
    for edge in vault.neighbor_edges_bounded(
        turn,
        false,
        Some(EdgeKind::PartOf),
        None,
        CONTEXT_SPEC_MEMORY_SCAN_LIMIT,
    )? {
        let Some(raw) = vault.get_raw(&edge.target)? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if header.entity_type != ENTITY_TYPE_MESSAGE {
            continue;
        }
        let mut child = &raw[ENTITY_METADATA_HEADER_LEN..];
        let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut child) else {
            continue;
        };
        let field = |key: &str| {
            fields
                .iter()
                .find(|(k, _)| k.as_str() == Some(key))
                .map(|(_, v)| v)
        };
        let author = ["author", "speaker"].iter().any(|k| {
            field(k)
                .and_then(rmpv::Value::as_str)
                .is_some_and(|v| !v.trim().is_empty())
        });
        let content = ["content", "text"].iter().any(|k| {
            field(k)
                .and_then(rmpv::Value::as_str)
                .is_some_and(|v| !v.is_empty())
        });
        if author && content {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A claim's memory domain: its predicate namespace, or the whole predicate
/// when it carries none.
fn memory_domain_of(predicate: &str) -> &str {
    predicate
        .split_once('.')
        .map_or(predicate, |(namespace, _)| namespace)
}

/// `contextFrom` is deliberately NOT parent-context projection: it injects
/// SETTLED sibling TASK results and nothing else. Admission is enforced here
/// and at dispatch, fail-closed with a typed error at every door:
///
/// 1. HERE (settlement + result binding): each ref must name a TASK whose
///    terminal record is `Completed` with a `result_ref`, proven through the
///    task_verb read-only seam. A durable-but-unsettled artifact, an
///    arbitrary non-TASK row, and a non-`Completed` terminal TASK all reject
///    — `land_task_result` resolves the artifact BEFORE the terminal write,
///    so existence alone never proved settlement.
/// 2. AT DISPATCH (lineage): [`crate::agent_dispatch`]'s resolution path
///    proves each ref's create-owner is the parent attempt's dispatched row
///    and that the spawn rides the parent's run, so a ref from a different
///    parent or run rejects.
fn resolve_sibling_results(vault: &Vault, context_from: &[EntityId]) -> Result<Vec<EntityId>> {
    let mut resolved = Vec::with_capacity(context_from.len());
    for entity_ref in context_from {
        let Some((disposition, result_ref)) =
            crate::task_verb::settled_task_result_binding(vault, *entity_ref)?
        else {
            return Err(Error::InvalidAgentDispatchInput(
                "contextFrom names no settled sibling TASK result",
            ));
        };
        if disposition != TaskTerminalDisposition::Completed {
            return Err(Error::InvalidAgentDispatchInput(
                "contextFrom names a sibling TASK settled without a completed result",
            ));
        }
        if resolved.contains(&result_ref) {
            return Err(Error::InvalidAgentDispatchInput(
                "contextFrom names the same sibling result twice",
            ));
        }
        resolved.push(result_ref);
    }
    Ok(resolved)
}

// ── typed referenced panel spec ─────────────────────────────────────────

/// A blind panel, its single judge pass, and its one synthesis.
///
/// Persisted as its own typed spec entity; NEVER inline in a `ConsultPayload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeadPanelSpec {
    pub members: Vec<PanelMemberSpec>,
    pub judge: PanelJudgeSpec,
    pub synthesis: PanelSynthesisSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelMemberSpec {
    #[serde(with = "assignee_wire")]
    pub responder: TaskAssignee,
    pub instructions: String,
    pub context_spec: ContextSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelJudgeSpec {
    #[serde(with = "assignee_wire")]
    pub responder: TaskAssignee,
    pub rubric: String,
    pub context_spec: ContextSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelSynthesisSpec {
    #[serde(with = "assignee_wire")]
    pub responder: TaskAssignee,
    pub instructions: String,
    pub context_spec: ContextSpec,
}

/// Structural validation of a panel spec, independent of any vault.
pub fn validate_lead_panel_spec(spec: &LeadPanelSpec) -> Result<()> {
    if spec.members.is_empty() {
        return Err(Error::InvalidTaskBody("panel spec must name a member"));
    }
    if spec.members.len() > LEAD_PANEL_MAX_MEMBERS {
        return Err(Error::InvalidTaskBody("panel spec names too many members"));
    }
    for (index, member) in spec.members.iter().enumerate() {
        if !matches!(member.responder, TaskAssignee::Peer { .. }) {
            return Err(Error::InvalidTaskBody("panel responders must be Peer"));
        }
        validate_panel_text(&member.instructions, "panel member instructions")?;
        validate_context_spec(&member.context_spec)?;
        // Distinct responders keep "N members" a count of ANSWERS, not of
        // duplicate asks landing on one actor.
        if spec.members[..index]
            .iter()
            .any(|prior| prior.responder == member.responder)
        {
            return Err(Error::InvalidTaskBody(
                "panel spec names one responder twice",
            ));
        }
    }
    if !matches!(spec.judge.responder, TaskAssignee::Peer { .. })
        || !matches!(spec.synthesis.responder, TaskAssignee::Peer { .. })
    {
        return Err(Error::InvalidTaskBody("panel responders must be Peer"));
    }
    validate_panel_text(&spec.judge.rubric, "panel judge rubric")?;
    validate_context_spec(&spec.judge.context_spec)?;
    validate_panel_text(&spec.synthesis.instructions, "panel synthesis instructions")?;
    validate_context_spec(&spec.synthesis.context_spec)
}

/// Persists a panel spec as a durable TURN and returns the already-legal
/// consult ref that points at it. No NOTE payload-ref variant, no new TASK
/// field, no inline text.
pub fn persist_lead_panel_spec(
    vault: &Vault,
    spec: &LeadPanelSpec,
    now: u64,
) -> Result<ConsultPayloadRef> {
    validate_lead_panel_spec(spec)?;
    let body = encode_lead_panel_spec(spec)?;
    let spec_ref = EntityId::now();
    vault.put_entity(
        &spec_ref,
        ENTITY_TYPE_TURN,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        &body,
    )?;
    Ok(ConsultPayloadRef::Turn(spec_ref))
}

/// Loads and validates the panel spec a consult ref points at.
pub fn load_lead_panel_spec(vault: &Vault, spec_ref: ConsultPayloadRef) -> Result<LeadPanelSpec> {
    let ConsultPayloadRef::Turn(entity_ref) = spec_ref else {
        return Err(Error::InvalidTaskBody(
            "panel spec ref must name the durable spec turn",
        ));
    };
    let raw = vault
        .get_raw(&entity_ref)?
        .ok_or(Error::InvalidTaskBody("panel spec ref does not resolve"))?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::InvalidTaskBody("panel spec row header is malformed"))?;
    if header.entity_type != ENTITY_TYPE_TURN {
        return Err(Error::InvalidTaskBody("panel spec ref is not a turn row"));
    }
    let spec = decode_lead_panel_spec(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    validate_lead_panel_spec(&spec)?;
    Ok(spec)
}

/// Encodes a panel spec into its pinned-key entity body.
pub fn encode_lead_panel_spec(spec: &LeadPanelSpec) -> Result<Vec<u8>> {
    let json = serde_json::to_string(spec)
        .map_err(|_| Error::InvalidTaskBody("panel spec does not encode"))?;
    let value = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("role"),
            rmpv::Value::from(LEAD_PANEL_SPEC_ROLE),
        ),
        (
            rmpv::Value::from("schema_version"),
            rmpv::Value::from(LEAD_PANEL_SPEC_SCHEMA_VERSION),
        ),
        (rmpv::Value::from("spec"), rmpv::Value::from(json.as_str())),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvalidTaskBody("panel spec body does not encode"))?;
    Ok(out)
}

/// Decodes a pinned-key panel-spec entity body.
pub fn decode_lead_panel_spec(bytes: &[u8]) -> Result<LeadPanelSpec> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidTaskBody("panel spec body is not MessagePack"))?;
    let rmpv::Value::Map(entries) = value else {
        return Err(Error::InvalidTaskBody("panel spec body must be a map"));
    };
    let field = |name: &str| {
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    };
    if field("role").and_then(rmpv::Value::as_str) != Some(LEAD_PANEL_SPEC_ROLE) {
        return Err(Error::InvalidTaskBody(
            "panel spec body role is not a panel",
        ));
    }
    if field("schema_version").and_then(rmpv::Value::as_u64) != Some(LEAD_PANEL_SPEC_SCHEMA_VERSION)
    {
        return Err(Error::InvalidTaskBody(
            "panel spec schema version must be 1",
        ));
    }
    let json = field("spec")
        .and_then(rmpv::Value::as_str)
        .ok_or(Error::InvalidTaskBody("panel spec body carries no spec"))?;
    serde_json::from_str(json).map_err(|_| Error::InvalidTaskBody("panel spec does not decode"))
}

/// Which settled results a planned TASK must wait for before it is mintable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelResultInputs {
    None,
    AllMemberResults,
    AllMemberAndJudgeResults,
}

/// A typed INPUT the lead turns into a real TASK with `tasks.create`. It is not
/// a pre-allocated task id, and it carries no entity the lead has not minted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeadPanelTaskInputSpec {
    pub responder: TaskAssignee,
    pub consult: ConsultPayload,
    pub context_spec: ContextSpec,
    pub result_inputs: PanelResultInputs,
}

/// The lead's plan for one panel run: N blind members, one judge pass, one
/// synthesis. Ordering is carried by [`PanelResultInputs`], not by a scheduler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeadPanelExecutionPlan {
    pub member_tasks: Vec<LeadPanelTaskInputSpec>,
    pub judge_task: LeadPanelTaskInputSpec,
    pub synthesis_task: LeadPanelTaskInputSpec,
}

/// Plans the typed task inputs for one `ask(lead, panel-spec)` run.
///
/// Every planned `ConsultPayload` uses ONE-1699's fields only: the shared
/// `question_ref`, `context_refs` carrying the persisted panel-spec ref, and
/// the shared `correlation_ref`. Member inputs carry NO sibling results — panel
/// blindness is structural, not a runtime check.
///
/// # Errors
///
/// [`Error::InvalidTaskBody`] when the spec is malformed or when the question
/// and panel-spec refs collide (a consult refuses duplicate refs).
pub fn plan_lead_panel_tasks(
    question_ref: ConsultPayloadRef,
    panel_spec_ref: ConsultPayloadRef,
    correlation_ref: EntityId,
    spec: &LeadPanelSpec,
) -> Result<LeadPanelExecutionPlan> {
    validate_lead_panel_spec(spec)?;
    if question_ref == panel_spec_ref {
        return Err(Error::InvalidTaskBody(
            "panel question and spec must be distinct refs",
        ));
    }
    let consult = || ConsultPayload::question(question_ref, vec![panel_spec_ref], correlation_ref);
    Ok(LeadPanelExecutionPlan {
        member_tasks: spec
            .members
            .iter()
            .map(|member| LeadPanelTaskInputSpec {
                responder: member.responder,
                consult: consult(),
                context_spec: member.context_spec.clone(),
                result_inputs: PanelResultInputs::None,
            })
            .collect(),
        judge_task: LeadPanelTaskInputSpec {
            responder: spec.judge.responder,
            consult: consult(),
            context_spec: spec.judge.context_spec.clone(),
            result_inputs: PanelResultInputs::AllMemberResults,
        },
        synthesis_task: LeadPanelTaskInputSpec {
            responder: spec.synthesis.responder,
            consult: consult(),
            context_spec: spec.synthesis.context_spec.clone(),
            result_inputs: PanelResultInputs::AllMemberAndJudgeResults,
        },
    })
}

// ── helpers ─────────────────────────────────────────────────────────────

fn normalize_tokens(tokens: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(tokens.len());
    for token in tokens {
        let trimmed = token.trim();
        if trimmed.is_empty() || out.iter().any(|known| known == trimmed) {
            continue;
        }
        out.push(trimmed.to_owned());
    }
    out
}

fn normalize_text(text: Option<String>) -> Option<String> {
    text.map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
}

fn validate_label(label: &str, reason: &'static str) -> Result<()> {
    if label.trim().is_empty() || label.len() > CONTEXT_SPEC_MAX_LABEL_BYTES {
        return Err(Error::InvalidAgentDispatchInput(reason));
    }
    Ok(())
}

fn validate_optional_text(text: Option<&str>, reason: &'static str) -> Result<()> {
    match text {
        Some(text) if text.len() > CONTEXT_SPEC_MAX_TEXT_BYTES => {
            Err(Error::InvalidAgentDispatchInput(reason))
        }
        Some(_) | None => Ok(()),
    }
}

fn validate_panel_text(text: &str, _field: &'static str) -> Result<()> {
    if text.trim().is_empty() {
        return Err(Error::InvalidTaskBody("panel spec text must be non-empty"));
    }
    if text.len() > CONTEXT_SPEC_MAX_TEXT_BYTES {
        return Err(Error::InvalidTaskBody("panel spec text is too long"));
    }
    Ok(())
}

/// Serde adapter for ONE-1699's `TaskAssignee`, which is consumed read-only and
/// carries no derives of its own.
mod assignee_wire {
    use super::TaskAssignee;
    use crate::entity_id::EntityId;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Wire {
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        entity_ref: Option<String>,
    }

    pub(super) fn serialize<S: Serializer>(
        assignee: &TaskAssignee,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        Wire {
            kind: assignee.as_str().to_owned(),
            entity_ref: assignee.entity_ref().map(|id| id.to_hex()),
        }
        .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<TaskAssignee, D::Error> {
        let wire = Wire::deserialize(deserializer)?;
        let entity_ref = wire
            .entity_ref
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()
            .map_err(|_| serde::de::Error::custom("assignee ref must be a hex EntityId"))?;
        match (wire.kind.as_str(), entity_ref) {
            ("dreamer", None) => Ok(TaskAssignee::Dreamer),
            ("agent_def", Some(agent_def_ref)) => Ok(TaskAssignee::AgentDef { agent_def_ref }),
            ("peer", Some(actor_ref)) => Ok(TaskAssignee::Peer { actor_ref }),
            ("human", Some(actor_ref)) => Ok(TaskAssignee::Human { actor_ref }),
            _ => Err(serde::de::Error::custom(
                "assignee kind and ref do not agree",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VaultConfig;
    use crate::test_util::{entity, open_test_vault_with, put_policy_manifest_bytes};

    const NOW: u64 = 1_800_000_000;

    fn open_vault() -> (tempfile::TempDir, Vault) {
        open_test_vault_with(VaultConfig::device())
    }

    /// The shared claim subject. A PERSON, deliberately not a TURN: a TURN
    /// subject would land in every chat projection the tests count.
    fn put_subject(vault: &Vault) -> EntityId {
        let id = entity(0x10);
        vault
            .put_entity(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"subject",
            )
            .expect("store claim subject");
        id
    }

    /// One CLAIM whose predicate namespace IS the memory domain.
    fn put_domain_claim(vault: &Vault, seed: u8, predicate: &str, learned_at: u64) -> EntityId {
        let subject = put_subject(vault);
        let id = entity(seed);
        vault
            .put_claim(
                &id,
                &crate::claim::ClaimBody::new(
                    predicate,
                    crate::claim::ClaimSubject::Entity(subject),
                    rmpv::Value::from("v"),
                    1.0,
                    crate::claim::ClaimApprovalStatus::Auto,
                    crate::claim::ClaimLifecycleStatus::Active,
                ),
                TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
            )
            .expect("store claim");
        id
    }

    /// One CONVERSATIONAL turn: speaker marker plus text payload, the shape
    /// the chat projection admits. Legacy `spkr`/`txt` keys ride the legacy
    /// arm so both markers stay covered.
    fn put_turn(vault: &Vault, seed: u8, learned_at: u64) -> EntityId {
        let id = entity(seed);
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![
                (rmpv::Value::from("speaker"), rmpv::Value::from("user")),
                (
                    rmpv::Value::from("text"),
                    rmpv::Value::from(format!("turn {seed:02x}")),
                ),
            ]),
        )
        .expect("encode turn body");
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_TURN,
                TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                &body,
            )
            .expect("store turn");
        id
    }

    // ONE-1709 F6 fixture helpers: IDs intentionally stay outside the
    // pinned-id byte range and fan-out IDs are distinct from one another.
    fn f6_other_id(n: u32) -> EntityId {
        let mut bytes = [0x5Au8; 16];
        bytes[0] = 0x5A;
        bytes[1] = (n & 0xff) as u8;
        bytes[2] = ((n >> 8) & 0xff) as u8;
        EntityId::from_bytes(bytes).expect("valid distinct fixture id")
    }

    fn f6_empty_turn(vault: &Vault, seed: u8, learned_at: u64) -> (EntityId, Vec<u8>) {
        let id = entity(seed);
        let mut body = Vec::new();
        rmpv::encode::write_value(&mut body, &rmpv::Value::Map(Vec::new()))
            .expect("encode empty turn map");
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_TURN,
                TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                &body,
            )
            .expect("store empty turn");
        (id, body)
    }

    fn f6_message(vault: &Vault, seed: u8, turn: &EntityId, learned_at: u64) -> EntityId {
        let id = entity(seed);
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![
                (rmpv::Value::from("author"), rmpv::Value::from("user")),
                (rmpv::Value::from("content"), rmpv::Value::from("hello")),
            ]),
        )
        .expect("encode message");
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_MESSAGE,
                TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                &body,
            )
            .expect("store message");
        vault
            .put_edge(&id, EdgeKind::PartOf, turn, 1.0)
            .expect("store PartOf edge");
        id
    }

    fn f6_claim(
        vault: &Vault,
        seed: u8,
        predicate: &str,
        world: Option<EntityId>,
        learned_at: u64,
    ) -> EntityId {
        let id = entity(seed);
        let mut claim = crate::claim::ClaimBody::new(
            predicate,
            crate::claim::ClaimSubject::Entity(put_subject(vault)),
            rmpv::Value::from("value"),
            1.0,
            crate::claim::ClaimApprovalStatus::Auto,
            crate::claim::ClaimLifecycleStatus::Active,
        );
        claim.world = world;
        vault
            .put_claim(
                &id,
                &claim,
                TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
            )
            .expect("store fixture claim");
        id
    }

    #[test]
    fn one_1709_t1_empty_map_facade_witness_projects_default_and_recent() {
        let (_dir, vault) = open_vault();
        let (turn, body) = f6_empty_turn(&vault, 0xC0, NOW);
        f6_message(&vault, 0xC1, &turn, NOW + 1);
        assert!(is_conversational_turn_body(&vault, &turn, &body).expect("classify"));
        let default = resolve(&vault, ContextSpec::default()).expect("default resolves");
        assert_eq!(default.chat_sections, [format!("tn_{}", turn.to_hex())]);
        let recent = resolve(
            &vault,
            ContextSpec {
                chat: ChatProjection::Recent { last_n: 1 },
                ..ContextSpec::excluded()
            },
        )
        .expect("recent resolves");
        assert_eq!(recent.chat_sections, [format!("tn_{}", turn.to_hex())]);
    }

    #[test]
    fn one_1709_t2_kind_qualified_window_survives_513_authoredby_edges() {
        let (_dir, vault) = open_vault();
        let (turn, body) = f6_empty_turn(&vault, 0xC2, NOW);
        for i in 0..513u32 {
            vault
                .put_edge(&f6_other_id(i), EdgeKind::AuthoredBy, &turn, 1.0)
                .expect("noise edge");
        }
        f6_message(&vault, 0xC3, &turn, NOW + 1);
        assert!(is_conversational_turn_body(&vault, &turn, &body).expect("classify"));
        let resolved = resolve(&vault, ContextSpec::default()).expect("default resolves");
        assert!(
            resolved
                .chat_sections
                .contains(&format!("tn_{}", turn.to_hex()))
        );
        let pre_f4_window: Vec<_> = vault
            .edges_in(&turn)
            .expect("edges_in")
            .into_iter()
            .take(CONTEXT_SPEC_MEMORY_SCAN_LIMIT)
            .filter(|e| e.kind == EdgeKind::PartOf)
            .collect();
        assert!(
            pre_f4_window.is_empty(),
            "pre-F4 edge window must lose PartOf"
        );
    }

    #[test]
    fn one_1709_t3_child_scoped_memory_must_be_a_strict_parent_subset() {
        let (_dir, vault) = open_vault();
        let world = f6_other_id(700);
        let base = f6_claim(&vault, 0xC4, "base.fact", None, NOW);
        let foreign = f6_claim(&vault, 0xC5, "world.fact", Some(world), NOW + 1);
        let parent_base = resolve_context_spec(
            &vault,
            ContextResolutionRequest {
                spec: ContextSpec {
                    memory: MemoryProjection::Default,
                    ..ContextSpec::excluded()
                },
                parent: None,
                context_from: Vec::new(),
                world_scope: Some(WorldScope::Base),
            },
        )
        .expect("base parent projection");
        assert!(
            parent_base
                .memory_sections
                .contains(&format!("base:cl_{}", base.to_hex()))
        );
        assert!(
            !parent_base
                .memory_sections
                .contains(&format!("world:cl_{}", foreign.to_hex()))
        );

        let inherited_base = ContextSpec {
            memory: MemoryProjection::Scoped {
                domains: vec!["base".into()],
                limit: 1,
            },
            ..ContextSpec::excluded()
        };
        let child_base = resolve_context_spec(
            &vault,
            ContextResolutionRequest {
                spec: inherited_base.clone(),
                parent: Some(parent_base.clone()),
                context_from: Vec::new(),
                world_scope: Some(WorldScope::Base),
            },
        )
        .expect("child may request the parent's base domain");
        assert!(
            child_base
                .memory_sections
                .contains(&format!("base:cl_{}", base.to_hex()))
        );
        assert!(
            !child_base
                .memory_sections
                .contains(&format!("world:cl_{}", foreign.to_hex()))
        );

        let invalid_child = ContextSpec {
            memory: MemoryProjection::Scoped {
                domains: vec!["base".into(), "world".into()],
                limit: 1,
            },
            ..ContextSpec::excluded()
        };
        let error = resolve_context_spec(
            &vault,
            ContextResolutionRequest {
                spec: invalid_child,
                parent: Some(parent_base),
                context_from: Vec::new(),
                world_scope: Some(WorldScope::Base),
            },
        )
        .expect_err("child must not request a domain absent from the parent projection");
        assert!(
            matches!(error, Error::InvalidAgentDispatchInput(message) if message == "child memory projection requests a domain the parent did not project")
        );

        let standalone = resolve_context_spec(
            &vault,
            ContextResolutionRequest {
                spec: ContextSpec {
                    memory: MemoryProjection::Scoped {
                        domains: vec!["base".into(), "world".into()],
                        limit: 32,
                    },
                    ..ContextSpec::excluded()
                },
                parent: None,
                context_from: Vec::new(),
                world_scope: None,
            },
        )
        .expect("foreign domain remains available without a parent grant");
        assert!(
            standalone
                .memory_sections
                .contains(&format!("world:cl_{}", foreign.to_hex()))
        );
    }

    #[test]
    fn one_1709_t4_world_a_to_world_b_membership() {
        let (_dir, vault) = open_vault();
        let world_a = f6_other_id(701);
        let world_b = f6_other_id(702);
        let base = f6_claim(&vault, 0xC6, "base.fact", None, NOW);
        let a = f6_claim(&vault, 0xC7, "alpha.fact", Some(world_a), NOW + 1);
        let b = f6_claim(&vault, 0xC8, "beta.fact", Some(world_b), NOW + 2);
        let projection = resolve_context_spec(
            &vault,
            ContextResolutionRequest {
                spec: ContextSpec::default(),
                parent: None,
                context_from: Vec::new(),
                world_scope: Some(WorldScope::World(world_b)),
            },
        )
        .expect("world B");
        assert!(
            projection
                .memory_sections
                .contains(&format!("base:cl_{}", base.to_hex()))
        );
        assert!(
            projection
                .memory_sections
                .contains(&format!("beta:cl_{}", b.to_hex()))
        );
        assert!(
            !projection
                .memory_sections
                .contains(&format!("alpha:cl_{}", a.to_hex()))
        );
    }

    #[test]
    fn one_1709_t5_default_is_implicit_base_under_base_scope() {
        let (_dir, vault) = open_vault();
        let base = f6_claim(&vault, 0xC9, "implicit.fact", None, NOW);
        let world = f6_claim(
            &vault,
            0xCA,
            "implicit.fact",
            Some(f6_other_id(703)),
            NOW + 1,
        );
        let projection = resolve_context_spec(
            &vault,
            ContextResolutionRequest {
                spec: ContextSpec::default(),
                parent: None,
                context_from: Vec::new(),
                world_scope: Some(WorldScope::Base),
            },
        )
        .expect("base default");
        assert!(
            projection
                .memory_sections
                .contains(&format!("implicit:cl_{}", base.to_hex()))
        );
        assert!(
            !projection
                .memory_sections
                .contains(&format!("implicit:cl_{}", world.to_hex()))
        );
    }

    fn scoped(domains: &[&str], limit: usize) -> ContextSpec {
        ContextSpec {
            memory: MemoryProjection::Scoped {
                domains: domains.iter().map(|d| (*d).to_owned()).collect(),
                limit,
            },
            ..ContextSpec::default()
        }
    }

    fn resolve(vault: &Vault, spec: ContextSpec) -> Result<ResolvedContextProjection> {
        resolve_context_spec(
            vault,
            ContextResolutionRequest {
                spec,
                parent: None,
                context_from: Vec::new(),
                world_scope: None,
            },
        )
    }

    fn resolve_under(
        vault: &Vault,
        parent: &ResolvedContextProjection,
        spec: ContextSpec,
    ) -> Result<ResolvedContextProjection> {
        resolve_context_spec(
            vault,
            ContextResolutionRequest {
                spec,
                parent: Some(parent.clone()),
                context_from: Vec::new(),
                world_scope: None,
            },
        )
    }

    fn assignee(seed: u8) -> TaskAssignee {
        TaskAssignee::Peer {
            actor_ref: entity(seed),
        }
    }

    fn panel_spec() -> LeadPanelSpec {
        LeadPanelSpec {
            members: (0..3)
                .map(|index| PanelMemberSpec {
                    responder: assignee(0x30 + index),
                    instructions: format!("member {index} answers alone"),
                    context_spec: ContextSpec::excluded(),
                })
                .collect(),
            judge: PanelJudgeSpec {
                responder: assignee(0x40),
                rubric: "rank the answers".to_owned(),
                context_spec: ContextSpec::excluded(),
            },
            synthesis: PanelSynthesisSpec {
                responder: assignee(0x41),
                instructions: "write one final answer".to_owned(),
                context_spec: ContextSpec::excluded(),
            },
        }
    }

    // ── descriptor identity + normalization ─────────────────────────────

    /// `self.context` is an identity call over a DESCRIPTOR: normalization is
    /// idempotent and nothing is resolved. The no-vault-read half is proven by
    /// signature — `context` takes no vault — and exercised at the code_run
    /// bridge.
    #[test]
    fn context_round_trips_the_descriptor_after_normalization() {
        let authored = ContextSpec {
            layers: vec![
                "  identity ".to_owned(),
                "identity".to_owned(),
                String::new(),
                "project".to_owned(),
            ],
            memory: MemoryProjection::Scoped {
                domains: vec![" health ".to_owned(), "health".to_owned()],
                limit: 3,
            },
            chat: ChatProjection::Recent { last_n: 2 },
            briefing: Some("  summarize the thread  ".to_owned()),
            annotation: Some(" dev note ".to_owned()),
        };

        let once = normalize_context_spec(authored);
        assert_eq!(once.layers, ["identity", "project"]);
        assert_eq!(
            once.memory,
            MemoryProjection::Scoped {
                domains: vec!["health".to_owned()],
                limit: 3,
            }
        );
        assert_eq!(once.briefing.as_deref(), Some("summarize the thread"));
        assert_eq!(once.annotation.as_deref(), Some("dev note"));

        // Idempotent, and `context` hands the descriptor straight back.
        let twice = normalize_context_spec(once.clone());
        assert_eq!(twice, once);
        assert_eq!(context(once.clone()), once);
        validate_context_spec(&once).expect("normalized descriptor validates");
    }

    #[test]
    fn malformed_descriptors_are_refused() {
        let rejects = [
            scoped(&[], 1),
            scoped(&["health"], 0),
            scoped(&["health"], CONTEXT_SPEC_MAX_MEMORY_LIMIT + 1),
            scoped(&["bad:domain"], 1),
            ContextSpec {
                chat: ChatProjection::Recent { last_n: 0 },
                ..ContextSpec::default()
            },
            ContextSpec {
                chat: ChatProjection::Recent {
                    last_n: CONTEXT_SPEC_MAX_CHAT_LAST_N + 1,
                },
                ..ContextSpec::default()
            },
            ContextSpec {
                layers: vec!["x".repeat(CONTEXT_SPEC_MAX_LABEL_BYTES + 1)],
                ..ContextSpec::default()
            },
            ContextSpec {
                briefing: Some("b".repeat(CONTEXT_SPEC_MAX_TEXT_BYTES + 1)),
                ..ContextSpec::default()
            },
        ];
        let refusals = rejects
            .iter()
            .filter(|spec| validate_context_spec(spec).is_err())
            .count();
        assert_eq!(refusals, rejects.len());
    }

    // ── resolution order + freshness ────────────────────────────────────

    /// Dispatch-time resolution reads LIVE state. A claim and a turn added
    /// AFTER the descriptor was authored are both projected, which is exactly
    /// what a create-time snapshot could not do.
    #[test]
    fn resolution_sees_state_added_after_the_descriptor_was_authored() {
        let (_dir, vault) = open_vault();
        let spec = scoped(&["health"], 4);
        put_domain_claim(&vault, 0x21, "health.weight", NOW);

        let before = resolve(&vault, spec.clone()).expect("resolve before");
        assert_eq!(before.memory_sections.len(), 1);

        put_domain_claim(&vault, 0x22, "health.sleep", NOW + 1);
        let after = resolve(&vault, spec).expect("resolve after");

        assert_eq!(after.memory_sections.len(), 2);
        // Newest-first, and every token names its domain.
        assert!(
            after
                .memory_sections
                .iter()
                .all(|section| section.starts_with("health:cl_"))
        );
        assert_eq!(after.memory_domains(), ["health"]);
    }

    /// Resolution runs Layers → Memory → Chat → Briefing and STRIPS the
    /// dev-only `_annotation`: it reaches no resolved projection, so it can
    /// reach no prompt.
    #[test]
    fn resolution_follows_the_fixed_order_and_strips_the_annotation() {
        let (_dir, vault) = open_vault();
        put_domain_claim(&vault, 0x23, "health.weight", NOW);
        put_turn(&vault, 0x24, NOW + 1);

        let resolved = resolve(
            &vault,
            ContextSpec {
                layers: vec!["identity".to_owned()],
                memory: MemoryProjection::Scoped {
                    domains: vec!["health".to_owned()],
                    limit: 4,
                },
                chat: ChatProjection::Recent { last_n: 4 },
                briefing: Some("delegated slice".to_owned()),
                annotation: Some("dev note".to_owned()),
            },
        )
        .expect("resolve");

        assert_eq!(resolved.layers, ["identity"]);
        assert_eq!(resolved.memory_sections.len(), 1);
        assert_eq!(resolved.chat_sections.len(), 1);
        assert!(resolved.chat_sections[0].starts_with("tn_"));
        assert_eq!(resolved.briefing.as_deref(), Some("delegated slice"));
        // The whole resolved shape carries no annotation field at all.
        assert!(
            !format!("{resolved:?}").contains("dev note"),
            "the dev-only annotation must not survive resolution"
        );
    }

    #[test]
    fn excluded_projections_resolve_to_nothing() {
        let (_dir, vault) = open_vault();
        put_domain_claim(&vault, 0x25, "health.weight", NOW);
        put_turn(&vault, 0x26, NOW);

        let resolved = resolve(&vault, ContextSpec::excluded()).expect("resolve");

        assert_eq!(resolved.memory_sections.len(), 0);
        assert_eq!(resolved.chat_sections.len(), 0);
        assert_eq!(resolved.layers.len(), 0);
    }

    // ── narrowing ───────────────────────────────────────────────────────

    /// Layers, domains, and limits can only narrow. Every widening request in
    /// the matrix is refused against the parent's RESOLVED projection.
    #[test]
    fn recursive_projections_can_only_narrow() {
        let (_dir, vault) = open_vault();
        put_domain_claim(&vault, 0x27, "health.weight", NOW);
        put_domain_claim(&vault, 0x28, "health.sleep", NOW + 1);
        put_domain_claim(&vault, 0x29, "work.role", NOW + 2);
        put_turn(&vault, 0x2A, NOW + 3);
        put_turn(&vault, 0x2B, NOW + 4);

        let parent = resolve(
            &vault,
            ContextSpec {
                layers: vec!["identity".to_owned(), "project".to_owned()],
                memory: MemoryProjection::Scoped {
                    domains: vec!["health".to_owned()],
                    limit: 2,
                },
                chat: ChatProjection::Recent { last_n: 2 },
                briefing: None,
                annotation: None,
            },
        )
        .expect("resolve parent");
        assert_eq!(parent.memory_sections.len(), 2);
        assert_eq!(parent.chat_sections.len(), 2);

        // Narrower requests all pass.
        let narrowed = resolve_under(
            &vault,
            &parent,
            ContextSpec {
                layers: vec!["identity".to_owned()],
                memory: MemoryProjection::Scoped {
                    domains: vec!["health".to_owned()],
                    limit: 1,
                },
                chat: ChatProjection::Recent { last_n: 1 },
                briefing: Some("only the weight question".to_owned()),
                annotation: None,
            },
        )
        .expect("narrower child resolves");
        assert_eq!(narrowed.layers, ["identity"]);
        assert_eq!(narrowed.memory_sections.len(), 1);
        assert_eq!(narrowed.chat_sections.len(), 1);
        // Briefing adds parent-authored text and grants no read scope.
        assert_eq!(
            narrowed.briefing.as_deref(),
            Some("only the weight question")
        );

        let widenings = [
            // A layer the parent did not project.
            ContextSpec {
                layers: vec!["secrets".to_owned()],
                ..ContextSpec::default()
            },
            // A domain outside the parent's scope.
            scoped(&["work"], 1),
            // A limit above the parent's projected section count.
            scoped(&["health"], 3),
            // A chat bound above the parent's.
            ContextSpec {
                chat: ChatProjection::Recent { last_n: 3 },
                ..ContextSpec::default()
            },
        ];
        let refusals = widenings
            .iter()
            .filter(|spec| resolve_under(&vault, &parent, (*spec).clone()).is_err())
            .count();
        assert_eq!(refusals, widenings.len());
    }

    /// A parent that EXCLUDED a channel cannot be widened back to included.
    #[test]
    fn excluded_parents_cannot_be_widened_back_to_included() {
        let (_dir, vault) = open_vault();
        put_domain_claim(&vault, 0x2C, "health.weight", NOW);
        put_turn(&vault, 0x2D, NOW);

        let parent = resolve(&vault, ContextSpec::excluded()).expect("resolve excluding parent");

        assert!(resolve_under(&vault, &parent, scoped(&["health"], 1)).is_err());
        assert!(
            resolve_under(
                &vault,
                &parent,
                ContextSpec {
                    chat: ChatProjection::Recent { last_n: 1 },
                    ..ContextSpec::default()
                },
            )
            .is_err()
        );
        // `Default` INHERITS, so it stays admissible and resolves to nothing.
        let inherited = resolve_under(&vault, &parent, ContextSpec::default())
            .expect("Default inherits an excluding parent");
        assert_eq!(inherited.memory_sections.len(), 0);
        assert_eq!(inherited.chat_sections.len(), 0);
    }

    /// The DECLARED bound is checked spec-against-spec, independently of what
    /// either side happens to resolve to today.
    #[test]
    fn declared_bounds_narrow_independently_of_content() {
        let parent = ContextSpec {
            layers: vec!["identity".to_owned()],
            memory: MemoryProjection::Scoped {
                domains: vec!["health".to_owned(), "work".to_owned()],
                limit: 4,
            },
            chat: ChatProjection::Recent { last_n: 4 },
            briefing: None,
            annotation: None,
        };

        validate_spec_narrows(&parent, &scoped(&["health"], 4)).expect("subset domain, same limit");
        validate_spec_narrows(&parent, &ContextSpec::excluded()).expect("exclude always narrows");
        validate_spec_narrows(&parent, &ContextSpec::default()).expect("Default inherits");

        let widenings = [
            scoped(&["secrets"], 1),
            scoped(&["health"], 5),
            ContextSpec {
                layers: vec!["secrets".to_owned()],
                ..ContextSpec::default()
            },
            ContextSpec {
                chat: ChatProjection::Recent { last_n: 5 },
                ..ContextSpec::default()
            },
        ];
        let refusals = widenings
            .iter()
            .filter(|child| validate_spec_narrows(&parent, child).is_err())
            .count();
        assert_eq!(refusals, widenings.len());

        // An excluding parent refuses any explicit request.
        let excluded = ContextSpec::excluded();
        assert!(validate_spec_narrows(&excluded, &scoped(&["health"], 1)).is_err());
        assert!(
            validate_spec_narrows(
                &excluded,
                &ContextSpec {
                    chat: ChatProjection::Recent { last_n: 1 },
                    ..ContextSpec::default()
                }
            )
            .is_err()
        );
    }

    /// Property: over arbitrary chains of narrowing requests, every level's
    /// resolved sections are a subset of the level above it.
    #[test]
    fn every_level_of_a_chain_is_a_subset_of_the_level_above() {
        let (_dir, vault) = open_vault();
        for (index, predicate) in [
            "health.weight",
            "health.sleep",
            "health.steps",
            "health.mood",
        ]
        .into_iter()
        .enumerate()
        {
            put_domain_claim(
                &vault,
                0x50 + u8::try_from(index).expect("small index"),
                predicate,
                NOW + index as u64,
            );
        }

        let mut projection = resolve(&vault, scoped(&["health"], 4)).expect("root resolves");
        assert_eq!(projection.memory_sections.len(), 4);

        for limit in [3usize, 2, 1] {
            let child = resolve_under(&vault, &projection, scoped(&["health"], limit))
                .expect("narrowing child resolves");
            assert_eq!(child.memory_sections.len(), limit);
            let contained = child
                .memory_sections
                .iter()
                .filter(|section| projection.memory_sections.contains(section))
                .count();
            assert_eq!(contained, child.memory_sections.len());
            projection = child;
        }
    }

    // ── claim surfacing gate (FIX-1) ───────────────────────────────────

    /// The canonical claim-surfacing gate applies inside the memory
    /// projection: each suppressed class yields NO section — at the root and
    /// under `Scoped` — while control claims still resolve, and suppressed
    /// rows never displace the limit accounting.
    #[test]
    fn memory_projection_suppresses_unsurfaced_claims() {
        use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};

        let put = |vault: &Vault,
                   seed: u8,
                   approval: ClaimApprovalStatus,
                   lifecycle: ClaimLifecycleStatus,
                   stale: bool| {
            let subject = put_subject(vault);
            let id = entity(seed);
            let mut claim = crate::claim::ClaimBody::new(
                "health.metric",
                crate::claim::ClaimSubject::Entity(subject),
                rmpv::Value::from("v"),
                1.0,
                approval,
                lifecycle,
            );
            claim.stale = stale;
            vault
                .put_claim(
                    &id,
                    &claim,
                    TimeRange {
                        start: NOW,
                        end: NOW,
                    },
                    NOW,
                )
                .expect("store claim");
            id
        };

        let (_dir, vault) = open_vault();
        // Controls first (oldest), then one claim per suppressed class as the
        // NEWER rows: suppression must not silently widen the scan.
        let control_a = put(
            &vault,
            0x30,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
            false,
        );
        let control_b = put(
            &vault,
            0x31,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
            false,
        );
        let suppressed = [
            put(
                &vault,
                0x32,
                ClaimApprovalStatus::Proposed,
                ClaimLifecycleStatus::Active,
                false,
            ),
            put(
                &vault,
                0x33,
                ClaimApprovalStatus::Rejected,
                ClaimLifecycleStatus::Active,
                false,
            ),
            put(
                &vault,
                0x34,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Superseded,
                false,
            ),
            put(
                &vault,
                0x35,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Retracted,
                false,
            ),
            put(
                &vault,
                0x36,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
                true,
            ),
        ];

        let expected: Vec<String> = [control_b, control_a]
            .iter()
            .map(|id| format!("health:cl_{}", id.to_hex()))
            .collect();
        // Root Default projection: exactly the two controls, newest-first;
        // no suppressed id appears anywhere.
        let root = resolve(&vault, ContextSpec::default()).expect("root resolves");
        assert_eq!(root.memory_sections, expected);
        for id in suppressed {
            assert!(
                !root
                    .memory_sections
                    .iter()
                    .any(|s| s.contains(&id.to_hex())),
                "suppressed claim {id:?} must not surface"
            );
        }

        // Scoped child with limit 1: contents, not just length — the single
        // section is the newest CONTROL, so suppressed rows did not count.
        let child = resolve(&vault, scoped(&["health"], 1)).expect("scoped resolves");
        assert_eq!(child.memory_sections, expected[..1]);
    }

    // ── conversational-turn filter (FIX-5) ─────────────────────────────

    /// Non-conversational TURN artifacts — the persisted panel spec and a
    /// consult-expiry receipt — never reach a chat projection and never
    /// displace conversational turns under `last_n`.
    #[test]
    fn chat_projection_skips_non_conversational_turn_artifacts() {
        let (_dir, vault) = open_vault();
        // Two conversational turns, then two NEWER artifact TURNs that must
        // not displace them under last_n = 2.
        let first = put_turn(&vault, 0x40, NOW);
        let second = put_turn(&vault, 0x41, NOW + 1);
        // Panel-spec artifact TURN (role = "lead_panel_spec" discriminant).
        persist_lead_panel_spec(&vault, &panel_spec(), NOW + 2).expect("persist panel spec");
        // Consult-expiry-style artifact: a kind map with neither a speaker
        // marker nor a text payload key.
        // 0x42 is a production-pinned seed byte (gate local-write actor ref);
        // 0x44 is free in this test's 0x4* block.
        let expiry = entity(0x44);
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![(
                rmpv::Value::from("kind"),
                rmpv::Value::from("consult.expiry"),
            )]),
        )
        .expect("encode artifact body");
        vault
            .put_entity(
                &expiry,
                ENTITY_TYPE_TURN,
                TimeRange {
                    start: NOW + 3,
                    end: NOW + 3,
                },
                NOW + 3,
                &body,
            )
            .expect("store expiry artifact");

        let resolved = resolve(
            &vault,
            ContextSpec {
                chat: ChatProjection::Recent { last_n: 2 },
                ..ContextSpec::excluded()
            },
        )
        .expect("chat resolves");
        assert_eq!(
            resolved.chat_sections,
            [
                format!("tn_{}", second.to_hex()),
                format!("tn_{}", first.to_hex())
            ],
            "artifacts are filtered before last_n, so they cannot displace chat"
        );

        // The legacy spkr/txt shape still projects.
        let (_dir2, legacy_vault) = open_vault();
        let legacy = entity(0x43);
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![
                (rmpv::Value::from("spkr"), rmpv::Value::from("user")),
                (rmpv::Value::from("txt"), rmpv::Value::from("legacy turn")),
            ]),
        )
        .expect("encode legacy body");
        legacy_vault
            .put_entity(
                &legacy,
                ENTITY_TYPE_TURN,
                TimeRange {
                    start: NOW,
                    end: NOW,
                },
                NOW,
                &body,
            )
            .expect("store legacy turn");
        let resolved = resolve(&legacy_vault, ContextSpec::default()).expect("default resolves");
        assert_eq!(resolved.chat_sections, [format!("tn_{}", legacy.to_hex())]);
    }

    // ── contextFrom ─────────────────────────────────────────────────────

    /// One facade-minted peer TASK plus a durable result TURN, landing its
    /// terminal record through the ONE result door. Mints state exactly the
    /// production way so the seen body is indistinguishable.
    fn member_task(
        vault: &Vault,
        seed: u8,
        disposition: Option<crate::task_verb::TaskTerminalDisposition>,
    ) -> (EntityId, EntityId) {
        // The first-party connector actor id (0xE1), constructed EXPLICITLY as
        // test_util::entity documents: it is the one actor the default policy
        // admits at Auto ceiling, so `tasks_create` mints instead of parking
        // (the precedent is task_verb tests' `own_agent`).
        let actor = EntityId::from_bytes([0xE1; 16]).expect("first-party actor id");
        vault
            .put_entity(
                &actor,
                crate::registry::ENTITY_TYPE_PERSON,
                TimeRange {
                    start: NOW,
                    end: NOW,
                },
                NOW,
                b"actor",
            )
            .expect("store member actor");
        let result_ref = entity(seed + 1);
        vault
            .put_entity(
                &result_ref,
                ENTITY_TYPE_TURN,
                TimeRange {
                    start: NOW,
                    end: NOW,
                },
                NOW,
                b"member result artifact",
            )
            .expect("store result artifact");
        let facade = vault.memory_facade(actor, crate::edge::EdgeActorClass::Agent);
        let task_ref = facade
            .tasks_create(
                &crate::task_verb::TaskCreateSpec::new(
                    rmpv::Value::from("member task"),
                    None,
                    None,
                    Some(NOW),
                )
                .with_assignee(crate::task_verb::TaskAssignee::Peer { actor_ref: actor }),
            )
            .expect("member task mints")
            .task_ref
            .expect("member task is minted, not parked");
        if let Some(disposition) = disposition {
            facade
                .land_task_result(
                    task_ref,
                    &crate::task_verb::TaskResultInput {
                        result_ref,
                        disposition,
                        finished_at: NOW + 1,
                    },
                )
                .expect("member task settles");
        }
        (task_ref, result_ref)
    }

    /// `contextFrom` injects SETTLED COMPLETED sibling TASK results and
    /// nothing else: the durable-but-unsettled pre-settlement window, an
    /// arbitrary existing non-TASK row, and a non-Completed settlement all
    /// fail closed with a typed error.
    #[test]
    fn context_from_resolves_only_settled_completed_sibling_task_results() {
        let (_dir, vault) = open_vault();
        // The legacy-test vault ships with NO policy manifest, so every
        // facade create would park at Proposed; one minimal manifest with an
        // agent-Auto ceiling row lets the members mint through the real
        // `tasks_create` door (mirrors the gate-test fixture shape).
        let manifest = rmpv::Value::Map(vec![
            (
                rmpv::Value::from("schema_version"),
                rmpv::Value::from("1.1"),
            ),
            (
                rmpv::Value::from("pack_id"),
                rmpv::Value::from("context-projection-test"),
            ),
            (rmpv::Value::from("pack_version"), rmpv::Value::from("v1")),
            (
                rmpv::Value::from("min_engine_version"),
                rmpv::Value::from(env!("CARGO_PKG_VERSION")),
            ),
            (
                rmpv::Value::from("defaults"),
                rmpv::Value::Map(vec![
                    (
                        rmpv::Value::from("criticality"),
                        rmpv::Value::from("normal"),
                    ),
                    (
                        rmpv::Value::from("sensitivity"),
                        rmpv::Value::from("normal"),
                    ),
                ]),
            ),
            (rmpv::Value::from("rules"), rmpv::Value::Array(Vec::new())),
            (
                rmpv::Value::from("actor_ceilings"),
                rmpv::Value::Array(vec![rmpv::Value::Map(vec![
                    (rmpv::Value::from("actor_class"), rmpv::Value::from("agent")),
                    (rmpv::Value::from("ceiling"), rmpv::Value::from("auto")),
                ])]),
            ),
        ]);
        let mut manifest_bytes = Vec::new();
        rmpv::encode::write_value(&mut manifest_bytes, &manifest).expect("encode policy manifest");
        put_policy_manifest_bytes(&vault, entity(0x15), &manifest_bytes)
            .expect("install agent-auto policy manifest");
        let (settled_task, result_a) = member_task(
            &vault,
            0x60,
            Some(crate::task_verb::TaskTerminalDisposition::Completed),
        );
        let (failed_task, _) = member_task(
            &vault,
            0x70,
            Some(crate::task_verb::TaskTerminalDisposition::Failed),
        );
        // A member whose result artifact is ALREADY durable while its TASK is
        // still unsettled (the require_resolved_entity pre-settlement window).
        let (unsettled_task, _) = member_task(&vault, 0x80, None);
        let arbitrary_row = put_turn(&vault, 0x90, NOW);

        let resolve = |context_from: Vec<EntityId>| {
            resolve_context_spec(
                &vault,
                ContextResolutionRequest {
                    spec: ContextSpec::excluded(),
                    parent: None,
                    context_from,
                    world_scope: None,
                },
            )
        };

        // A genuinely settled sibling TASK's terminal result resolves — to
        // the RESULT ref, not the TASK row.
        let resolved = resolve(vec![settled_task]).expect("settled sibling result resolves");
        assert_eq!(resolved.sibling_result_refs, [result_a]);

        let refusals = [
            vec![unsettled_task],             // pre-settlement window closed
            vec![arbitrary_row],              // arbitrary existing non-TASK row
            vec![failed_task],                // settled, but not Completed
            vec![entity(0x63)],               // unresolved
            vec![settled_task, settled_task], // same sibling result twice
        ]
        .into_iter()
        .filter(|context_from| resolve(context_from.clone()).is_err())
        .count();
        assert_eq!(refusals, 5);
    }

    // ── panel spec ──────────────────────────────────────────────────────

    #[test]
    fn panel_spec_round_trips_through_a_durable_ref() {
        let (_dir, vault) = open_vault();
        let spec = panel_spec();

        let spec_ref = persist_lead_panel_spec(&vault, &spec, NOW).expect("persist panel spec");

        // The ref is one of ONE-1699's already-legal payload-ref variants, and
        // it resolves as such against the vault.
        assert!(matches!(spec_ref, ConsultPayloadRef::Turn(_)));
        assert_eq!(
            ConsultPayloadRef::parse(&vault, &spec_ref.short_ref()).expect("ref parses"),
            spec_ref
        );
        assert_eq!(
            load_lead_panel_spec(&vault, spec_ref).expect("load panel spec"),
            spec
        );
        assert_eq!(
            decode_lead_panel_spec(&encode_lead_panel_spec(&spec).expect("encode"))
                .expect("decode"),
            spec
        );
    }

    #[test]
    fn panel_spec_rejects_non_peer_responders_before_planning() {
        let mut spec = panel_spec();
        spec.judge.responder = TaskAssignee::Human {
            actor_ref: entity(0xEE),
        };
        assert!(matches!(
            validate_lead_panel_spec(&spec),
            Err(Error::InvalidTaskBody(_))
        ));
    }

    #[test]
    fn malformed_panel_specs_are_refused() {
        let mut no_members = panel_spec();
        no_members.members.clear();
        let mut duplicate_responder = panel_spec();
        duplicate_responder.members[1].responder = duplicate_responder.members[0].responder;
        let mut blank_rubric = panel_spec();
        blank_rubric.judge.rubric = "   ".to_owned();
        let mut blank_synthesis = panel_spec();
        blank_synthesis.synthesis.instructions = String::new();
        let mut malformed_member_context = panel_spec();
        malformed_member_context.members[0].context_spec = scoped(&["health"], 0);

        let rejects = [
            no_members,
            duplicate_responder,
            blank_rubric,
            blank_synthesis,
            malformed_member_context,
        ];
        let refusals = rejects
            .iter()
            .filter(|spec| validate_lead_panel_spec(spec).is_err())
            .count();
        assert_eq!(refusals, rejects.len());
    }

    /// The planner returns typed INPUTS. It allocates no entity id, and every
    /// payload it plans carries ONE-1699 refs only — never the question text,
    /// the member instructions, or the judge rubric.
    #[test]
    fn planner_returns_ref_only_task_inputs_with_no_preallocated_ids() {
        let (_dir, vault) = open_vault();
        let spec = panel_spec();
        let question_ref = ConsultPayloadRef::Turn(put_turn(&vault, 0x64, NOW));
        let spec_ref = persist_lead_panel_spec(&vault, &spec, NOW).expect("persist panel spec");
        let correlation_ref = entity(0x65);

        let plan = plan_lead_panel_tasks(question_ref, spec_ref, correlation_ref, &spec)
            .expect("plan panel tasks");

        assert_eq!(plan.member_tasks.len(), 3);
        let planned = plan
            .member_tasks
            .iter()
            .chain([&plan.judge_task, &plan.synthesis_task]);
        for input in planned {
            assert_eq!(input.consult.question_ref, question_ref);
            assert_eq!(input.consult.context_refs, [spec_ref]);
            assert_eq!(input.consult.correlation_ref, correlation_ref);
            // ONE-1888's optional additions stay absent for an ordinary panel.
            assert_eq!(input.consult.purpose, None);
            assert_eq!(input.consult.entity_delta, None);
            assert_eq!(input.consult.lineage, None);
            assert_eq!(input.consult.ref_count(), 2);
        }

        // Instruction/rubric text lives ONLY in the referenced spec entity.
        let rendered = format!("{plan:?}");
        for text in [
            "member 0 answers alone",
            "rank the answers",
            "write one final answer",
        ] {
            assert!(
                !rendered.contains(text),
                "free-form panel text must not ride the planned TASK payload"
            );
        }

        // A colliding question/spec ref is refused: a consult refuses duplicates.
        assert!(plan_lead_panel_tasks(spec_ref, spec_ref, correlation_ref, &spec).is_err());
    }

    /// Blindness is structural: no member input carries a sibling result, the
    /// judge waits for ALL member results, and synthesis waits for the judge
    /// plus the members.
    #[test]
    fn panel_members_are_blind_and_the_judge_runs_once_after_them() {
        let (_dir, vault) = open_vault();
        let spec = panel_spec();
        let question_ref = ConsultPayloadRef::Turn(put_turn(&vault, 0x66, NOW));
        let spec_ref = persist_lead_panel_spec(&vault, &spec, NOW).expect("persist panel spec");

        let plan = plan_lead_panel_tasks(question_ref, spec_ref, entity(0x67), &spec)
            .expect("plan panel tasks");

        let blind_members = plan
            .member_tasks
            .iter()
            .filter(|input| input.result_inputs == PanelResultInputs::None)
            .count();
        assert_eq!(blind_members, 3);
        assert_eq!(
            plan.judge_task.result_inputs,
            PanelResultInputs::AllMemberResults
        );
        assert_eq!(
            plan.synthesis_task.result_inputs,
            PanelResultInputs::AllMemberAndJudgeResults
        );

        // Distinct responders — three members means three answers.
        let mut responders: Vec<String> = plan
            .member_tasks
            .iter()
            .map(|input| format!("{:?}", input.responder))
            .collect();
        responders.sort();
        responders.dedup();
        assert_eq!(responders.len(), 3);
    }
}
