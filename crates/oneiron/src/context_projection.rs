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
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TASK, ENTITY_TYPE_TURN};
use crate::task_verb::{ConsultPayload, ConsultPayloadRef, TaskAssignee};
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
    Scoped { domains: Vec<String>, limit: usize },
}

/// How much of the parent's chat history the delegate may project.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ChatProjection {
    #[default]
    Default,
    Exclude,
    Recent { last_n: usize },
}

/// One dispatch-time resolution request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextResolutionRequest {
    pub spec: ContextSpec,
    /// The parent's already-resolved projection, absent at a root dispatch.
    pub parent: Option<ResolvedContextProjection>,
    /// Settled sibling RESULT refs, injected separately from parent context.
    pub context_from: Vec<EntityId>,
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
        validate_label(layer, "context spec layer name must be non-empty and bounded")?;
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
    validate_optional_text(spec.briefing.as_deref(), "context spec briefing is too long")?;
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
/// it widens beyond `request.parent`, or when a `context_from` ref is
/// unresolved or names a live TASK row rather than a settled result artifact.
pub fn resolve_context_spec(
    vault: &Vault,
    request: ContextResolutionRequest,
) -> Result<ResolvedContextProjection> {
    let ContextResolutionRequest {
        spec,
        parent,
        context_from,
    } = request;
    let spec = normalize_context_spec(spec);
    validate_context_spec(&spec)?;
    if let Some(parent) = parent.as_ref() {
        validate_context_narrows(parent, &spec)?;
    }

    // 1. Layers.
    let layers = spec.layers.clone();
    // 2. Memory.
    let memory_sections = resolve_memory_sections(vault, &spec.memory, parent.as_ref())?;
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
) -> Result<Vec<String>> {
    match projection {
        MemoryProjection::Exclude => Ok(Vec::new()),
        // Inherit: a `Default` child sees exactly what its parent saw, which is
        // both the widest legal request and the no-context-rot answer.
        MemoryProjection::Default => match parent {
            Some(parent) => Ok(parent.memory_sections.clone()),
            None => scan_memory_sections(vault, None, CONTEXT_SPEC_DEFAULT_MEMORY_LIMIT),
        },
        MemoryProjection::Scoped { domains, limit } => {
            let sections = scan_memory_sections(vault, Some(domains), *limit)?;
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
fn intersect_with_parent(sections: Vec<String>, parent: Option<&[String]>, limit: usize) -> Vec<String> {
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
        let domain = memory_domain_of(&claim.predicate);
        if domains.is_some_and(|scope| !scope.iter().any(|known| known == domain)) {
            continue;
        }
        sections.push(format!("{domain}:cl_{}", id.to_hex()));
    }
    Ok(sections)
}

/// Live read: the newest TURN rows, newest-first.
fn scan_chat_sections(vault: &Vault, last_n: usize) -> Result<Vec<String>> {
    Ok(vault
        .latest_entity_bodies_by_type(ENTITY_TYPE_TURN, last_n, CONTEXT_SPEC_MEMORY_SCAN_LIMIT)?
        .into_iter()
        .map(|(id, _learned_at, _body)| format!("tn_{}", id.to_hex()))
        .collect())
}

/// A claim's memory domain: its predicate namespace, or the whole predicate
/// when it carries none.
fn memory_domain_of(predicate: &str) -> &str {
    predicate
        .split_once('.')
        .map_or(predicate, |(namespace, _)| namespace)
}

/// `contextFrom` is deliberately NOT parent-context projection: it injects
/// SETTLED sibling results and nothing else. A `result_ref` exists only once
/// its TASK settled, so refusing TASK rows here makes "after settlement"
/// structural rather than a timing convention.
fn resolve_sibling_results(vault: &Vault, context_from: &[EntityId]) -> Result<Vec<EntityId>> {
    let mut resolved = Vec::with_capacity(context_from.len());
    for entity_ref in context_from {
        match vault.get_entity_type(entity_ref)? {
            None => {
                return Err(Error::InvalidAgentDispatchInput(
                    "contextFrom names an unresolved sibling result",
                ));
            }
            Some(ENTITY_TYPE_TASK) => {
                return Err(Error::InvalidAgentDispatchInput(
                    "contextFrom takes settled sibling RESULT refs, not TASK rows",
                ));
            }
            Some(_) => {}
        }
        if resolved.contains(entity_ref) {
            return Err(Error::InvalidAgentDispatchInput(
                "contextFrom names the same sibling result twice",
            ));
        }
        resolved.push(*entity_ref);
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
        return Err(Error::InvalidTaskBody("panel spec body role is not a panel"));
    }
    if field("schema_version").and_then(rmpv::Value::as_u64) != Some(LEAD_PANEL_SPEC_SCHEMA_VERSION)
    {
        return Err(Error::InvalidTaskBody("panel spec schema version must be 1"));
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
    use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
}
