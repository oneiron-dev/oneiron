//! Dispatch-time resolution of a `ContextSpec` against live vault state.

use super::narrowing::validate_context_narrows;
use super::panel_spec::LEAD_PANEL_SPEC_ROLE;
use super::spec::{
    CONTEXT_SPEC_DEFAULT_CHAT_LAST_N, CONTEXT_SPEC_DEFAULT_MEMORY_LIMIT, ChatProjection,
    ContextSpec, MemoryProjection, domain_contains, normalize_context_spec, validate_context_spec,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::compaction::output::OutputRef;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::pipeline::WorldScope;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::store::GateSystemNoticeRecord;
use crate::task_verb::TaskTerminalDisposition;

/// Rows a memory resolution may walk before it stops looking.
pub const CONTEXT_SPEC_MEMORY_SCAN_LIMIT: usize = 512;

/// The notice a projection names what a member's lane left out of it under.
const NARROWED_NOTICE_TYPE: &str = "workflow_context_narrowed";

/// Ancestor records a dispatch walk reads past which it asks whether
/// everything is okay (rule 5): an advisory threshold, never a bound. Every
/// ancestor is read; `depth_remaining` is the policy.
pub const CONTEXT_PROJECTION_ANCESTOR_CHECK: u64 = 16;

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

/// One prior workflow step's recoverable output, bound to its producer.
/// This is not a memory section or a read grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkflowOutputContextRef {
    pub step_ordinal: usize,
    pub producing_attempt: AttemptId,
    pub source: OutputRef,
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
    /// Prior results of this saved workflow only. Assembled from settled
    /// attempts, never inherited through the parent memory projection.
    pub workflow_output_refs: Vec<WorkflowOutputContextRef>,
    /// The sections this projection resolved to before a member's own read
    /// lane left rows out of them (FIX 5416); `None` when it left none out.
    /// They stay its bound, which the narrowing law and an inheriting child
    /// read, so an omission never narrows what a descriptor may ask for.
    pre_lane: Option<LaneBound>,
}

/// A member-narrowed projection's sections as they resolved before the
/// member's lane left rows out.
#[derive(Clone, PartialEq, Eq)]
struct LaneBound {
    memory: Vec<String>,
    chat: Vec<String>,
    /// The cut that left them out was that of the owner or agent who bound
    /// the run, its private-thread cut (FIX 6412) and an agent's or the
    /// system's own admission (FIX 6715), not a member's own lane: what the
    /// notice names (FIX 6485).
    binder: bool,
}

impl std::fmt::Debug for LaneBound {
    /// Counts only: the sections name the rows the lane left out.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaneBound")
            .field("memory", &self.memory.len())
            .field("chat", &self.chat.len())
            .finish()
    }
}

impl ResolvedContextProjection {
    /// The distinct memory domains this projection actually reached.
    #[must_use]
    pub fn memory_domains(&self) -> Vec<&str> {
        domains_of(&self.memory_sections)
    }

    /// What a member's own read lane left out of this projection (FIX
    /// 5416), or the cut of the owner or agent who bound its run: the
    /// private-thread cut (FIX 6412) and an agent's or the system's own
    /// admission (FIX 6715), rows that cut could not name or judge included
    /// (FIX 6550), as a gate system notice naming which of the two it was
    /// (FIX 6485): how many memory and chat rows, never which, and never
    /// another member's join. `None` when it left nothing out, as for every
    /// projection not read so.
    #[must_use]
    pub fn narrowed_notice(&self) -> Option<GateSystemNoticeRecord> {
        let bound = self.pre_lane.as_ref()?;
        let memory = bound
            .memory
            .len()
            .saturating_sub(self.memory_sections.len());
        let chat = bound.chat.len().saturating_sub(self.chat_sections.len());
        let why = if bound.binder {
            "they sit in private threads the owner or agent who bound this run does not read, \
             or they or the words they carry came before that agent's own admission to their \
             room, or they could not be named or judged against those threads or that admission"
        } else {
            "the member whose run this is does not read them"
        };
        Some(GateSystemNoticeRecord {
            notice_type: NARROWED_NOTICE_TYPE.to_owned(),
            channel: "workflow.context".to_owned(),
            voice: "system".to_owned(),
            audience: "agent".to_owned(),
            body: format!(
                "{memory} memory rows and {chat} chat rows of this step's context are left out: \
                 {why}."
            ),
            row_ref: None,
            setting_change_offer: None,
            policy_plane: None,
            policy_version: None,
            docs_url: None,
        })
    }

    /// This projection keeping only `memory` and `chat` of its sections,
    /// the ones a member's own read lane reads, each in this projection's
    /// order (FIX 5416). What it resolved to stays its bound; when every
    /// section is kept, nothing is left out.
    pub(crate) fn lane_narrowed(self, memory: Vec<String>, chat: Vec<String>) -> Self {
        self.narrowed(memory, chat, false)
    }

    /// [`Self::lane_narrowed`] by the cut of the owner or agent who bound
    /// the run: its private-thread cut (FIX 6412) and an agent's or the
    /// system's own admission (FIX 6715), which the notice names so (FIX
    /// 6485).
    pub(crate) fn binder_narrowed(self, memory: Vec<String>, chat: Vec<String>) -> Self {
        self.narrowed(memory, chat, true)
    }

    /// [`Self::lane_narrowed`], `binder` naming whose cut it was.
    fn narrowed(mut self, memory: Vec<String>, chat: Vec<String>, binder: bool) -> Self {
        if memory.len() == self.memory_sections.len() && chat.len() == self.chat_sections.len() {
            return self;
        }
        let bound = LaneBound {
            memory: std::mem::replace(&mut self.memory_sections, memory),
            chat: std::mem::replace(&mut self.chat_sections, chat),
            binder,
        };
        if self.pre_lane.is_none() {
            self.pre_lane = Some(bound);
        }
        self
    }

    /// The memory sections this projection resolved to before a member's
    /// lane left any out: its bound.
    pub(super) fn memory_bound(&self) -> &[String] {
        self.pre_lane
            .as_ref()
            .map_or(&self.memory_sections, |bound| &bound.memory)
    }

    /// The chat sections this projection resolved to before a member's lane
    /// left any out: its bound.
    pub(super) fn chat_bound(&self) -> &[String] {
        self.pre_lane
            .as_ref()
            .map_or(&self.chat_sections, |bound| &bound.chat)
    }

    /// The distinct memory domains of [`Self::memory_bound`].
    pub(super) fn bound_domains(&self) -> Vec<&str> {
        domains_of(self.memory_bound())
    }
}

/// The distinct memory domains `sections` name.
fn domains_of(sections: &[String]) -> Vec<&str> {
    let mut domains: Vec<&str> = sections
        .iter()
        .filter_map(|section| section.split_once(':').map(|(domain, _)| domain))
        .collect();
    domains.sort_unstable();
    domains.dedup();
    domains
}

/// Resolves one descriptor against LIVE vault state in the fixed order
/// Layers → Memory → Chat → Briefing, stripping `_annotation`.
///
/// # Errors
///
/// [`ArtifactError::InvalidAgentDispatchInput`](crate::error::ArtifactError::InvalidAgentDispatchInput) when the descriptor is malformed, when
/// it widens beyond `request.parent`, or when a `context_from` ref does not
/// name a SETTLED sibling TASK with a `Completed` terminal result (missing,
/// unsettled, non-TASK, or non-completed rows all reject).
pub fn resolve_context_spec(
    vault: &Vault,
    request: ContextResolutionRequest,
) -> Result<ResolvedContextProjection> {
    let txn = vault.store.env.read_txn()?;
    resolve_context_spec_in_txn(vault, &txn, request)
}

/// [`resolve_context_spec`] in the caller's transaction: every read the
/// resolution makes, in the same order and under the same limits and
/// surfacing rules, comes from `txn`, so a dispatch writer resolves in its
/// own view and opens no snapshot beside it.
///
/// # Errors
///
/// As [`resolve_context_spec`].
pub(crate) fn resolve_context_spec_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
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
        resolve_memory_sections(vault, txn, &spec.memory, parent.as_ref(), world_scope)?;
    // 3. Chat.
    let chat_sections = resolve_chat_sections(vault, txn, &spec.chat, parent.as_ref())?;
    // 4. Briefing — parent-authored delegation text, never a read grant. The
    //    dev-only `_annotation` is dropped here and reaches no prompt.
    let briefing = spec.briefing;

    let projection = ResolvedContextProjection {
        layers,
        memory_sections,
        chat_sections,
        briefing,
        sibling_result_refs: resolve_sibling_results(vault, txn, &context_from)?,
        workflow_output_refs: Vec::new(),
        pre_lane: None,
    };
    // A child resolves against its parent's bound, so a row a member's lane
    // left out of the parent is left out of the child too (FIX 5416).
    // Whose cut it was stays the parent's (FIX 6485).
    let inherited = parent.and_then(|parent| {
        let binder = parent.pre_lane.as_ref()?.binder;
        Some((binder, parent))
    });
    Ok(match inherited {
        Some((binder, parent)) => {
            let memory = kept_in(&projection.memory_sections, &parent.memory_sections);
            let chat = kept_in(&projection.chat_sections, &parent.chat_sections);
            projection.narrowed(memory, chat, binder)
        }
        None => projection,
    })
}

/// Of `sections`, the ones `kept` holds, in order.
fn kept_in(sections: &[String], kept: &[String]) -> Vec<String> {
    sections
        .iter()
        .filter(|section| kept.contains(section))
        .cloned()
        .collect()
}

fn resolve_memory_sections(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    projection: &MemoryProjection,
    parent: Option<&ResolvedContextProjection>,
    world_scope: Option<WorldScope>,
) -> Result<Vec<String>> {
    match projection {
        MemoryProjection::Exclude => Ok(Vec::new()),
        // Inherit: a `Default` child sees exactly what its parent saw, which is
        // both the widest legal request and the no-context-rot answer.
        MemoryProjection::Default => match parent {
            Some(parent) if matches!(world_scope, None | Some(WorldScope::All)) => {
                Ok(parent.memory_bound().to_vec())
            }
            Some(parent) => Ok(intersect_with_parent(
                scan_memory_sections(vault, txn, None, parent.memory_bound().len(), world_scope)?,
                Some(parent.memory_bound()),
                parent.memory_bound().len(),
            )),
            None => scan_memory_sections(
                vault,
                txn,
                None,
                CONTEXT_SPEC_DEFAULT_MEMORY_LIMIT,
                world_scope,
            ),
        },
        MemoryProjection::Scoped { domains, limit } => {
            let sections = scan_memory_sections(vault, txn, Some(domains), *limit, world_scope)?;
            Ok(intersect_with_parent(
                sections,
                parent.map(ResolvedContextProjection::memory_bound),
                *limit,
            ))
        }
    }
}

fn resolve_chat_sections(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    projection: &ChatProjection,
    parent: Option<&ResolvedContextProjection>,
) -> Result<Vec<String>> {
    match projection {
        ChatProjection::Exclude => Ok(Vec::new()),
        ChatProjection::Default => match parent {
            Some(parent) => Ok(parent.chat_bound().to_vec()),
            None => scan_chat_sections(vault, txn, CONTEXT_SPEC_DEFAULT_CHAT_LAST_N),
        },
        ChatProjection::Recent { last_n } => {
            let sections = scan_chat_sections(vault, txn, *last_n)?;
            Ok(intersect_with_parent(
                sections,
                parent.map(ResolvedContextProjection::chat_bound),
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
    txn: &heed::RoTxn<'_>,
    domains: Option<&[String]>,
    limit: usize,
    world_scope: Option<WorldScope>,
) -> Result<Vec<String>> {
    let rows = vault.latest_entity_bodies_by_type_in_txn(
        txn,
        ENTITY_TYPE_CLAIM,
        CONTEXT_SPEC_MEMORY_SCAN_LIMIT,
        CONTEXT_SPEC_MEMORY_SCAN_LIMIT,
    )?;
    let mut sections = Vec::with_capacity(limit.min(rows.len()));
    for (id, _learned_at, _body) in rows {
        if sections.len() >= limit {
            break;
        }
        let Some(claim) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        // `get_claim` is the deliberately-ungated history door (claim.rs D19):
        // apply the crate's canonical surfacing gate so Proposed/Rejected/
        // Superseded/Retracted/stale claims never reach a memory projection.
        if !crate::claim::claim_surfaceable(&claim) {
            continue;
        }
        let in_world = match world_scope.as_ref().unwrap_or(&WorldScope::All) {
            WorldScope::All => true,
            WorldScope::Base => claim.world.is_none(),
            WorldScope::World(world) => claim.world.is_none() || claim.world == Some(*world),
            WorldScope::WorldSet(worlds) => worlds.admits(claim.world),
            WorldScope::CodebaseSet(key) => {
                crate::codebase::codebase_candidate_matches_scope_key(&vault.store, txn, &id, key)?
            }
            // Also outside the AgentScope mapping (ONE-1420): the per-turn
            // ActiveSet selection lives on the retrieval builder, and this
            // projection has none to enforce — so it admits nothing rather
            // than falling through to "everything".
            WorldScope::ActiveSet => false,
        };
        if !in_world {
            continue;
        }
        // A requested domain matches the whole predicate at a dot boundary
        // (FIX 7751): `goal.career` reads `goal.career.pm`. The section
        // keeps its top-level token either way.
        if domains.is_some_and(|scope| {
            !scope
                .iter()
                .any(|known| domain_contains(known, &claim.predicate))
        }) {
            continue;
        }
        let domain = memory_domain_of(&claim.predicate);
        sections.push(format!("{domain}:cl_{}", id.to_hex()));
    }
    Ok(sections)
}

/// Live read: the newest CONVERSATIONAL TURN rows, newest-first. Non-
/// conversational artifacts persisted AS TURNs (the panel-spec entity,
/// consult-expiry receipts, marker bodies) are filtered BEFORE `last_n`
/// applies, so they can neither reach a chat projection nor displace real
/// conversational turns under the bounded over-scan.
fn scan_chat_sections(vault: &Vault, txn: &heed::RoTxn<'_>, last_n: usize) -> Result<Vec<String>> {
    let mut sections = Vec::with_capacity(last_n);
    for (id, _learned_at, body) in vault.latest_entity_bodies_by_type_in_txn(
        txn,
        ENTITY_TYPE_TURN,
        CONTEXT_SPEC_MEMORY_SCAN_LIMIT,
        CONTEXT_SPEC_MEMORY_SCAN_LIMIT,
    )? {
        if !is_conversational_turn_body(vault, txn, &id, &body)? {
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
pub(super) fn is_conversational_turn_body(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    body: &[u8],
) -> Result<bool> {
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
    for edge in vault.neighbor_edges_bounded_in_txn(
        txn,
        turn,
        false,
        Some(EdgeKind::PartOf),
        None,
        CONTEXT_SPEC_MEMORY_SCAN_LIMIT,
    )? {
        let Some(raw) = vault.get_raw_sealed_in_txn(txn, &edge.target)? else {
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
fn resolve_sibling_results(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    context_from: &[EntityId],
) -> Result<Vec<EntityId>> {
    let mut resolved = Vec::with_capacity(context_from.len());
    for entity_ref in context_from {
        let Some((disposition, result_ref)) =
            crate::task_verb::settled_task_result_binding_in_txn(vault, txn, *entity_ref)?
        else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "contextFrom names no settled sibling TASK result",
            )));
        };
        if disposition != TaskTerminalDisposition::Completed {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "contextFrom names a sibling TASK settled without a completed result",
            )));
        }
        if resolved.contains(&result_ref) {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "contextFrom names the same sibling result twice",
            )));
        }
        resolved.push(result_ref);
    }
    Ok(resolved)
}
