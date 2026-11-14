//! The task-brief composer (census L8-07; canon workbench-engine-asks.md:76:
//! the brief is "composed by a local model from a one-liner plus lens
//! context, approved like any proposal").
//!
//! A `tasks.create` that names a one-liner and lens refs instead of a brief
//! is composed here, in the same call (RULING L8-07-DOOR = A, 14 Nov 09:11):
//! each lens ref is read under the caller's own scoped read, the local model
//! the host installed drafts the brief's text slots as schema-checked JSON,
//! and the engine fills every other slot and mints the [`ComposerStamp`].
//! The stamp is engine attestation: a brief that arrives from a caller
//! already stamped is refused.
//!
//! The model is local only (`OnDevice` or `OwnServer`). With none installed,
//! or with a third-party one, the create is refused and nothing leaves the
//! device. A composed post always parks as a proposal, whatever the
//! caller's ceiling (RULING L8-07-APPROVAL = A): its text is the model's,
//! and no person has read it yet.
//!
//! Entry: [`Memory::compose_task_brief`].

use std::sync::Arc;

use serde::Deserialize;
use serde_json::json;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::llm::ModelLocality;
use crate::llm::decision::Reversibility;
use crate::llm::decision::questions::QuestionCriteria;
use crate::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult};

use super::ask_types::{TaskAskDefault, TaskAskTarget};
use super::brief::{
    BriefConstraints, BriefContext, BriefIntent, ComposerStamp, Criterion, DoneMeans,
    EscalationRule, EscalationTrigger, QueueTaskBrief, TypeRef,
};
use super::consts::TASK_BRIEF_SCHEMA;

/// Derivation context of a [`ComposerStamp::one_liner_digest`].
const ONE_LINER_DIGEST_CONTEXT: &str = "oneiron tasks brief one-liner v1";
/// Longest one-liner a create may name, in bytes.
const MAX_ONE_LINER_BYTES: usize = 2_000;
/// Most lens refs one create may name.
const MAX_LENS_REFS: usize = 16;
/// Longest text one lens row hands the model, in bytes; a longer row is cut
/// at a character boundary.
const MAX_LENS_TEXT_BYTES: usize = 8_000;
/// The reason a NOTE lens read records.
const LENS_READ_REASON: &str = "tasks.create composes a brief from this row";
/// The role the refusal names: the local reasoner the host binds to an
/// on-device or own-server model (ARCH-0036 r9).
const LOCAL_MODEL_SUGGESTION: &str = "Bind an on-device or own-server model to [models.roles.local_reasoner] on the host that serves this vault, or post the brief written out with `brief`.";

/// What the model is told. The schema it answers to travels beside it.
const COMPOSE_INSTRUCTION: &str = "You draft a task brief from a one-line request and the context rows the requester named. Answer with one JSON object that matches the schema, and nothing else. objective: the task in one line. need: why the work is wanted, apart from how to do it. type: the id of the task type that fits best, from the list; root when none fits. notes: the constraints the request or the rows state, one per line; none when they state none. question: one yes-or-no question that asks whether the work is done. yes_if_all: the lines that must all hold for a yes, at least one. no_if_any: the lines any one of which means no. Use only what the request and the rows say.";

/// The local model the engine composes task briefs with, installed by the
/// host that serves the vault ([`Vault::install_task_brief_model`]).
///
/// The engine owns the prompt, the reply schema, the reply check and every
/// slot the model does not draft; the host owns only the call. It admits
/// the call on its own local lease. The engine calls it under the caller's
/// task-work turn, so it never calls the vault's task doors itself.
pub trait TaskBriefModel: Send + Sync {
    /// Which model answers, and where it runs.
    fn binding(&self) -> TaskBriefModelBinding;

    /// Answers one draft request with the model's reply text: one JSON
    /// object constrained to `request.schema`.
    ///
    /// # Errors
    ///
    /// The host's own refusal or the call's failure; the create is refused
    /// with it.
    fn draft(&self, request: &TaskBriefDraftRequest<'_>) -> MemoryResult<String>;
}

/// The model a [`TaskBriefModel`] calls: its name, which the stamp's `seat`
/// records, and its locality, which the engine checks before every call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskBriefModelBinding {
    pub model: String,
    pub locality: ModelLocality,
}

/// One draft call: the instruction, the one-liner and the lens rows as the
/// model reads them, and the JSON schema its reply must match.
#[derive(Debug, Clone, Copy)]
pub struct TaskBriefDraftRequest<'a> {
    pub instruction: &'a str,
    pub input: &'a str,
    pub schema: &'a serde_json::Value,
}

/// A create's request to have its brief composed: the caller's one-liner
/// and the rows it names as lens context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneLinerBrief {
    pub one_liner: String,
    pub lens_refs: Vec<EntityId>,
}

impl OneLinerBrief {
    /// The digest a [`ComposerStamp`] carries for this one-liner.
    #[must_use]
    pub fn one_liner_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(ONE_LINER_DIGEST_CONTEXT);
        hasher.update(self.one_liner.as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Whether `brief` is this request's composition: engine-stamped with
    /// this one-liner and these lens refs. A replay under the same key
    /// answers with that brief instead of composing again.
    pub(super) fn stamped(&self, brief: &QueueTaskBrief) -> bool {
        brief.composed.as_ref().is_some_and(|stamp| {
            stamp.one_liner_digest == self.one_liner_digest() && stamp.lens_refs == self.lens_refs
        })
    }
}

impl Vault {
    /// Installs the local model this vault composes task briefs with. The
    /// first install holds; a later one is refused and handed back. Until
    /// one is installed, a one-liner create is refused.
    ///
    /// # Errors
    ///
    /// `Err(model)` when this vault already carries an installed model.
    pub fn install_task_brief_model(
        &self,
        model: Arc<dyn TaskBriefModel>,
    ) -> Result<(), Arc<dyn TaskBriefModel>> {
        self.task_brief_model.set(model)
    }

    /// The installed task-brief model, if any.
    pub(crate) fn task_brief_model(&self) -> Option<Arc<dyn TaskBriefModel>> {
        self.task_brief_model.get().cloned()
    }
}

/// The model's reply, as the schema [`draft_schema`] states it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BriefDraft {
    objective: String,
    need: String,
    #[serde(rename = "type")]
    type_node: String,
    #[serde(default)]
    notes: Vec<String>,
    question: String,
    yes_if_all: Vec<String>,
    #[serde(default)]
    no_if_any: Vec<String>,
}

/// The reply schema: the model's text slots, and the task type as one of
/// `type_nodes`, the live nodes of the tree in force.
fn draft_schema(type_nodes: &[String]) -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["objective", "need", "type", "notes", "question", "yes_if_all", "no_if_any"],
        "properties": {
            "objective": {"type": "string", "minLength": 1},
            "need": {"type": "string", "minLength": 1},
            "type": {"type": "string", "enum": type_nodes},
            "notes": {"type": "array", "items": {"type": "string"}},
            "question": {"type": "string", "minLength": 1},
            "yes_if_all": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1}
            },
            "no_if_any": {"type": "array", "items": {"type": "string"}}
        }
    })
}

/// A caller-written brief that carries a composer stamp. The stamp is the
/// engine's attestation that its own local model drafted the brief, so a
/// caller never sets it (RULING L8-07-DOOR = A).
pub(super) fn refuse_caller_stamp(brief: &QueueTaskBrief) -> MemoryResult<()> {
    if brief.composed.is_some() {
        return Err(MemoryError::bad_request_with(
            "tasks.composer_stamp_reserved: a brief's composer stamp is set by the engine, never by its caller",
            &[
                "Drop `composed` from the brief, or name `one_liner` and `lens_refs` instead of `brief` to have the engine compose it.",
            ],
        ));
    }
    Ok(())
}

/// The refusal of a draft that does not fit the brief: the model's answer
/// did not fit the call, so nothing stands in for it.
fn unfit_draft(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        format!("the local model's brief draft does not fit a task brief: {why}"),
        &["Compose again, or post the brief written out with `brief`."],
    )
}

/// `text` cut to at most `limit` bytes at a character boundary.
fn cut(text: &str, limit: usize) -> &str {
    if text.len() <= limit {
        return text;
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// `lines` trimmed, blank ones dropped.
fn kept_lines(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect()
}

/// What the model reads: the request, the live task types, and the lens
/// rows.
fn draft_input(one_liner: &str, tree: &crate::task_type::TaskTypeTree, lens: &str) -> String {
    let mut input = format!("Request: {one_liner}\n\nTask types (id: name):\n");
    for node in tree.nodes.values().filter(|node| node.is_live()) {
        input.push_str(&format!("- {}: {}\n", node.node_id, node.name));
    }
    input.push_str("\nContext rows:\n");
    input.push_str(if lens.is_empty() { "(none)\n" } else { lens });
    input
}

/// The brief `draft` describes, every slot the model does not draft set by
/// the engine: the schema, the type at the tree's version, escalation to
/// `owners` under `hold` on a block, a widened scope or overspend, and
/// reversibility `outbound_effect`, since the engine cannot know the work's
/// effects. `stamp` is the composer's.
fn brief_from_draft(
    draft: BriefDraft,
    tree: &crate::task_type::TaskTypeTree,
    owners: Vec<EntityId>,
    stamp: ComposerStamp,
) -> MemoryResult<QueueTaskBrief> {
    let node = tree
        .node(draft.type_node.trim())
        .filter(|node| node.is_live())
        .ok_or_else(|| unfit_draft("its type is not a live node of the tree in force"))?;
    let type_ref = TypeRef {
        node_id: node.entity_id()?,
        tree_version: tree.version,
    };
    let objective = draft.objective.trim().to_owned();
    let need = draft.need.trim().to_owned();
    let question = draft.question.trim().to_owned();
    let yes_if_all = kept_lines(draft.yes_if_all);
    if objective.is_empty() || need.is_empty() || question.is_empty() {
        return Err(unfit_draft("its objective, need or question is blank"));
    }
    if yes_if_all.is_empty() {
        return Err(unfit_draft("it names no done criterion"));
    }
    let criterion = |text: String| Criterion {
        text,
        evidence_ref: None,
    };
    Ok(QueueTaskBrief {
        schema: TASK_BRIEF_SCHEMA,
        type_ref,
        objective,
        intent: BriefIntent { need, care: None },
        constraints: BriefConstraints {
            notes: kept_lines(draft.notes),
            ..BriefConstraints::default()
        },
        context: BriefContext::default(),
        success: DoneMeans {
            question,
            criteria: QuestionCriteria {
                yes_if_all: yes_if_all.into_iter().map(criterion).collect(),
                no_if_any: kept_lines(draft.no_if_any)
                    .into_iter()
                    .map(criterion)
                    .collect(),
                ..QuestionCriteria::default()
            },
            outcome_binding: None,
            browser_checks: Vec::new(),
            strict_verified_reuse: false,
        },
        settled: Vec::new(),
        escalation: EscalationRule {
            to: TaskAskTarget::People(owners.into_iter().collect()),
            triggers: vec![
                EscalationTrigger::Blocked,
                EscalationTrigger::ScopeWiden,
                EscalationTrigger::SpendOver,
            ],
            default: TaskAskDefault::Hold,
            until: None,
            reversibility: Reversibility::OutboundEffect,
            question_ref: None,
        },
        project_ref: None,
        composed: Some(stamp),
    })
}

impl Memory<'_> {
    /// Composes the brief `request` describes (L8-07): reads each lens ref
    /// under this surface's own scoped read, asks the installed local model
    /// for the text slots, and fills the rest ([`brief_from_draft`]). The
    /// model picks the type from the live nodes of the tree in force, root
    /// when unsure. The stamp names the model, the one-liner's digest, the
    /// lens refs and the vault clock.
    ///
    /// # Errors
    ///
    /// `BAD_REQUEST` for a blank or oversized one-liner or too many lens
    /// refs; `MODEL_UNAVAILABLE` when no local model is installed, when the
    /// installed one runs at a third party, or when its draft does not fit;
    /// `NOT_FOUND` for a lens ref this surface does not read; the host's
    /// own refusal of the call.
    pub(super) fn compose_task_brief(
        &self,
        request: &OneLinerBrief,
    ) -> MemoryResult<QueueTaskBrief> {
        let one_liner = request.one_liner.trim();
        if one_liner.is_empty() {
            return Err(MemoryError::bad_request("a one-liner must not be blank"));
        }
        if one_liner.len() > MAX_ONE_LINER_BYTES {
            return Err(MemoryError::bad_request(format!(
                "a one-liner holds at most {MAX_ONE_LINER_BYTES} bytes"
            )));
        }
        if request.lens_refs.len() > MAX_LENS_REFS {
            return Err(MemoryError::bad_request(format!(
                "a composed create names at most {MAX_LENS_REFS} lens refs"
            )));
        }
        crate::memory::verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let (model, binding) = self.local_brief_model()?;
        let lens = self.lens_context(&request.lens_refs)?;
        let tree = crate::agent_dispatch::load_team_type_tree(self.vault(), None)?;
        let type_nodes: Vec<String> = tree
            .nodes
            .values()
            .filter(|node| node.is_live())
            .map(|node| node.node_id.clone())
            .collect();
        let input = draft_input(one_liner, &tree, &lens);
        let schema = draft_schema(&type_nodes);
        let reply = model.draft(&TaskBriefDraftRequest {
            instruction: COMPOSE_INSTRUCTION,
            input: &input,
            schema: &schema,
        })?;
        let draft: BriefDraft = serde_json::from_str(reply.trim()).map_err(|error| {
            unfit_draft(&format!("the reply is not the schema's JSON ({error})"))
        })?;
        let owners = {
            let txn = self
                .vault()
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            crate::policy_model::owners_in_txn(self.vault(), &txn)?
        };
        let stamp = ComposerStamp {
            seat: binding.model,
            one_liner_digest: request.one_liner_digest(),
            lens_refs: request.lens_refs.clone(),
            at: self.vault().now_recorded_at(),
        };
        brief_from_draft(draft, &tree, owners, stamp)
    }

    /// The installed task-brief model and its binding, refused unless it is
    /// local: with none installed, or with one at a third party, no brief is
    /// composed and nothing leaves the device.
    fn local_brief_model(&self) -> MemoryResult<(Arc<dyn TaskBriefModel>, TaskBriefModelBinding)> {
        let Some(model) = self.vault().task_brief_model() else {
            return Err(MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                "no local model composes task briefs on this vault",
                &[LOCAL_MODEL_SUGGESTION],
            ));
        };
        let binding = model.binding();
        if binding.locality == ModelLocality::ThirdParty {
            return Err(MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                format!(
                    "the task-brief model {:?} runs at a third party; a brief is composed by a local model only",
                    binding.model
                ),
                &[LOCAL_MODEL_SUGGESTION],
            ));
        }
        Ok((model, binding))
    }

    /// The lens rows as the model reads them, each read under this
    /// surface's own scoped read: its kind and id, then a NOTE's text or any
    /// other row's body. A ref this surface does not read refuses the whole
    /// composition as not found.
    fn lens_context(&self, lens_refs: &[EntityId]) -> MemoryResult<String> {
        if lens_refs.is_empty() {
            return Ok(String::new());
        }
        let refs: Vec<String> = lens_refs.iter().map(EntityId::to_hex).collect();
        let views = self.hydrate(&refs)?.value;
        let mut context = String::new();
        for (index, view) in views.iter().enumerate() {
            let text = if view.kind == "NOTE" {
                self.read_note(&crate::note::NoteReadRequest {
                    note_ref: view.id_hex.clone(),
                    reason: Some(LENS_READ_REASON.to_owned()),
                    version: None,
                    spans: Vec::new(),
                })?
                .value
                .map(|note| note.markdown)
                .ok_or_else(|| MemoryError::from(crate::Error::EntityNotFound))?
            } else {
                view.body
                    .as_ref()
                    .map_or_else(String::new, serde_json::Value::to_string)
            };
            context.push_str(&format!(
                "[{}] {} {}:\n{}\n",
                index + 1,
                view.kind,
                view.id_hex,
                cut(&text, MAX_LENS_TEXT_BYTES)
            ));
        }
        Ok(context)
    }
}
