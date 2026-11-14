//! Plan mode's plan-doc (agent-runtime-v1.md, "Plan mode reuses built review
//! parts"): "a plan-doc `NOTE` (kind `Plugin("plan")`, kin to ARCH-0032's
//! brief — never an OF-368 blob)", answered by the owner before its run.
//!
//! An agent proposes a plan through `vault.plans.propose`: the door writes a
//! NOTE `plugin/plan` from a typed body ([`PlanDocBody`]: title, steps, the
//! scope it asks, its budget) as fixed markdown sections, and one review row
//! beside it ([`PLAN_DOC_REVIEW`]). Only that door writes the row, so a
//! `plugin/plan` NOTE made any other way is no plan-doc.
//!
//! A plan-doc's revision is the BLAKE3 hash of its id and its text at the
//! head. The owner answers one revision (`vault.plans.approve`,
//! `vault.plans.reject`): the writer refuses an answer to a revision the
//! text has left, stores the verdict with the revision it was given at, and
//! appends one gate decision that records it. The state is derived on every
//! read: approved or rejected while the text is the revision answered, in
//! review otherwise. So any edit that lands after the verdict (the owner's,
//! an agent's under a grant, a merged fork) returns the plan to review with
//! no edit hook, and a text edited back to the answered one holds its
//! verdict again.

use serde::{Deserialize, Serialize};

use super::NoteKind;
use crate::anchored_annotation::ThreadSubSession;
use crate::claim::ScopedReadResult;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::PLAN_RUN_SESSION;
use crate::error::{Error, RecordError, Result};
use crate::memory::{EntityRefReceipt, Memory, MemoryResult};
use crate::registry::{ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::side_table::{self, Named, SideTable};
use crate::store::{GateDecisionId, GateDecisionRecord, GateSystemNoticeRecord};
use crate::{EdgeActorClass, TimeRange, Vault, WriteActor};

/// The plan-doc's NOTE kind on the wire.
pub const PLAN_DOC_NOTE_KIND: &str = "plugin/plan";
/// The plugin tag of [`PLAN_DOC_NOTE_KIND`].
const PLAN_DOC_PLUGIN_TAG: &str = "plan";
/// The key a plan-doc's revision hash is derived under.
const REVISION_CONTEXT: &str = "oneiron plan_doc revision v1";
/// The content kind of the gate decision that records the owner's verdict.
const VERDICT_CONTENT_KIND: &str = "plan_doc_verdict";
/// The reason code of an approval.
const APPROVE_REASON: &str = "gate.allow.owner_plan_doc";
/// The reason code of a rejection.
const REJECT_REASON: &str = "gate.deny.owner_plan_doc";

const STEPS_HEADING: &str = "## Steps";
const SCOPE_HEADING: &str = "## Scope asked";
const BUDGET_HEADING: &str = "## Budget";
/// The budget line of a plan that asks no budget.
const NO_BUDGET: &str = "none";

/// The review row beside each plan-doc NOTE, keyed by the NOTE.
pub(crate) const PLAN_DOC_REVIEW: SideTable<EntityId, PlanDocReview, Named> =
    SideTable::new(&side_table::NOTE_PLAN_DOC_REVIEW);

/// What a plan asks the owner to approve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanDocBody {
    /// One line naming the work.
    pub title: String,
    /// The steps the run takes, in order; at least one, each one line.
    pub steps: Vec<String>,
    /// The scope the run asks for, one line each.
    #[serde(default)]
    pub scope_asked: Vec<String>,
    /// The budget the run asks, in the units a task brief's budget pin
    /// takes; `None` asks none.
    #[serde(default)]
    pub budget: Option<u64>,
}

/// Where [`PlanDocBody::from_markdown`] is in a plan-doc's text.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Head,
    Steps,
    Scope,
    Budget,
}

impl PlanDocBody {
    /// The plan-doc's text: the title as its heading, then the steps,
    /// numbered, the scope asked, one bullet each, and the budget.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = format!("# {}\n\n{STEPS_HEADING}\n\n", self.title);
        for (index, step) in self.steps.iter().enumerate() {
            out.push_str(&format!("{}. {step}\n", index + 1));
        }
        out.push_str(&format!("\n{SCOPE_HEADING}\n\n"));
        for scope in &self.scope_asked {
            out.push_str(&format!("- {scope}\n"));
        }
        let budget = match self.budget {
            Some(budget) => budget.to_string(),
            None => NO_BUDGET.to_owned(),
        };
        out.push_str(&format!("\n{BUDGET_HEADING}\n\n{budget}\n"));
        out
    }

    /// The body `markdown` reads as, when it holds exactly the sections
    /// [`Self::to_markdown`] writes; `None` for any other text, such as a
    /// plan-doc whose text an edit took out of that shape.
    #[must_use]
    pub fn from_markdown(markdown: &str) -> Option<Self> {
        let mut lines = markdown.lines();
        let title = lines.next()?.strip_prefix("# ")?.to_owned();
        let mut section = Section::Head;
        let mut steps = Vec::new();
        let mut scope_asked = Vec::new();
        let mut budget = None;
        for line in lines.filter(|line| !line.is_empty()) {
            match (section, line) {
                (Section::Head, STEPS_HEADING) => section = Section::Steps,
                (Section::Steps, SCOPE_HEADING) => section = Section::Scope,
                (Section::Scope, BUDGET_HEADING) => section = Section::Budget,
                (Section::Steps, _) => {
                    let (number, step) = line.split_once(". ")?;
                    if number.parse::<usize>().ok()? != steps.len() + 1 {
                        return None;
                    }
                    steps.push(step.to_owned());
                }
                (Section::Scope, _) => scope_asked.push(line.strip_prefix("- ")?.to_owned()),
                (Section::Budget, _) if budget.is_none() => {
                    budget = Some(if line == NO_BUDGET {
                        None
                    } else {
                        Some(line.parse().ok()?)
                    });
                }
                _ => return None,
            }
        }
        let body = Self {
            title,
            steps,
            scope_asked,
            budget: budget?,
        };
        body.validate().ok()?;
        Some(body)
    }

    /// A title and at least one step, and every line of the body one
    /// non-blank line with no surrounding space, so its text reads back as
    /// the same body.
    fn validate(&self) -> Result<()> {
        one_line(&self.title, "a plan-doc's title is one non-blank line")?;
        if self.steps.is_empty() {
            return Err(invalid("a plan-doc names at least one step"));
        }
        for step in &self.steps {
            one_line(step, "each plan-doc step is one non-blank line")?;
        }
        for scope in &self.scope_asked {
            one_line(scope, "each scope a plan-doc asks is one non-blank line")?;
        }
        Ok(())
    }
}

fn one_line(text: &str, refusal: &'static str) -> Result<()> {
    if text.is_empty() || text.trim() != text || text.contains(['\n', '\r']) {
        return Err(invalid(refusal));
    }
    Ok(())
}

fn invalid(refusal: &'static str) -> Error {
    Error::Record(RecordError::InvalidNoteBody(refusal))
}

/// How the owner answered a plan-doc revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanDocDecision {
    Approved,
    Rejected,
}

/// Where a plan-doc stands, derived from its last verdict and its text now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanDocState {
    /// No verdict, or the text has moved since the last one.
    InReview,
    /// The owner approved the revision the text is at.
    Approved,
    /// The owner rejected the revision the text is at.
    Rejected,
}

/// The owner's last verdict on a plan-doc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PlanDocVerdict {
    decision: PlanDocDecision,
    /// The revision answered, as 64 lowercase hex characters.
    revision: String,
    decided_at: u64,
    /// The gate decision that records it, as `gate:<id hex>`.
    receipt_ref: String,
}

/// One plan-doc's review row: when it was proposed, the agent definition
/// that runs it on approval, and the last verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PlanDocReview {
    proposed_at: u64,
    #[serde(default)]
    agent_def_ref: Option<EntityId>,
    verdict: Option<PlanDocVerdict>,
}

/// `vault.plans.propose`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanDocProposeRequest {
    pub plan: PlanDocBody,
    /// The agent definition that runs the plan: the owner's approval lands
    /// its run. `None` starts no run on approval; a run then starts from a
    /// `tasks.create` that pins the approved revision.
    #[serde(default)]
    pub agent_def_ref: Option<EntityId>,
}

/// `vault.plans.get`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanDocRequest {
    /// The plan-doc NOTE, as `vault.plans.propose` named it.
    pub plan_ref: EntityId,
}

/// The owner's verdict on one plan-doc revision.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanDocVerdictRequest {
    /// The plan-doc NOTE.
    pub plan_ref: EntityId,
    /// The revision the owner read (`vault.plans.get`), as 64 hex
    /// characters. The verdict is refused once the text has moved on.
    pub expected_revision: String,
    /// The conversation TURN the owner approved from; an approval that lands
    /// the plan's run hangs it off this turn as a sub-session
    /// (agent-runtime-v1.md:342). Approval only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approving_turn_ref: Option<EntityId>,
    /// The anchored review thread on this plan-doc the owner approved from;
    /// it records the run's sub-session. Approval only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approving_thread_ref: Option<EntityId>,
}

/// The last verdict, as a read shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PlanDocVerdictView {
    pub decision: PlanDocDecision,
    /// The revision answered.
    pub revision: String,
    pub decided_at: u64,
    /// The gate decision that records it, as `gate:<id hex>`.
    pub receipt_ref: String,
}

/// One plan-doc as it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PlanDocView {
    pub plan_ref: EntityId,
    pub state: PlanDocState,
    /// The revision the text is at, as 64 lowercase hex characters.
    pub revision: String,
    /// The text at that revision.
    pub markdown: String,
    /// The typed body the text reads as; `None` once an edit took the text
    /// out of the plan-doc's sections.
    pub body: Option<PlanDocBody>,
    /// The agent that proposed it, the NOTE's author; `None` once erased.
    pub proposed_by: Option<EntityId>,
    pub proposed_at: u64,
    /// The agent definition whose run the owner's approval lands, if any.
    pub agent_def_ref: Option<EntityId>,
    /// The owner's last verdict, at whichever revision it was given.
    pub verdict: Option<PlanDocVerdictView>,
}

/// What the owner's verdict wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PlanDocSettlementView {
    pub plan_ref: EntityId,
    pub decision: PlanDocDecision,
    /// The revision answered.
    pub revision: String,
    /// The agent that proposed it; `None` once erased.
    pub proposed_by: Option<EntityId>,
    /// The gate decision that records the verdict, as `gate:<id hex>`.
    pub receipt_ref: String,
    /// The run the approval landed: the TASK of the plan's agent definition,
    /// pinned at the approved revision. `None` for a rejection, a plan that
    /// names no agent definition, or a text an edit took out of the
    /// plan-doc's sections.
    pub run_task_ref: Option<EntityId>,
    /// The SESSION the run hangs off the approving turn by a spawned_by
    /// edge; `None` when the approval named no turn or landed no run.
    pub sub_session_id: Option<EntityId>,
}

/// Where the owner answered a plan-doc from: the approving turn its run
/// hangs off and the review thread that records the run's sub-session.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PlanApprovalOrigin {
    /// The conversation TURN the run hangs off as a sub-session.
    turn: Option<EntityId>,
    /// The review thread that records the run's sub-session.
    thread: Option<EntityId>,
}

/// The revision of plan-doc `plan` whose text is `markdown`: BLAKE3 under
/// [`REVISION_CONTEXT`] over the id's bytes, then the text's.
fn revision_of(plan: EntityId, markdown: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(REVISION_CONTEXT);
    hasher.update(plan.as_bytes());
    hasher.update(markdown.as_bytes());
    *hasher.finalize().as_bytes()
}

fn revision_hex(revision: &[u8; 32]) -> String {
    crate::entity_id::bytes_to_hex_lower(revision)
}

pub(super) fn is_plan_doc_kind(kind: &NoteKind) -> bool {
    matches!(kind, NoteKind::Plugin(tag) if tag == PLAN_DOC_PLUGIN_TAG)
}

fn proposer(core: &super::NoteCore) -> Option<EntityId> {
    // An erased author is no one, and an imported one is no local actor.
    match core.author_ref {
        super::NoteActor::Actor(actor) => Some(actor),
        _ => None,
    }
}

/// Where a plan-doc whose text is at `revision` (hex) stands under `review`.
fn state_at(review: &PlanDocReview, revision: &str) -> PlanDocState {
    match &review.verdict {
        Some(verdict) if verdict.revision == revision => match verdict.decision {
            PlanDocDecision::Approved => PlanDocState::Approved,
            PlanDocDecision::Rejected => PlanDocState::Rejected,
        },
        _ => PlanDocState::InReview,
    }
}

/// The view of plan-doc `plan` whose text is `markdown`, under `review`.
fn plan_doc_view(
    plan: EntityId,
    core: &super::NoteCore,
    markdown: String,
    review: PlanDocReview,
) -> PlanDocView {
    let revision = revision_hex(&revision_of(plan, &markdown));
    let state = state_at(&review, &revision);
    PlanDocView {
        plan_ref: plan,
        state,
        revision,
        body: PlanDocBody::from_markdown(&markdown),
        markdown,
        proposed_by: proposer(core),
        proposed_at: review.proposed_at,
        agent_def_ref: review.agent_def_ref,
        verdict: review.verdict.map(|verdict| PlanDocVerdictView {
            decision: verdict.decision,
            revision: verdict.revision,
            decided_at: verdict.decided_at,
            receipt_ref: verdict.receipt_ref,
        }),
    }
}

/// Plan-doc `plan` in the caller's read: its core, its text at the head and
/// its review row. A NOTE with no review row, or of another kind, is no
/// plan-doc.
fn plan_doc_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    plan: EntityId,
) -> Result<(super::NoteCore, String, PlanDocReview)> {
    let not_plan_doc = || invalid("NOTE is not a plan-doc");
    let (_, core) = super::verbs::note_core(vault, txn, plan)?;
    let review = PLAN_DOC_REVIEW
        .get(&vault.store, txn, &plan)?
        .filter(|_| is_plan_doc_kind(&core.kind))
        .ok_or_else(not_plan_doc)?;
    let markdown = super::documents::load_doc(vault, txn, plan)?
        .ok_or_else(not_plan_doc)?
        .text();
    Ok((core, markdown, review))
}

/// The revision row `id` is at and where it stands, when `id` names a
/// plan-doc; `None` for any other row. A task brief pins a plan-doc at this
/// revision, so the run carries the hash of the text the owner approved, and
/// an edit to the text, and no other write, moves the pin.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn plan_doc_pin_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<([u8; 32], PlanDocState)>> {
    let Some(review) = PLAN_DOC_REVIEW.get(&vault.store, txn, &id)? else {
        return Ok(None);
    };
    let (_, core) = super::verbs::note_core(vault, txn, id)?;
    if !is_plan_doc_kind(&core.kind) {
        return Ok(None);
    }
    let Some(doc) = super::documents::load_doc(vault, txn, id)? else {
        return Ok(None);
    };
    let revision = revision_of(id, &doc.text());
    let state = state_at(&review, &revision_hex(&revision));
    Ok(Some((revision, state)))
}

impl Memory<'_> {
    /// `vault.plans.propose`: writes `input.plan` as a new plan-doc NOTE by
    /// this handle's actor, in review, with its review row in the same
    /// commit.
    ///
    /// # Errors
    ///
    /// A body that is no plan ([`PlanDocBody`]'s rules); an actor whose plan
    /// mode is `off` (`gate.deny.plan_mode.off`); and the refusals
    /// `vault.notes.create` meets.
    pub fn propose_plan_doc(&self, input: &PlanDocProposeRequest) -> MemoryResult<PlanDocView> {
        input.plan.validate()?;
        let vault = self.vault();
        let proposer = self.actor();
        let proposed_at = crate::unix_seconds_now();
        let (_, view): (EntityRefReceipt, PlanDocView) = self.create_note_then(
            PLAN_DOC_NOTE_KIND,
            &input.plan.to_markdown(),
            |txn, plan| {
                // Plan mode `off` (SETTING = A): the owner switched this
                // agent's plans off, so it proposes none.
                crate::agent_def::refuse_plan_from_off_agent_in_txn(&vault.store, txn, proposer)?;
                if let Some(agent_def_ref) = input.agent_def_ref {
                    crate::task_verb::TaskAssignee::AgentDef { agent_def_ref }
                        .validate_in(vault, txn)?;
                }
                let review = PlanDocReview {
                    proposed_at,
                    agent_def_ref: input.agent_def_ref,
                    verdict: None,
                };
                PLAN_DOC_REVIEW.put(&vault.store, txn, &plan, &review)?;
                let (core, markdown, review) = plan_doc_in_txn(vault, txn, plan)?;
                Ok(plan_doc_view(plan, &core, markdown, review))
            },
        )?;
        Ok(view)
    }

    /// `vault.plans.get`: plan-doc `input.plan_ref` as it stands, through the
    /// NOTE's own read, so a caller reads a plan-doc where it reads the NOTE.
    /// The revision and state are those of the text this read returns.
    ///
    /// # Errors
    ///
    /// The NOTE read's refusals, and a NOTE that is no plan-doc.
    pub fn read_plan_doc(
        &self,
        input: &PlanDocRequest,
    ) -> MemoryResult<ScopedReadResult<Option<PlanDocView>>> {
        let read = self.read_note(&super::NoteReadRequest {
            note_ref: input.plan_ref.to_hex(),
            reason: None,
            version: None,
            spans: Vec::new(),
        })?;
        let Some(markdown) = read.value.as_ref().map(|note| note.markdown.clone()) else {
            return Ok(read.map(|_| None));
        };
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let (core, _, review) = plan_doc_in_txn(vault, &txn, input.plan_ref)?;
        let view = plan_doc_view(input.plan_ref, &core, markdown, review);
        Ok(read.map(|_| Some(view)))
    }
}

impl Vault {
    /// The owner answers plan-doc `plan` at revision `expected_revision`,
    /// in one writer that rechecks the owner's proof: the verdict is stored
    /// with that revision, and one gate decision records it.
    ///
    /// # Errors
    ///
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof no longer holds; [`RecordError::InvalidNoteBody`] for a
    /// NOTE that is no plan-doc, a revision that is no 64 hex characters, an
    /// `approving_turn_ref` that names no live TURN, or an
    /// `approving_thread_ref` that names no thread on the plan-doc;
    /// [`Error::ConcurrentWrite`] when the text is no longer at
    /// `expected_revision`; an approval's run that cannot land (its agent
    /// definition gone). Every refusal writes nothing.
    pub(crate) fn answer_plan_doc_as(
        &self,
        owner: &AuthenticatedOwner,
        plan: EntityId,
        expected_revision: &str,
        decision: PlanDocDecision,
        origin: PlanApprovalOrigin,
    ) -> MemoryResult<PlanDocSettlementView> {
        if expected_revision.len() != 64
            || !expected_revision
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid("a plan-doc revision is 64 hex characters").into());
        }
        let expected = expected_revision.to_ascii_lowercase();
        let settled = self.try_with_write_txn(|txn| -> MemoryResult<PlanDocSettlementView> {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let (core, markdown, mut review) = plan_doc_in_txn(self, txn, plan)?;
            let revision = revision_of(plan, &markdown);
            if revision_hex(&revision) != expected {
                return Err(Error::ConcurrentWrite("plan-doc revision changed").into());
            }
            if let Some(turn) = origin.turn {
                crate::conversation_dag::require_type(&self.store, txn, &turn, ENTITY_TYPE_TURN)
                    .map_err(|_| invalid("approving_turn_ref names no live conversation TURN"))?;
            }
            if let Some(thread) = origin.thread
                && self
                    .annotation_thread_in_txn(txn, &plan, &thread, false)?
                    .is_none()
            {
                return Err(
                    invalid("approving_thread_ref names no thread on this plan-doc").into(),
                );
            }
            let before = review.verdict.take();
            let receipt_ref = self.record_plan_doc_verdict_in_txn(
                txn,
                actor,
                plan,
                &core,
                &revision,
                decision,
                before.as_ref(),
            )?;
            review.verdict = Some(PlanDocVerdict {
                decision,
                revision: expected,
                decided_at: crate::unix_seconds_now(),
                receipt_ref: receipt_ref.clone(),
            });
            PLAN_DOC_REVIEW.put(&self.store, txn, &plan, &review)?;
            // Execute-on-approve: an approval of a plan that names its agent
            // definition lands the run in this writer, pinned at the revision
            // approved, with the budget the plan's text asks.
            let run_task_ref = match (decision, review.agent_def_ref) {
                (PlanDocDecision::Approved, Some(agent_def_ref)) => {
                    match PlanDocBody::from_markdown(&markdown) {
                        Some(body) => Some(
                            self.memory(actor, EdgeActorClass::Human)
                                .land_plan_run_in_txn(txn, plan, &revision, &body, agent_def_ref)?,
                        ),
                        None => None,
                    }
                }
                _ => None,
            };
            // Execute-on-approve hangs the run off the approving turn: the
            // run's derived SESSION, kept when the revision is approved
            // again (agent-runtime-v1.md:342).
            let sub_session_id = match (run_task_ref, origin.turn) {
                (Some(task), Some(turn)) => {
                    Some(self.plan_run_sub_session_in_txn(txn, actor, task, turn)?)
                }
                _ => None,
            };
            if let (Some(session), Some(thread)) = (sub_session_id, origin.thread) {
                let now = self.store.clock.now_recorded_at();
                self.record_thread_sub_session_in_txn(
                    txn,
                    ThreadSubSession {
                        artifact_id: plan,
                        thread_id: thread,
                        session,
                        actor: WriteActor::new(actor, EdgeActorClass::Human),
                        occurred: TimeRange {
                            start: now,
                            end: now,
                        },
                        learned_at: now,
                    },
                )?;
            }
            Ok(PlanDocSettlementView {
                plan_ref: plan,
                decision,
                revision: revision_hex(&revision),
                proposed_by: proposer(&core),
                receipt_ref,
                run_task_ref,
                sub_session_id,
            })
        })?;
        if settled.run_task_ref.is_some() {
            self.store.notify_attempt_observers();
        }
        Ok(settled)
    }

    /// The SESSION the run TASK `task` hangs off approving TURN `turn` by a
    /// spawned_by edge, derived from the run TASK's id: a revision approved
    /// again keeps its first session and its first spawning turn, and a
    /// later approval naming another turn never re-parents it.
    fn plan_run_sub_session_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        task: EntityId,
        turn: EntityId,
    ) -> MemoryResult<EntityId> {
        let id = EntityId::derive(PLAN_RUN_SESSION, &[task.as_bytes()])?;
        let live = crate::vault::live_entity_row_in_txn(&self.store, txn, &id)?.live_type();
        if live == Some(ENTITY_TYPE_SESSION) {
            return Ok(id);
        }
        self.spawn_dag_sub_session_in_txn(
            txn,
            &turn,
            WriteActor::new(owner, EdgeActorClass::Human),
            id,
            self.store.clock.now_recorded_at(),
        )?;
        Ok(id)
    }

    /// Appends the gate decision that records the owner's verdict: the owner
    /// as actor, `gate.allow.` or `gate.deny.owner_plan_doc`, the NOTE as its
    /// `note:` grant ref, the revision as its diff handle, and the plan, the
    /// revision, the proposer and the verdict it replaces as audit details.
    /// Returns its `gate:<id hex>` ref.
    #[allow(clippy::too_many_arguments)]
    fn record_plan_doc_verdict_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        plan: EntityId,
        core: &super::NoteCore,
        revision: &[u8; 32],
        decision: PlanDocDecision,
        before: Option<&PlanDocVerdict>,
    ) -> Result<String> {
        let (outcome, reason) = match decision {
            PlanDocDecision::Approved => ("allow", APPROVE_REASON),
            PlanDocDecision::Rejected => ("deny", REJECT_REASON),
        };
        let mut details = vec![
            format!("plan:{}", plan.to_hex()),
            format!("revision:{}", revision_hex(revision)),
        ];
        details.extend(proposer(core).map(|agent| format!("proposed_by:{}", agent.to_hex())));
        details.extend(before.map(|verdict| {
            let decision = match verdict.decision {
                PlanDocDecision::Approved => "approved",
                PlanDocDecision::Rejected => "rejected",
            };
            format!("verdict_before:{decision}@{}", verdict.revision)
        }));
        let actor = WriteActor::new(actor, EdgeActorClass::Human);
        let mut record = GateDecisionRecord {
            version: crate::store::GATE_DECISION_LEDGER_VERSION,
            decision_id: GateDecisionId::from_bytes(self.store.clock.ulid()?),
            created_at: crate::ports::recorded_at_in_txn(&self.store, txn)?,
            outcome: outcome.to_owned(),
            reason_codes: vec![reason.to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: GateSystemNoticeRecord::receipt_details(VERDICT_CONTENT_KIND, details),
            actor_class: actor.actor_class().gate_actor_class().to_owned(),
            actor_ref: Some(actor.entity_ref().to_hex()),
            content_kind: VERDICT_CONTENT_KIND.to_owned(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            claim_id: None,
            grant_ref: Some(format!("note:{}", plan.to_hex())),
            diff_handle: revision.to_vec(),
            read_frontier_hash: crate::gate::resolve_policy_manifest(&self.store, txn)?
                .read_frontier_hash()?,
            context: Default::default(),
            redacted_at: None,
        };
        self.store
            .append_fresh_gate_decision_in_txn(txn, &mut record)?;
        Ok(format!("gate:{}", record.decision_id.to_hex()))
    }
}

/// `vault.plans.approve`: the owner approves plan-doc `input.plan_ref` at
/// the revision they read. An approval that names `approving_turn_ref` hangs
/// the run it lands off that turn as a sub-session, and records the
/// sub-session on `approving_thread_ref`.
///
/// # Errors
///
/// The owner proof's refusal; a NOTE that is no plan-doc; a text no longer at
/// `input.expected_revision`; an `approving_turn_ref` that names no live TURN
/// or an `approving_thread_ref` that names no thread on the plan-doc.
pub fn approve_plan_doc_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: PlanDocVerdictRequest,
) -> MemoryResult<PlanDocSettlementView> {
    vault.answer_plan_doc_as(
        owner,
        input.plan_ref,
        &input.expected_revision,
        PlanDocDecision::Approved,
        PlanApprovalOrigin {
            turn: input.approving_turn_ref,
            thread: input.approving_thread_ref,
        },
    )
}

/// `vault.plans.reject`: the owner rejects plan-doc `input.plan_ref` at the
/// revision they read. A rejection names no approving turn or thread.
///
/// # Errors
///
/// As [`approve_plan_doc_as`], and a rejection that names either ref.
pub fn reject_plan_doc_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: PlanDocVerdictRequest,
) -> MemoryResult<PlanDocSettlementView> {
    if input.approving_turn_ref.is_some() || input.approving_thread_ref.is_some() {
        return Err(invalid("a rejection names no approving turn or thread").into());
    }
    vault.answer_plan_doc_as(
        owner,
        input.plan_ref,
        &input.expected_revision,
        PlanDocDecision::Rejected,
        PlanApprovalOrigin::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::PlanDocBody;

    fn body() -> PlanDocBody {
        PlanDocBody {
            title: "Tidy the tide log".to_owned(),
            steps: vec![
                "Read the week. Then stop".to_owned(),
                "## Budget".to_owned(),
            ],
            scope_asked: vec!["notes tagged tide".to_owned()],
            budget: Some(400),
        }
    }

    #[test]
    fn a_plan_doc_body_reads_back_from_its_text() {
        for body in [
            body(),
            PlanDocBody {
                scope_asked: Vec::new(),
                budget: None,
                ..body()
            },
        ] {
            assert_eq!(PlanDocBody::from_markdown(&body.to_markdown()), Some(body));
        }
    }

    #[test]
    fn a_text_out_of_the_plan_doc_sections_reads_as_no_body() {
        let text = body().to_markdown();
        for edited in [
            text.replace("2. ", "3. "),
            format!("{text}\nA closing paragraph.\n"),
            text.replace("## Scope asked", "## Scope"),
            text.replacen("# ", "", 1),
        ] {
            assert_eq!(PlanDocBody::from_markdown(&edited), None, "{edited}");
        }
    }
}
