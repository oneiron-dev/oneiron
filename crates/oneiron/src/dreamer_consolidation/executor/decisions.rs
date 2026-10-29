//! The consolidation's typed questions through the host's ladder: how a conflict set
//! resolves and which candidate's identity a merge keeps, and which listed claim an
//! extracted candidate corrects. The verdict role's generation is each pack's first read.

use serde_json::json;

use super::*;
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind};
use crate::dreamer_consolidation::provenance::KeptDecision;
use crate::dreamer_consolidation::settle::decision_pages::{json_len, split_pages};
use crate::dreamer_wake::WakePassDeadline;
use crate::llm::BoundedAutoChecker;
use crate::llm::decision::{
    AnswerActor, AskAct, AskRole, AskTo, DecisionAsk, DecisionBand, DecisionBandPolicy,
    DecisionDial, DecisionQuestion, DecisionRung, HeldLadder, HumanAskReason,
    MAX_DECISION_STATE_BYTES, RoleRank, TypedDecision,
};

mod identity_choice;
mod read;
pub(super) use identity_choice::FinalChoice;
pub(in crate::dreamer_consolidation) use read::{Decider, ScopedRead};

/// The answer that names no listed id.
pub(super) const NONE: &str = "none";
/// The most ids one choice offers beside [`NONE`]; the contract allows 64 options.
const IDS_PER_QUESTION: usize = 63;
/// How long work waiting on a role's answer sits before the attempt reads
/// the ask again (CALLS: Dreamer ask recheck).
pub(super) const ASK_RECHECK_MS: u64 = 15 * 60 * 1_000;
/// The highest rung a Dreamer verdict reads at. The Dreamer applies its own
/// verdict and the owner reverts it (owner ruling 10-18, "autoapply + revert
/// rather than holdout"), so no verdict goes up to a role and holds its
/// work: one still in band at this rung escalates, and its pair parks as an
/// open conflict the Dreamer's own review settles.
const VERDICT_CEILING: DecisionRung = DecisionRung::Big;
/// The highest role a Dreamer verdict's ask climbs to, and what its answer
/// authorises (CALLS: Dreamer ask route), were [`VERDICT_CEILING`] the person
/// rung.
const ASK_CEILING: RoleRank = RoleRank::Owner;
const ASK_ACT: AskAct = AskAct::Judgment;

/// The host's ladder for the Dreamer's typed questions, the dial and learned bands they
/// route under, and its wording of each question. The verdict role's generated read sits at
/// the dial's first rung, in place of that slot's provider.
#[derive(Clone)]
pub struct ConsolidationDecisions {
    pub ladder: HeldLadder,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    /// How a conflict set resolves.
    pub resolution_wording: String,
    /// Which candidate's identity a merge keeps.
    pub identity_wording: String,
    /// Which listed claim an extracted candidate corrects.
    pub correction_wording: String,
    /// Whether a sieve span's mention is new information (OF-498a).
    pub sieve_novelty_wording: String,
    /// Which span kind a sieve span is.
    pub sieve_kind_wording: String,
    /// Which supplied candidate, if any, a sieve span names.
    pub sieve_entity_wording: String,
    /// How sure a sieve reading is, as an integer percent.
    pub sieve_confidence_wording: String,
    /// Whether two claims different children of one night proposed state the
    /// same thing (OF-498d): same_as, no_link or unresolved.
    pub nightly_link_wording: String,
    /// The host's write-gate auto check, when it runs one. `None` promotes
    /// without a check, as before.
    pub checker: Option<BoundedAutoChecker>,
}

impl ConsolidationDecisions {
    /// The shipped wording on an unstaffed ladder: the verdict role's read, at the big
    /// rung, is the one rung, and every band starts in shadow.
    pub fn shipped() -> Result<Self> {
        let wording: Wording = serde_json::from_str(include_str!("decision_wording.json"))
            .map_err(|_| invalid_consolidation("shipped decision wording is not readable"))?;
        Ok(Self {
            ladder: HeldLadder::unstaffed(),
            dial: DecisionDial {
                first: DecisionRung::Big,
                ceiling: DecisionRung::Big,
                band: DecisionBand::default(),
            },
            bands: DecisionBandPolicy::default(),
            resolution_wording: wording.resolution,
            identity_wording: wording.identity,
            correction_wording: wording.correction,
            sieve_novelty_wording: wording.sieve_novelty,
            sieve_kind_wording: wording.sieve_kind,
            sieve_entity_wording: wording.sieve_entity,
            sieve_confidence_wording: wording.sieve_confidence,
            nightly_link_wording: wording.nightly_link,
            checker: None,
        })
    }

    /// The decisions, each NOTE review promotion through `checker`'s auto
    /// check.
    #[must_use]
    pub fn with_checker(mut self, checker: Option<BoundedAutoChecker>) -> Self {
        self.checker = checker;
        self
    }
}

/// The shipped wording, as data.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Wording {
    resolution: String,
    identity: String,
    correction: String,
    sieve_novelty: String,
    sieve_kind: String,
    sieve_entity: String,
    sieve_confidence: String,
    nightly_link: String,
}

/// `ids` as a choice's option groups, each of at most [`IDS_PER_QUESTION`] ids, with
/// [`NONE`] first when `none` holds or there is more than one group. Each group comes with
/// the same options as its call shows them (FIX 7506): every id by its claim label in
/// `labels`, [`NONE`] as it is. The canonical options are the question's; the shown ones
/// go on the wire only.
pub(super) fn id_options(
    ids: &[EntityId],
    none: bool,
    labels: &mut CallLabelMap,
) -> Vec<(Vec<String>, Vec<String>)> {
    let none = none || ids.len() > IDS_PER_QUESTION;
    ids.chunks(IDS_PER_QUESTION)
        .map(|group| {
            let first = none.then(|| NONE.to_owned());
            let options: Vec<String> = first
                .clone()
                .into_iter()
                .chain(group.iter().map(EntityId::to_hex))
                .collect();
            let shown: Vec<String> = first
                .into_iter()
                .chain(
                    group
                        .iter()
                        .map(|id| labels.assign(LabelKind::Claim, *id).to_string()),
                )
                .collect();
            (options, shown)
        })
        .collect()
}

/// Whether the ladder put this decision to a role: its last pin is the person rung's.
fn went_up(decision: &TypedDecision) -> bool {
    decision
        .receipt
        .providers
        .last()
        .is_some_and(|pin| pin.rung == DecisionRung::Human)
}

/// Whether an ask holds the work it decides: an answered one always does,
/// and an open one unless the ladder only asked because the read ran out of
/// time; that pass checkpoints, and its resume reads again.
fn holds(ask: &DecisionAsk) -> bool {
    ask.answer.is_some() || ask.reason != HumanAskReason::Deadline
}

impl ConsolidationExecutor<'_> {
    /// Labels `questions` `Q1`, `Q2`, in order, then the ladder's paired and
    /// person questions (FIX 7506), before the pack's state renders: every
    /// request the pack splits into shows the same labels, and its state
    /// names its questions by them.
    pub(in crate::dreamer_consolidation) fn label_questions(
        &self,
        labels: &mut CallLabelMap,
        questions: &[DecisionQuestion],
    ) {
        let held = &self.decisions.ladder;
        for question in questions.iter().chain(&held.paired).chain(&held.person) {
            labels.assign(LabelKind::Question, question.id);
        }
    }

    /// Who a verdict over `project`'s claims asks when it goes up: the
    /// project's leader as the responsible actor, then its boards and the
    /// owners; its boards when it has no leader but the Dreamer itself; the
    /// owners when the vault folds no such project. Never the Dreamer: a
    /// system actor holds no role.
    pub(super) fn ask_route(
        &self,
        vault: &crate::Vault,
        project: Option<EntityId>,
    ) -> Result<AskTo> {
        let Some(project) = project else {
            return Ok(AskTo::owner());
        };
        let effective = {
            let txn = vault.store.env.read_txn()?;
            vault.effective_project_in_txn(&txn, project)?
        };
        let Some((_, effective)) = effective else {
            return Ok(AskTo::owner());
        };
        let role = match EntityId::from_hex(&effective.leader)
            .ok()
            .filter(|leader| *leader != self.actor.entity_ref())
        {
            Some(actor) => AskRole::Responsible {
                actor: AnswerActor::Actor(actor),
                project: Some(project),
            },
            None => AskRole::Board { project },
        };
        Ok(AskTo {
            role,
            ceiling: ASK_CEILING,
            act: ASK_ACT,
        })
    }

    /// `questions` over `state` through the host's ladder, the verdict role's generation
    /// the dial's first read, on the time the pass has left, any ask going to `to` for
    /// the work `correlation` names. Each generation that finished joins `charges`, even
    /// when a later one traps or fails. None when the step trapped: the attempt is parked.
    ///
    /// Every read shows the pack through `labels` (FIX 7506): the generation's
    /// questions by their labels and its choices as registered, every rung
    /// past it the same choices, and each answer reads back canonical. The map
    /// binds into each generation's identity.
    ///
    /// A question already put to `to` for this work is not put again: an open ask
    /// still holds its work, and an answered one is the answer, so the read stops below
    /// the person rung. Each decision keeps its ask, and its receipt names the version
    /// of every evidence body the branch pinned.
    #[expect(
        clippy::too_many_arguments,
        reason = "the step, its pass clock, branch and route join the pack and the charge tally"
    )]
    pub(super) async fn decide(
        &self,
        step_ctx: &DurableStepContext<'_>,
        pass: &WakePassDeadline,
        resources: &BranchResources<'_>,
        to: &AskTo,
        correlation: EntityId,
        questions: &[DecisionQuestion],
        evidence: &[EntityId],
        state: &serde_json::Value,
        labels: &CallLabelMap,
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<Option<Vec<KeptDecision>>> {
        let vault = step_ctx.vault;
        let call = self.role(DREAMER_VERDICT_ROLE);
        let seal = |request: LlmRequest| -> Result<LlmRequest> {
            let mut request = vault
                .authorize_model_role(DREAMER_VERDICT_ROLE, request, &call.inference)?
                .into_request();
            super::super::roles::bind_reasoning(vault, call.backend, &mut request)?;
            Ok(request)
        };
        // Every decision's receipt names the version of each evidence body
        // the branch pinned.
        let versions = resources.evidence_versions(evidence);
        let mut spent = Vec::new();
        let decided = self
            .decider()
            .decide_scoped(
                ScopedRead {
                    step: step_ctx,
                    pass,
                    call: &call,
                    shell: verdict_shell(&call, resources.scope())?,
                    seal: &seal,
                    versions: &versions,
                    to,
                    correlation,
                    evidence,
                    state,
                    ceiling: VERDICT_CEILING,
                },
                questions,
                labels,
                &mut spent,
            )
            .await;
        // Every generation that finished is spent, whatever the pack's outcome: a later
        // step that traps or fails leaves the prefix on the tally.
        for (hash, usage) in &spent {
            charges.record_terminal(vault, step_ctx.attempt_id, *hash, usage)?;
        }
        decided
    }
}

/// The verdict role's request for a typed read: its model, scope and binding, with no
/// messages yet.
fn verdict_shell(call: &RoleCall<'_>, scope: &crate::llm::Scope) -> Result<LlmRequest> {
    Ok(LlmRequest {
        model: call.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: scope.clone(),
            purpose: CallPurpose::Consolidation,
            class: CallClass::Durable {
                fallback: crate::llm::DeterministicFallback {
                    name: "json_rules_v1".into(),
                    config: None,
                },
            },
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("consolidation".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: call.inference.selected_locality().ok_or_else(|| {
                crate::Error::InvalidConfig("consolidation host binding needs locality".into())
            })?,
        }
        .with_purpose_defaults(),
        messages: Vec::new(),
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    })
}

/// Which read of a pack one state is for: the whole pack, one of its pages,
/// or a final identity choice (FIX 8693).
#[derive(Debug, Clone, Copy)]
pub(super) enum StatePart {
    Whole,
    Page { page: usize, pages: usize },
    Final,
}

impl StatePart {
    /// `state` marked as this part's: a page says which of how many, a final
    /// choice says it is one.
    pub(super) fn mark(self, mut state: serde_json::Value) -> serde_json::Value {
        if let serde_json::Value::Object(fields) = &mut state {
            match self {
                Self::Whole => {}
                Self::Page { page, pages } => {
                    fields.insert("page".to_owned(), json!(page + 1));
                    fields.insert("pages".to_owned(), json!(pages));
                }
                Self::Final => {
                    fields.insert("final_choice".to_owned(), json!(true));
                }
            }
        }
        state
    }
}

/// A conflict as its pack reads it, every value whole (Rule 5, FIX 7637):
/// the predicate and the prior heads every read shows, and each candidate.
/// Each claim goes by its label in the read's map (FIX 7506).
pub(super) struct ConflictRows {
    predicate: String,
    priors: Vec<(EntityId, String, Option<&'static str>, serde_json::Value)>,
    candidates: Vec<(EntityId, String, serde_json::Value)>,
}

impl ConflictRows {
    pub(super) fn of(
        identity: &ConflictIdentity,
        members: &[&PromotionCandidate],
        priors: &[super::super::PriorHead],
    ) -> Result<Self> {
        let priors = priors
            .iter()
            .map(|prior| {
                (
                    prior.claim_id,
                    prior.body.predicate.clone(),
                    prior.body.source.map(ClaimSource::as_str),
                    rmpv_to_json(&prior.body.value),
                )
            })
            .collect();
        let candidates = members
            .iter()
            .map(|member| {
                let facts = candidate_facts(&member.candidate)?;
                Ok((member.claim_id, facts.predicate, rmpv_to_json(&facts.value)))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            predicate: identity.predicate.clone(),
            priors,
            candidates,
        })
    }

    /// Every candidate's index, in order.
    pub(super) fn all(&self) -> Vec<usize> {
        (0..self.candidates.len()).collect()
    }

    /// The indexes of the candidates `ids` name, in their order.
    pub(super) fn indexes(&self, ids: &[EntityId]) -> Vec<usize> {
        ids.iter()
            .filter_map(|id| self.candidates.iter().position(|row| row.0 == *id))
            .collect()
    }

    /// The candidate ids at `shown`, in order.
    pub(super) fn ids(&self, shown: &[usize]) -> Vec<EntityId> {
        shown
            .iter()
            .filter_map(|at| self.candidates.get(*at).map(|row| row.0))
            .collect()
    }

    /// The state one read of the pack takes: the predicate, every prior head
    /// and the candidates at `shown`, each whole, marked as `part`'s.
    pub(super) fn state(
        &self,
        shown: &[usize],
        part: StatePart,
        labels: &mut CallLabelMap,
    ) -> serde_json::Value {
        let candidates: Vec<serde_json::Value> = shown
            .iter()
            .filter_map(|at| self.candidates.get(*at))
            .map(|(claim, predicate, value)| {
                let claim = labels.assign(LabelKind::Claim, *claim).to_string();
                json!({"claim": claim, "predicate": predicate, "value": value})
            })
            .collect();
        let priors: Vec<serde_json::Value> = self
            .priors
            .iter()
            .map(|(claim, predicate, source, value)| {
                let claim = labels.assign(LabelKind::Claim, *claim).to_string();
                json!({"claim": claim, "predicate": predicate, "source": source, "value": value})
            })
            .collect();
        part.mark(json!({
            "predicate": self.predicate,
            "prior_heads": priors,
            "candidates": candidates,
        }))
    }

    /// The candidates' indexes in pages: all on one when the whole state fits
    /// the ladder's bound; else split in order, each page beside every prior
    /// head, a candidate wider than a page on a page of its own. Each is
    /// measured with its full id.
    pub(super) fn pages(&self) -> Vec<Vec<usize>> {
        let all = self.all();
        let whole = self.state(&all, StatePart::Whole, &mut CallLabelMap::default());
        if json_len(&whole) <= MAX_DECISION_STATE_BYTES {
            return vec![all];
        }
        let part = StatePart::Page { page: 0, pages: 2 };
        let frame = json_len(&self.state(&[], part, &mut CallLabelMap::default()));
        let bytes =
            |at: usize| {
                self.candidates.get(at).map_or(0, |(claim, predicate, value)| {
                json_len(&json!({"claim": claim.to_hex(), "predicate": predicate, "value": value}))
                    .saturating_add(1)
            })
            };
        split_pages(frame, &all, |_, at| bytes(at), |_, _| true)
    }
}
