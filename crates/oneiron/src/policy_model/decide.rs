//! Registered owner and hosted policy questions through the shared ladder: a
//! host-selected ladder's row questions, and the safeguard model's own read of
//! the contract the policy declared.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::llm::decision::catalogue::{
    POLICY_HOSTED_ROW, POLICY_HOSTED_VIOLATION, POLICY_OWNER_ROW, POLICY_OWNER_VIOLATION,
};
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial,
    DecisionQuestion, DecisionRung, GeneratedDecisions, GeneratedMiss, GeneratedRung,
    GeneratedStep, HeldLadder, MAX_DECISION_STATE_BYTES, ProviderPin, Reversibility, TypedDecision,
    cut_text, fit_state,
};
use crate::llm::{BudgetGuard, BudgetLease, DurableStepResult, LlmBackend, LlmRequest};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Error, Result};

use super::binding::PolicyContentBinding;
use super::contract::PolicyOutputContract;
use super::notes::rationale_notes;
use super::planes::PolicyPlane;
use super::prompt::{
    AnswerPlane, PolicyClassifyPrompt, decision_severity, resolve_violation, vocabulary_label,
};
use super::request::{PolicyClassifyRequest, PolicyModelConfig};
use super::verdict::{
    PolicyClassifyVerdict, PolicyConfidence, PolicyHedgeBucket, PolicyPassAudit, PolicySkipReason,
    PolicyVerdictCategory,
};

/// The time the safeguard read has, from its start to its answer. Generous: a
/// reasoning safeguard model thinks before it answers, and a reply after it is
/// no answer.
const SAFEGUARD_READ_BUDGET: Duration = Duration::from_secs(600);

/// The option a category question offers for content the policy allows.
pub(super) const CLEAN: &str = "clean";

/// The most rows one category question names beside [`CLEAN`]; a choice offers
/// at most 64 options.
const ROWS_PER_QUESTION: usize = 63;

/// The longest label a choice option carries.
const OPTION_MAX_BYTES: usize = 256;

/// One host-selected ladder snapshot for a policy plane. The host supplies its
/// providers, principal, ceiling, learned bands and clock budget. Nothing is
/// selected or enabled by default. `revision` identifies the complete provider
/// and band snapshot and must advance when either changes. `wording` asks
/// whether the candidate violates the following row; the engine adds only the
/// row itself, never an instruction of its own.
#[derive(Clone)]
pub struct PolicyDecisions {
    ladder: Arc<HeldLadder>,
    principal: EntityId,
    dial: DecisionDial,
    bands: DecisionBandPolicy,
    revision: String,
    wording: String,
    budget: Duration,
}

impl std::fmt::Debug for PolicyDecisions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyDecisions")
            .field("principal", &self.principal)
            .field("dial", &self.dial)
            .field("revision", &self.revision)
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl PolicyDecisions {
    pub fn new(
        ladder: Arc<HeldLadder>,
        principal: EntityId,
        dial: DecisionDial,
        bands: DecisionBandPolicy,
        revision: String,
        wording: String,
        budget: Duration,
    ) -> Result<Self> {
        dial.band.validate()?;
        if dial.first > dial.ceiling
            || revision.trim().is_empty()
            || wording.trim().is_empty()
            || budget.is_zero()
        {
            return Err(Error::InvalidConfig(
                "invalid policy decision configuration".into(),
            ));
        }
        Ok(Self {
            ladder,
            principal,
            dial,
            bands,
            revision,
            wording,
            budget,
        })
    }

    /// A cached verdict cannot survive a change to this plane's ladder.
    pub(super) fn binding(&self) -> String {
        let slots = [
            self.ladder.rule.as_ref(),
            self.ladder.local.as_ref(),
            self.ladder.system_one.as_ref(),
            self.ladder.escalation.as_ref(),
            self.ladder.big.as_ref(),
        ];
        let pins: Vec<_> = slots
            .into_iter()
            .map(|slot| slot.map(|provider| provider.pin()))
            .collect();
        let value = serde_json::json!({
            "revision": self.revision,
            "principal": self.principal.to_hex(),
            "dial": self.dial,
            "wording": self.wording,
            "providers": pins,
            "queue": self.ladder.human_pin,
            "person_question": self.ladder.person,
            "budget_nanos": self.budget.as_nanos().to_string(),
        });
        blake3::hash(value.to_string().as_bytes())
            .to_hex()
            .to_string()
    }

    pub(super) fn classify(
        &self,
        request: &PolicyClassifyRequest,
        prompt: &PolicyClassifyPrompt,
        plane: AnswerPlane<'_>,
        binding: PolicyContentBinding,
        config: &PolicyModelConfig,
        mut audit: PolicyPassAudit,
    ) -> Result<PolicyClassifyVerdict> {
        let (plane_id, family) = match &plane {
            AnswerPlane::Owner => (PolicyPlane::OwnerPolicy, POLICY_OWNER_ROW),
            AnswerPlane::Hosted(_) => (PolicyPlane::HostedLegal, POLICY_HOSTED_ROW),
        };
        if prompt.rubric_rows.is_empty() {
            return Ok(
                PolicyClassifyVerdict::clean_allow(binding, config, plane_id).with_audit(audit),
            );
        }
        let document_hash = blake3::hash(prompt.system.as_bytes());
        let questions = prompt
            .rubric_rows
            .iter()
            .map(|row| {
                family.question(
                    &[
                        document_hash.as_bytes(),
                        row.row_ref.as_bytes(),
                        row.action.as_str().as_bytes(),
                    ],
                    format!("{}\n{}", self.wording, row.text),
                    AnswerContract::Noul,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        // Never cut the policy or candidate to fit: a model must not clear a
        // candidate it only partly read. The ladder refuses an oversized state.
        let state = serde_json::json!({
            "subject": request.subject.as_str(),
            "content": prompt.user,
            "world_ref": request.world_ref,
            "project_ref": request.project_ref,
            "policy_document": prompt.system,
            "policy_rows": prompt.rubric_rows.iter().map(|row| serde_json::json!({
                "row_ref": row.row_ref, "action": row.action.as_str(), "why": row.why,
            })).collect::<Vec<_>>(),
        });
        let deadline = RetrievalDeadline::hard(Instant::now(), self.budget);
        let ladder = self.ladder.ladder();
        let decisions = ladder.run_pack(
            &questions.iter().collect::<Vec<_>>(),
            self.principal,
            &[],
            &state,
            self.dial,
            &self.bands,
            Reversibility::OutboundEffect,
            &deadline,
        );
        let decisions = match decisions {
            Ok(decisions) => decisions,
            Err(_) => {
                return Ok(PolicyClassifyVerdict::skipped(
                    PolicySkipReason::BackendUnavailable,
                    binding,
                    config,
                    plane_id,
                )
                .with_audit(audit));
            }
        };
        audit.typed_decisions = decisions;
        // An unfinished row is not a clean answer for the whole policy. The
        // owner fails open visibly; the hosted caller degrades and applies
        // its own outage posture. A queued ladder ask never grants a permit.
        if audit
            .typed_decisions
            .iter()
            .any(|decision| !matches!(decision.answer, DecisionAnswer::Noul(_)))
        {
            return Ok(PolicyClassifyVerdict::skipped(
                PolicySkipReason::ResponseUnusable,
                binding,
                config,
                plane_id,
            )
            .with_audit(audit));
        }
        let mut governing = None;
        for (row, decision) in prompt.rubric_rows.iter().zip(&audit.typed_decisions) {
            if decision.answer == DecisionAnswer::Noul(true) {
                audit.model_rule_ids.push(row.row_ref.clone());
                if governing.as_ref().is_none_or(
                    |(old, _): &(&super::planes::PolicyRubricRow, f64)| {
                        decision_severity(row.action) > decision_severity(old.action)
                    },
                ) {
                    governing = Some((row, decision.probability.unwrap_or_default()));
                }
            }
        }
        let Some((row, probability)) = governing else {
            return Ok(
                PolicyClassifyVerdict::clean_allow(binding, config, plane_id).with_audit(audit),
            );
        };
        let category = match plane {
            AnswerPlane::Owner => PolicyVerdictCategory::OwnerPolicy {
                row_ref: row.row_ref.clone(),
            },
            AnswerPlane::Hosted(policy) => {
                let registered = policy
                    .rows
                    .iter()
                    .find(|registered| registered.row_ref == row.row_ref)
                    .ok_or_else(|| {
                        Error::InvalidConfig("policy decision named an unregistered row".into())
                    })?;
                PolicyVerdictCategory::HostedLegal {
                    category: registered.category.clone(),
                    jurisdiction: policy.jurisdiction.clone(),
                    policy_version: policy.version.clone(),
                    row_ref: registered.row_ref.clone(),
                }
            }
        };
        Ok(PolicyClassifyVerdict::new(
            row.action,
            category,
            decided_confidence(probability),
            binding,
            config,
            plane_id,
        )
        .with_audit(audit))
    }
}

/// The confidence a decided probability carries, in its hedge bucket.
fn decided_confidence(probability: f64) -> PolicyConfidence {
    PolicyConfidence {
        calibrated: probability as f32,
        hedge_bucket: if probability >= f64::from(PolicyConfidence::HIGH.calibrated) {
            PolicyHedgeBucket::High
        } else if probability >= f64::from(PolicyConfidence::MEDIUM.calibrated) {
            PolicyHedgeBucket::Medium
        } else {
            PolicyHedgeBucket::Low
        },
    }
}

/// The safeguard model a pass reads, and how its calls go out: on the lease the
/// caller issued, or each under its own admission on the guard.
#[derive(Clone, Copy)]
pub(super) enum SafeguardModel<'a> {
    Leased {
        backend: &'a dyn LlmBackend,
        lease: &'a BudgetLease,
    },
    Budgeted {
        backend: &'a dyn LlmBackend,
        budget: &'a BudgetGuard,
    },
}

impl<'a> SafeguardModel<'a> {
    fn backend(self) -> &'a dyn LlmBackend {
        match self {
            Self::Leased { backend, .. } | Self::Budgeted { backend, .. } => backend,
        }
    }

    fn step(self) -> GeneratedStep<'a> {
        match self {
            Self::Leased { lease, .. } => GeneratedStep::Raw { lease },
            Self::Budgeted { budget, .. } => GeneratedStep::Admitted { guard: budget },
        }
    }
}

/// The safeguard model's verdict for `prompt` on `plane`, decided through the
/// shared ladder. The prompt's own request is the read's shell, so the policy
/// document and the candidate reach the model verbatim, in their own messages,
/// and never in the read's state. The question is the one the declared
/// contract asks: under `binary`, does the candidate violate the policy (yes
/// resolves to the strictest row); otherwise, which row it violates, or clean.
/// The row decides the action. A read that does not decide is a skip, never an
/// allow; under `rationale_json` a decided read is followed by the notes call
/// that fills the audit.
#[expect(
    clippy::too_many_arguments,
    reason = "the pass's plane, principal, binding and audit join the read's inputs"
)]
pub(super) async fn safeguard_verdict(
    safeguard: SafeguardModel<'_>,
    request: &PolicyClassifyRequest,
    prompt: &PolicyClassifyPrompt,
    plane: &AnswerPlane<'_>,
    principal: EntityId,
    binding: PolicyContentBinding,
    config: &PolicyModelConfig,
    mut audit: PolicyPassAudit,
) -> Result<PolicyClassifyVerdict> {
    let plane_id = match plane {
        AnswerPlane::Owner => PolicyPlane::OwnerPolicy,
        AnswerPlane::Hosted(_) => PolicyPlane::HostedLegal,
    };
    let skipped = |reason: PolicySkipReason, audit: PolicyPassAudit| {
        PolicyClassifyVerdict::skipped(reason, binding, config, plane_id).with_audit(audit)
    };
    let wording = Wording::shipped()?;
    let asked = ask(prompt, plane, &wording)?;
    let decisions = match read(safeguard, request, prompt, &asked, principal, config).await {
        Ok(GeneratedDecisions::Decided { decisions, .. }) => decisions,
        Ok(GeneratedDecisions::Unread(GeneratedMiss::Budget(_))) => {
            return Ok(skipped(PolicySkipReason::BudgetExhausted, audit));
        }
        // A raw read never traps, and a read the ladder failed reached no
        // model answer.
        Ok(GeneratedDecisions::Unread(GeneratedMiss::Backend(_)) | GeneratedDecisions::Trapped)
        | Err(_) => {
            return Ok(skipped(PolicySkipReason::BackendUnavailable, audit));
        }
    };
    audit.typed_decisions = decisions;
    let decided = reading(&asked, &audit.typed_decisions);
    let violation = match decided {
        Reading::Unusable => return Ok(skipped(PolicySkipReason::ResponseUnusable, audit)),
        Reading::Clean => None,
        Reading::Violation { label, probability } => {
            match resolve_violation(prompt, plane, label) {
                Ok((decision, category)) => Some((label, decision, category, probability)),
                Err(_) => return Ok(skipped(PolicySkipReason::ResponseUnusable, audit)),
            }
        }
    };
    if prompt.output_contract == PolicyOutputContract::RationaleJson {
        let label = violation.as_ref().and_then(|(label, ..)| *label);
        rationale_notes(safeguard, prompt, config, label, &wording.notes, &mut audit).await?;
    } else {
        // With no notes owed, the audit names the decided row.
        let row_ref = violation
            .as_ref()
            .and_then(|(_, _, category, _)| row_ref_of(category));
        audit.model_rule_ids.extend(row_ref.map(str::to_owned));
    }
    let Some((_, decision, category, probability)) = violation else {
        return Ok(PolicyClassifyVerdict::clean_allow(binding, config, plane_id).with_audit(audit));
    };
    Ok(PolicyClassifyVerdict::new(
        decision,
        category,
        decided_confidence(probability),
        binding,
        config,
        plane_id,
    )
    .with_audit(audit))
}

/// The row a verdict is attributed to, if any.
fn row_ref_of(category: &PolicyVerdictCategory) -> Option<&str> {
    match category {
        PolicyVerdictCategory::None => None,
        PolicyVerdictCategory::OwnerPolicy { row_ref }
        | PolicyVerdictCategory::HostedLegal { row_ref, .. } => Some(row_ref.as_str()),
    }
}

/// The shipped wording of the safeguard read's questions and of its notes
/// request, as data.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Wording {
    binary: String,
    category: String,
    notes: String,
}

impl Wording {
    fn shipped() -> Result<Self> {
        serde_json::from_str(include_str!("decision_wording.json")).map_err(|_| {
            Error::InvalidConfig("shipped policy decision wording is not readable".into())
        })
    }
}

/// What the safeguard read asks about one candidate: its questions and, under a
/// category contract, each option beside the vocabulary label of the row it
/// names.
struct Asked<'p> {
    questions: Vec<DecisionQuestion>,
    options: Vec<(String, &'p str)>,
}

/// The candidate's questions under `prompt`'s contract: one noul under
/// `binary`, else one choice per group of at most [`ROWS_PER_QUESTION`] rows,
/// [`CLEAN`] first in each. Each is keyed by the document hash, the contract
/// and its options; a hosted one by the policy version too.
fn ask<'p>(
    prompt: &'p PolicyClassifyPrompt,
    plane: &AnswerPlane<'_>,
    wording: &Wording,
) -> Result<Asked<'p>> {
    let (family, version) = match plane {
        AnswerPlane::Owner => (POLICY_OWNER_VIOLATION, None),
        AnswerPlane::Hosted(policy) => (POLICY_HOSTED_VIOLATION, Some(policy.version.as_bytes())),
    };
    let document = blake3::hash(prompt.system.as_bytes());
    let contract = prompt.output_contract.as_str().as_bytes();
    let question = |options: &str, text: &str, answer: AnswerContract| {
        let mut parts = vec![document.as_bytes().as_slice(), contract, options.as_bytes()];
        parts.extend(version);
        family.question(&parts, text.to_owned(), answer)
    };
    if prompt.output_contract == PolicyOutputContract::Binary {
        return Ok(Asked {
            questions: vec![question("", wording.binary.as_str(), AnswerContract::Noul)?],
            options: Vec::new(),
        });
    }
    let options = option_labels(prompt.violation_labels());
    // A rubric with no rows still asks; clean is the one answer it offers.
    let groups: Vec<&[(String, &str)]> = if options.is_empty() {
        vec![options.as_slice()]
    } else {
        options.chunks(ROWS_PER_QUESTION).collect()
    };
    let questions = groups
        .into_iter()
        .map(|group| {
            let labels: Vec<String> = std::iter::once(CLEAN.to_owned())
                .chain(group.iter().map(|(label, _)| label.clone()))
                .collect();
            let key = json!(labels).to_string();
            question(
                key.as_str(),
                wording.category.as_str(),
                AnswerContract::Choice { options: labels },
            )
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Asked { questions, options })
}

/// Each vocabulary label as the option offered for it: the label itself while
/// every label fits an option and none reads as [`CLEAN`], else the row's place
/// in the vocabulary. No row is dropped to fit.
fn option_labels(labels: Vec<&str>) -> Vec<(String, &str)> {
    let fits = labels
        .iter()
        .all(|label| !label.is_empty() && label.len() <= OPTION_MAX_BYTES && *label != CLEAN);
    labels
        .into_iter()
        .enumerate()
        .map(|(index, label)| {
            let option = if fits {
                label.to_owned()
            } else {
                format!("row-{}", index + 1)
            };
            (option, label)
        })
        .collect()
}

/// The candidate's questions through an unstaffed ladder whose one rung, the
/// big one, is the safeguard model's generated read over the prompt's own
/// request.
async fn read(
    safeguard: SafeguardModel<'_>,
    request: &PolicyClassifyRequest,
    prompt: &PolicyClassifyPrompt,
    asked: &Asked<'_>,
    principal: EntityId,
    config: &PolicyModelConfig,
) -> DurableStepResult<GeneratedDecisions> {
    let shell = prompt.llm_request(config);
    let model = shell.model.to_string();
    let seal = |request: LlmRequest| -> Result<LlmRequest> { Ok(request) };
    let rung = GeneratedRung {
        pin: ProviderPin {
            rung: DecisionRung::Big,
            model: model.clone(),
            version: model,
        },
        backend: safeguard.backend(),
        step: safeguard.step(),
        request: shell,
        seal: &seal,
    };
    let questions: Vec<&DecisionQuestion> = asked.questions.iter().collect();
    let state = read_state(request, prompt, &asked.options);
    let held = HeldLadder::unstaffed();
    held.ladder()
        .run_pack_generated(
            &rung,
            &questions,
            principal,
            &[],
            &state,
            DecisionDial {
                first: DecisionRung::Big,
                ceiling: DecisionRung::Big,
                band: DecisionBand::default(),
            },
            &DecisionBandPolicy::default(),
            Reversibility::OutboundEffect,
            &RetrievalDeadline::hard(Instant::now(), SAFEGUARD_READ_BUDGET),
        )
        .await
}

/// The read's bounded state: the request's subject and scope, and each row by
/// its reference, action and reason and, under a category contract, the option
/// it answers to when that is not its reference. Long reasons are cut to fit;
/// a table too long to fit even then leaves its rows to the shell and the
/// options, so no rubric is refused for its size. The policy document and the
/// candidate ride in the shell's own messages, never here.
fn read_state(
    request: &PolicyClassifyRequest,
    prompt: &PolicyClassifyPrompt,
    options: &[(String, &str)],
) -> Value {
    let longest = prompt
        .rubric_rows
        .iter()
        .filter_map(|row| row.why.as_deref())
        .map(str::len)
        .max()
        .unwrap_or(0);
    let state = fit_state(longest, |cut| {
        let rows: Vec<Value> = prompt
            .rubric_rows
            .iter()
            .map(|row| {
                let why = row.why.as_deref().map(|why| cut_text(why, cut));
                let mut entry = json!({
                    "row_ref": row.row_ref,
                    "action": row.action.as_str(),
                    "why": why,
                });
                if let Some((label, _)) = options
                    .iter()
                    .find(|(_, named)| *named == vocabulary_label(row))
                    && *label != row.row_ref
                {
                    entry["label"] = json!(label);
                }
                entry
            })
            .collect();
        json!({
            "subject": request.subject.as_str(),
            "world_ref": request.world_ref,
            "project_ref": request.project_ref,
            "policy_rows": rows,
            "cut_at_bytes": cut,
        })
    });
    if serde_json::to_vec(&state).is_ok_and(|bytes| bytes.len() <= MAX_DECISION_STATE_BYTES) {
        return state;
    }
    json!({
        "subject": request.subject.as_str(),
        "world_ref": request.world_ref,
        "project_ref": request.project_ref,
        "policy_rows_omitted": prompt.rubric_rows.len(),
    })
}

/// What the read decided about the candidate.
enum Reading<'p> {
    Clean,
    /// The vocabulary label the answer named (none under `binary`), at the
    /// answer's probability.
    Violation {
        label: Option<&'p str>,
        probability: f64,
    },
    Unusable,
}

/// The candidate's reading from `decisions`: the noul's yes or no, or the most
/// probable row any group named, clean only when no group named one. An answer
/// of another kind, or an option the question never offered, is unusable.
fn reading<'p>(asked: &Asked<'p>, decisions: &[TypedDecision]) -> Reading<'p> {
    let mut named: Option<(&'p str, f64)> = None;
    for decision in decisions {
        match (&decision.answer, decision.probability) {
            (DecisionAnswer::Noul(true), Some(probability)) => {
                return Reading::Violation {
                    label: None,
                    probability,
                };
            }
            (DecisionAnswer::Noul(false), _) => return Reading::Clean,
            (DecisionAnswer::Choice(option), _) if option == CLEAN => {}
            (DecisionAnswer::Choice(option), Some(probability)) => {
                let Some(row) = asked
                    .options
                    .iter()
                    .find(|(offered, _)| offered == option)
                    .map(|(_, row)| *row)
                else {
                    return Reading::Unusable;
                };
                if named.is_none_or(|(_, best)| probability > best) {
                    named = Some((row, probability));
                }
            }
            _ => return Reading::Unusable,
        }
    }
    named.map_or(Reading::Clean, |(label, probability)| Reading::Violation {
        label: Some(label),
        probability,
    })
}
