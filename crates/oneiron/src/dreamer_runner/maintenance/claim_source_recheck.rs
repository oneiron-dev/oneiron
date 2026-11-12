//! The Dreamer's re-check of the claims drawn from a message the provider
//! deleted and the vault kept (FIX 15414; owner MAIL-DELETE = A, 2026-11-03:
//! "The message leaves the live inbox and stays as a labelled source-deleted
//! copy; the claims drawn from it are checked again"). The mail writer that
//! marks the copy source-deleted owes one re-check, ids only, and queues it
//! here in that write (`mail_pack::claim_recheck`): no scheduler of its own.
//! A pass admits it as it admits any maintenance; its host lends the judging
//! model and the rubric, which is prompt data the host ships, never prose
//! here.
//!
//! The re-check finds every live claim the message's TURN or MESSAGE
//! revisions support, by its logical head: a claim whose own typed evidence
//! cites them, or the head of a live support assertion that does. Each head
//! is judged once, by its ref, revision and subject, with every record it and
//! its live support assertions cite as they stand now, the provider's hold on
//! each, and the words of each TURN the Dreamer may read. The judge answers
//! `supported`, `weakened` or `unsupported`, as a registered question on the
//! host's decision ladder (ARCH-0076 #decide-required, DECIDE-BYPASS-1): the
//! judge's generated read is the ladder's one rung, and only the typed answer
//! is the verdict. A claim not yet approved, or one the Dreamer's read
//! withholds, stays owed: the job waits and reads again.
//!
//! A verdict changes belief only through the curator's own doors: a weaker
//! support moves the claim one rung down its demotion ladder, none left
//! marks it stale, and a claim already stale stays as it is. Nothing here
//! retracts a claim, rewrites a body or deletes a record. A rung applies as
//! the Dreamer with its receipt and the inverse the owner reverts; on a
//! critical claim it waits in the run tray, and the owner's approval applies
//! it through the curator's approved door. A rung the door refuses, and a
//! reply that is no verdict, wait for the owner's review as a plain finding.
//! Each claim's finding lands in one write with its settled mark, and only
//! while the message is still the source-deleted copy at the generation the
//! re-check was owed for: a restore, a later delete or an erase of the
//! message makes it moot, and it settles changing nothing. Findings carry
//! ids, hashes and the verdict, never the judge's words or the message's.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::MAINTENANCE_QUEUE_KIND;
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerParkCause, DreamerRunnerStore,
};
use crate::dreamer_wake::{
    DREAMER_HARD_CUT_PARK_REASON, DreamerAttemptExecution, WakeAttemptContext,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::inference_context::HostInferenceContext;
use crate::llm::decision::{DecisionLadder, GeneratedDecisions, GeneratedRung, GeneratedStep};
use crate::model_binding::ModelRole;
use crate::model_decision::catalogue::CLAIM_SOURCE_SUPPORT;
use crate::model_decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial,
    DecisionQuestion, DecisionRung, ProviderPin, Reversibility,
};
use crate::model_step_context::{DurableStepContext, StepEffectBinding};
use crate::model_step_error::DurableStepError;
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Error, Result, Vault};
use oneiron_model::llm::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, LlmBackend, LlmMessage,
    LlmMessageRole, LlmRequest, LlmUsage, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence,
};

mod landing;
mod read;

/// The maintenance facet the re-check of one provider-deleted, kept message
/// rides.
pub const CLAIM_SOURCE_RECHECK_FACET: &str = "dreamer.claim_source_recheck";

/// The predicate of the Dreamer's plain finding about one re-checked claim:
/// one the verdict leaves as it stands, or one that waits for the owner's
/// review. A rung lands as the curator's own finding.
pub const CLAIM_SOURCE_RECHECK_PREDICATE: &str = "dreamer.claim_source_recheck.verdict";

/// The payload key the declaration rides under.
const DECLARATION_KEY: &str = "declaration";

/// Why a re-check waits when no host lends it a judge.
const UNLENT_REASON: &str = "no host lends this pass a claim re-check";

/// Why a re-check parks when its durable step suspended it.
const TRAPPED_REASON: &str = "durable step trapped for resume";

/// Why a re-check waits when the judge's read came back with no reply.
const UNREAD_REASON: &str = "the claim re-check judge's read came back unread";

/// Why a re-check waits with a claim it found still owed: one not yet
/// approved, or one the Dreamer's read withholds.
const DEFERRED_REASON: &str = "a claim it found waits for its approval or for the Dreamer's read";

/// What one provider-deleted, kept message owes the claims drawn from it:
/// ids only, never a word of the message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimSourceRecheckDeclaration {
    /// The mail source the message came from.
    pub(crate) source: EntityId,
    /// The BLAKE3 of the provider's message id: the message's key in its
    /// source.
    pub(crate) occurrence: [u8; 32],
    /// The presence generation the delete moved the message to.
    pub(crate) generation: u64,
    /// Moved on each time a claim born later from the kept copy reopens the
    /// re-check of this generation.
    pub(crate) round: u64,
    /// The message's TURN.
    pub(crate) turn: EntityId,
    /// Each revision's MESSAGE, oldest first.
    pub(crate) messages: Vec<EntityId>,
}

impl ClaimSourceRecheckDeclaration {
    /// The queue key the declaration fixes: one job per message, generation
    /// and round, however often the write that owes it replays.
    fn key(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron:claim-source-recheck:v1");
        hasher.update(self.source.as_bytes());
        hasher.update(&self.occurrence);
        hasher.update(&self.generation.to_be_bytes());
        hasher.update(&self.round.to_be_bytes());
        format!(
            "{CLAIM_SOURCE_RECHECK_FACET}:{}",
            hasher.finalize().to_hex()
        )
    }

    fn input(&self) -> Result<Value> {
        let json = serde_json::to_string(self)
            .map_err(|_| Error::InvariantViolation("a claim re-check did not encode"))?;
        Ok(Value::Map(vec![(
            Value::from(DECLARATION_KEY),
            Value::from(json),
        )]))
    }

    pub(crate) fn from_input(input: &Value) -> Result<Self> {
        let invalid = || Error::InvalidConfig("invalid claim re-check declaration".into());
        let json = input
            .as_map()
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|(key, _)| key.as_str() == Some(DECLARATION_KEY))
            })
            .and_then(|(_, value)| value.as_str())
            .ok_or_else(invalid)?;
        serde_json::from_str(json).map_err(|_| invalid())
    }

    /// The entity rows the re-check is about: the message's TURN and each
    /// MESSAGE revision. The source is a pack row, never an entity.
    pub(crate) fn about(&self) -> Vec<EntityId> {
        let mut about = Vec::with_capacity(self.messages.len() + 1);
        about.push(self.turn);
        about.extend(self.messages.iter().copied());
        about
    }
}

/// Queues the re-check `declaration` names in the caller's write: the
/// delete that owes it, or the later birth that reopens it. A replayed write
/// finds the job it queued; a rolled-back one queued none.
pub(crate) fn queue_claim_source_recheck_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    declaration: &ClaimSourceRecheckDeclaration,
    now: u64,
) -> Result<()> {
    DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        txn,
        MAINTENANCE_QUEUE_KIND,
        DreamerAttemptPayload {
            attempt_type: CLAIM_SOURCE_RECHECK_FACET.into(),
            input: declaration.input()?,
            parent_attempt: None,
        },
        Some(declaration.key()),
        None,
        now,
    )?;
    Ok(())
}

/// What the host lends one re-check: the judging model on its own route and
/// meter, the rubric it judges by, and the decision ladder that asks it.
pub struct ClaimSourceRecheckModel<'a> {
    pub backend: &'a dyn LlmBackend,
    pub guard: &'a BudgetGuard,
    pub model: ModelId,
    pub inference: HostInferenceContext<'a>,
    /// The vault role whose route the judge's call is admitted on.
    pub role: ModelRole,
    /// The host's rubric: prompt data, never engine prose.
    pub rubric: &'a str,
    /// The host's decision path for each claim's verdict.
    pub decisions: ClaimSourceRecheckDecisions<'a>,
}

/// The host's decision path for a claim's verdict (ARCH-0076
/// #decide-required): its shared ladder, the bands an answer is read under,
/// and its wording of the question. A host with no ladder to lend lends no
/// re-check: it waits ([`unlent`]), never judged outside the ladder.
pub struct ClaimSourceRecheckDecisions<'a> {
    /// The host's shared decision ladder.
    pub ladder: DecisionLadder<'a>,
    /// The bands an answer is read under.
    pub bands: DecisionBandPolicy,
    /// The host's wording of the support question: prompt data, never
    /// engine prose.
    pub wording: String,
}

/// The dial a claim's question climbs: the judge's generated read at the Big
/// rung, with no stronger rung and no person above it. The read quotes the
/// kept mail's words in an uncaptured step of this attempt (fix list row
/// 20501); a stronger seat or a person's ask would hold them outside it. One
/// read also keeps the spend at one booked generation per claim, as before.
fn dial() -> DecisionDial {
    DecisionDial {
        first: DecisionRung::Big,
        ceiling: DecisionRung::Big,
        band: DecisionBand::default(),
    }
}

/// A re-check whose host lends no judge stays queued, never judged as
/// passed: it resumes after its retry delay.
#[must_use]
pub fn unlent() -> DreamerAttemptExecution {
    DreamerAttemptExecution::Park {
        reason: UNLENT_REASON.to_owned(),
        cause: DreamerParkCause::Retry,
    }
}

/// What the judge answers about one claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Its current supports still carry it as it stands.
    Supported,
    /// They carry it, more weakly than before.
    Weakened,
    /// They no longer carry it.
    Unsupported,
}

impl Verdict {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Weakened => "weakened",
            Self::Unsupported => "unsupported",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "supported" => Some(Self::Supported),
            "weakened" => Some(Self::Weakened),
            "unsupported" => Some(Self::Unsupported),
            _ => None,
        }
    }
}

/// Runs one admitted re-check.
///
/// # Errors
///
/// A declaration that does not decode, a host binding that names no
/// locality, or a vault read or write that fails.
pub async fn run_claim_source_recheck(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    model: ClaimSourceRecheckModel<'_>,
) -> Result<DreamerAttemptExecution> {
    if attempt.status.payload.attempt_type != CLAIM_SOURCE_RECHECK_FACET {
        return Err(Error::InvalidConfig("not a claim re-check attempt".into()));
    }
    let declaration = ClaimSourceRecheckDeclaration::from_input(&attempt.status.payload.input)?;
    let attempt_id = attempt.status.attempt.id;
    let now = ctx.now_ms / 1_000;
    let Some(read) = read::read_asks(ctx.vault, &declaration)? else {
        // Moot: the message was restored, deleted again or erased.
        settle(ctx.vault, &declaration, now)?;
        return Ok(Spend::default().completed());
    };
    let locality = model.inference.selected_locality().ok_or_else(|| {
        Error::InvalidConfig("the re-check's host binding names no locality".into())
    })?;
    let keyless = model.inference.selected_keyless();
    let mut spend = Spend::default();
    let mut moot = false;
    // Keyed by the rubric the judge reads by: a new rubric is a new question
    // with its own bands.
    let rubric = blake3::hash(model.rubric.as_bytes());
    let question = CLAIM_SOURCE_SUPPORT.question(
        &[rubric.as_bytes().as_slice()],
        model.decisions.wording.clone(),
        AnswerContract::Choice {
            options: [Verdict::Supported, Verdict::Weakened, Verdict::Unsupported]
                .map(|verdict| verdict.as_str().to_owned())
                .to_vec(),
        },
    )?;
    for ask in &read.asks {
        let asked = ask_judge(
            attempt,
            ctx,
            &model,
            &question,
            ask,
            (locality, keyless),
            &mut spend,
        )
        .await;
        let judging = match noted(asked, &spend, ctx)? {
            Asked::Answered(judging) => judging,
            Asked::Trapped => return Ok(spend.park(TRAPPED_REASON, DreamerParkCause::Signal)),
            Asked::Unread => return Ok(spend.park(UNREAD_REASON, DreamerParkCause::Retry)),
            Asked::Failed(error) => return spend.parked_on(error, ctx),
        };
        let judge = judging.judge(&model);
        let landed = noted(
            landing::land(
                ctx.vault,
                attempt_id,
                &declaration,
                ask,
                judging.verdict,
                &judge,
                &read.rubric,
                now,
            ),
            &spend,
            ctx,
        )?;
        // Moot meanwhile: the rest are judged by nothing.
        if landed.is_none() {
            moot = true;
            break;
        }
    }
    // A claim not yet approved, or one the Dreamer may not read, keeps the
    // re-check owed: it is never judged before it is a belief, nor on words
    // withheld from its judge. The same job waits the runtime's retry pause
    // with what it spent, and reads again; a claim gone from the live set
    // meanwhile is owed nothing.
    if !moot && read.deferred {
        return Ok(spend.park(DEFERRED_REASON, DreamerParkCause::Retry));
    }
    noted(settle(ctx.vault, &declaration, now), &spend, ctx)?;
    Ok(spend.completed())
}

/// `result`, its error handed to the meter with what `spend` spent before
/// it (FIX 11558).
fn noted<T>(result: Result<T>, spend: &Spend, ctx: &WakeAttemptContext<'_>) -> Result<T> {
    result.map_err(|error| {
        spend.note_before_error(ctx);
        error
    })
}

/// Settles the re-check's round in its own write: checked, review-needed,
/// or obsolete when moot.
fn settle(vault: &Vault, declaration: &ClaimSourceRecheckDeclaration, now: u64) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        crate::mail_pack::claim_recheck::settle_claim_recheck_in_txn(vault, txn, declaration, now)
    })
}

/// The judge's request before the ladder's turn: the host's rubric alone.
/// The ladder adds the question and the claim with its supports as the
/// call's state, and sets the reply's shape, a weight per verdict and no
/// field for words: the durable step keeps its reply under the claim, not
/// under the mail it read, so a reply with free text could keep the kept
/// mail's words past their erase (fix list row 20501). The message's
/// retained words leave the vault as an extraction's do, so they pass the
/// same egress gate.
fn judge_shell(
    model: &ClaimSourceRecheckModel<'_>,
    locality: ModelLocality,
    keyless: bool,
) -> LlmRequest {
    LlmRequest {
        model: model.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: oneiron_model::llm::Scope::default(),
            purpose: CallPurpose::Extraction,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("consolidation".into()),
            ),
            response_format: ResponseFormat::Json {
                schema: serde_json::json!({}),
            },
            locality,
            host_keyless: keyless,
            host_paid: false,
        }
        .with_purpose_defaults(),
        messages: vec![LlmMessage {
            role: LlmMessageRole::System,
            content: vec![ContentPart::Text {
                text: model.rubric.to_owned(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    }
}

/// One claim's answer from the ladder: the verdict, the typed decision
/// behind it, and the judge's step.
struct Judging {
    /// `None` for an abstention or an answer off the contract: no verdict.
    verdict: Option<Verdict>,
    /// The ladder's decision with its receipt: ids, pins, bands and
    /// readings, never the judge's words or the message's.
    decision: Option<serde_json::Value>,
    step_hash: [u8; 32],
    usage: LlmUsage,
}

impl Judging {
    /// The judge's model, step, usage and decision, as a finding records
    /// them.
    fn judge(&self, model: &ClaimSourceRecheckModel<'_>) -> serde_json::Value {
        serde_json::json!({
            "model": model.model.as_str(),
            "step_hash": bytes_to_hex_lower(&self.step_hash),
            "usage_in": self.usage.input.total,
            "usage_out": self.usage.output.total,
            "decision": self.decision,
        })
    }
}

/// How one claim's question ended.
enum Asked {
    Answered(Judging),
    /// The durable step suspended the attempt, to resume.
    Trapped,
    /// The read came back with no reply; nothing was decided.
    Unread,
    Failed(DurableStepError),
}

/// Asks the ladder `question` about `ask`'s claim, the judge's read a
/// durable step of `attempt` admitted on the host's role, its words
/// uncaptured. Each generation that finished is booked on `spend`, whatever
/// the outcome.
async fn ask_judge(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    model: &ClaimSourceRecheckModel<'_>,
    question: &DecisionQuestion,
    ask: &read::Ask,
    (locality, keyless): (ModelLocality, bool),
    spend: &mut Spend,
) -> Result<Asked> {
    let attempt_id = attempt.status.attempt.id;
    let actor = ctx.vault.dreamer_actor_for_attempt(attempt_id)?;
    let step = DurableStepContext {
        vault: ctx.vault,
        attempt_id,
        run_id: attempt.status.attempt.run_id.clone(),
        envelope_actor: actor,
        subject: ask.head,
        deadline: Some(ctx.deadline),
        now_ms: ctx.now_ms,
        spend_scope: None,
        wake_pass_bound: true,
    };
    let (vault, role, inference) = (ctx.vault, model.role, &model.inference);
    let seal = move |request: LlmRequest| -> Result<LlmRequest> {
        Ok(vault
            .authorize_model_role(role, request, inference)?
            .into_request())
    };
    let dial = dial();
    let rung = GeneratedRung {
        pin: ProviderPin {
            rung: dial.first,
            model: model.model.as_str().to_owned(),
            version: model.model.as_str().to_owned(),
        },
        backend: model.backend,
        step: GeneratedStep::Durable {
            step: &step,
            guard: model.guard,
        },
        request: judge_shell(model, locality, keyless),
        seal: &seal,
    };
    let deadline = RetrievalDeadline::hard(
        Instant::now(),
        Duration::from_millis(ctx.deadline.remaining_ms()),
    );
    // The judge's request quotes the kept mail's words, which the replay
    // capture's owners would not retire when that mail is erased: this
    // attempt's steps keep no capture (fix list row 20501).
    let _uncaptured =
        crate::self_heal::blocked_reports::UncapturedSteps::hold(ctx.vault, attempt_id);
    let mut spent = Vec::new();
    let decided = model
        .decisions
        .ladder
        .run_pack_generated_spent(
            &rung,
            &[question],
            actor.entity_ref(),
            std::slice::from_ref(&ask.head),
            &ask.input,
            dial,
            &model.decisions.bands,
            Reversibility::ReversibleRead,
            &deadline,
            &mut spent,
            None,
        )
        .await;
    spend.book(&spent);
    Ok(match decided {
        Ok(GeneratedDecisions::Decided { decisions, .. }) => {
            // A read the work time could not start sent nothing: the
            // attempt waits for the next pass, as a hard cut does.
            let Some((step_hash, usage, ..)) = spent.last() else {
                return Ok(Asked::Failed(DurableStepError::DeadlineHardCut));
            };
            let decision = decisions.into_iter().next();
            let verdict = decision
                .as_ref()
                .and_then(|decision| match &decision.answer {
                    DecisionAnswer::Choice(choice) => Verdict::parse(choice),
                    _ => None,
                });
            let decision = decision
                .map(|decision| serde_json::to_value(&decision))
                .transpose()
                .map_err(|_| {
                    Error::InvariantViolation("a claim re-check decision did not encode")
                })?;
            Asked::Answered(Judging {
                verdict,
                decision,
                step_hash: *step_hash,
                usage: usage.clone(),
            })
        }
        Ok(GeneratedDecisions::Trapped) => Asked::Trapped,
        Ok(GeneratedDecisions::Unread(_)) => Asked::Unread,
        Err(error) => Asked::Failed(error),
    })
}

/// What a re-check's steps spent, each step that finished booked once.
#[derive(Default)]
struct Spend {
    units: u64,
    step_bindings: Vec<StepEffectBinding>,
}

impl Spend {
    /// Books each generation in `spent` once: nothing for a memoized one,
    /// which the pass that asked it paid for.
    fn book(&mut self, spent: &[([u8; 32], LlmUsage, Option<StepEffectBinding>, bool)]) {
        for (_, usage, binding, memoized) in spent {
            if *memoized {
                continue;
            }
            if let Some(binding) = binding {
                if self.step_bindings.contains(binding) {
                    continue;
                }
                self.step_bindings.push(*binding);
            }
            self.units = self.units.saturating_add(units(usage));
        }
    }

    /// Hands this spend to the meter before an `Err`, so the driver charges
    /// what the shared pass line lent (FIX 11558).
    fn note_before_error(&self, ctx: &WakeAttemptContext<'_>) {
        ctx.note_spend_before_error(self.units, &self.step_bindings);
    }

    /// The attempt completed, this spend settled with its steps pinned as
    /// paid.
    fn completed(self) -> DreamerAttemptExecution {
        DreamerAttemptExecution::Completed {
            completed_units: self.units,
            step_bindings: self.step_bindings,
        }
    }

    /// The attempt parked for `reason`; a plain park while nothing was
    /// spent.
    fn park(self, reason: &str, cause: DreamerParkCause) -> DreamerAttemptExecution {
        if self.units == 0 && self.step_bindings.is_empty() {
            DreamerAttemptExecution::Park {
                reason: reason.to_owned(),
                cause,
            }
        } else {
            DreamerAttemptExecution::ParkWithSpend {
                reason: reason.to_owned(),
                cause,
                completed_units: self.units,
                step_bindings: self.step_bindings,
            }
        }
    }

    /// How the attempt waits after a durable step failed, this spend kept;
    /// an engine error stays one, this spend handed to the meter first.
    fn parked_on(
        mut self,
        error: DurableStepError,
        ctx: &WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        // A spend scope refused the step for good: the try ends Failed,
        // typed, this spend settled with its paid steps.
        if let Some(failed) = crate::dreamer_runner::dreamer_failed_on_refused_step(
            &error,
            self.units,
            &self.step_bindings,
        ) {
            return Ok(failed);
        }
        Ok(match error {
            DurableStepError::SpentFinalizeRefused { usage } => {
                self.units = self.units.saturating_add(units(&usage));
                self.park(DREAMER_HARD_CUT_PARK_REASON, DreamerParkCause::Checkpoint)
            }
            DurableStepError::DeadlineHardCut => {
                self.park(DREAMER_HARD_CUT_PARK_REASON, DreamerParkCause::Checkpoint)
            }
            DurableStepError::FinalizeRefused => {
                self.park("wake pass finalize window", DreamerParkCause::Checkpoint)
            }
            DurableStepError::Engine(error) => {
                self.note_before_error(ctx);
                return Err(error);
            }
            other => self.park(
                &other.to_string(),
                crate::dreamer_runner::dreamer_park_cause_of_step(&other),
            ),
        })
    }
}

/// The units one generation spent.
fn units(usage: &LlmUsage) -> u64 {
    usage.input.total.saturating_add(usage.output.total)
}
