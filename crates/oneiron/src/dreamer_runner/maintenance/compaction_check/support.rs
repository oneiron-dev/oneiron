//! The support verdict of a compaction check (FIX 8713). With the host's
//! decisions lent, the shared decision ladder answers whether the retained
//! span supports the summary, its first read the host's judge as a durable
//! step of the check's own attempt, and only that typed answer is the
//! verdict. The diagnostic step before it keeps the conflicts and the reason
//! it cites as provenance, never as the verdict. An abstention, or an answer
//! off the contract, is no verdict: the check parks unjudged, never a
//! mismatch, and the landed summary stays as it is. Every generation that
//! finished is booked once, even when a later one traps. With no decisions
//! lent, the diagnostic's own verdict stands as before, recorded untyped.

use std::time::{Duration, Instant};

use super::{CompactionCheckModel, CompactionCheckVerdict, Judging, judge_shell};
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause, DreamerRunnerStore};
use crate::dreamer_wake::{
    DREAMER_HARD_CUT_PARK_REASON, DreamerAttemptExecution, WakeAttemptContext,
};
use crate::llm::decision::catalogue::COMPACTION_SUPPORT;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionLadder,
    GeneratedDecisions, GeneratedRung, GeneratedStep, ProviderPin, Reversibility,
};
use crate::llm::{DurableStepContext, DurableStepError, LlmRequest, LlmUsage, ModelLocality};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Error, Result, Vault};

/// The support question's choices, named as the finding names its verdicts.
const SUPPORTED: &str = "supported";
const MISMATCH: &str = "mismatch";
/// Why a check parks when no verdict came back.
const NO_VERDICT: &str = "the check judge wrote no verdict";
/// Why a check parks when its durable step suspended it.
const TRAPPED: &str = "durable step trapped for resume";

/// The host's decision path for a check's support verdict: its shared
/// ladder, the dial and bands it runs under, and its wording of the
/// question.
pub struct CompactionCheckDecisions<'a> {
    /// The host's shared decision ladder.
    pub ladder: DecisionLadder<'a>,
    /// The dial the question climbs; the judge's generated read is its
    /// first rung.
    pub dial: DecisionDial,
    /// The bands an answer is read under.
    pub bands: DecisionBandPolicy,
    /// The host's wording of the support question: prompt data, never
    /// engine prose.
    pub wording: String,
}

/// What a check's steps spent, each terminal step booked once.
#[derive(Default)]
pub(super) struct Spend {
    pub(super) units: u64,
    step_hashes: Vec<[u8; 32]>,
}

impl Spend {
    /// The diagnostic step's spend: nothing when memoized, which the pass
    /// that asked it paid for.
    pub(super) fn of(judging: &Judging) -> Self {
        Self {
            units: judging.units,
            step_hashes: if judging.memoized {
                Vec::new()
            } else {
                vec![judging.step_hash]
            },
        }
    }

    /// Hands this spend to the meter before an `Err`, so the driver
    /// charges what the shared pass line lent (FIX 11558).
    pub(super) fn note_before_error(&self, ctx: &WakeAttemptContext<'_>) {
        ctx.note_spend_before_error(self.units, &self.step_hashes);
    }

    /// Books each generation in `spent` that neither this spend nor an
    /// earlier checkpoint of `attempt` charged.
    fn book(
        &mut self,
        vault: &Vault,
        attempt: AttemptId,
        spent: &[([u8; 32], LlmUsage)],
    ) -> Result<()> {
        let store = DreamerRunnerStore::new(vault);
        for (hash, usage) in spent {
            if self.step_hashes.contains(hash) || store.checkpoint_step_charged(attempt, hash)? {
                continue;
            }
            self.step_hashes.push(*hash);
            self.units = self.units.saturating_add(units(usage));
        }
        Ok(())
    }

    /// The attempt completed, this spend settled with its terminal steps
    /// pinned as paid (FIX 11555).
    pub(super) fn completed(self) -> DreamerAttemptExecution {
        DreamerAttemptExecution::Completed {
            completed_units: self.units,
            step_hashes: self.step_hashes,
        }
    }

    /// The attempt parked for `reason`, this spend kept.
    pub(super) fn park_with_spend(
        self,
        reason: &str,
        cause: DreamerParkCause,
    ) -> DreamerAttemptExecution {
        DreamerAttemptExecution::ParkWithSpend {
            reason: reason.to_owned(),
            cause,
            completed_units: self.units,
            step_hashes: self.step_hashes,
        }
    }

    /// The attempt parked for `reason`; a plain park while nothing was
    /// spent.
    fn park(self, reason: &str, cause: DreamerParkCause) -> DreamerAttemptExecution {
        if self.units == 0 && self.step_hashes.is_empty() {
            DreamerAttemptExecution::Park {
                reason: reason.to_owned(),
                cause,
            }
        } else {
            self.park_with_spend(reason, cause)
        }
    }

    /// The attempt parked, this spend kept, when no verdict came back.
    pub(super) fn unjudged(self) -> DreamerAttemptExecution {
        self.park_with_spend(NO_VERDICT, DreamerParkCause::Other)
    }

    /// The attempt a durable step suspended, to resume.
    pub(super) fn trapped(self) -> DreamerAttemptExecution {
        self.park(TRAPPED, DreamerParkCause::Signal)
    }

    /// How the attempt waits after a durable step failed, this spend kept;
    /// an engine error stays one.
    pub(super) fn parked_on(mut self, error: DurableStepError) -> Result<DreamerAttemptExecution> {
        Ok(match error {
            DurableStepError::SpentFinalizeRefused { usage } => {
                self.units = self.units.saturating_add(units(&usage));
                self.park_with_spend(DREAMER_HARD_CUT_PARK_REASON, DreamerParkCause::Checkpoint)
            }
            DurableStepError::DeadlineHardCut => {
                self.park(DREAMER_HARD_CUT_PARK_REASON, DreamerParkCause::Checkpoint)
            }
            DurableStepError::FinalizeRefused => {
                self.park("wake pass finalize window", DreamerParkCause::Checkpoint)
            }
            DurableStepError::Engine(error) => return Err(error),
            other => self.park(&other.to_string(), DreamerParkCause::of_step(&other)),
        })
    }
}

/// The units one generation spent.
fn units(usage: &LlmUsage) -> u64 {
    usage.input.total.saturating_add(usage.output.total)
}

/// What the support question is asked about.
pub(super) struct Ask<'a> {
    /// The landing's kind: `epoch`, `fold` or `conversation`.
    pub(super) kind: &'a str,
    /// The agent the summary is written as.
    pub(super) subject: EntityId,
    /// The records the finding cites.
    pub(super) evidence: &'a [EntityId],
    /// The span and the summary, whole, as the judge reads them.
    pub(super) state: &'a serde_json::Value,
    /// Where the host's binding lets the judge's call be served.
    pub(super) locality: ModelLocality,
    /// Host-attested keyless bit, read beside the locality stamp (FIX 10592).
    pub(super) keyless: bool,
}

/// The verdict a check records, the typed decision behind it and what its
/// steps spent.
pub(super) struct Verdict {
    pub(super) verdict: CompactionCheckVerdict,
    /// The ladder's decision with its receipt; `None` when the diagnostic's
    /// own verdict stands, untyped.
    pub(super) decision: Option<serde_json::Value>,
    pub(super) spend: Spend,
}

/// The check's verdict once its diagnostic step answered (`diagnostic`, its
/// verdict when the reply read), or how the attempt waits for one. With the
/// host's decisions, the typed ladder's answer about `ask` alone; without
/// them, the diagnostic's verdict as before.
///
/// # Errors
///
/// The question's own errors, a storage error booking the spend, or an
/// engine error from the ladder's durable step.
pub(super) async fn verdict(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    model: &CompactionCheckModel<'_>,
    judging: &Judging,
    diagnostic: Option<CompactionCheckVerdict>,
    ask: &Ask<'_>,
) -> Result<std::result::Result<Verdict, DreamerAttemptExecution>> {
    let mut spend = Spend::of(judging);
    let Some(decisions) = &model.decisions else {
        return Ok(match diagnostic {
            Some(verdict) => Ok(Verdict {
                verdict,
                decision: None,
                spend,
            }),
            None => Err(spend.unjudged()),
        });
    };
    let attempt_id = attempt.status.attempt.id;
    let actor = ctx
        .vault
        .dreamer_actor_for_attempt(attempt_id)
        .map_err(|error| {
            spend.note_before_error(ctx);
            error
        })?;
    let step = DurableStepContext {
        vault: ctx.vault,
        attempt_id,
        run_id: attempt.status.attempt.run_id.clone(),
        envelope_actor: actor,
        subject: ask.subject,
        deadline: Some(ctx.deadline),
        now_ms: ctx.now_ms,
    };
    // Keyed by the landing's kind and the rubric the judge reads by: a new
    // rubric is a new question with its own bands.
    let rubric = blake3::hash(model.rubric.as_bytes());
    let question = COMPACTION_SUPPORT
        .question(
            &[ask.kind.as_bytes(), rubric.as_bytes().as_slice()],
            decisions.wording.clone(),
            AnswerContract::Choice {
                options: vec![SUPPORTED.to_owned(), MISMATCH.to_owned()],
            },
        )
        .map_err(|error| {
            spend.note_before_error(ctx);
            error
        })?;
    let (vault, role, inference) = (ctx.vault, model.role, &model.inference);
    let seal = move |request: LlmRequest| -> Result<LlmRequest> {
        Ok(vault
            .authorize_model_role(role, request, inference)?
            .into_request())
    };
    let rung = GeneratedRung {
        pin: ProviderPin {
            rung: decisions.dial.first,
            model: model.model.as_str().to_owned(),
            version: model.model.as_str().to_owned(),
        },
        backend: model.backend,
        step: GeneratedStep::Durable {
            step: &step,
            guard: model.guard,
        },
        request: judge_shell(model, serde_json::json!({}), ask.locality, ask.keyless),
        seal: &seal,
    };
    let deadline = RetrievalDeadline::hard(
        Instant::now(),
        Duration::from_millis(ctx.deadline.remaining_ms()),
    );
    let mut spent = Vec::new();
    let decided = decisions
        .ladder
        .run_pack_generated_spent(
            &rung,
            &[&question],
            actor.entity_ref(),
            ask.evidence,
            ask.state,
            decisions.dial,
            &decisions.bands,
            Reversibility::ReversibleRead,
            &deadline,
            &mut spent,
            None,
        )
        .await;
    // Every generation that finished is spent, whatever the pack's outcome.
    spend.book(ctx.vault, attempt_id, &spent).map_err(|error| {
        spend.note_before_error(ctx);
        error
    })?;
    let decision = match decided {
        Ok(GeneratedDecisions::Decided { decisions, .. }) => decisions.into_iter().next(),
        Ok(GeneratedDecisions::Trapped) => return Ok(Err(spend.trapped())),
        Ok(GeneratedDecisions::Unread(_)) => None,
        Err(DurableStepError::Engine(error)) => {
            spend.note_before_error(ctx);
            return Err(error);
        }
        Err(error) => return spend.parked_on(error).map(Err),
    };
    let verdict = decision
        .as_ref()
        .and_then(|decision| match &decision.answer {
            DecisionAnswer::Choice(choice) if choice == SUPPORTED => {
                Some(CompactionCheckVerdict::Supported)
            }
            DecisionAnswer::Choice(choice) if choice == MISMATCH => {
                Some(CompactionCheckVerdict::Mismatch)
            }
            _ => None,
        });
    let (Some(verdict), Some(decision)) = (verdict, decision) else {
        return Ok(Err(spend.unjudged()));
    };
    let decision = serde_json::to_value(&decision).map_err(|_| {
        spend.note_before_error(ctx);
        Error::InvariantViolation("a support decision did not encode")
    })?;
    Ok(Ok(Verdict {
        verdict,
        decision: Some(decision),
        spend,
    }))
}
