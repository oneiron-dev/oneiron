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
//! `supported`, `weakened` or `unsupported`. A claim not yet approved, or one
//! the Dreamer's read withholds, stays owed: the job waits and reads again.
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
use crate::llm::call_as_step;
use crate::model_binding::ModelRole;
use crate::model_step_context::{DurableStepContext, StepOutcome};
use crate::model_step_error::DurableStepError;
use crate::{EntityId, Error, Result, Vault};
use oneiron_model::llm::{
    BudgetGuard, BudgetLease, CallClass, CallEnvelope, CallPurpose, ContentPart, LlmBackend,
    LlmCapability, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse,
    LlmStreamResult, LlmUsage, ModelId, ModelLocality, ModelTierRef, ReplyAssertions,
    ResponseFormat, TierPrecedence,
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
/// meter, and the rubric it judges by.
pub struct ClaimSourceRecheckModel<'a> {
    pub backend: &'a dyn LlmBackend,
    pub guard: &'a BudgetGuard,
    pub model: ModelId,
    pub inference: HostInferenceContext<'a>,
    /// The vault role whose route the judge's call is admitted on.
    pub role: ModelRole,
    /// The host's rubric: prompt data, never engine prose.
    pub rubric: &'a str,
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
    // One scan finds the claims of every re-check owed, this one's too
    // (FIX 20502).
    read::discover_pending(ctx.vault)?;
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
    for ask in &read.asks {
        let request = noted(
            judge_request(&model, &ask.input, locality, keyless),
            &spend,
            ctx,
        )?;
        let judging = match noted(
            ask_judge(attempt, ctx, &model, request, ask.head).await,
            &spend,
            ctx,
        )? {
            Asked::Answered(judging) => judging,
            Asked::Trapped => return Ok(spend.park(TRAPPED_REASON, DreamerParkCause::Signal)),
            Asked::Failed(error) => return spend.parked_on(error, ctx),
        };
        spend.add(&judging);
        let judge = judging.judge(&model);
        let landed = noted(
            landing::land(
                ctx.vault,
                attempt_id,
                &declaration,
                ask,
                verdict_of(&judging.response),
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

/// The judge's reply shape: a verdict alone. The durable step keeps its
/// reply under the claim, not under the mail it read, so a reply with free
/// text could keep the kept mail's words past their erase (fix list row
/// 20501): the reply has no field for words.
fn reply_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["verdict"],
        "properties": {
            "verdict": {"type": "string", "enum": ["supported", "weakened", "unsupported"]}
        }
    })
}

/// The judge's call: the host's rubric, then the claim and its supports.
/// The message's retained words leave the vault as an extraction's do, so
/// they pass the same egress gate.
fn judge_request(
    model: &ClaimSourceRecheckModel<'_>,
    input: &serde_json::Value,
    locality: ModelLocality,
    keyless: bool,
) -> Result<LlmRequest> {
    let input = serde_json::to_string(input)
        .map_err(|_| Error::InvariantViolation("the re-check input did not encode"))?;
    Ok(LlmRequest {
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
                schema: reply_schema(),
            },
            locality,
            host_keyless: keyless,
        }
        .with_purpose_defaults(),
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: model.rubric.to_owned(),
                }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text { text: input }],
            },
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    })
}

/// One judge call's answer, as a durable step of its attempt.
struct Judging {
    response: LlmResponse,
    memoized: bool,
    step_hash: [u8; 32],
    /// What it spent: nothing when memoized, paid for by the pass that
    /// asked it.
    units: u64,
}

impl Judging {
    /// The judge's model, step and usage, as a finding records them.
    fn judge(&self, model: &ClaimSourceRecheckModel<'_>) -> serde_json::Value {
        serde_json::json!({
            "model": model.model.as_str(),
            "step_hash": bytes_to_hex_lower(&self.step_hash),
            "usage_in": self.response.usage.input.total,
            "usage_out": self.response.usage.output.total,
        })
    }
}

/// How one judge call ended.
enum Asked {
    Answered(Judging),
    /// The durable step suspended the attempt, to resume.
    Trapped,
    Failed(DurableStepError),
}

/// Asks the judge `request` about `subject`, as a durable step of
/// `attempt`, admitted on the host's role.
async fn ask_judge(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    model: &ClaimSourceRecheckModel<'_>,
    request: LlmRequest,
    subject: EntityId,
) -> Result<Asked> {
    let attempt_id = attempt.status.attempt.id;
    let request = ctx
        .vault
        .authorize_model_role(model.role, request, &model.inference)?
        .into_request();
    let step_hash = request
        .canonical_hash()
        .map_err(|_| Error::InvalidConfig("the re-check request did not hash".into()))?;
    let step_ctx = DurableStepContext {
        vault: ctx.vault,
        attempt_id,
        run_id: attempt.status.attempt.run_id.clone(),
        envelope_actor: ctx.vault.dreamer_actor_for_attempt(attempt_id)?,
        subject,
        deadline: Some(ctx.deadline),
        now_ms: ctx.now_ms,
    };
    // The judge request quotes the kept mail's words, which the replay
    // capture's owners would not retire when that mail is erased: this
    // attempt's steps keep no capture (fix list row 20501).
    let _uncaptured =
        crate::self_heal::blocked_reports::UncapturedSteps::hold(ctx.vault, attempt_id);
    // The step stores the reply the backend gives it, so the backend gives
    // it the verdict alone (fix list row 20501).
    let backend = VerdictOnly {
        backend: model.backend,
    };
    Ok(
        match call_as_step(&step_ctx, &backend, model.guard, request).await {
            Ok(StepOutcome::Finished {
                response, memoized, ..
            }) => {
                let units = if memoized { 0 } else { units(&response.usage) };
                Asked::Answered(Judging {
                    response,
                    memoized,
                    step_hash,
                    units,
                })
            }
            Ok(StepOutcome::Trapped { .. }) => Asked::Trapped,
            Err(error) => Asked::Failed(error),
        },
    )
}

/// The judge's backend as its durable step reads it (fix list row 20501):
/// each reply keeps its verdict alone, as one JSON text, and nothing else
/// the provider sent (reasoning, other parts, token scores, assertions), so
/// no word of the mail the request quoted outlives that mail's erase in the
/// stored reply. A reply with no verdict keeps an empty text, which the
/// reply schema refuses. The durable step only generates; a stream passes
/// as the backend gives it.
struct VerdictOnly<'a> {
    backend: &'a dyn LlmBackend,
}

impl VerdictOnly<'_> {
    fn kept(mut response: LlmResponse) -> LlmResponse {
        let text = verdict_of(&response).map_or_else(String::new, |verdict| {
            serde_json::json!({ "verdict": verdict.as_str() }).to_string()
        });
        // Built through the part's wire form, so it holds the text alone
        // whatever optional fields a text part carries; a part that does not
        // build leaves no content, which the reply schema refuses.
        response.message.content = serde_json::from_value::<ContentPart>(
            serde_json::json!({ "kind": "text", "text": text }),
        )
        .map_or_else(|_| Vec::new(), |part| vec![part]);
        response.token_scores = None;
        response.reply_assertions = ReplyAssertions::default();
        response
    }
}

impl LlmBackend for VerdictOnly<'_> {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.backend.supports(model, capability)
    }

    fn generate<'b>(
        &'b self,
        request: LlmRequest,
        lease: &'b BudgetLease,
    ) -> LlmGenerateFuture<'b> {
        Box::pin(async move { self.backend.generate(request, lease).await.map(Self::kept) })
    }

    fn generate_sourced<'b>(
        &'b self,
        request: LlmRequest,
        lease: &'b BudgetLease,
        sources: Option<Vec<EntityId>>,
    ) -> LlmGenerateFuture<'b> {
        Box::pin(async move {
            self.backend
                .generate_sourced(request, lease, sources)
                .await
                .map(Self::kept)
        })
    }

    fn stream<'b>(&'b self, request: LlmRequest, lease: &'b BudgetLease) -> LlmStreamResult<'b> {
        self.backend.stream(request, lease)
    }
}

/// The judge's verdict, or `None` for a reply that is not one.
fn verdict_of(response: &LlmResponse) -> Option<Verdict> {
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let reply: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    Verdict::parse(reply.get("verdict")?.as_str()?)
}

/// What a re-check's steps spent, each step that finished booked once.
#[derive(Default)]
struct Spend {
    units: u64,
    step_hashes: Vec<[u8; 32]>,
}

impl Spend {
    /// Books one judge call: nothing when memoized, which the pass that
    /// asked it paid for.
    fn add(&mut self, judging: &Judging) {
        if !judging.memoized {
            self.units = self.units.saturating_add(judging.units);
            self.step_hashes.push(judging.step_hash);
        }
    }

    /// Hands this spend to the meter before an `Err`, so the driver charges
    /// what the shared pass line lent (FIX 11558).
    fn note_before_error(&self, ctx: &WakeAttemptContext<'_>) {
        ctx.note_spend_before_error(self.units, &self.step_hashes);
    }

    /// The attempt completed, this spend settled with its steps pinned as
    /// paid.
    fn completed(self) -> DreamerAttemptExecution {
        DreamerAttemptExecution::Completed {
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
            DreamerAttemptExecution::ParkWithSpend {
                reason: reason.to_owned(),
                cause,
                completed_units: self.units,
                step_hashes: self.step_hashes,
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
            other => self.park(&other.to_string(), DreamerParkCause::of_step(&other)),
        })
    }
}

/// The units one generation spent.
fn units(usage: &LlmUsage) -> u64 {
    usage.input.total.saturating_add(usage.output.total)
}
