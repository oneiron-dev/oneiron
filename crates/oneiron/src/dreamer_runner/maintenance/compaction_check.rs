//! The Dreamer's check of a self-written compaction (FIX 4465 B; owner
//! 10-19: the Dreamer "checks the agent's summary against the retained
//! turns and never rewrites it"). Each admitted self-written landing, an
//! epoch or a fold, declares one check in its own landing write, keyed by the
//! landing, on the Dreamer's existing maintenance queue: no scheduler of its
//! own and no sweep of the vault. A pass admits it as it admits any
//! maintenance; its host lends the judging model and the rubric, which is
//! prompt data the host ships, never prose here.
//!
//! The check reads the landing's durable receipt and the run's retained
//! replay for exactly the sealed span, never a summary in its place and never
//! the home the call wore. The receipt, the artifact's hash and length, the
//! writer and the evidence revision must still be the declaration's, or the
//! check records `stale_evidence`; a receipt or replay it cannot read is
//! `unreadable_evidence`. The six deterministic gate checks already ran
//! before the summary landed. Only then does the judge read the summary
//! against the span and answer `supported` or `mismatch`. With the host's
//! decisions lent, that reply is a diagnostic kept for the conflicts and
//! reason it cites, and the shared decision ladder's typed answer alone is
//! the verdict ([`support`], FIX 8713); without them the judge's own verdict
//! stands, recorded as untyped.
//!
//! The verdict is a Dreamer finding about the agent, citing the agent, its
//! filed step and the summary, with the hashes, revisions, the steps each
//! conflict cites, the judge's model, step and usage, and its reason. A
//! mismatch also reaches the agent's own inbox. Nothing here writes
//! replacement text, changes a byline, regenerates the agent's words or
//! hands them to the curator's grading, which can retract what it grades.

use std::collections::BTreeMap;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::proposals;
use crate::attempt_queue::AttemptId;
use crate::code_run::ExecutorStorage;
use crate::compaction::{
    CompactionEvidence, CompactionExecution, CompactionLanding, CompactionStepRef,
};
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause, DreamerRunnerStore};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::entity_id::bytes_to_hex_lower;
use crate::inbox::{
    NOTIFICATION_PRODUCER_FINDING, NotificationEvent, NotificationKind, NotificationSource,
};
use crate::llm::manifest::ModelRole;
use crate::llm::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext,
    DurableStepResult, HostInferenceContext, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest,
    LlmResponse, ModelId, ModelTierRef, ResponseFormat, StepOutcome, TierPrecedence, call_as_step,
};
use crate::{EntityId, Error, Result, Vault};

mod conversation;
mod support;
pub(crate) use conversation::{ConversationCheckDeclaration, declare_conversation_check_in_txn};
pub use support::CompactionCheckDecisions;

/// The maintenance facet a self-written landing's check rides.
pub const COMPACTION_CHECK_FACET: &str = "dreamer.compaction_check";

/// The predicate of the Dreamer's finding a check records.
pub const COMPACTION_CHECK_PREDICATE: &str = "dreamer.compaction_check.verdict";

/// The payload key the declaration rides under.
const DECLARATION_KEY: &str = "declaration";

/// A finding's reason when the diagnostic step's reply did not read: the
/// typed verdict stands without its conflicts.
const NO_DIAGNOSTIC: &str = "diagnostic_unreadable";

/// What a check records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionCheckVerdict {
    /// The retained span supports what the summary says.
    Supported,
    /// The summary says what the span does not support or contradicts.
    Mismatch,
    /// The landing, its words or its evidence are no longer what the
    /// declaration names.
    StaleEvidence,
    /// The receipt or the retained span could not be read.
    UnreadableEvidence,
}

impl CompactionCheckVerdict {
    /// The stable name a finding carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Mismatch => "mismatch",
            Self::StaleEvidence => "stale_evidence",
            Self::UnreadableEvidence => "unreadable_evidence",
        }
    }
}

/// What one admitted self-written landing asks the Dreamer to check: refs,
/// hashes and revisions only, never the words of the summary, its span or
/// the home its call wore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionCheckDeclaration {
    /// The run whose window the summary compacted.
    pub run: EntityId,
    pub landing: CompactionLanding,
    /// The sealed span, its run's committed steps `first..=last`.
    pub first: u64,
    pub last: u64,
    /// The agent the summary is written as.
    pub writer: EntityId,
    /// The accepted summary's hex BLAKE3 and byte length.
    pub artifact_hash: String,
    pub artifact_len: u64,
    /// The span's evidence revision: its last checkpoint's state hash.
    pub evidence_revision: String,
    /// The answering call's filed step.
    #[serde(default)]
    pub step: Option<CompactionStepRef>,
    /// The landed receipt's digest, the one the summary's birth names.
    pub receipt_digest: String,
}

impl CompactionCheckDeclaration {
    fn of(landing: CompactionLanding, execution: &CompactionExecution) -> Result<Self> {
        let missing =
            || Error::InvariantViolation("a self-written landing carries no checkable receipt");
        let Some(CompactionEvidence::Executor {
            run,
            first,
            last,
            revision,
        }) = execution.evidence.as_ref()
        else {
            return Err(missing());
        };
        Ok(Self {
            run: *run,
            landing,
            first: *first,
            last: *last,
            writer: execution.writer,
            artifact_hash: execution.snapshot_hash.clone().ok_or_else(missing)?,
            artifact_len: execution.snapshot_len.ok_or_else(missing)?,
            evidence_revision: revision.clone(),
            step: execution.step.clone(),
            receipt_digest: execution.receipt_digest_hex()?,
        })
    }

    /// The queue key the landing fixes: one check per landing, however
    /// often its write replays.
    fn landing_key(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron:compaction-check:v1");
        hasher.update(self.run.as_bytes());
        match self.landing {
            CompactionLanding::Epoch { summary, .. } => {
                hasher.update(b"epoch");
                hasher.update(summary.as_bytes());
            }
            CompactionLanding::Fold { fold } => {
                hasher.update(b"fold");
                hasher.update(&fold.to_be_bytes());
            }
        }
        format!("{COMPACTION_CHECK_FACET}:{}", hasher.finalize().to_hex())
    }

    fn input(&self) -> Result<Value> {
        let json = serde_json::to_string(self)
            .map_err(|_| Error::InvariantViolation("a compaction check did not encode"))?;
        Ok(Value::Map(vec![(
            Value::from(DECLARATION_KEY),
            Value::from(json),
        )]))
    }

    /// The landing's kind, as the support question is keyed.
    const fn landing_kind(&self) -> &'static str {
        match self.landing {
            CompactionLanding::Epoch { .. } => "epoch",
            CompactionLanding::Fold { .. } => "fold",
        }
    }

    /// The records a finding cites: the writer, its filed step and, while
    /// `words_live`, an epoch's summary.
    pub(crate) fn cited(&self, words_live: bool) -> Vec<EntityId> {
        let mut evidence = vec![self.writer];
        if let Some(step) = &self.step {
            evidence.push(step.claim);
        }
        if let (CompactionLanding::Epoch { summary, .. }, true) = (self.landing, words_live) {
            evidence.push(summary);
        }
        evidence
    }

    pub(crate) fn from_input(input: &Value) -> Result<Self> {
        let invalid = || Error::InvalidConfig("invalid compaction check declaration".into());
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
}

/// Declares the check of one admitted self-written landing in the landing's
/// own write (FIX 4465 B): a rolled-back landing declares nothing, and a
/// replayed one finds the check it declared.
pub(crate) fn declare_compaction_check_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    landing: CompactionLanding,
    execution: &CompactionExecution,
) -> Result<()> {
    let declaration = CompactionCheckDeclaration::of(landing, execution)?;
    DreamerRunnerStore::new(vault).enqueue_compaction_check_in_txn(
        txn,
        declaration.input()?,
        declaration.landing_key(),
        unix_now(),
    )?;
    Ok(())
}

/// What the host lends one check: the judging model on its own route and
/// meter, and the rubric it judges by.
pub struct CompactionCheckModel<'a> {
    pub backend: &'a dyn LlmBackend,
    pub guard: &'a BudgetGuard,
    pub model: ModelId,
    pub inference: HostInferenceContext<'a>,
    /// The vault role whose route the judge's call is admitted on.
    pub role: ModelRole,
    /// The host's rubric: prompt data, never engine prose.
    pub rubric: &'a str,
    /// The host's decision path for the typed support verdict (FIX 8713);
    /// `None` before the host staffs one, when the judge's own verdict
    /// stands, recorded as untyped.
    pub decisions: Option<CompactionCheckDecisions<'a>>,
}

/// A check whose host lends no judge stays queued, never judged as passed.
#[must_use]
pub fn unlent() -> DreamerAttemptExecution {
    DreamerAttemptExecution::Park {
        reason: "no host lends this pass a compaction check".to_owned(),
        cause: DreamerParkCause::Other,
    }
}

/// Runs one admitted check.
///
/// # Errors
///
/// A declaration that does not decode, or a vault read or write that fails.
pub async fn run_compaction_check(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    model: CompactionCheckModel<'_>,
) -> Result<DreamerAttemptExecution> {
    if attempt.status.payload.attempt_type != COMPACTION_CHECK_FACET {
        return Err(Error::InvalidConfig(
            "not a compaction check attempt".into(),
        ));
    }
    // A conversation's landing (FIX 4465 D) declares its own source.
    if let Some(declaration) =
        conversation::ConversationCheckDeclaration::from_input(&attempt.status.payload.input)?
    {
        return conversation::run_conversation_check(attempt, ctx, model, declaration).await;
    }
    let declaration = CompactionCheckDeclaration::from_input(&attempt.status.payload.input)?;
    let attempt_id = attempt.status.attempt.id;
    let now = ctx.now_ms / 1_000;
    let read = match read_evidence(ctx.vault, &declaration)? {
        Read::Ready(read) => read,
        Read::Settled(settled) => {
            record(ctx.vault, attempt_id, &declaration, &settled, now)?;
            return Ok(DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_hashes: Vec::new(),
            });
        }
    };
    let locality = judge_locality(&model)?;
    let keyless = model.inference.selected_keyless();
    let request = judge_request(&model, &declaration, &read, locality, keyless)?;
    let judging = match ask_judge(attempt, ctx, &model, request, declaration.writer).await? {
        Ok(judging) => judging,
        Err(parked) => return Ok(parked),
    };
    let judged = judgment(&judging.response, &declaration);
    let diagnostic = judged.as_ref().map(|judged| judged.verdict);
    let (cited, state) = (declaration.cited(true), judge_input(&declaration, &read));
    let ask = support::Ask {
        kind: declaration.landing_kind(),
        subject: declaration.writer,
        evidence: &cited,
        state: &state,
        locality,
        keyless,
    };
    let verdict = match support::verdict(attempt, ctx, &model, &judging, diagnostic, &ask).await? {
        Ok(verdict) => verdict,
        Err(parked) => return Ok(parked),
    };
    let (reason, conflicts) = judged.map_or_else(
        || (NO_DIAGNOSTIC.to_owned(), Vec::new()),
        |judged| (judged.reason, judged.conflicts),
    );
    let settled = Settled {
        verdict: verdict.verdict,
        reason,
        conflicts,
        evidence_now: Some(declaration.evidence_revision.clone()),
        words_live: true,
        judge: Some(judging.judge(&model)),
        diagnostic,
        decision: verdict.decision,
    };
    if let Err(error) = record(ctx.vault, attempt_id, &declaration, &settled, now) {
        verdict.spend.note_before_error(ctx);
        return Err(error);
    }
    Ok(DreamerAttemptExecution::Completed {
        completed_units: verdict.spend.units,
        step_hashes: Vec::new(),
    })
}

/// Where the host's binding lets the judge's call be served.
fn judge_locality(model: &CompactionCheckModel<'_>) -> Result<crate::llm::ModelLocality> {
    model
        .inference
        .selected_locality()
        .ok_or_else(|| Error::InvalidConfig("the check's host binding names no locality".into()))
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
    fn judge(&self, model: &CompactionCheckModel<'_>) -> serde_json::Value {
        serde_json::json!({
            "model": model.model.as_str(),
            "step_hash": bytes_to_hex_lower(&self.step_hash),
            "usage_in": self.response.usage.input.total,
            "usage_out": self.response.usage.output.total,
        })
    }
}

/// Asks the judge `request` about `subject`, as a durable step of
/// `attempt`, admitted on the host's role: its answer, or how the attempt
/// waits for one.
async fn ask_judge(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    model: &CompactionCheckModel<'_>,
    request: LlmRequest,
    subject: EntityId,
) -> Result<std::result::Result<Judging, DreamerAttemptExecution>> {
    let attempt_id = attempt.status.attempt.id;
    let request = ctx
        .vault
        .authorize_model_role(model.role, request, &model.inference)?
        .into_request();
    let step_hash = request
        .canonical_hash()
        .map_err(|_| Error::InvalidConfig("the check request did not hash".into()))?;
    let step_ctx = DurableStepContext {
        vault: ctx.vault,
        attempt_id,
        run_id: attempt.status.attempt.run_id.clone(),
        envelope_actor: ctx.vault.dreamer_actor_for_attempt(attempt_id)?,
        subject,
        deadline: Some(ctx.deadline),
        now_ms: ctx.now_ms,
    };
    let outcome = call_as_step(&step_ctx, model.backend, model.guard, request).await;
    let (response, memoized) = match step_answer(outcome)? {
        Ok(answer) => answer,
        Err(parked) => return Ok(Err(parked)),
    };
    let units = if memoized {
        0
    } else {
        response
            .usage
            .input
            .total
            .saturating_add(response.usage.output.total)
    };
    Ok(Ok(Judging {
        response,
        memoized,
        step_hash,
        units,
    }))
}

/// The judge's answer and whether it was memoized, or how the attempt
/// waits for one.
type StepAnswer = std::result::Result<(LlmResponse, bool), DreamerAttemptExecution>;

/// [`StepAnswer`] from the durable step's outcome: nothing was spent before
/// it, so a step that did not finish parks with only its own spend.
fn step_answer(outcome: DurableStepResult<StepOutcome>) -> Result<StepAnswer> {
    match outcome {
        Ok(StepOutcome::Finished {
            response, memoized, ..
        }) => Ok(Ok((response, memoized))),
        Ok(StepOutcome::Trapped { .. }) => Ok(Err(support::Spend::default().trapped())),
        Err(error) => support::Spend::default().parked_on(error).map(Err),
    }
}

/// What the deterministic reads found.
enum Read {
    /// The summary's words and its span's retained text, both as declared.
    Ready(Ready),
    /// A verdict the reads settle without a judge.
    Settled(Settled),
}

struct Ready {
    summary: String,
    evidence: String,
}

/// One verdict as a finding records it.
struct Settled {
    verdict: CompactionCheckVerdict,
    reason: String,
    /// Each conflict: the summary's assertion number and the steps it cites.
    conflicts: Vec<serde_json::Value>,
    /// The span's evidence revision as the check read it, when it did.
    evidence_now: Option<String>,
    words_live: bool,
    judge: Option<serde_json::Value>,
    /// The diagnostic step's own verdict, when its reply read: provenance
    /// beside the verdict, which it may disagree with.
    diagnostic: Option<CompactionCheckVerdict>,
    /// The typed ladder's decision with its receipt; `None` for a verdict
    /// the reads settled, or the judge's own when no host decisions were
    /// lent (FIX 8713).
    decision: Option<serde_json::Value>,
}

impl Settled {
    fn new(verdict: CompactionCheckVerdict, reason: &str) -> Self {
        Self {
            verdict,
            reason: reason.to_owned(),
            conflicts: Vec::new(),
            evidence_now: None,
            words_live: false,
            judge: None,
            diagnostic: None,
            decision: None,
        }
    }

    fn of(verdict: CompactionCheckVerdict, reason: &str) -> Read {
        Read::Settled(Self::new(verdict, reason))
    }
}

/// Reads the landing's receipt and the run's retained span, and checks
/// them against the declaration.
fn read_evidence(vault: &Vault, declaration: &CompactionCheckDeclaration) -> Result<Read> {
    use CompactionCheckVerdict::{StaleEvidence, UnreadableEvidence};
    let storage = ExecutorStorage::Canonical(vault);
    let Ok(receipts) = storage.code_run_self_receipts(declaration.run) else {
        return Ok(Settled::of(UnreadableEvidence, "receipt_unreadable"));
    };
    let Some(receipt) = receipts
        .into_iter()
        .find(|receipt| receipt.landing == declaration.landing)
    else {
        return Ok(Settled::of(UnreadableEvidence, "landing_not_found"));
    };
    if receipt.execution.writer != declaration.writer
        || receipt.execution.receipt_digest_hex()? != declaration.receipt_digest
        || (receipt.first, receipt.last) != (declaration.first, declaration.last)
    {
        return Ok(Settled::of(StaleEvidence, "receipt_changed"));
    }
    let Some(summary) = receipt.summary else {
        return Ok(Settled::of(StaleEvidence, "summary_withdrawn"));
    };
    if summary.len() as u64 != declaration.artifact_len
        || bytes_to_hex_lower(blake3::hash(summary.as_bytes()).as_bytes())
            != declaration.artifact_hash
    {
        return Ok(Settled::of(StaleEvidence, "artifact_changed"));
    }
    let Some(record) = vault.get_code_run_replay_record(&declaration.run)? else {
        return Ok(Settled::of(UnreadableEvidence, "replay_not_found"));
    };
    let revision = record
        .step_checkpoints
        .iter()
        .find(|checkpoint| checkpoint.seq == declaration.last)
        .map(|checkpoint| bytes_to_hex_lower(&checkpoint.state_hash));
    if revision.as_deref() != Some(declaration.evidence_revision.as_str()) {
        let mut settled = Settled::new(StaleEvidence, "evidence_revision_moved");
        settled.evidence_now = revision;
        settled.words_live = true;
        return Ok(Read::Settled(settled));
    }
    let Ok(evidence) = storage.compaction_span_text(&record, declaration.first, declaration.last)
    else {
        return Ok(Settled::of(UnreadableEvidence, "span_unreadable"));
    };
    Ok(Read::Ready(Ready { summary, evidence }))
}

/// The judge's call: the host's rubric, then the summary and the span it
/// was cut from. The reply is a verdict, the conflicts by ref and a reason;
/// nothing it answers becomes text anyone's summary carries.
fn judge_request(
    model: &CompactionCheckModel<'_>,
    declaration: &CompactionCheckDeclaration,
    read: &Ready,
    locality: crate::llm::ModelLocality,
    keyless: bool,
) -> Result<LlmRequest> {
    let input = judge_input(declaration, read);
    judge_call(model, diagnostic_schema(), &input, locality, keyless)
}

/// What the judge reads: the span, the summary and the span's retained
/// words, whole.
fn judge_input(declaration: &CompactionCheckDeclaration, read: &Ready) -> serde_json::Value {
    serde_json::json!({
        "span": {"first": declaration.first, "last": declaration.last},
        "summary": read.summary,
        "evidence": read.evidence,
    })
}

/// The diagnostic reply's shape: a verdict, the conflicts by step and a
/// reason.
fn diagnostic_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["verdict", "conflicts", "reason"],
        "properties": {
            "verdict": {"type": "string"},
            "conflicts": {"type": "array", "items": {
                "type": "object", "additionalProperties": false,
                "required": ["assertion", "steps"],
                "properties": {
                    "assertion": {"type": "integer"},
                    "steps": {"type": "array", "items": {"type": "integer"}}
                }
            }},
            "reason": {"type": "string"}
        }
    })
}

/// The judge's call for `input` under `schema`: the host's rubric first,
/// then the input. The span's retained words leave the vault as an
/// extraction's do.
fn judge_call(
    model: &CompactionCheckModel<'_>,
    schema: serde_json::Value,
    input: &serde_json::Value,
    locality: crate::llm::ModelLocality,
    keyless: bool,
) -> Result<LlmRequest> {
    let input = serde_json::to_string(input)
        .map_err(|_| Error::InvariantViolation("the check input did not encode"))?;
    let mut request = judge_shell(model, schema, locality, keyless);
    request.messages.push(LlmMessage {
        role: LlmMessageRole::User,
        content: vec![ContentPart::Text { text: input }],
    });
    Ok(request)
}

/// The judge's request with the host's rubric and no input yet, its reply
/// shaped by `schema`; the typed read adds its own turn and shape.
fn judge_shell(
    model: &CompactionCheckModel<'_>,
    schema: serde_json::Value,
    locality: crate::llm::ModelLocality,
    keyless: bool,
) -> LlmRequest {
    LlmRequest {
        model: model.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: crate::llm::Scope::default(),
            // The run's retained words leave the vault as an extraction's
            // do, so they pass the same egress gate.
            purpose: CallPurpose::Extraction,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("consolidation".into()),
            ),
            response_format: ResponseFormat::Json { schema },
            locality,
            host_keyless: keyless,
        }
        .with_purpose_defaults(),
        messages: vec![LlmMessage {
            role: LlmMessageRole::System,
            content: vec![ContentPart::Text {
                text: model.rubric.to_owned(),
            }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    }
}

/// The judge's verdict, or `None` for a reply that is not one. A conflict
/// keeps only the steps of the checked span: the judge read no other.
struct Judged {
    verdict: CompactionCheckVerdict,
    conflicts: Vec<serde_json::Value>,
    reason: String,
}

fn judgment(response: &LlmResponse, declaration: &CompactionCheckDeclaration) -> Option<Judged> {
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
    let verdict = match reply.get("verdict")?.as_str()? {
        "supported" => CompactionCheckVerdict::Supported,
        "mismatch" => CompactionCheckVerdict::Mismatch,
        _ => return None,
    };
    let span = declaration.first..=declaration.last;
    let mut conflicts = Vec::new();
    for conflict in reply.get("conflicts")?.as_array()? {
        let assertion = conflict.get("assertion")?.as_u64()?;
        let steps: Vec<u64> = conflict
            .get("steps")?
            .as_array()?
            .iter()
            .filter_map(serde_json::Value::as_u64)
            .filter(|step| span.contains(step))
            .collect();
        conflicts.push(serde_json::json!({"assertion": assertion, "steps": steps}));
    }
    Some(Judged {
        verdict,
        conflicts,
        reason: reply.get("reason")?.as_str()?.to_owned(),
    })
}

/// Records one verdict as the Dreamer's finding about the writer, citing
/// the writer, its filed step and, while its words stand, the summary. A
/// mismatch also reaches the writer's own inbox. Recording twice finds the
/// finding already landed.
fn record(
    vault: &Vault,
    attempt: AttemptId,
    declaration: &CompactionCheckDeclaration,
    settled: &Settled,
    now: u64,
) -> Result<EntityId> {
    let value = serde_json::json!({
        "verdict": settled.verdict.as_str(),
        "run": declaration.run.to_hex(),
        "landing": declaration.landing,
        "first": declaration.first,
        "last": declaration.last,
        "writer": declaration.writer.to_hex(),
        "artifact": {"hash": declaration.artifact_hash, "len": declaration.artifact_len},
        "evidence": {
            "declared": declaration.evidence_revision,
            "read": settled.evidence_now,
        },
        "step": declaration.step,
        "receipt_digest": declaration.receipt_digest,
        "conflicts": settled.conflicts,
        "judge": settled.judge,
        "reason": settled.reason,
        "diagnostic_verdict": settled.diagnostic.map(CompactionCheckVerdict::as_str),
        "decision": settled.decision,
    });
    emit_finding(
        vault,
        attempt,
        declaration.writer,
        &value,
        &declaration.cited(settled.words_live),
        settled.verdict,
        now,
    )
}

/// The Dreamer's finding about `writer`, `value` citing `evidence`; a
/// mismatch also reaches the writer's own inbox. Recording twice finds the
/// finding already landed.
fn emit_finding(
    vault: &Vault,
    attempt: AttemptId,
    writer: EntityId,
    value: &serde_json::Value,
    evidence: &[EntityId],
    verdict: CompactionCheckVerdict,
    now: u64,
) -> Result<EntityId> {
    let envelope = proposals::run_tray_envelope(vault, COMPACTION_CHECK_FACET, attempt)?;
    vault.with_write_txn_grouped(|txn| {
        let finding = proposals::emit_in_txn(
            vault,
            txn,
            writer,
            COMPACTION_CHECK_PREDICATE,
            value,
            evidence,
            &envelope,
            now,
        )?;
        if verdict == CompactionCheckVerdict::Mismatch {
            vault.record_notification_in_txn(
                txn,
                &NotificationEvent {
                    kind: NotificationKind::Finding,
                    source: NotificationSource {
                        producer: NOTIFICATION_PRODUCER_FINDING.to_owned(),
                        event: format!("{}:{}", finding.to_hex(), writer.to_hex()),
                        ..NotificationSource::default()
                    },
                    subject_refs: vec![finding, writer],
                    recipient: Some(writer),
                    created_at: now,
                    origin_conversation: None,
                },
            )?;
        }
        Ok(finding)
    })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
