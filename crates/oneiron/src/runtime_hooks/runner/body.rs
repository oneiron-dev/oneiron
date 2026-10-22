//! A fact-hook run's body call and what comes of it (ARCH-0080 §4, §6): its
//! `ai.verdict` asks and their pins, how its end is judged against its
//! binding, and the memo row and Hook receipt the run commits.

use std::collections::BTreeMap;
use std::time::Instant;

use crate::receipt::{ReceiptKind, ReceiptRecord, hex_lower};
use crate::runtime_hooks::body::{HookBodyRun, HookBodyUsage, HookBudgetOverrun, HookVerdict};
use crate::runtime_hooks::filter;
use crate::runtime_hooks::grant::HookGrant;
use crate::runtime_hooks::lineage::HookCheckReason;
use crate::runtime_hooks::outcome::{HookOutcome, kind_token};
use crate::runtime_hooks::store::{self, HookReadPin, HookRunRecord, HookRunState, HookVerdictPin};
use crate::skill_hub::pack_catalog::{HookPhase, HookRenderClass, PackHookBinding};
use crate::{EntityId, Result};

use super::{MAX_OUTCOME_BYTES, MAX_PINNED_INPUT, Run, bounded};

/// The most bytes of `ai.verdict` requests and replies one memo row pins.
const MAX_PINNED_VERDICT_BYTES: usize = 256 * 1024;

/// One `ai.verdict` of a fact hook, answered as the live runner answers it:
/// only a generative hook asks, of `host`, for its grant's reader, the
/// identity whose reach the hook reads with. Beside it, the rows its
/// evidence resolved to ([`HookVerdict::verdict`]); a refusal here reads none.
pub(in crate::runtime_hooks) fn ask_verdict(
    binding: &PackHookBinding,
    grant: &HookGrant,
    host: Option<&dyn HookVerdict>,
    request: &str,
    deadline: Instant,
) -> (std::result::Result<String, String>, Option<Vec<EntityId>>) {
    let refused = match (binding.selector.render_class, host) {
        (HookRenderClass::Generative, Some(host)) => {
            let class = filter::edge_class(grant.reader_class);
            return host.verdict(grant.reader, class, request, deadline);
        }
        (HookRenderClass::Generative, None) => "no verdict host serves this run",
        (HookRenderClass::DeterministicEager, _) => {
            "a deterministic hook calls no model: declare render_class: generative"
        }
    };
    (Err(refused.to_owned()), Some(Vec::new()))
}

/// The verdicts one run heard, pinned in order while their requests and
/// replies fit [`MAX_PINNED_VERDICT_BYTES`]; the first that does not ends
/// the pins.
pub(super) struct VerdictPins {
    pins: Vec<HookVerdictPin>,
    bytes: usize,
    complete: bool,
}

impl VerdictPins {
    pub(super) const fn new() -> Self {
        Self {
            pins: Vec::new(),
            bytes: 0,
            complete: true,
        }
    }

    pub(super) fn push(
        &mut self,
        request: &str,
        reply: &std::result::Result<String, String>,
        evidence: Option<Vec<EntityId>>,
    ) {
        let (Ok(text) | Err(text)) = reply;
        // Each evidence row pins as its 32-hex id.
        let rows = evidence.as_ref().map_or(0, Vec::len).saturating_mul(32);
        let bytes = self
            .bytes
            .saturating_add(request.len())
            .saturating_add(text.len())
            .saturating_add(rows);
        if !self.complete || bytes > MAX_PINNED_VERDICT_BYTES {
            self.complete = false;
            return;
        }
        self.bytes = bytes;
        self.pins.push(HookVerdictPin {
            request_json: request.to_owned(),
            reply: reply.clone(),
            evidence,
        });
    }
}

/// How a body run ended, judged against its binding.
pub(in crate::runtime_hooks) struct Verdict {
    pub(in crate::runtime_hooks) state: HookRunState,
    pub(in crate::runtime_hooks) outcome: Option<HookOutcome>,
    pub(in crate::runtime_hooks) outcome_json: Option<String>,
    /// The outcome kind, or `refused` / `failed`.
    pub(in crate::runtime_hooks) token: String,
    pub(in crate::runtime_hooks) reason: Option<String>,
    /// What the body used: a failed run's as its runtime measured it, or
    /// unavailable, never a zero standing in (FIX 9332).
    pub(in crate::runtime_hooks) usage: HookBodyUsage,
    /// The run ended past its `budget_ms`: a measured fact beside the
    /// outcome, never part of the judgement (FIX 8842).
    pub(in crate::runtime_hooks) budget_overrun: Option<HookBudgetOverrun>,
}

/// A body that failed or trapped is `failed`, with what it used as its run's
/// context holds it (`usage`, FIX 9332). An outcome that does not parse, is
/// not a kind of the binding's phase, is not one the binding allows, or has
/// the wrong shape is `refused`. Time is not judged: a run past its budget
/// keeps whichever of these it is, with `overrun` beside it.
pub(in crate::runtime_hooks) fn judge(
    binding: &PackHookBinding,
    result: Result<HookBodyRun>,
    overrun: Option<HookBudgetOverrun>,
    usage: HookBodyUsage,
) -> Verdict {
    let run = match result {
        Ok(run) => run,
        Err(error) => {
            return Verdict {
                state: HookRunState::Failed,
                outcome: None,
                outcome_json: None,
                token: "failed".to_owned(),
                reason: Some(bounded(&error.to_string())),
                usage,
                budget_overrun: overrun,
            };
        }
    };
    let usage = HookBodyUsage {
        fuel_used: Some(run.fuel_used),
        host_calls: Some(run.host_calls),
    };
    match accept(binding, &run.outcome_json) {
        Ok(outcome) => Verdict {
            state: HookRunState::Completed,
            token: kind_token(outcome.kind()).to_owned(),
            outcome: Some(outcome),
            outcome_json: Some(run.outcome_json),
            reason: None,
            usage,
            budget_overrun: overrun,
        },
        Err(reason) => Verdict {
            state: HookRunState::Refused,
            token: "refused".to_owned(),
            outcome: None,
            outcome_json: (run.outcome_json.len() <= MAX_OUTCOME_BYTES).then_some(run.outcome_json),
            reason: Some(reason),
            usage,
            budget_overrun: overrun,
        },
    }
}

fn accept(binding: &PackHookBinding, json: &str) -> std::result::Result<HookOutcome, String> {
    if json.len() > MAX_OUTCOME_BYTES {
        return Err("the outcome is too large".to_owned());
    }
    let outcome: HookOutcome =
        serde_json::from_str(json).map_err(|_| "the outcome does not parse".to_owned())?;
    let kind = outcome.kind();
    let phase = binding.selector.phase;
    if !kind.applies_in(phase) {
        return Err(format!(
            "{} is not a {} outcome",
            kind_token(kind),
            match phase {
                HookPhase::Pre => "pre-hook",
                HookPhase::Post => "post-hook",
                HookPhase::Fact => "fact-hook",
            }
        ));
    }
    if !binding.selector.outcomes.contains(&kind) {
        return Err(format!("the binding does not allow {}", kind_token(kind)));
    }
    outcome.validate()?;
    Ok(outcome)
}

/// The run's memo row; the commit stamps its write time.
pub(super) fn record(
    run: &Run<'_>,
    input: &str,
    reads: Vec<HookReadPin>,
    verdicts: VerdictPins,
    verdict: &Verdict,
    duration_ms: u64,
    now: u64,
) -> HookRunRecord {
    HookRunRecord {
        binding: run.binding_id,
        code: run.binding.code,
        body_hash: run.binding.body_hash.clone(),
        source: run.entry.position.source(),
        position: run.entry.position.hex(),
        fact: run.entry.kind,
        entity: run.entry.entity,
        input_json: (input.len() <= MAX_PINNED_INPUT).then(|| input.to_owned()),
        input_hash: blake3::hash(input.as_bytes()).to_hex().to_string(),
        reads,
        verdicts: verdicts.pins,
        verdicts_complete: verdicts.complete,
        outcome_json: verdict.outcome_json.clone(),
        outcome: verdict.token.clone(),
        reason: verdict.reason.clone(),
        state: verdict.state,
        receipt_id: store::receipt_id(&run.key),
        duration_ms,
        budget_overrun: verdict.budget_overrun,
        now,
        committed_at: 0,
    }
}

/// The run's Hook receipt: the hook, its CODE id and body hash, the duration,
/// the outcome, `now`, the rows read and the run key, and the overrun of a
/// run past its budget.
pub(super) fn receipt(
    run: &Run<'_>,
    verdict: &Verdict,
    check: Option<HookCheckReason>,
    rows_read: usize,
    duration_ms: u64,
    now: u64,
) -> ReceiptRecord {
    let binding = run.binding;
    let mut fields: BTreeMap<String, String> = [
        ("binding", run.binding_id.to_hex()),
        ("code", binding.code.to_hex()),
        ("body_hash", binding.body_hash.clone()),
        ("hook", format!("{}/{}", binding.pack, binding.hook)),
        ("hook_version", binding.hook_version.clone()),
        ("fact", run.entry.kind.as_str().to_owned()),
        ("source", run.entry.position.source().as_str().to_owned()),
        ("position", run.entry.position.hex()),
        ("duration_ms", duration_ms.to_string()),
        ("now", now.to_string()),
        ("rows_read", rows_read.to_string()),
        ("run_key", hex_lower(&run.key)),
    ]
    .into_iter()
    .chain(verdict.usage.receipt_fields())
    .map(|(name, value)| (name.to_owned(), value))
    .collect();
    if let Some(check) = check {
        fields.insert("check".to_owned(), check.as_str().to_owned());
    }
    if let Some(reason) = &verdict.reason {
        fields.insert("reason".to_owned(), bounded(reason));
    }
    if let Some(overrun) = &verdict.budget_overrun {
        for (name, value) in overrun.receipt_fields() {
            fields.insert(name.to_owned(), value);
        }
    }
    ReceiptRecord {
        receipt_id: store::receipt_id(&run.key),
        receipt_kind: ReceiptKind::Hook,
        occurred_at: now / 1_000,
        actor: Some(binding.author_id().to_hex()),
        on_behalf_of: None,
        outcome: verdict.token.clone(),
        job_ref: None,
        trigger_ref: Some(run.entry.entity.to_hex()),
        policy_trace: Vec::new(),
        fields,
    }
}
