//! One follow-up draft: its call over every eligible source and, when that
//! fails, its rescue over the newest (FIX 7428). A failure is reported by the
//! stage it happened at. The request is read again after any failure, so a
//! source deleted since the page was read is never sent again: when a
//! source or scheduling failure finds the request changed, evidence alone
//! included, the current request is drafted whole at once, and the rescue
//! always drafts from the request as it reads now. A failure over inputs
//! that did not move leaves the reach-out pending for the next round.
use std::collections::BTreeMap;

use oneiron::dreamer_runner::maintenance::representation::PrematerializedDraft;
use oneiron::dreamer_runner::maintenance::stewardship::{
    StewardshipDraftOutcome, StewardshipDraftRequest,
};
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart, Error, LlmRequest,
    ModelTierRef, ResponseFormat, TierPrecedence, Vault,
};

use super::Drafter;
use super::sources::{DraftSources, draft_messages};
use crate::models::ModelRuntime;

/// The purpose a draft's call is metered and routed under.
const DRAFT_PURPOSE: &str = "stewardship_follow_up";
/// The newest sources a draft is written from again, once, after its call
/// over every eligible source failed: a model's window is its provider's
/// format bound. Used only after the full set failed; never a cap on a
/// first attempt.
const FALLBACK_DRAFT_EVIDENCE: usize = 8;

/// Where a draft failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DraftStage {
    /// Its sources did not read on this device.
    Sources,
    /// No seat, the role's admission, the budget or the model call.
    Call,
    /// The answer was not scheduled: no offer was sent anything, or the
    /// engine refused its plan.
    Schedule,
}

impl DraftStage {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Sources => "sources",
            Self::Call => "call",
            Self::Schedule => "schedule",
        }
    }

    /// Whether a failure here can come from the request moving under it: a
    /// source erased or rewritten since it was read.
    const fn inputs_may_move(self) -> bool {
        matches!(self, Self::Sources | Self::Schedule)
    }
}

/// One failed attempt at a draft: its stage and the engine's error.
pub(super) struct DraftFailure {
    pub(super) stage: DraftStage,
    pub(super) error: Error,
}

/// What drafting one request came to.
pub(super) enum DraftPass {
    /// The engine scheduled the draft, or found it stale.
    Done(StewardshipDraftOutcome),
    /// After a source or scheduling failure the request reads differently
    /// now: draft it whole, at once.
    Moved(StewardshipDraftRequest),
    /// The reach-out makes no draft request now.
    Gone,
    /// The draft failed over inputs that did not move, the last of them the
    /// request as it read after the failure.
    Failed(DraftFailure, StewardshipDraftRequest),
}

/// [`draft_one`] over every eligible source of `draft` and, when that fails
/// and the request as it reads now cites more than
/// [`FALLBACK_DRAFT_EVIDENCE`] sources, once more over the newest of them,
/// so a draft that was written before every source was fed is still
/// written.
///
/// # Errors
///
/// Reading the request again failed.
pub(super) async fn draft_pass(
    vault: &Vault,
    runtime: &ModelRuntime,
    drafter: Drafter,
    draft: &StewardshipDraftRequest,
) -> oneiron::Result<DraftPass> {
    let failure = match draft_one(vault, runtime, drafter, draft).await {
        Ok(outcome) => return Ok(DraftPass::Done(outcome)),
        Err(failure) => failure,
    };
    let Some(current) = vault.stewardship_draft_request(draft.proposal)? else {
        return Ok(DraftPass::Gone);
    };
    if failure.stage.inputs_may_move() && current != *draft {
        return Ok(DraftPass::Moved(current));
    }
    if current.request.evidence.len() <= FALLBACK_DRAFT_EVIDENCE {
        return Ok(DraftPass::Failed(failure, current));
    }
    // By kind only: an engine error can quote the vault.
    tracing::info!(
        proposal = %draft.proposal.to_hex(),
        stage = failure.stage.as_str(),
        kind = ?failure.error.kind(),
        sources = current.request.evidence.len(),
        "a stewardship draft over every source failed; drafting over the newest"
    );
    // The request's evidence is newest first.
    let mut newest = current.clone();
    newest.request.evidence.truncate(FALLBACK_DRAFT_EVIDENCE);
    let failure = match draft_one(vault, runtime, drafter, &newest).await {
        Ok(outcome) => return Ok(DraftPass::Done(outcome)),
        Err(failure) => failure,
    };
    if failure.stage.inputs_may_move() {
        let Some(again) = vault.stewardship_draft_request(draft.proposal)? else {
            return Ok(DraftPass::Gone);
        };
        if again != current {
            return Ok(DraftPass::Moved(again));
        }
    }
    Ok(DraftPass::Failed(failure, current))
}

/// The failure at `stage` of an engine error.
fn at(stage: DraftStage) -> impl Fn(Error) -> DraftFailure {
    move |error| DraftFailure { stage, error }
}

/// One model draft of `draft`, scheduled as the request the model that
/// answered read: `Stale` when the owner's rule or the reach-out moved
/// meanwhile.
async fn draft_one(
    vault: &Vault,
    runtime: &ModelRuntime,
    drafter: Drafter,
    draft: &StewardshipDraftRequest,
) -> Result<StewardshipDraftOutcome, DraftFailure> {
    use DraftStage::{Call, Schedule, Sources};
    // Read on this device, for the call's admission: no byte of it goes to
    // a model before its own destination's read (FIX 8714).
    let context = vault
        .representation_context(&draft.request)
        .map_err(at(Sources))?;
    let seat = runtime
        .seat(drafter.role)
        .ok_or_else(|| Error::InvalidConfig("no [models] rung drafts follow-ups".into()))
        .map_err(at(Call))?;
    let purpose = CallPurpose::Other {
        name: DRAFT_PURPOSE.to_owned(),
    };
    let request = LlmRequest {
        model: seat.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef(DRAFT_PURPOSE.to_owned())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: seat.locality,
            host_keyless: false,
        },
        messages: draft_messages(draft, &context),
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    };
    let call = runtime
        .admit_role(vault, drafter.role, request)
        .map_err(|refusal| Error::InvalidConfig(format!("stewardship draft refused: {refusal}")))
        .map_err(at(Call))?;
    // The Dreamer pays, on its own live budget policy rows, the drafting
    // budget for each draft (FIX 1002).
    let run_id = format!("stewardship-draft:{}", draft.proposal.to_hex());
    let authority = vault.dreamer_authority().map_err(at(Call))?;
    let guard = vault
        .policy_budget_guard(
            run_id.clone(),
            drafter.budget_units,
            oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS,
            BudgetExhaustionPolicy::Suspend,
            authority,
        )
        .map_err(at(Call))?;
    let run = runtime.undeclared_run(run_id, guard);
    // Each offer the call reaches, the first included, is sent only what its
    // own destination may receive, read and kept before the send.
    let sources = DraftSources::new(vault, draft);
    let response = call
        .ladder
        .generate_admitted(&run, call.request, None, &sources)
        .await
        .map_err(|error| Error::InvalidConfig(format!("stewardship draft call failed: {error}")))
        .map_err(at(Call))?;
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    // Scheduled with the evidence and voice the offer that answered was sent.
    let served = sources
        .served()
        .ok_or_else(|| Error::InvalidConfig("stewardship draft was sent no sources".into()))
        .map_err(at(Schedule))?;
    vault
        .schedule_stewardship_draft(&served, &mut PrematerializedDraft { text }, now)
        .map_err(at(Schedule))
}
