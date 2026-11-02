//! The host's composition seam for [`Memory::chat`], and the two things chat
//! settles before it composes: the owner's chat budget the composition runs
//! on (FIX 9951) and the rendering budget its pack is cut to (FIX 9962).
//!
//! With the owner's budget set, the composer is handed that budget and
//! meters each model call it makes on it. With none set, the composer runs
//! exactly as before, on the caller's own lease if any.

use super::*;

use crate::llm::{BudgetGuard, BudgetLease};
use crate::retrieval_depth::RecallExecution;

/// What the host composer is handed: the question and the retrieved pack, and
/// nothing else. No vault handle crosses this seam.
pub struct ChatComposeRequest<'a> {
    /// The caller's prose question, exactly as asked.
    pub question: &'a str,
    /// The depth that priced this retrieval.
    pub depth: ChatDepth,
    /// The full pack the evidence pass produced, provenance included. This
    /// exact pack is what the answer's citations are checked against, so an
    /// id it does not carry is an id the answer may not stand on.
    pub pack: &'a MemoryPack,
}

/// What a composer returns: the answer text, the evidence it stands on, what
/// it could not cover, its own token accounting, and its right to refuse.
#[derive(Debug, Clone, PartialEq)]
pub struct ComposedChatAnswer {
    /// The composed answer text. Blank text is never answered.
    pub answer: String,
    /// The short ids the answer cites. The engine validates them against the
    /// pack it handed over; proposing is the composer's whole part in it.
    pub source_short_ids: Vec<String>,
    /// What the evidence could not cover, surfaced verbatim.
    pub gaps: Vec<String>,
    /// Tokens the composer spent. Surfaced verbatim; on the owner's budget,
    /// [`ChatComposer::compose_on_budget`]'s default charges them.
    pub tokens_used: u32,
    /// The composer's own refusal to answer, which is a typed abstention
    /// ([`ChatAbstentionReason::BackendDeclined`]) and never an error.
    pub declined: bool,
}

/// The host-injected, provider-neutral composition seam.
///
/// Implementations live above the engine (the `LlmBackend` precedent). The
/// lease arrives as the opaque admission token the caller already held; the
/// implementation must not settle or abort it either.
pub trait ChatComposer: Send + Sync {
    /// Turns one retrieved pack into one answer. Called at most once per
    /// [`Memory::chat`] call, and never at minimal depth.
    fn compose(
        &self,
        request: &ChatComposeRequest<'_>,
        lease: Option<&BudgetLease>,
    ) -> MemoryResult<ComposedChatAnswer>;

    /// [`Self::compose`] on the budget the owner set for chat (FIX 9951),
    /// called instead of it when one is set. A composer that calls a model
    /// meters each call on `budget` at its request-aware seam: it admits the
    /// call for its request, starts it with `begin_dispatch` before any byte
    /// leaves, and settles its usage, a started call that fails included, so
    /// each call is charged once. The default, for a composer that meters
    /// nothing itself, runs [`Self::compose`] on one lease admitted from
    /// `budget`, settled with the tokens the answer reports, or with the
    /// lease's reservation when composing fails.
    ///
    /// # Errors
    /// `BUDGET_SPENT` when `budget` cannot admit the composition; the
    /// composer's own error otherwise.
    fn compose_on_budget(
        &self,
        request: &ChatComposeRequest<'_>,
        budget: &BudgetGuard,
    ) -> MemoryResult<ComposedChatAnswer> {
        compose_on_one_lease(self, request, budget)
    }
}

/// [`ChatComposer::compose_on_budget`]'s default: one lease for the whole
/// composition, charged once.
fn compose_on_one_lease<C: ChatComposer + ?Sized>(
    composer: &C,
    request: &ChatComposeRequest<'_>,
    budget: &BudgetGuard,
) -> MemoryResult<ComposedChatAnswer> {
    let admitted = budget.admit().map_err(|denied| {
        MemoryError::new(
            MEMORY_CODE_BUDGET_SPENT,
            format!("the owner's chat budget refused the composition: {denied}"),
            &["Raise the chat budget, or ask at light depth for an extractive answer."],
        )
    })?;
    let composed = composer.compose(request, Some(&admitted.lease));
    // A failed composition may have spent upstream: it pays the
    // reservation, as a started call that ends with no usage does.
    let _ = match &composed {
        Ok(answer) => budget.settle_usage(&admitted.lease, u64::from(answer.tokens_used)),
        Err(_) => budget.settle_reserved(&admitted.lease),
    };
    composed
}

impl Memory<'_> {
    /// Runs `composer` once for `request`: on the owner's `budget` when one
    /// is set, else with the caller's `lease` as before. Light chat never
    /// reaches here, so it stays lease-free.
    pub(super) fn run_composer(
        &self,
        composer: &dyn ChatComposer,
        request: &ChatComposeRequest<'_>,
        lease: Option<&BudgetLease>,
        budget: Option<&BudgetGuard>,
    ) -> MemoryResult<ComposedChatAnswer> {
        match budget {
            Some(budget) => composer.compose_on_budget(request, budget),
            None => composer.compose(request, lease),
        }
    }

    /// The execution chat's evidence pass and document rendering run
    /// under: `execution`, its rendering budget resolved from the chat
    /// caller's own `token_budget` and `reader_agent_ref` by the one recall
    /// resolver (FIX 9962) when the caller names either, else the one
    /// `execution` carries.
    pub(super) fn chat_execution<'e>(
        &self,
        options: &ChatOptions<'_>,
        execution: &RecallExecution<'e>,
    ) -> RecallExecution<'e> {
        let render_budget = if options.token_budget.is_some() || options.reader_agent_ref.is_some()
        {
            Some(self.recall_render_budget(options.token_budget, options.reader_agent_ref))
        } else {
            execution.render_budget
        };
        RecallExecution {
            render_budget,
            ..*execution
        }
    }
}
