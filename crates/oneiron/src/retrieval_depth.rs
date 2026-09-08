//! ONE-207: the retrieval half of the effort dial.
//!
//! One wire value — [`Effort`], the SAME enum `memory::recall` and `.chat`
//! already price retrieval with — decides how much work a raw search does.
//! There is deliberately no second depth type here: a `SearchDepth` alias with
//! `low | med | high` values would be a fourth vocabulary for a dial that
//! already has one, and callers would have to learn which of them a given
//! endpoint speaks.
//!
//! The three tiers are cost classes, not quality hints, and each is defined by
//! what it is NOT allowed to do:
//!
//! - [`Effort::Minimal`] — ONE direct top-k channel. No graph expansion, no
//!   subqueries, no reranker, no backend, no lease. This is the omission
//!   default on raw search, so an existing caller that never sends `depth`
//!   keeps paying exactly what it paid before.
//! - [`Effort::Standard`] — deterministic and still model-free: one-hop PPR
//!   over the direct hits plus up to [`STANDARD_SUBQUERY_LIMIT`] lexical
//!   subqueries derived from the query by [`deterministic_subqueries`]. The
//!   same query yields the same subqueries on every call and every process.
//! - [`Effort::Deep`] — lease-gated AND host-injected. The engine still owns
//!   retrieval and the caps; a [`DeepSearchBackend`] supplied by the host owns
//!   decomposition and cross-encoder scoring. Without both a [`BudgetLease`]
//!   and a backend this tier refuses rather than silently degrading.
//!
//! The caps on the deep tier are enforced HERE, on the backend's output, not
//! documented at the backend. An over-eager host that returns nine subqueries
//! for a round gets four of them run; one that repeats a query it already
//! asked for gets it dropped. A cap the engine only asks for is not a cap.
//!
//! Nothing in this module knows a provider, a model id, a prompt, or a
//! persona: the backend trait is the whole seam, exactly as
//! [`crate::rerank::Reranker`] and `LlmBackend` are.
//!
//! Effort-dialed, actor-scoped retrieval with execution quality diagnostics.
//! Quality is metadata; channel scores, admission, and backend caps are unchanged.

use crate::claim::{ScopedRead, decode_claim_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::BudgetLease;
use crate::memory::{Effort, MEMORY_CODE_LEASE_REQUIRED};
use crate::pipeline::ScoredEntity;
use crate::ppr::{SeedWeighting, ppr_query_scoped_in_txn_with_diagnostics};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::rerank::RerankCandidate;
use crate::retrieval_quality::{
    RetrievalDiagnostics, RetrievalQualityReport, classify_retrieval_quality,
};
use crate::store::RetrievalSignal;
use crate::vault::Vault;

mod accumulation;
mod session_scope;
mod spend;
use accumulation::DepthAccumulator;
pub use session_scope::{SessionScope, narrow_to_session_scope};
pub use spend::{RetrievalError, RetrievalResult};

/// Deterministic subqueries a [`Effort::Standard`] text pass may run,
/// INCLUDING the caller's own query. Four is the whole fan-out: the tier's
/// promise is that it costs a bounded, predictable multiple of a minimal read.
pub const STANDARD_SUBQUERY_LIMIT: usize = 4;

/// Recursive decomposition rounds a [`Effort::Deep`] pass may run.
pub const DEEP_MAX_ROUNDS: usize = 2;

/// Queries the engine will run per deep round, whatever the backend returns.
pub const DEEP_QUERIES_PER_ROUND: usize = 4;

/// One-hop graph expansion: the standard tier expands neighbors, not the
/// whole reachable graph.
const STANDARD_PPR_DEPTH: u32 = 1;

/// Restart probability for the standard expansion, matching the landed
/// scoped-walk entries (`code_memory`'s L2 pull uses the same value).
const STANDARD_PPR_ALPHA: f32 = 0.15;

/// Direct hits promoted to PPR seeds. Mirrors `recall`'s own seed cap so the
/// two expansions cost the same order of work.
const STANDARD_PPR_SEED_LIMIT: usize = 8;

/// Stable `signals_used` tokens. Free-form strings would drift between the
/// engine that emits them and the surface that shows them.
const SIGNAL_TEXT: &str = "text";
const SIGNAL_VECTOR: &str = "vector";
const SIGNAL_PPR: &str = "ppr";
const SIGNAL_SUBQUERIES: &str = "subqueries";
const SIGNAL_BACKEND_DECOMPOSE: &str = "backend_decompose";
const SIGNAL_BACKEND_RERANK: &str = "backend_rerank";

/// Lexical stop list for [`deterministic_subqueries`].
///
/// A fixed, engine-pinned word list — NOT a prompt and not a language model.
/// It exists so the derived subqueries drop the words a BM25 index scores
/// near-zero anyway, and it is `const` precisely so the derivation is
/// reproducible across processes and releases.
const SUBQUERY_STOPWORDS: &[&str] = &[
    "a", "about", "an", "and", "any", "are", "as", "at", "be", "been", "but", "by", "can", "did",
    "do", "does", "for", "from", "had", "has", "have", "how", "i", "if", "in", "into", "is", "it",
    "its", "me", "my", "of", "on", "or", "our", "so", "that", "the", "their", "then", "there",
    "these", "they", "this", "to", "was", "we", "were", "what", "when", "where", "which", "who",
    "why", "will", "with", "would", "you", "your",
];

/// The retrieval probe a depth request ranks from.
///
/// A probe is the QUERY, not the tier: the same probe is legal at every
/// effort, and the effort decides what else runs around it.
#[derive(Debug, Clone, PartialEq)]
pub enum SearchProbe {
    /// Lexical probe over the BM25 index.
    Text {
        /// The caller's query text.
        query: String,
    },
    /// Dense probe over a caller-supplied embedding.
    Vector {
        /// Query embedding, in the vault's configured dimensionality.
        embedding: Vec<f32>,
        /// The text the embedding was produced from.
        ///
        /// Optional at minimal and standard effort, where nothing ever reads
        /// it, and REQUIRED at [`Effort::Deep`]: deep decomposition and
        /// cross-encoder scoring are operations on language, and an engine
        /// that invented query text from a float vector would be inventing
        /// the question it then answers.
        query_text: Option<String>,
    },
}

impl SearchProbe {
    /// The probe's natural-language form, when it has one.
    #[must_use]
    pub fn query_text(&self) -> Option<&str> {
        match self {
            Self::Text { query } => Some(query.as_str()),
            Self::Vector { query_text, .. } => query_text.as_deref(),
        }
    }
}

/// One effort-dialed read.
///
/// `lease` and `backend` are both `None` for the two model-free tiers and both
/// REQUIRED for [`Effort::Deep`]; see [`ScopedRead::search_with_effort`].
pub struct DepthSearchRequest<'a> {
    /// What to rank from.
    pub probe: SearchProbe,
    /// How much work the caller is paying for.
    pub effort: Effort,
    /// Maximum hits returned. Must be at least 1.
    pub limit: usize,
    /// Optional narrowing, applied before each channel's top-k and backend calls.
    pub session_scope: Option<&'a SessionScope>,
    /// Budget lease minted by [`crate::llm::BudgetGuard`]. Deep only.
    pub lease: Option<&'a BudgetLease>,
    /// Host-injected deep executor. Deep only.
    pub backend: Option<&'a dyn DeepSearchBackend>,
    /// Total token cap for all deep calls in this search. `None` adds no cap
    /// beyond the host's lease policy. Ignored by the model-free tiers.
    pub token_budget: Option<u64>,
}

/// The result of one effort-dialed read, plus what it cost to produce.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DepthSearchResult {
    /// Admitted hits, best first, at most `limit` of them.
    pub hits: Vec<ScoredEntity>,
    /// The text queries this read actually executed, in order.
    ///
    /// A dense probe contributes none — a float vector is not a query string —
    /// and shows up in `signals_used` instead. Carrying the queries themselves
    /// rather than a count is what makes the deep caps auditable from the
    /// outside: an over-eager backend's discarded proposals are the entries
    /// that are NOT here.
    pub queries_run: Vec<String>,
    /// Stable signal tokens, in the order the signals ran.
    pub signals_used: Vec<String>,
    /// Candidates considered before dedupe and the final cut.
    pub candidates_scanned: u64,
    /// Whether a host backend was invoked at all.
    pub backend_used: bool,
    /// ACTUAL backend spend for this read (`decompose` + `rerank`), summed
    /// from what the backend reported. Never a budget or a request cap: a
    /// tier that ran no backend reports `0`, and a caller can therefore read
    /// this as "what this call really cost", not "what it was allowed to".
    pub tokens_used: u64,
    /// Attempted and completed channels from this execution, not from hit counts.
    pub retrieval_diagnostics: RetrievalDiagnostics,
    /// Shared presentation metadata. Does not alter engine or backend ranking.
    pub retrieval_quality: RetrievalQualityReport,
}

/// A backend result carrying what producing it actually cost.
///
/// The spend travels WITH the value rather than being asked for afterwards,
/// so a backend cannot report a value and then be queried for a cost that no
/// longer corresponds to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendSpend<T> {
    /// The backend's answer.
    pub value: T,
    /// Tokens the backend spent producing `value`.
    pub tokens_used: u64,
}

impl<T> BackendSpend<T> {
    /// A result that cost nothing (a cached or deterministic backend answer).
    pub const fn free(value: T) -> Self {
        Self {
            value,
            tokens_used: 0,
        }
    }
}

/// Host-injected deep retrieval (the ONE-207 sibling of
/// [`crate::rerank::Reranker`]).
///
/// Implemented app-side, like `LlmBackend`: no provider SDK, model id, prompt
/// text or persona enters this crate. The engine calls these methods under its
/// own caps and truncates whatever comes back, so an implementation is free to
/// be sloppy about limits without widening the read. Both calls receive the
/// same admitted lease that pays for this read. On failure, report any tokens
/// this call consumed in [`RetrievalError`]; a plain engine error converts to
/// zero usage only. The host, not the backend, settles the shared lease.
///
/// `token_budget` is the remaining request allowance, not a fresh per-call cap.
/// A backend must bound its total input and output tokens (including retries)
/// to this allowance, or refuse with actual usage. `None` adds no request cap.
/// The engine rejects reported overruns and stops before any subsequent call.
pub trait DeepSearchBackend: Send + Sync {
    /// Proposes follow-up queries for one deep round.
    ///
    /// `already_run` is every query this read has executed so far, so a
    /// backend can avoid repeating one; the engine drops repeats regardless.
    /// Returning more than `max_queries` is not an error — the engine keeps
    /// the first `max_queries` distinct, non-blank entries and discards the
    /// rest. Returning an empty list ends decomposition early.
    fn decompose(
        &self,
        query: &str,
        already_run: &[String],
        max_queries: usize,
        token_budget: Option<u64>,
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<String>>>;

    /// Cross-encoder scoring over the merged candidate set.
    ///
    /// Must return exactly one score per candidate, in the same order; higher
    /// is more relevant. The engine uses the scores only to REORDER, never to
    /// overwrite [`ScoredEntity::score`], so the engine score scale downstream
    /// is unchanged (the [`crate::rerank`] contract, kept identical here).
    fn rerank(
        &self,
        query: &str,
        candidates: &[RerankCandidate<'_>],
        token_budget: Option<u64>,
        lease: &BudgetLease,
    ) -> RetrievalResult<BackendSpend<Vec<f32>>>;
}

/// The `short_id:hash` reference for an entity, or its hex id when the entity
/// has no short-id row yet.
///
/// Short refs are what a depth read cites, so this is the one place the
/// citation form is produced for this lane.
pub fn short_ref_or_hex(vault: &Vault, id: &EntityId) -> Result<String> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.short_ids_reverse.get(&rtxn, id.as_bytes())? else {
        return Ok(id.to_hex());
    };
    let (short_id, content_hash) = crate::batch::parse_short_id_value(&raw)?;
    Ok(format!("{short_id}:{content_hash:02x}"))
}

/// Derives the standard tier's lexical subqueries from one query.
///
/// PURE and total: the same input yields the same output, in the same order,
/// on every call. Order is first-appearance and duplicates collapse, so a
/// query whose variants coincide simply runs fewer channels rather than the
/// same channel twice.
///
/// The four derivations, in order: the whitespace-normalized query; the query
/// with `SUBQUERY_STOPWORDS` removed; its leading half; its trailing half.
/// Halving is what makes this useful on a compound question — "what did we
/// decide about the launch date" retrieves differently for "decide launch" and
/// for "date" than it does for the whole sentence — and it is arithmetic, not
/// inference.
#[must_use]
pub fn deterministic_subqueries(query: &str) -> Vec<String> {
    let tokens: Vec<&str> = query.split_whitespace().collect();
    let mut out: Vec<String> = Vec::new();
    if tokens.is_empty() {
        return out;
    }
    push_subquery(&mut out, tokens.join(" "));

    let content: Vec<&str> = tokens
        .iter()
        .copied()
        .filter(|token| !is_stopword(token))
        .collect();
    let content = if content.is_empty() { tokens } else { content };
    push_subquery(&mut out, content.join(" "));

    if content.len() >= 2 {
        let mid = content.len().div_ceil(2);
        push_subquery(&mut out, content[..mid].join(" "));
        push_subquery(&mut out, content[mid..].join(" "));
    }
    out
}

fn push_subquery(out: &mut Vec<String>, candidate: String) {
    if candidate.trim().is_empty()
        || out.len() >= STANDARD_SUBQUERY_LIMIT
        || out.contains(&candidate)
    {
        return;
    }
    out.push(candidate);
}

fn is_stopword(token: &str) -> bool {
    let folded: String = token
        .chars()
        .filter(|ch| ch.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    !folded.is_empty() && SUBQUERY_STOPWORDS.contains(&folded.as_str())
}

/// Runs one effort-dialed read against an actor-keyed lane.
///
/// Every channel here goes through `scoped`, so the tier changes HOW MUCH is
/// retrieved and never WHAT is admissible: the direct channels filter through
/// the same predicate `ScopedRead::search_text` already applies, and the
/// expansion walks under [`crate::ppr::PprNodeVisibility`], conjoining the
/// actor-read gate with the same resolved retrieval floor before traversal.
pub(crate) fn execute(
    scoped: &ScopedRead<'_>,
    request: &DepthSearchRequest<'_>,
) -> RetrievalResult<DepthSearchResult> {
    validate(request)?;
    let mut acc = DepthAccumulator::default();
    run_direct_channel(scoped, request, &mut acc)?;

    if request.effort == Effort::Minimal {
        return Ok(acc.finish(request.limit));
    }

    run_subquery_channels(scoped, request, &mut acc)?;
    run_graph_expansion(scoped, request, &mut acc)?;
    acc.fuse();

    if request.effort == Effort::Standard {
        return Ok(acc.finish(request.limit));
    }

    let backend = request
        .backend
        .ok_or_else(|| Error::InvalidConfig("deep retrieval requires a backend".to_owned()))?;
    let query = deep_query(request)?.to_owned();
    run_deep_rounds(scoped, request, backend, &query, &mut acc)
        .and_then(|()| run_deep_rerank(scoped, request, backend, &query, &mut acc))
        .map_err(|mut failure| {
            // Successful calls were charged before later fallible work. A
            // failed backend call reports only its own additional spend.
            failure.tokens_used = failure.tokens_used.saturating_add(acc.tokens_used);
            failure
        })?;
    Ok(acc.finish(request.limit))
}

/// Fail-closed preflight. The HTTP surface checks the same three things to
/// produce field-specific refusals; this exists so no OTHER caller of the
/// engine door can skip them.
fn validate(request: &DepthSearchRequest<'_>) -> Result<()> {
    if request.limit == 0 {
        return Err(Error::InvalidConfig(
            "search limit must be at least 1".to_owned(),
        ));
    }
    if request.effort != Effort::Deep {
        return Ok(());
    }
    if request.lease.is_none() {
        return Err(Error::InvalidConfig(format!(
            "{MEMORY_CODE_LEASE_REQUIRED}: deep retrieval requires a budget lease"
        )));
    }
    if request.backend.is_none() {
        return Err(Error::InvalidConfig(
            "deep retrieval requires a host-injected backend".to_owned(),
        ));
    }
    deep_query(request).map(drop)
}

fn deep_query<'a>(request: &'a DepthSearchRequest<'_>) -> Result<&'a str> {
    request
        .probe
        .query_text()
        .ok_or_else(|| Error::InvalidConfig("deep vector search requires query text".to_owned()))
}

fn run_direct_channel(
    scoped: &ScopedRead<'_>,
    request: &DepthSearchRequest<'_>,
    acc: &mut DepthAccumulator,
) -> Result<()> {
    match &request.probe {
        SearchProbe::Text { query } => {
            acc.mark(SIGNAL_TEXT);
            acc.attempt(RetrievalSignal::Text);
            let hits = scoped.search_text(query, request.channel_limit(scoped, true)?, None)?;
            acc.merge(request.narrow_hits(scoped, hits)?);
            acc.complete(RetrievalSignal::Text);
            acc.record_query(query.clone());
        }
        SearchProbe::Vector { embedding, .. } => {
            acc.mark(SIGNAL_VECTOR);
            acc.attempt(RetrievalSignal::Vector);
            let hits =
                scoped.search_vector(embedding, request.channel_limit(scoped, false)?, None)?;
            acc.merge(request.narrow_hits(scoped, hits)?);
            acc.complete(RetrievalSignal::Vector);
            // No query recorded: a float vector is not a string a later
            // channel could compare against, and `signals_used` is where a
            // dense channel is reported.
        }
    }
    Ok(())
}

/// The standard tier's lexical fan-out. Text probes only: a subquery is a
/// rewriting of the caller's WORDS. Vector query text grounds deep backend
/// calls only; it must not turn standard vector retrieval into lexical search.
fn run_subquery_channels(
    scoped: &ScopedRead<'_>,
    request: &DepthSearchRequest<'_>,
    acc: &mut DepthAccumulator,
) -> Result<()> {
    let SearchProbe::Text { query } = &request.probe else {
        return Ok(());
    };
    for subquery in deterministic_subqueries(query) {
        if acc.already_ran(&subquery) {
            continue;
        }
        // Marked per channel rather than once up front: a query whose derived
        // variants all collapse onto the direct query runs no subquery
        // channel, and must not claim the signal.
        acc.mark(SIGNAL_SUBQUERIES);
        acc.attempt(RetrievalSignal::Text);
        let hits = scoped.search_text(&subquery, request.channel_limit(scoped, true)?, None)?;
        acc.merge(request.narrow_hits(scoped, hits)?);
        acc.complete(RetrievalSignal::Text);
        acc.record_query(subquery);
    }
    Ok(())
}

/// One-hop expansion seeded by the hits retrieved so far.
///
/// Uses the COMPUTE-ONLY scoped walk: the shared `ppr_cache` is keyed by seeds
/// and carries no actor, so an actor-scoped ranking must never be read from or
/// written to it.
fn run_graph_expansion(
    scoped: &ScopedRead<'_>,
    request: &DepthSearchRequest<'_>,
    acc: &mut DepthAccumulator,
) -> Result<()> {
    let seeds: Vec<EntityId> = acc
        .order
        .iter()
        .copied()
        .take(STANDARD_PPR_SEED_LIMIT)
        .collect();
    if seeds.is_empty() {
        return Ok(());
    }
    acc.mark(SIGNAL_PPR);
    acc.attempt(RetrievalSignal::Ppr);
    let vault = scoped.vault();
    let rtxn = vault.store.env.read_txn()?;
    // Graph candidates must inherit the same retrieval floor as direct hits;
    // actor readability alone does not enforce entity-type and numeric limits.
    let visibility = scoped.retrieval_visibility_in(&rtxn, None)?;
    let expanded = ppr_query_scoped_in_txn_with_diagnostics(
        &vault.store,
        &rtxn,
        &seeds,
        STANDARD_PPR_DEPTH,
        STANDARD_PPR_ALPHA,
        vault.config.ppr_vad_alpha,
        SeedWeighting::Specificity,
        &visibility,
    )?;
    drop(rtxn);
    acc.retrieval_diagnostics.ppr_cache = Some(expanded.cache);
    acc.merge(request.narrow_hits(scoped, expanded.scores)?);
    acc.complete(RetrievalSignal::Ppr);
    Ok(())
}

/// The deep tier's recursive decomposition, capped by construction.
fn run_deep_rounds(
    scoped: &ScopedRead<'_>,
    request: &DepthSearchRequest<'_>,
    backend: &dyn DeepSearchBackend,
    query: &str,
    acc: &mut DepthAccumulator,
) -> RetrievalResult<()> {
    for _ in 0..DEEP_MAX_ROUNDS {
        let token_budget = request.remaining_token_budget(acc.tokens_used)?;
        let proposed = backend
            .decompose(
                query,
                &acc.queries_run,
                DEEP_QUERIES_PER_ROUND,
                token_budget,
                request.lease.expect("deep preflight requires a lease"),
            )?
            .enforce_token_budget(token_budget)?;
        acc.charge_backend(SIGNAL_BACKEND_DECOMPOSE, proposed.tokens_used);
        let round = acc.admissible_round_queries(proposed.value);
        if round.is_empty() {
            return Ok(());
        }
        for subquery in round {
            acc.attempt(RetrievalSignal::Text);
            let hits = scoped.search_text(&subquery, request.channel_limit(scoped, true)?, None)?;
            acc.merge(request.narrow_hits(scoped, hits)?);
            acc.complete(RetrievalSignal::Text);
            acc.record_query(subquery);
        }
    }
    Ok(())
}

/// Cross-encoder pass over the merged candidate set.
///
/// Reorders only. A backend that returns the wrong number of scores is a
/// contract violation and fails the read rather than being partially applied:
/// a truncated or padded score vector silently mis-pairs scores with
/// candidates, which is worse than no rerank at all.
fn run_deep_rerank(
    scoped: &ScopedRead<'_>,
    request: &DepthSearchRequest<'_>,
    backend: &dyn DeepSearchBackend,
    query: &str,
    acc: &mut DepthAccumulator,
) -> RetrievalResult<()> {
    if acc.order.is_empty() {
        return Ok(());
    }
    acc.attempt(RetrievalSignal::Rerank);
    let bodies = acc.candidate_claim_bodies(scoped)?;
    let candidates = acc.rerank_candidates(&bodies);
    let token_budget = request.remaining_token_budget(acc.tokens_used)?;
    let scored = backend
        .rerank(
            query,
            &candidates,
            token_budget,
            request.lease.expect("deep preflight requires a lease"),
        )?
        .enforce_token_budget(token_budget)?;
    acc.charge_backend(SIGNAL_BACKEND_RERANK, scored.tokens_used);
    if scored.value.len() != acc.order.len() {
        return Err(Error::InvalidConfig(
            "deep rerank backend returned one score per candidate".to_owned(),
        )
        .into());
    }
    acc.reorder_by(&scored.value);
    acc.complete(RetrievalSignal::Rerank);
    Ok(())
}

#[cfg(test)]
mod tests;
