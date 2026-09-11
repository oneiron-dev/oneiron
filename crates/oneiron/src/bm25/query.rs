//! Query-side: term collection, prefix expansion, search entry points, hint collapse.
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str;

use heed::RoTxn;

use crate::analyzer::{AnalyzerChannel, AnalyzerContext, MultilingualAnalyzer, Token, TokenKind};
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::pipeline::ScoredEntity;
use crate::store::ManifestDbs;

use super::codec::{PostingEntry, corrupted, decode_posting_entry, read_field_stats};
use super::config::{Bm25Config, Bm25RecencyConfig};
use super::scoring;

// === Scoring ===

#[derive(Debug, Clone, PartialEq)]
pub(super) struct QueryTerm {
    pub(super) term: String,
    pub(super) weight: f64,
}

pub(crate) struct Bm25SearchOptions<'a, F>
where
    F: FnMut(&EntityId) -> Result<bool>,
{
    pub(crate) recency: Option<Bm25RecencyConfig>,
    pub(crate) exact_posting_matches_scope: &'a mut F,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PrefixExpansionPostingDecision {
    pub(crate) matches_scope: bool,
    pub(crate) rejected_by_gate: bool,
}

pub(super) const FINAL_TOKEN_PREFIX_WEIGHT: f64 = 0.5;

pub(super) const MAX_FINAL_TOKEN_PREFIX_TERMS: usize = 64;

/// Bound term-key reads for any one prefix after the scoped expansion cap.
///
/// Out-of-scope completions do not consume the 64-term expansion budget, but
/// broad prefixes still need a hard cursor-walk ceiling.
pub(super) const MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS: usize = MAX_FINAL_TOKEN_PREFIX_TERMS * 64;

pub(super) fn collect_query_terms(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    config: &Bm25Config,
    query: &str,
    tokens: &[Token],
    exact_posting_matches_scope: &mut impl FnMut(&EntityId) -> Result<bool>,
) -> Result<Vec<QueryTerm>> {
    // Dedupe query terms across channels — one term per unique string
    // (scorer looks up posting list then combines field TFs from the
    // posting entries themselves). This preserves the pre-ONE-317
    // "query dedupe" semantics for exact query tokens.
    let mut terms: BTreeMap<String, f64> = BTreeMap::new();
    for token in tokens {
        insert_query_term(&mut terms, token.term.as_ref().to_owned(), 1.0);
    }

    collect_final_token_prefix_terms(
        store,
        rtxn,
        query.trim_end().len(),
        config,
        tokens,
        &mut terms,
        exact_posting_matches_scope,
    )?;

    Ok(terms
        .into_iter()
        .map(|(term, weight)| QueryTerm { term, weight })
        .collect())
}

pub(super) fn collect_final_token_prefix_terms(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    trimmed_query_end: usize,
    config: &Bm25Config,
    tokens: &[Token],
    terms: &mut BTreeMap<String, f64>,
    exact_posting_matches_scope: &mut impl FnMut(&EntityId) -> Result<bool>,
) -> Result<()> {
    let prefixes = final_token_prefix_terms(tokens, trimmed_query_end);

    let mut expanded_terms = 0usize;
    'prefixes: for prefix in prefixes {
        if exact_term_has_scoped_posting(store, rtxn, config, &prefix, exact_posting_matches_scope)?
        {
            continue;
        }
        if expanded_terms == MAX_FINAL_TOKEN_PREFIX_TERMS {
            break;
        }

        // The scan cap is per distinct final surface prefix. A query can
        // carry multiple final surface tokens, so total cursor reads are
        // bounded by prefix_count * MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS while
        // accepted expansions still share MAX_FINAL_TOKEN_PREFIX_TERMS.
        for (scanned_terms, row) in store
            .text_postings()
            .prefix_iter(rtxn, prefix.as_bytes())?
            .move_between_keys()
            .enumerate()
        {
            if scanned_terms == MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS {
                break;
            }
            if expanded_terms == MAX_FINAL_TOKEN_PREFIX_TERMS {
                break 'prefixes;
            }
            let (term_bytes, _) = row?;
            let term = str::from_utf8(&term_bytes)
                .map_err(|_| corrupted("posting term key is not valid utf-8"))?
                .to_owned();
            if !exact_term_has_scoped_posting(
                store,
                rtxn,
                config,
                &term,
                exact_posting_matches_scope,
            )? {
                continue;
            }
            insert_query_term(terms, term, FINAL_TOKEN_PREFIX_WEIGHT);
            expanded_terms += 1;
        }
    }

    Ok(())
}

pub(crate) fn final_token_exact_posting_matches<F>(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    analyzer: &MultilingualAnalyzer,
    config: &Bm25Config,
    query: &str,
    mut posting_matches: F,
) -> Result<bool>
where
    F: FnMut(&EntityId) -> Result<bool>,
{
    let trimmed_query_end = query.trim_end().len();
    if trimmed_query_end == 0 {
        return Ok(false);
    }

    let mut tokens = Vec::new();
    analyzer.analyze(query, &AnalyzerContext::for_query(), &mut tokens);
    for term in final_token_prefix_terms(&tokens, trimmed_query_end) {
        let Some(dups) = store
            .text_postings()
            .get_duplicates(rtxn, term.as_bytes())?
        else {
            continue;
        };
        for item in dups {
            let (_, dup) = item?;
            let entry = decode_posting_entry(&store.diagnostics().bm25, &dup)?;
            let Some(scope_id) = lexical_query_hint_scope_id(store, rtxn, &entry.id)? else {
                continue;
            };
            if posting_has_enabled_channel(config, &entry)? && posting_matches(&scope_id)? {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

pub(crate) fn final_token_prefix_expansion_has_scoped_and_rejected_postings<F>(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    analyzer: &MultilingualAnalyzer,
    config: &Bm25Config,
    query: &str,
    mut classify_posting: F,
) -> Result<bool>
where
    F: FnMut(&EntityId) -> Result<PrefixExpansionPostingDecision>,
{
    let trimmed_query_end = query.trim_end().len();
    if trimmed_query_end == 0 {
        return Ok(false);
    }

    let mut tokens = Vec::new();
    analyzer.analyze(query, &AnalyzerContext::for_query(), &mut tokens);

    let prefixes = final_token_prefix_terms(&tokens, trimmed_query_end);
    let mut expanded_terms = 0usize;
    'prefixes: for prefix in prefixes {
        let exact_status =
            term_posting_decisions(store, rtxn, config, &prefix, &mut classify_posting)?;
        if exact_status.has_scoped_posting {
            continue;
        }
        if expanded_terms == MAX_FINAL_TOKEN_PREFIX_TERMS {
            break;
        }

        for (scanned_terms, row) in store
            .text_postings()
            .prefix_iter(rtxn, prefix.as_bytes())?
            .move_between_keys()
            .enumerate()
        {
            if scanned_terms == MAX_FINAL_TOKEN_PREFIX_SCAN_TERMS {
                break;
            }
            if expanded_terms == MAX_FINAL_TOKEN_PREFIX_TERMS {
                break 'prefixes;
            }
            let (term_bytes, _) = row?;
            let term = str::from_utf8(&term_bytes)
                .map_err(|_| corrupted("posting term key is not valid utf-8"))?;
            let status = term_posting_decisions(store, rtxn, config, term, &mut classify_posting)?;
            if !status.has_scoped_posting {
                continue;
            }
            if status.has_rejected_posting {
                return Ok(true);
            }
            expanded_terms += 1;
        }
    }

    Ok(false)
}

fn final_token_prefix_terms(tokens: &[Token], trimmed_query_end: usize) -> BTreeSet<String> {
    tokens
        .iter()
        .filter(|token| final_token_prefix_candidate(token, trimmed_query_end))
        .map(|token| token.term.as_ref().to_owned())
        .collect()
}

fn final_token_prefix_candidate(token: &Token, trimmed_query_end: usize) -> bool {
    token.byte_end as usize == trimmed_query_end
        && !token.term.is_empty()
        && token.channel == AnalyzerChannel::Surface
        && matches!(token.kind, TokenKind::Word | TokenKind::Numeric)
}

fn exact_term_has_scoped_posting(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    config: &Bm25Config,
    term: &str,
    exact_posting_matches_scope: &mut impl FnMut(&EntityId) -> Result<bool>,
) -> Result<bool> {
    let Some(dups) = store
        .text_postings()
        .get_duplicates(rtxn, term.as_bytes())?
    else {
        return Ok(false);
    };
    for item in dups {
        let (_, dup) = item?;
        let entry = decode_posting_entry(&store.diagnostics().bm25, &dup)?;
        let Some(scope_id) = lexical_query_hint_scope_id(store, rtxn, &entry.id)? else {
            continue;
        };
        if exact_posting_matches_scope(&scope_id)? && posting_has_enabled_channel(config, &entry)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Debug, Clone, Copy, Default)]
struct TermPostingDecisions {
    has_scoped_posting: bool,
    has_rejected_posting: bool,
}

fn term_posting_decisions(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    config: &Bm25Config,
    term: &str,
    classify_posting: &mut impl FnMut(&EntityId) -> Result<PrefixExpansionPostingDecision>,
) -> Result<TermPostingDecisions> {
    let Some(dups) = store
        .text_postings()
        .get_duplicates(rtxn, term.as_bytes())?
    else {
        return Ok(TermPostingDecisions::default());
    };

    let mut decisions = TermPostingDecisions::default();
    for item in dups {
        let (_, dup) = item?;
        let entry = decode_posting_entry(&store.diagnostics().bm25, &dup)?;
        if !posting_has_enabled_channel(config, &entry)? {
            continue;
        }
        let Some(scope_id) = lexical_query_hint_scope_id(store, rtxn, &entry.id)? else {
            continue;
        };
        let decision = classify_posting(&scope_id)?;
        decisions.has_scoped_posting |= decision.matches_scope;
        decisions.has_rejected_posting |= decision.rejected_by_gate;
        if decisions.has_scoped_posting && decisions.has_rejected_posting {
            break;
        }
    }

    Ok(decisions)
}

fn posting_has_enabled_channel(config: &Bm25Config, entry: &PostingEntry) -> Result<bool> {
    for (fid, _) in &entry.fields {
        let Some(channel) = AnalyzerChannel::from_field_id(*fid) else {
            return Err(corrupted("posting field_id not in current schema"));
        };
        if config.field(channel).weight != 0.0 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn insert_query_term(terms: &mut BTreeMap<String, f64>, term: String, weight: f64) {
    match terms.entry(term) {
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            if weight > *entry.get() {
                *entry.get_mut() = weight;
            }
        }
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(weight);
        }
    }
}

pub(super) fn apply_recency_blend(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    recency: Option<Bm25RecencyConfig>,
    scores: &mut HashMap<EntityId, f64>,
) -> Result<()> {
    let Some(recency) = recency else {
        return Ok(());
    };
    if !recency.is_enabled() {
        return Ok(());
    }

    let seconds_per_half_life = recency.half_life_days * 86_400.0;
    if seconds_per_half_life <= 0.0 {
        return Ok(());
    }
    let decay = std::f64::consts::LN_2 / seconds_per_half_life;

    for (id, score) in scores {
        let Some(raw) = store.entities().get(rtxn, id.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        let age_secs = recency.now_secs.saturating_sub(header.learned_at) as f64;
        let freshness = (-decay * age_secs).exp();
        *score *= 1.0 + recency.boost * freshness;
    }

    Ok(())
}

pub(crate) fn search_text(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    analyzer: &MultilingualAnalyzer,
    config: &Bm25Config,
    query: &str,
    limit: usize,
) -> Result<Vec<ScoredEntity>> {
    search_text_with_recency(store, rtxn, analyzer, config, query, limit, None)
}

pub(super) fn search_text_with_recency(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    analyzer: &MultilingualAnalyzer,
    config: &Bm25Config,
    query: &str,
    limit: usize,
    recency: Option<Bm25RecencyConfig>,
) -> Result<Vec<ScoredEntity>> {
    let mut exact_posting_matches_scope = |_id: &EntityId| Ok(true);
    search_text_scoped_with_recency(
        store,
        rtxn,
        analyzer,
        config,
        query,
        limit,
        Bm25SearchOptions {
            recency,
            exact_posting_matches_scope: &mut exact_posting_matches_scope,
        },
    )
}

pub(crate) fn search_text_scoped_with_recency<F>(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    analyzer: &MultilingualAnalyzer,
    config: &Bm25Config,
    query: &str,
    limit: usize,
    options: Bm25SearchOptions<'_, F>,
) -> Result<Vec<ScoredEntity>>
where
    F: FnMut(&EntityId) -> Result<bool>,
{
    if limit == 0 {
        return Ok(Vec::new());
    }

    let mut tokens: Vec<Token> = Vec::new();
    analyzer.analyze(query, &AnalyzerContext::for_query(), &mut tokens);
    if tokens.is_empty() {
        return Ok(Vec::new());
    }

    let query_terms = collect_query_terms(
        store,
        rtxn,
        config,
        query,
        &tokens,
        options.exact_posting_matches_scope,
    )?;

    let mut ranked =
        scoring::score_query_terms(store, rtxn, config, &query_terms, options.recency, |id| {
            Ok(!crate::vault_cleanup::is_archived_in_txn(store, rtxn, id)?)
        })?;
    ranked.sort_by(|a, b| {
        b.1.total_cmp(&a.1)
            .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
    });
    ranked.truncate(limit);
    Ok(scoring::scored_entities(ranked))
}

pub(super) fn compute_avgdl(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    field_id: u16,
) -> Result<f64> {
    let (doc_count, total_length) = read_field_stats(store, rtxn, field_id)?;
    if doc_count == 0 {
        return Ok(0.0);
    }
    Ok(total_length as f64 / f64::from(doc_count))
}

pub(super) fn collapse_lexical_query_hint_scores(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    scores: &mut HashMap<EntityId, f64>,
) -> Result<()> {
    let mut collapsed = HashMap::<EntityId, f64>::with_capacity(scores.len());
    for (id, score) in scores.drain() {
        let target = match resolve_lexical_query_hint_record(store, rtxn, &id)? {
            LexicalQueryHintResolution::Live { target } => {
                if !lexical_query_hint_target_is_live_claim(store, rtxn, &target)? {
                    continue;
                }
                target
            }
            LexicalQueryHintResolution::DeadHint => continue,
            LexicalQueryHintResolution::NonHint => id,
        };
        match collapsed.entry(target) {
            Entry::Occupied(mut entry) => {
                if score > *entry.get() {
                    *entry.get_mut() = score;
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(score);
            }
        }
    }
    *scores = collapsed;
    Ok(())
}

enum LexicalQueryHintResolution {
    NonHint,
    Live { target: EntityId },
    DeadHint,
}

fn resolve_lexical_query_hint_record(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<LexicalQueryHintResolution> {
    if !id
        .as_bytes()
        .starts_with(&crate::claim::LEXICAL_QUERY_HINT_ID_PREFIX)
    {
        return Ok(LexicalQueryHintResolution::NonHint);
    }
    let Some(raw) = store.entities().get(rtxn, id.as_bytes())? else {
        return Ok(LexicalQueryHintResolution::NonHint);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(corrupted("entity header"));
    };
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(LexicalQueryHintResolution::NonHint);
    }
    if raw.len() == crate::batch::ENTITY_METADATA_HEADER_LEN {
        return Ok(LexicalQueryHintResolution::DeadHint);
    }
    let body =
        crate::claim::decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)
            .map_err(|_| corrupted("lexical query hint claim"))?;
    if body.predicate != crate::claim::PREDICATE_LEXICAL_QUERY_HINT {
        return Ok(LexicalQueryHintResolution::NonHint);
    }
    if body.lifecycle != crate::claim::ClaimLifecycleStatus::Active {
        return Ok(LexicalQueryHintResolution::DeadHint);
    }
    if !body.stale {
        return Ok(LexicalQueryHintResolution::DeadHint);
    }
    let Some(target) = crate::claim::lexical_query_hint_target(&body)
        .map_err(|_| corrupted("lexical query hint claim"))?
    else {
        return Ok(LexicalQueryHintResolution::DeadHint);
    };
    Ok(LexicalQueryHintResolution::Live { target })
}

fn lexical_query_hint_target_is_live_claim(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    target: &EntityId,
) -> Result<bool> {
    let Some(raw) = store.entities().get(rtxn, target.as_bytes())? else {
        return Ok(false);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(corrupted("entity header"));
    };
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(false);
    }
    let Ok(body) =
        crate::claim::decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)
    else {
        return Ok(false);
    };
    Ok(body.lifecycle == crate::claim::ClaimLifecycleStatus::Active)
}

pub(super) fn lexical_query_hint_scope_id(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    match resolve_lexical_query_hint_record(store, rtxn, id)? {
        LexicalQueryHintResolution::Live { target } => {
            if lexical_query_hint_target_is_live_claim(store, rtxn, &target)? {
                Ok(Some(target))
            } else {
                Ok(None)
            }
        }
        LexicalQueryHintResolution::NonHint => Ok(Some(*id)),
        LexicalQueryHintResolution::DeadHint => Ok(None),
    }
}
