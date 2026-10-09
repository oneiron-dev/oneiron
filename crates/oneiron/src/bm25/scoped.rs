//! Exact top-k over the existing BM25F scorer for a scoped read, under one
//! read snapshot: one pass over the query's postings, each matching document
//! admitted once.
use super::*;

pub(crate) fn search_text_filtered_with_recency<F>(
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
    search_text_bounded(
        store,
        rtxn,
        analyzer,
        config,
        query,
        limit,
        BoundedSearchOptions {
            scope: options,
            category: None,
        },
    )
}

pub(crate) struct Bm25CategorySearchOptions<'a, F: FnMut(&EntityId) -> Result<bool>> {
    pub(crate) scope: Bm25SearchOptions<'a, F>,
    pub(crate) category: &'a mut dyn FnMut(&EntityId) -> Result<bool>,
}

pub(crate) fn search_text_category_with_recency<F>(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    analyzer: &MultilingualAnalyzer,
    config: &Bm25Config,
    query: &str,
    limit: usize,
    options: Bm25CategorySearchOptions<'_, F>,
) -> Result<Vec<ScoredEntity>>
where
    F: FnMut(&EntityId) -> Result<bool>,
{
    search_text_bounded(
        store,
        rtxn,
        analyzer,
        config,
        query,
        limit,
        BoundedSearchOptions {
            scope: options.scope,
            category: Some(options.category),
        },
    )
}

type CategoryPredicate<'a> = &'a mut dyn FnMut(&EntityId) -> Result<bool>;
struct BoundedSearchOptions<'a, F: FnMut(&EntityId) -> Result<bool>> {
    scope: Bm25SearchOptions<'a, F>,
    category: Option<CategoryPredicate<'a>>,
}

fn search_text_bounded<F>(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    analyzer: &MultilingualAnalyzer,
    config: &Bm25Config,
    query: &str,
    limit: usize,
    mut options: BoundedSearchOptions<'_, F>,
) -> Result<Vec<ScoredEntity>>
where
    F: FnMut(&EntityId) -> Result<bool>,
{
    if limit == 0 {
        return Ok(Vec::new());
    }
    let mut tokens = Vec::new();
    analyzer.analyze(query, &AnalyzerContext::for_query(), &mut tokens);
    if tokens.is_empty() {
        return Ok(Vec::new());
    }
    // Prefix expansion sees the WHOLE scope, never a page-local corpus.
    let terms = collect_query_terms(
        store,
        rtxn,
        config,
        query,
        &tokens,
        options.scope.exact_posting_matches_scope,
    )?;
    // One scoring pass. Scoring the corpus a page at a time re-read every
    // query term's whole posting list once per page, so a common term cost
    // the square of the vault size.
    let mut admitted = HashMap::<EntityId, bool>::new();
    let mut best =
        scoring::score_query_terms(store, rtxn, config, &terms, options.scope.recency, |id| {
            if let Some(admit) = admitted.get(id) {
                return Ok(*admit);
            }
            let admit = match lexical_query_hint_scope_id(store, rtxn, id)? {
                None => false,
                Some(target) => match options.category.as_mut() {
                    Some(category) => category(&target)?,
                    None => (options.scope.exact_posting_matches_scope)(&target)?,
                },
            };
            admitted.insert(*id, admit);
            Ok(admit)
        })?;
    scoring::retain_best(&mut best, limit);
    Ok(scoring::scored_entities(best))
}
