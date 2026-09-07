//! Bounded exact top-k over the existing BM25F scorer, under one read snapshot.
use super::*;

const CANDIDATE_PAGE: usize = 256;

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
        options.exact_posting_matches_scope,
    )?;
    let mut rows = store.text_doc_field_lengths().iter(rtxn)?;
    let mut best = Vec::new();
    loop {
        let mut page = BTreeSet::new();
        for row in rows.by_ref().take(CANDIDATE_PAGE) {
            let (key, _) = row?;
            let bytes: [u8; ENTITY_ID_LEN] = key[..]
                .try_into()
                .map_err(|_| corrupted("field-length document id"))?;
            page.insert(EntityId::from_bytes(bytes)?);
        }
        if page.is_empty() {
            break;
        }
        let scores =
            scoring::score_query_terms(store, rtxn, config, &terms, options.recency, |id| {
                if !page.contains(id) {
                    return Ok(false);
                }
                let Some(target) = lexical_query_hint_scope_id(store, rtxn, id)? else {
                    return Ok(false);
                };
                (options.exact_posting_matches_scope)(&target)
            })?;
        best.extend(scores);
        scoring::retain_best(&mut best, limit);
    }
    Ok(scoring::scored_entities(best))
}
