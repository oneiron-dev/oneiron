//! Shared BM25F scoring. Scoped reads restrict admitted ids, not corpus statistics.
use super::*;

pub(super) fn score_query_terms(
    store: &impl ManifestDbs,
    rtxn: &RoTxn<'_>,
    config: &Bm25Config,
    query_terms: &[QueryTerm],
    recency: Option<Bm25RecencyConfig>,
    mut accept: impl FnMut(&EntityId) -> Result<bool>,
) -> Result<Vec<(EntityId, f64)>> {
    let total_docs = read_total_docs(store, rtxn)?;
    if total_docs == 0 {
        return Ok(Vec::new());
    }
    let n = f64::from(total_docs);

    // Cache per-field avgdl and per-(doc, field) length so we don't reopen
    // the same DB entries once per query term.
    let mut avgdl_cache: HashMap<u16, f64> = HashMap::new();
    let mut field_length_cache: HashMap<EntityId, HashMap<u16, u32>> = HashMap::new();
    let mut scores: HashMap<EntityId, f64> = HashMap::new();

    for query_term in query_terms {
        let Some(dups) = store
            .text_postings()
            .get_duplicates(rtxn, query_term.term.as_bytes())?
        else {
            continue;
        };

        // One duplicate item per (term, entity): df = the dup count. LMDB
        // yields duplicates bytewise sorted, so entity ids must arrive
        // strictly ascending — an equal or descending neighbour means two
        // dup items share one entity (df drift) and scoring fails closed.
        let mut previous = None;
        let mut count = 0u64;
        for item in dups {
            let (_, dup) = item?;
            let entry = decode_posting_entry(&dup)?;
            if previous.is_some_and(|id: EntityId| id.as_bytes() >= entry.id.as_bytes()) {
                return Err(corrupted_with_diagnostic(
                    "duplicate posting entries for one entity",
                    Bm25DiagnosticKind::MalformedPostingAlignment,
                ));
            }
            previous = Some(entry.id);
            count += 1;
        }
        if count == 0 {
            continue;
        }
        let df = count as f64;
        if df > n {
            return Err(corrupted_with_diagnostic(
                "posting list length exceeds total_docs",
                Bm25DiagnosticKind::MalformedPostingAlignment,
            ));
        }
        let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
        let Some(dups) = store
            .text_postings()
            .get_duplicates(rtxn, query_term.term.as_bytes())?
        else {
            continue;
        };
        for item in dups {
            let (_, dup) = item?;
            let entry = decode_posting_entry(&dup)?;
            let id = entry.id;
            if !accept(&id)? {
                continue;
            }

            // Enforce row-existence for every scored entry, not only those
            // that reach a `CountLengthIncrement` branch — otherwise a
            // NoNorm-only match silently skips the corruption guard.
            if let Entry::Vacant(v) = field_length_cache.entry(id) {
                let raw = store.text_doc_field_lengths().get(rtxn, id.as_bytes())?;
                let Some(bytes) = raw else {
                    return Err(corrupted_with_diagnostic(
                        "missing field lengths for scored doc",
                        Bm25DiagnosticKind::MissingScoredDocumentMetadata,
                    ));
                };
                let map = decode_field_lengths(&bytes)?;
                v.insert(map);
            }

            let mut x_t_d = 0.0_f64;

            for (fid, tf) in &entry.fields {
                let Some(channel) = AnalyzerChannel::from_field_id(*fid) else {
                    return Err(corrupted("posting field_id not in current schema"));
                };
                let cfg = config.field(channel);
                if cfg.weight == 0.0 {
                    continue;
                }

                let lens = field_length_cache
                    .get(&id)
                    .expect("field-lengths row loaded above for this entry id");
                // The posting-entry-implies-row invariant applies per-field:
                // a referenced `fid` must have an entry in the length row,
                // including on NoNorm channels where the value is unused.
                // Indexing always inserts the entry (including a 0 for
                // overlay-only channels), so absence is corruption. Silently
                // defaulting would yield `norm = 1 - b = 0.25` for the
                // default `b=0.75` — a 4× artificial boost.
                let stored_len = match lens.get(fid).copied() {
                    None => {
                        return Err(corrupted_with_diagnostic(
                            "posting field missing from per-doc field lengths",
                            Bm25DiagnosticKind::MissingScoredDocumentMetadata,
                        ));
                    }
                    Some(n) => n,
                };
                let len_f = match cfg.length_policy {
                    FieldLengthPolicy::NoNorm => 0.0,
                    FieldLengthPolicy::CountLengthIncrement => {
                        if stored_len == 0 {
                            return Err(corrupted_with_diagnostic(
                                "zero length for scored CountLengthIncrement field",
                                Bm25DiagnosticKind::MissingScoredDocumentMetadata,
                            ));
                        }
                        f64::from(stored_len)
                    }
                };

                let avgdl = if matches!(cfg.length_policy, FieldLengthPolicy::NoNorm) {
                    0.0
                } else {
                    // Fail closed on a corrupted `text_bm25_field_stats`
                    // row — scoring without a real avgdl would silently
                    // return wrong rankings instead of the caller's
                    // `Err(CorruptedIndex)`.
                    match avgdl_cache.entry(*fid) {
                        Entry::Occupied(o) => *o.get(),
                        Entry::Vacant(v) => *v.insert(compute_avgdl(store, rtxn, *fid)?),
                    }
                };

                let norm = match cfg.length_policy {
                    FieldLengthPolicy::NoNorm => 1.0,
                    FieldLengthPolicy::CountLengthIncrement => {
                        // avgdl must be positive for any field that has
                        // postings — absence means stats corruption.
                        if avgdl <= 0.0 {
                            return Err(corrupted("field stats missing for scored field"));
                        }
                        1.0 - cfg.b + cfg.b * (len_f / avgdl)
                    }
                };

                x_t_d += cfg.weight * f64::from(*tf) / norm;
            }

            if x_t_d == 0.0 {
                continue;
            }

            let saturated = (config.k1 + 1.0) * x_t_d / (config.k1 + x_t_d);
            let mut contribution = idf * saturated;
            if let Bm25Formula::Plus { delta } = config.formula {
                contribution += idf * delta;
            }
            contribution *= query_term.weight;
            *scores.entry(id).or_insert(0.0) += contribution;
        }
    }

    collapse_lexical_query_hint_scores(store, rtxn, &mut scores)?;
    apply_recency_blend(store, rtxn, recency, &mut scores)?;

    Ok(scores.into_iter().collect())
}

pub(super) fn retain_best(ranked: &mut Vec<(EntityId, f64)>, limit: usize) {
    ranked.sort_by(|a, b| {
        b.1.total_cmp(&a.1)
            .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
    });
    // Query hints may map ids from different pages to the same target.
    let mut seen = BTreeSet::new();
    ranked.retain(|(id, _)| seen.insert(*id));
    ranked.truncate(limit);
}

pub(super) fn scored_entities(ranked: Vec<(EntityId, f64)>) -> Vec<ScoredEntity> {
    ranked
        .into_iter()
        .map(|(id, score)| ScoredEntity {
            id,
            score: score as f32,
        })
        .collect()
}
