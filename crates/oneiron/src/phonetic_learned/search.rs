//! The learned rung's candidate list (CROSS-ARCH-0013 `#flow` CANDIDATE-GEN): exact cosine of
//! the caller's vector against every stored name vector of its model, each entity scored by
//! its best name. Exact search returns a superset of what an HNSW index would; at canon's sizes
//! (`#perf-size`, up to 100k entities) it stays inside the lookup budget.

use heed::RoTxn;

use super::{LEARNED_VECTOR, model_key};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::pipeline::ScoredEntity;
use crate::side_table::SideTableDbs;
use oneiron_store::vector_row::decode_vector_row_into;

/// The list length a learned query takes when it names none (canon `#flow`: top-200..1000).
pub const PHONETIC_VECTOR_DEFAULT_LIMIT: usize = 200;
/// The longest list a learned query may take.
pub const PHONETIC_VECTOR_MAX_LIMIT: usize = 1000;

/// The entities whose names are nearest `query` among the vectors of `model_id`, best first, at
/// most `limit`; each entity scores the cosine of its best name. Only entities `admit` keeps
/// take a place. Rows of other models are never compared.
///
/// # Errors
///
/// [`Error::DimensionMismatch`] when the model's stored vectors are of another width than
/// `query`; [`Error::InvalidConfig`] for an empty or non-finite query; storage errors.
pub(crate) fn search_phonetic_vectors_in_txn(
    store: &impl SideTableDbs,
    txn: &RoTxn<'_>,
    model_id: &str,
    query: &[f32],
    limit: usize,
    mut admit: impl FnMut(&EntityId) -> Result<bool>,
) -> Result<Vec<ScoredEntity>> {
    if query.is_empty() {
        return Err(Error::InvalidConfig(
            "a learned phonetic query needs a vector".into(),
        ));
    }
    if let Some(error) = Error::invalid_vector_component(query) {
        return Err(error);
    }
    let query_norm = norm(query);
    if limit == 0 || query_norm == 0.0 {
        return Ok(Vec::new());
    }
    let model = model_key(model_id);
    let mut best: Vec<ScoredEntity> = Vec::new();
    let mut scratch = Vec::with_capacity(query.len());
    for row in LEARNED_VECTOR.iter_from(store, txn, &[])? {
        let ((id, _), row) = row?;
        if row.model != model {
            continue;
        }
        if row.dimensions() != query.len() {
            return Err(Error::DimensionMismatch {
                expected: row.dimensions(),
                got: query.len(),
            });
        }
        let vector = decode_vector_row_into(&row.row, query.len(), &mut scratch)?;
        let vector_norm = norm(vector);
        if vector_norm == 0.0 {
            continue;
        }
        let dot: f32 = query.iter().zip(vector).map(|(a, b)| a * b).sum();
        let score = (dot / (query_norm * vector_norm)).clamp(-1.0, 1.0);
        // Rows are keyed by entity first, so one entity's names are adjacent.
        match best.last_mut() {
            Some(last) if last.id == id => last.score = last.score.max(score),
            _ => best.push(ScoredEntity { id, score }),
        }
    }
    crate::fusion::sort_scored_entities_desc(&mut best);
    let mut admitted = Vec::with_capacity(limit.min(best.len()));
    for scored in best {
        if admitted.len() == limit {
            break;
        }
        if admit(&scored.id)? {
            admitted.push(scored);
        }
    }
    Ok(admitted)
}

fn norm(vector: &[f32]) -> f32 {
    vector.iter().map(|value| value * value).sum::<f32>().sqrt()
}
