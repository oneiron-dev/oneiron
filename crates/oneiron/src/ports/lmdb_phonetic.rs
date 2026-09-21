//! Phonetic candidate retrieval over canonical and session snapshots.
use super::RetrievalIndexRead;
use crate::entity_id::ENTITY_ID_LEN;
use crate::{
    EntityId, Vault,
    error::{Error, Result},
    pipeline::ScoredEntity,
    store::ManifestDbs,
};
use std::collections::HashMap;
#[derive(Default)]
struct Accumulator {
    score: f32,
    matches: usize,
}
impl<T: ManifestDbs> RetrievalIndexRead for T {
    fn port_retrieval_phonetic_search(
        &self,
        rtxn: &heed::RoTxn<'_>,
        codes: &[String],
    ) -> Result<Vec<ScoredEntity>> {
        let mut unique = codes.to_vec();
        unique.sort();
        unique.dedup();

        let mut accumulators = HashMap::<EntityId, Accumulator>::new();

        for code in unique {
            let Some(posting) = self.phonetic_index().get(rtxn, code.as_bytes())? else {
                continue;
            };

            if !posting.len().is_multiple_of(ENTITY_ID_LEN) {
                return Err(Error::CorruptedIndex("phonetic posting"));
            }

            let (chunks, rem) = posting.as_chunks::<ENTITY_ID_LEN>();
            debug_assert!(rem.is_empty());
            for bytes in chunks {
                let id = EntityId::from_bytes(*bytes)
                    .map_err(|_| Error::CorruptedIndex("phonetic posting"))?;
                let entry = accumulators.entry(id).or_default();
                entry.score += 1.0;
                entry.matches += 1;
            }
        }

        let mut out: Vec<ScoredEntity> = accumulators
            .into_iter()
            .map(|(id, accumulator)| {
                let boosted = if accumulator.matches >= 2 {
                    accumulator.score * 1.2
                } else {
                    accumulator.score
                };
                ScoredEntity { id, score: boosted }
            })
            .collect();

        crate::fusion::sort_scored_entities_desc(&mut out);
        Ok(out)
    }
}
impl RetrievalIndexRead for Vault {
    fn port_retrieval_phonetic_search(
        &self,
        txn: &heed::RoTxn<'_>,
        codes: &[String],
    ) -> Result<Vec<ScoredEntity>> {
        self.store.port_retrieval_phonetic_search(txn, codes)
    }
}
