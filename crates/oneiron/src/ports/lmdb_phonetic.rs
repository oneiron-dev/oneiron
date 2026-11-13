//! Phonetic candidate retrieval over canonical and session snapshots.
use super::query::{PHONETIC_IDS_PER_CHECKPOINT, phonetic_checkpoint};
use super::RetrievalIndexRead;
use crate::EntityId;
use crate::Vault;
use crate::entity_id::ENTITY_ID_LEN;
use crate::error::Error;
use crate::error::Result;
use crate::retrieval_depth::RetrievalDeadline;
use crate::store::ManifestDbs;
use oneiron_retrieval::pipeline::ScoredEntity;
use std::collections::HashMap;
#[derive(Default)]
struct Accumulator {
    score: f32,
    matches: usize,
}
impl<T: ManifestDbs> RetrievalIndexRead for T {
    fn port_retrieval_phonetic_search_with_deadline(
        &self,
        rtxn: &heed::RoTxn<'_>,
        codes: &[String],
        deadline: Option<&RetrievalDeadline>,
    ) -> Result<Vec<ScoredEntity>> {
        let mut unique = codes.to_vec();
        unique.sort();
        unique.dedup();

        let mut accumulators = HashMap::<EntityId, Accumulator>::new();

        for code in unique {
            phonetic_checkpoint(deadline)?;
            let key = crate::batch::phonetic_posting_key(&code);
            let Some(posting) = self.phonetic_index().get(rtxn, &key)? else {
                continue;
            };

            if !posting.len().is_multiple_of(ENTITY_ID_LEN) {
                return Err(Error::CorruptedIndex("phonetic posting"));
            }

            let (chunks, rem) = posting.as_chunks::<ENTITY_ID_LEN>();
            debug_assert!(rem.is_empty());
            for (index, bytes) in chunks.iter().enumerate() {
                if index > 0 && index.is_multiple_of(PHONETIC_IDS_PER_CHECKPOINT) {
                    phonetic_checkpoint(deadline)?;
                }
                let id = EntityId::from_bytes(*bytes)
                    .map_err(|_| Error::CorruptedIndex("phonetic posting"))?;
                let entry = accumulators.entry(id).or_default();
                entry.score += 1.0;
                entry.matches += 1;
            }
        }
        phonetic_checkpoint(deadline)?;

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
    fn port_retrieval_phonetic_search_with_deadline(
        &self,
        txn: &heed::RoTxn<'_>,
        codes: &[String],
        deadline: Option<&RetrievalDeadline>,
    ) -> Result<Vec<ScoredEntity>> {
        self.store
            .port_retrieval_phonetic_search_with_deadline(txn, codes, deadline)
    }
}
