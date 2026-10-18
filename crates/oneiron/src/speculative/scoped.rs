//! Credential-bound candidate admission, inside every speculative pass.
use std::sync::Arc;

use crate::claim::{ScopedReadActorKey, ScopedReadReceipt, ScopedReadResult};
use crate::corpus::CorpusScope;
use crate::error::Result;
use crate::pipeline::{FacetMode, ScoredEntity, WorldScope};
use crate::ports::EntityStoreRead;
use crate::retrieval_depth::RetrievalDeadline;

use super::{
    PassOutput, SpeculativeFinal, SpeculativePartial, SpeculativePass, SpeculativeSession,
};

#[derive(Clone)]
pub(crate) struct SpeculativeReadScope {
    pub key: ScopedReadActorKey,
    pub worlds: WorldScope,
    pub corpus: CorpusScope,
    pub facet: Option<crate::EntityId>,
    pub kinds: Option<Vec<u8>>,
}

impl SpeculativeReadScope {
    pub(super) fn run(
        &self,
        vault: &crate::Vault,
        pass: &SpeculativePass,
        deadline: Option<&RetrievalDeadline>,
    ) -> Result<PassOutput> {
        let lane = vault.scoped_read(self.key.clone());
        let (filter, policy) = lane.recall_plan()?;
        let admitted =
            |store: &crate::store::StoreRead<'_>, txn: &heed::RoTxn<'_>, id: &crate::EntityId| {
                let Some(row) = store.port_entity_record(txn, id)? else {
                    return Ok(false);
                };
                let wanted = self.kinds.as_ref().map_or_else(
                    || !crate::memory::CONTAINER_KINDS.contains(&row.entity_type),
                    |kinds| kinds.contains(&row.entity_type),
                );
                Ok(wanted && lane.recall_candidate_in(txn, &policy, &filter, id)?)
            };
        let mut builder = pass
            .builder(vault, deadline)
            .world(self.worlds.clone())
            .corpus(self.corpus.clone())
            .authority_filter(filter.clone())
            .scoped_note_reader(self.key.clone())
            .filter_candidates(&admitted);
        if let Some(facet) = &self.facet {
            builder = builder.facet(facet, FacetMode::Strict);
        }
        let mut output = pass.execute(builder, deadline)?;
        lane.end_recall_plan()?;
        output.scores = lane.filter_scored_entities(output.scores)?.value;
        Ok(output)
    }

    fn release(
        &self,
        vault: &crate::Vault,
        scores: Vec<ScoredEntity>,
    ) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        vault
            .scoped_read(self.key.clone())
            .filter_scored_entities(scores)
    }
}

impl SpeculativeSession {
    pub(crate) fn with_scope(mut self, scope: SpeculativeReadScope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// The current policy receipt of this credential-bound utterance.
    pub fn scoped_read_receipt(&self) -> Result<ScopedReadReceipt> {
        let scope = self.scope.as_ref().ok_or(crate::Error::InvalidConfig(
            "speculative session has no credential-bound read".to_owned(),
        ))?;
        self.vault
            .scoped_read(scope.key.clone())
            .read_receipt(None, 0)
    }

    /// Release only the candidates the current credential still reads. This
    /// does not run retrieval, alter the meaning signature or consume a fire.
    pub fn scoped_warm_candidates(&self) -> Result<ScopedReadResult<Vec<ScoredEntity>>> {
        let scope = self.scope.as_ref().ok_or(crate::Error::InvalidConfig(
            "speculative session has no credential-bound read".to_owned(),
        ))?;
        scope.release(&self.vault, self.warm_candidates().to_vec())
    }

    /// Finalize through OF-108, then recheck the warm/fresh candidates under
    /// current authority before releasing them, without another retrieval.
    pub fn finalize_scoped(
        self,
        partial: SpeculativePartial<'_>,
    ) -> Result<(SpeculativeFinal, ScopedReadReceipt)> {
        let scope = self.scope.clone().ok_or(crate::Error::InvalidConfig(
            "speculative session has no credential-bound read".to_owned(),
        ))?;
        let vault = Arc::clone(&self.vault);
        let output = self.finalize(partial)?;
        match output {
            SpeculativeFinal::Promoted {
                scores,
                run_id,
                partial,
            } => {
                let released = scope.release(&vault, scores)?;
                Ok((
                    SpeculativeFinal::Promoted {
                        scores: released.value,
                        run_id,
                        partial,
                    },
                    released.receipt,
                ))
            }
            SpeculativeFinal::Finalized {
                scores,
                run_id,
                warm_appended,
                partial,
            } => {
                let released = scope.release(&vault, scores)?;
                Ok((
                    SpeculativeFinal::Finalized {
                        scores: released.value,
                        run_id,
                        warm_appended,
                        partial,
                    },
                    released.receipt,
                ))
            }
        }
    }
}
