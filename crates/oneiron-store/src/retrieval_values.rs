//! Retrieval result values and transaction-local candidate admission contracts.

use oneiron_base::retrieval_quality::RetrievalQualityReport;
use oneiron_contracts::entity_id::EntityId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingVectorEmbedding {
    pub id: EntityId,
    pub token: Vec<u8>,
}
