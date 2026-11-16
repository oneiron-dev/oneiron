//! Moved from `crates/oneiron/src/ingest/audience.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::model_decision::DecisionQuestion;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Who a topic's later imports are shared with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImportAudience {
    /// Only the owner.
    OnlyMe,
    /// Whoever the source itself shared the conversation with.
    Source,
    /// One of the owner's projects.
    Project { project: EntityId },
}

/// One option of an owner ask, frozen when it was asked: a later rename never makes
/// the same label pick another project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportAudienceOption {
    pub label: String,
    pub audience: ImportAudience,
}

/// Where one topic cluster stands.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImportAudienceState {
    /// The sensitivity read found the topic not sensitive: no owner ask.
    Clear,
    /// The owner was asked; ask `seq` carries `question` over `evidence`, and each of
    /// the question's options maps to one audience.
    Asked {
        seq: u64,
        question: DecisionQuestion,
        evidence: Vec<EntityId>,
        options: Vec<ImportAudienceOption>,
    },
    /// The owner's answer stands as the `disclosure.import_audience` CLAIM `rule`.
    Settled {
        seq: u64,
        rule: EntityId,
        audience: ImportAudience,
    },
}

/// One topic cluster of imported claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportAudienceCluster {
    pub topic: EntityId,
    /// The topic as a question shows it.
    pub label: String,
    /// Every claim seen in the topic.
    pub claims: BTreeSet<EntityId>,
    /// Every import review those claims came from: the batches a later rule never
    /// widens.
    pub reviews: BTreeSet<String>,
    pub state: ImportAudienceState,
}
