//! `vault.batch` (OF-181): an atomic core entity batch, the write `POST
//! /v1/core/batch` makes. Every put commits in one transaction or none
//! does. The grade it commits at is its host credential's, which no input
//! names: below owner grade, a put that turns an agent definition back on
//! is refused in the write transaction
//! ([`crate::BatchBuilder::commit_below_owner`]).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::shape::{
    CORE_MAX_BATCH_ENTITIES, CoreWriteTextField, core_write_times, stage_core_put, text_pairs,
    write_id,
};
use crate::Vault;
use crate::memory::{Memory, MemoryError, MemoryResult};

/// One entity put in a batch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreBatchEntityInput {
    /// The entity's id; a fresh one when omitted.
    #[serde(default)]
    pub id: Option<String>,
    /// The entity type byte.
    #[serde(alias = "entityType")]
    pub entity_type: u8,
    #[serde(default, alias = "occurredStart")]
    pub occurred_start: Option<u64>,
    #[serde(default, alias = "occurredEnd")]
    pub occurred_end: Option<u64>,
    #[serde(default, alias = "learnedAt")]
    pub learned_at: Option<u64>,
    pub body: Value,
    #[serde(default)]
    pub text: Option<Vec<CoreWriteTextField>>,
}

/// The puts to commit atomically, at most [`CORE_MAX_BATCH_ENTITIES`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreBatchWriteInput {
    pub entities: Vec<CoreBatchEntityInput>,
}

/// One put a batch committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreBatchEntityReceipt {
    pub id: String,
    pub entity_type: u8,
}

/// The puts a batch committed, in input order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreBatchWriteReceipt {
    pub count: usize,
    pub entities: Vec<CoreBatchEntityReceipt>,
}

/// The grade a batch commits at, which its host selects from the
/// credential that sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreBatchCommit {
    Owner,
    BelowOwner,
}

impl Vault {
    /// Stages every put of `input` and commits them once, at `commit`.
    /// # Errors
    /// Too many entities, a bad id, interval or body, or the commit's
    /// refusal; nothing is written then.
    pub fn write_core_batch(
        &self,
        input: &CoreBatchWriteInput,
        commit: CoreBatchCommit,
    ) -> MemoryResult<CoreBatchWriteReceipt> {
        if input.entities.len() > CORE_MAX_BATCH_ENTITIES {
            return Err(MemoryError::bad_request(format!(
                "entities must contain at most {CORE_MAX_BATCH_ENTITIES} entries"
            )));
        }
        let mut batch = self.batch();
        let mut entities = Vec::with_capacity(input.entities.len());
        for entity in &input.entities {
            let id = write_id(entity.id.as_deref())?;
            let times = core_write_times(
                entity.occurred_start,
                entity.occurred_end,
                entity.learned_at,
            )?;
            batch = stage_core_put(
                batch,
                &id,
                entity.entity_type,
                times,
                &entity.body,
                entity.text.as_deref().map(text_pairs),
            )?;
            entities.push(CoreBatchEntityReceipt {
                id: id.to_hex(),
                entity_type: entity.entity_type,
            });
        }
        match commit {
            CoreBatchCommit::Owner => batch.commit(),
            CoreBatchCommit::BelowOwner => batch.commit_below_owner(),
        }?;
        Ok(CoreBatchWriteReceipt {
            count: entities.len(),
            entities,
        })
    }
}

impl Memory<'_> {
    /// `vault.batch` on an embedded handle, which carries no credential
    /// grade: it commits below owner grade, never above it.
    /// # Errors
    /// As [`Vault::write_core_batch`].
    pub fn core_batch_write(
        &self,
        input: &CoreBatchWriteInput,
    ) -> MemoryResult<CoreBatchWriteReceipt> {
        self.vault()
            .write_core_batch(input, CoreBatchCommit::BelowOwner)
    }
}
