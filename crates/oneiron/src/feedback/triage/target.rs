//! Queue inputs retain only the original opaque handoff key after an erase.
use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::{
    FeedbackTriageHandoff, FeedbackTriageSourceRef, HANDOFFS, erased, handoff_in_txn, handoff_key,
    invalid_job,
};
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::store::Store;
use crate::{EntityId, Error, Result, Vault};

#[derive(Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Target {
    Retained {
        source_ref: FeedbackTriageSourceRef,
        evidence: EntityId,
    },
    Erased {
        handoff: [u8; 32],
    },
}

impl Target {
    pub(super) fn decode(input: &Value) -> Result<Self> {
        rmpv::ext::from_value(input.clone()).map_err(|_| invalid_job())
    }

    pub(super) fn encode(&self) -> Result<Value> {
        rmpv::ext::to_value(self).map_err(|_| invalid_job())
    }

    pub(super) fn retained(self) -> Result<(FeedbackTriageSourceRef, EntityId)> {
        match self {
            Self::Retained {
                source_ref,
                evidence,
            } => Ok((source_ref, evidence)),
            Self::Erased { .. } => Err(invalid_job()),
        }
    }

    pub(super) fn handoff_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<FeedbackTriageHandoff> {
        match self {
            Self::Retained {
                source_ref,
                evidence,
            } => {
                let handoff = handoff_in_txn(vault, txn, source_ref)?
                    .ok_or(Error::CorruptedIndex("feedback triage handoff missing"))?;
                if let Ok((_, retained)) = handoff.retained()
                    && retained != *evidence
                {
                    return Err(invalid_job());
                }
                Ok(handoff)
            }
            Self::Erased { handoff: key } => {
                let handoff = HANDOFFS
                    .get(&vault.store, txn, key)?
                    .ok_or(Error::CorruptedIndex("feedback triage handoff missing"))?;
                if !erased::evidence_erased_in_txn(vault, txn, &handoff)? {
                    return Err(invalid_job());
                }
                Ok(handoff)
            }
        }
    }

    fn erase_in_txn(
        &mut self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        only_evidence: Option<EntityId>,
    ) -> Result<bool> {
        match self {
            Self::Erased { .. } => Ok(only_evidence.is_none()),
            Self::Retained {
                source_ref,
                evidence,
            } => {
                if only_evidence.is_some_and(|id| id != *evidence) {
                    return Ok(false);
                }
                if !store.port_deletion_marked(txn, DeletionMarker::HardDelete, evidence)? {
                    return Ok(false);
                }
                *self = Self::Erased {
                    handoff: handoff_key(source_ref),
                };
                Ok(true)
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NodeInput {
    pub(super) target: Target,
    pub(super) generation: u32,
    pub(super) node: u32,
}

impl NodeInput {
    pub(super) fn decode(input: &Value) -> Result<Self> {
        rmpv::ext::from_value(input.clone()).map_err(|_| invalid_job())
    }
}

/// A valid triage input in its erased form, or None when it names no erased
/// evidence. Malformed inputs establish no source; marker/read errors propagate.
pub(crate) fn erased_queue_input_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    facet: &str,
    input: &Value,
    only_evidence: Option<EntityId>,
) -> Result<Option<Value>> {
    if facet == super::COACH_FEEDBACK_TRIAGE_FACET {
        let Ok(mut target) = Target::decode(input) else {
            return Ok(None);
        };
        return if target.erase_in_txn(store, txn, only_evidence)? {
            target.encode().map(Some)
        } else {
            Ok(None)
        };
    }
    if matches!(
        facet,
        super::COACH_FEEDBACK_TRIAGE_PART_FACET | super::COACH_FEEDBACK_TRIAGE_SYNTHESIS_FACET
    ) {
        let Ok(mut node) = NodeInput::decode(input) else {
            return Ok(None);
        };
        if node.target.erase_in_txn(store, txn, only_evidence)? {
            return rmpv::ext::to_value(node)
                .map(Some)
                .map_err(|_| invalid_job());
        }
    }
    Ok(None)
}
