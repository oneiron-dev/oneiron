//! Vault-local custom-agent failure index and content-free health projection.
//!
//! The producer supplies the observability taxonomy class. It is deliberately
//! distinct from the three-way retry/healer routing class: a retry verdict
//! cannot truthfully infer whether the user saw a memory miss or a refusal.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::agent_dispatch::{AGENT_DISPATCH_ATTEMPT_TYPE, decode_agent_dispatch_input};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

const FAILURE: SideTable<[u8; 16], FailureSignalClass, Raw> =
    SideTable::new(&side_table::CUSTOM_AGENT_FAILURE);
const VERSION: u8 = 1;

/// Version-one agent observability taxonomy; not the failure ladder's routing class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum FailureSignalClass {
    RefusalOverreach,
    TaskFailure,
    UserFrustration,
    MemoryMiss,
    MemoryIntrusion,
    PersonaBreak,
    LatencyAbandon,
    SilentDegradation,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    System,
    Custom,
}

/// Local review members are attempt refs; no transcript or receipt is exported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomFailureGroup {
    pub class: FailureSignalClass,
    pub count: u64,
    pub member_refs: Vec<AttemptId>,
}

/// Content-free tier-1 projection. The local member refs never cross this door.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierOneFailureCount {
    pub taxonomy_version: u8,
    pub agent_kind: AgentKind,
    pub class: FailureSignalClass,
    pub count: u64,
}

impl RawValue for FailureSignalClass {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(vec![VERSION, *self as u8])
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        match bytes {
            [VERSION, 0] => Ok(Self::RefusalOverreach),
            [VERSION, 1] => Ok(Self::TaskFailure),
            [VERSION, 2] => Ok(Self::UserFrustration),
            [VERSION, 3] => Ok(Self::MemoryMiss),
            [VERSION, 4] => Ok(Self::MemoryIntrusion),
            [VERSION, 5] => Ok(Self::PersonaBreak),
            [VERSION, 6] => Ok(Self::LatencyAbandon),
            [VERSION, 7] => Ok(Self::SilentDegradation),
            [VERSION, 8] => Ok(Self::Other),
            _ => Err(Error::CorruptedIndex("custom-agent failure").into()),
        }
    }
}

fn row_error(error: Error) -> Error {
    match error {
        Error::Store(crate::error::StoreError::SideTableRow { .. }) => {
            Error::CorruptedIndex("custom-agent failure")
        }
        other => other,
    }
}

fn invalid() -> Error {
    Error::InvalidConfig("custom-agent failure requires a terminal custom-agent dispatch".into())
}

fn custom_agent_ref(record: &AttemptRecord) -> Result<crate::entity_id::EntityId> {
    // Observability classifies outcomes, not the queue's execution result. A
    // successful run may miss memory or break persona; an abandoned or
    // cancelled run may still have produced a latency-abandon signal. Only
    // terminal rows qualify, so an in-flight signal cannot be indexed early.
    if !record.state.is_terminal() || record.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return Err(invalid());
    }
    let payload = decode_dreamer_attempt_payload(&record.payload).map_err(|_| invalid())?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return Err(invalid());
    }
    let input = decode_agent_dispatch_input(&payload.input).map_err(|_| invalid())?;
    if input.definition.logical_id.is_some() {
        return Err(invalid());
    }
    input.target.agent_definition_ref().map_err(|_| invalid())
}

/// Point-check a caller-selected member and class on the SAME snapshot used
/// for owner validation. A stale group result cannot turn into a read of an
/// unrelated attempt. The terminal dispatch snapshot is the historical
/// identity proof: deletion of the live definition does not delete its trace.
pub(super) fn member_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt_id: AttemptId,
    class: FailureSignalClass,
) -> Result<AttemptRecord> {
    let Some(indexed) = FAILURE.get_bytes(&vault.store, txn, attempt_id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    if indexed.as_slice() != [VERSION, class as u8] {
        return Err(Error::EntityNotFound);
    }
    let record = AttemptQueue::new(vault)
        .get_in_txn(txn, attempt_id)?
        .ok_or(Error::CorruptedIndex("custom-agent failure"))?;
    custom_agent_ref(&record).map_err(|_| Error::CorruptedIndex("custom-agent failure"))?;
    Ok(record)
}

impl Vault {
    /// Indexes one terminal custom dispatch under its producer-supplied
    /// taxonomy class, without changing its execution outcome. Same-class
    /// repeats are idempotent; conflicting reports fail closed. This does not
    /// invent a taxonomy label from a retry verdict.
    ///
    /// # Errors
    /// Rejects absent/nonterminal/noncustom rows, conflicting classification,
    /// or a target that is not a live custom AGENT_DEF in this vault.
    pub fn record_custom_agent_failure(
        &self,
        attempt_id: AttemptId,
        class: FailureSignalClass,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            let record = AttemptQueue::new(self)
                .get_in_write_txn(txn, attempt_id)?
                .ok_or_else(invalid)?;
            let agent_ref = custom_agent_ref(&record)?;
            // A queue payload is caller-writable. Confirm its classification
            // against the live definition, rather than trusting its snapshot.
            let live = crate::vault::live_entity_row_in_txn(&self.store, txn, &agent_ref)?;
            let crate::vault::LiveEntityRow::Live { entity_type, body } = live else {
                return Err(invalid());
            };
            if entity_type != ENTITY_TYPE_AGENT_DEF
                || crate::agent_def::decode_agent_definition(&body)?
                    .logical_id
                    .is_some()
            {
                return Err(invalid());
            }
            let key = *attempt_id.as_bytes();
            if let Some(existing) = FAILURE.get_bytes(&self.store, txn, &key)? {
                if existing.as_slice() == [VERSION, class as u8] {
                    return Ok(());
                }
                return Err(Error::InvalidConfig(
                    "conflicting custom-agent failure class".into(),
                ));
            }
            FAILURE.put(&self.store, txn, &key, &class)?;
            Ok(())
        })
    }

    /// Returns class counts and attempt refs from THIS vault only, in stable
    /// taxonomy order and attempt-id order. No off-vault/global scan occurs.
    ///
    /// # Errors
    /// Fails closed on corrupt index values or dangling/nonterminal members.
    pub fn custom_agent_failure_groups(&self) -> Result<Vec<CustomFailureGroup>> {
        let txn = self.store.env.read_txn()?;
        let queue = AttemptQueue::new(self);
        let mut groups: BTreeMap<FailureSignalClass, Vec<AttemptId>> = BTreeMap::new();
        for item in FAILURE.iter_from(&self.store, &txn, &[])? {
            let (key, class) = item.map_err(row_error)?;
            let id = AttemptId::from_bytes(&key)
                .map_err(|_| Error::CorruptedIndex("custom-agent failure"))?;
            let record = queue
                .get_in_txn(&txn, id)?
                .ok_or(Error::CorruptedIndex("custom-agent failure"))?;
            custom_agent_ref(&record).map_err(|_| Error::CorruptedIndex("custom-agent failure"))?;
            groups.entry(class).or_default().push(id);
        }
        Ok(groups
            .into_iter()
            .map(|(class, member_refs)| CustomFailureGroup {
                class,
                count: member_refs.len() as u64,
                member_refs,
            })
            .collect())
    }

    /// Health projection without member refs or vault-local detail.
    ///
    /// # Errors
    /// Propagates corrupt local index errors instead of publishing partial counts.
    pub fn custom_agent_tier_one_counts(&self) -> Result<Vec<TierOneFailureCount>> {
        Ok(self
            .custom_agent_failure_groups()?
            .into_iter()
            .map(|group| TierOneFailureCount {
                taxonomy_version: VERSION,
                agent_kind: AgentKind::Custom,
                class: group.class,
                count: group.count,
            })
            .collect())
    }
}
