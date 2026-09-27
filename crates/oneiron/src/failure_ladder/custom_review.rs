//! Vault-local custom-agent failure index and content-free health projection.
//!
//! The producer supplies the observability taxonomy class. It is deliberately
//! distinct from the three-way retry/healer routing class: a retry verdict
//! cannot truthfully infer whether the user saw a memory miss or a refusal.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::agent_dispatch::{AGENT_DISPATCH_ATTEMPT_TYPE, decode_agent_dispatch_input};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_AGENT_DEF;

const PREFIX: &[u8] = b"custom-agent:failure:v1:";
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

fn key(id: AttemptId) -> Vec<u8> {
    [PREFIX, id.as_bytes()].concat()
}

fn invalid() -> Error {
    Error::InvalidConfig("custom-agent failure requires a failed custom-agent dispatch".into())
}

fn custom_agent_ref(record: &AttemptRecord) -> Result<crate::entity_id::EntityId> {
    if record.state != AttemptState::Failed || record.kind != DREAMER_RUNNER_ATTEMPT_KIND {
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

impl Vault {
    /// Indexes one already-failed custom dispatch under its producer-supplied
    /// taxonomy class. Same-class repeats are idempotent; conflicting reports
    /// fail closed. This does not invent a taxonomy label from a retry verdict.
    ///
    /// # Errors
    /// Rejects absent/nonfailed/noncustom rows, conflicting classification,
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
            let key = key(attempt_id);
            if let Some(existing) = self.store.vault_meta.get(txn, &key)? {
                if existing.as_ref() == [VERSION, class as u8] {
                    return Ok(());
                }
                return Err(Error::InvalidConfig(
                    "conflicting custom-agent failure class".into(),
                ));
            }
            self.store
                .vault_meta
                .put(txn, &key, &[VERSION, class as u8])?;
            Ok(())
        })
    }

    /// Returns class counts and attempt refs from THIS vault only, in stable
    /// taxonomy order and attempt-id order. No off-vault/global scan occurs.
    ///
    /// # Errors
    /// Fails closed on corrupt index values or dangling/nonfailed members.
    pub fn custom_agent_failure_groups(&self) -> Result<Vec<CustomFailureGroup>> {
        let txn = self.store.env.read_txn()?;
        let queue = AttemptQueue::new(self);
        let mut groups: BTreeMap<FailureSignalClass, Vec<AttemptId>> = BTreeMap::new();
        for item in self.store.vault_meta.prefix_iter(&txn, PREFIX)? {
            let (key, bytes) = item?;
            let id = AttemptId::from_bytes(
                key.get(PREFIX.len()..)
                    .ok_or(Error::CorruptedIndex("custom-agent failure"))?,
            )
            .map_err(|_| Error::CorruptedIndex("custom-agent failure"))?;
            let class = match bytes.as_ref() {
                [VERSION, 0] => FailureSignalClass::RefusalOverreach,
                [VERSION, 1] => FailureSignalClass::TaskFailure,
                [VERSION, 2] => FailureSignalClass::UserFrustration,
                [VERSION, 3] => FailureSignalClass::MemoryMiss,
                [VERSION, 4] => FailureSignalClass::MemoryIntrusion,
                [VERSION, 5] => FailureSignalClass::PersonaBreak,
                [VERSION, 6] => FailureSignalClass::LatencyAbandon,
                [VERSION, 7] => FailureSignalClass::SilentDegradation,
                [VERSION, 8] => FailureSignalClass::Other,
                _ => return Err(Error::CorruptedIndex("custom-agent failure")),
            };
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
