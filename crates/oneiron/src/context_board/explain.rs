//! Explain receipts (OF-278): why a memory appeared, and why a write needed
//! approval. An answer carries only what its asker may read. Memory answers
//! come from the session's served read set and the serving run's
//! telemetry; approval answers from the gate decision ledger. Neither keeps
//! a store of its own.

use super::read_set::{ServedWhy, SessionReadSet};
use crate::claim::ScopedRead;
use crate::store::{GateDecisionId, RetrievalRunId, RetrievalScoreBreakdown};
use crate::{EntityId, Result, Vault};

/// Why one memory appeared in a session.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryExplanation {
    pub id: EntityId,
    /// How the session was served it: its run and place, and its board tier.
    pub why: ServedWhy,
    /// The serving run's breakdown for this row alone: final place and score,
    /// and each signal's part. `None` when no persisted run ranked it.
    pub breakdown: Option<RetrievalScoreBreakdown>,
}

/// Why a write needed approval: one gate decision, as its asker may see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateExplanation {
    /// `gate:<hex>`, the receipt id the ledger projects.
    pub receipt_id: String,
    pub decided_at: u64,
    /// `allow`, `pending` or `deny`.
    pub outcome: String,
    pub reason_codes: Vec<String>,
    /// The policy rows and checks behind the outcome, by opaque reference.
    pub receipt_reasons: Vec<String>,
    /// Each system notice's type, and the policy row it cites.
    pub notices: Vec<(String, Option<String>)>,
    pub actor_class: String,
    /// The writer, when the asker is it, is the owner, or may read it.
    pub actor_ref: Option<String>,
    pub content_kind: String,
    pub policy_manifest_version: String,
    /// The claim the write proposed, when the asker may read it.
    pub claim_ref: Option<String>,
}

impl Vault {
    /// Why `id` appeared in the session `reads` belongs to, for `read`'s
    /// actor. `None` when the session was not served it, or `read` cannot
    /// read it now. The answer names this row's place alone, never the
    /// run's other rows.
    pub fn explain_served_memory(
        &self,
        read: &ScopedRead<'_>,
        reads: &SessionReadSet,
        id: EntityId,
    ) -> Result<Option<MemoryExplanation>> {
        let Some(why) = reads.served_why(&id.to_hex()).cloned() else {
            return Ok(None);
        };
        if !read.is_entity_readable(&id)? {
            return Ok(None);
        }
        let run = why
            .run_id
            .as_deref()
            .and_then(decode_hex16)
            .map(RetrievalRunId::from_bytes);
        let breakdown = match run {
            Some(run) => self.retrieval_run(run)?.and_then(|record| {
                record
                    .score_breakdown
                    .into_iter()
                    .find(|row| row.result_id == *id.as_bytes())
            }),
            None => None,
        };
        Ok(Some(MemoryExplanation { id, why, breakdown }))
    }

    /// Why the write behind gate receipt `receipt` (`gate:<hex>`) was decided
    /// as it was. The asker sees it when it made the write, is the vault
    /// owner, or may read the claim the write proposed in any approval state.
    /// Every ref the answer names is one it may read. `None` otherwise, the
    /// same as an unknown receipt.
    pub fn explain_gate_receipt(
        &self,
        read: &ScopedRead<'_>,
        receipt: &str,
    ) -> Result<Option<GateExplanation>> {
        let Some(bytes) = receipt.strip_prefix("gate:").and_then(decode_hex16) else {
            return Ok(None);
        };
        let txn = self.store.env.read_txn()?;
        let record = self
            .store
            .gate_decision_in_txn(&txn, GateDecisionId::from_bytes(bytes))?;
        drop(txn);
        let Some(record) = record else {
            return Ok(None);
        };
        let own = record.actor_ref.as_deref() == Some(read.actor_key().actor_ref());
        let owner = read.actor_key().reads_as_vault_owner();
        let claim = record
            .claim_id
            .and_then(|claim| EntityId::from_bytes(claim).ok());
        // A write held for approval proposed its claim: read it in any
        // approval state, as the record verbs do, never wider.
        let claim_readable = match claim {
            Some(claim) => match read.recorded_lane() {
                Ok(lane) => lane.is_entity_readable(&claim)?,
                Err(_) => read.is_entity_readable(&claim)?,
            },
            None => false,
        };
        if !(own || owner || claim_readable) {
            return Ok(None);
        }
        let actor_ref = match record.actor_ref.as_deref() {
            Some(actor) if own || owner => Some(actor.to_owned()),
            Some(actor) => match EntityId::from_hex(actor) {
                Ok(actor) if read.is_ref_readable(&actor)? => Some(actor.to_hex()),
                _ => None,
            },
            None => None,
        };
        Ok(Some(GateExplanation {
            receipt_id: format!("gate:{}", record.decision_id.to_hex()),
            decided_at: record.created_at,
            outcome: record.outcome,
            reason_codes: record.reason_codes,
            receipt_reasons: record.receipt_reasons,
            notices: record
                .system_notices
                .into_iter()
                .map(|notice| (notice.notice_type, notice.row_ref))
                .collect(),
            actor_class: record.actor_class,
            actor_ref,
            content_kind: record.content_kind,
            policy_manifest_version: record.policy_manifest_version,
            claim_ref: claim
                .filter(|_| claim_readable || owner)
                .map(|claim| claim.to_hex()),
        }))
    }
}

/// Sixteen bytes from 32 lowercase or uppercase hex digits.
fn decode_hex16(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(bytes)
}
