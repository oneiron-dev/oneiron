//! ARCH-0038 deletion/redaction contract types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::EntityId;

pub(crate) const HARD_ERASE_SWEEP_PREFIX: &[u8] = b"h:";
pub(crate) const LAST_HARD_ERASE_SWEEP_SEQ_KEY: &[u8] = b"m:last_hard_erase_sweep_seq";
pub(crate) const HARD_ERASE_SWEEP_SLA_SECS: u64 = 30 * 86_400;

const HISTORICAL_CARRIER_CLASSES: &[&str] = &[
    "historical_loro_updates",
    "historical_loro_snapshots",
    "derived_carriers",
];

/// CROSS-ARCH-0002a / ARCH-0038 delete reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeleteReason {
    UserDelete,
    UserHardDelete,
    GdprDelete,
    PolicyDelete,
}

impl DeleteReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserDelete => "user_delete",
            Self::UserHardDelete => "user_hard_delete",
            Self::GdprDelete => "gdpr_delete",
            Self::PolicyDelete => "policy_delete",
        }
    }

    pub(crate) const fn writes_receipt(self) -> bool {
        !matches!(self, Self::UserDelete)
    }

    pub(crate) const fn active_store_hard_purge_v1(self) -> bool {
        !matches!(self, Self::UserDelete)
    }

    pub(crate) const fn queues_historical_sweep(self) -> bool {
        !matches!(self, Self::UserDelete)
    }
}

/// Result for a reason-aware delete request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteEntityOutcome {
    pub existed: bool,
    pub receipt_id: Option<EntityId>,
    pub sweep_key: Option<Vec<u8>>,
}

impl DeleteEntityOutcome {
    pub(crate) const fn missing() -> Self {
        Self {
            existed: false,
            receipt_id: None,
            sweep_key: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RedactionScope {
    pub entity_ids: Vec<String>,
    pub revision_ids: Vec<String>,
}

impl RedactionScope {
    pub(crate) fn entity(entity_id: &EntityId) -> Self {
        Self {
            entity_ids: vec![entity_id.to_hex()],
            revision_ids: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize)]
struct RedactionAuditReceipt {
    request_id: String,
    scope: RedactionScope,
    reason: String,
    requested_at: u64,
    soft_complete_at: u64,
    hard_purge_complete_at: u64,
    sweep_queued_at: Option<u64>,
    sweep_complete_at: Option<u64>,
    affected_revision_ids: Vec<String>,
    verification: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct HardEraseSweepJob {
    scope: HardEraseSweepScope,
    retry_state: HardEraseRetryState,
}

#[derive(Debug, Serialize)]
struct HardEraseSweepScope {
    entity_ids: Vec<String>,
    revision_ids: Vec<String>,
    carrier_classes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HardEraseRetryState {
    attempt_count: u32,
    next_attempt_at: u64,
    last_error_code: Option<String>,
    queued_at: u64,
    deadline_at: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct RedactionReceiptInput {
    pub request_id: String,
    pub scope: RedactionScope,
    pub reason: DeleteReason,
    pub requested_at: u64,
    pub soft_complete_at: u64,
    pub hard_purge_complete_at: u64,
    pub sweep_queued_at: Option<u64>,
}

pub(crate) fn encode_redaction_audit_receipt(input: RedactionReceiptInput) -> Result<Vec<u8>> {
    let receipt = RedactionAuditReceipt {
        request_id: input.request_id,
        scope: input.scope,
        reason: input.reason.as_str().to_owned(),
        requested_at: input.requested_at,
        soft_complete_at: input.soft_complete_at,
        hard_purge_complete_at: input.hard_purge_complete_at,
        sweep_queued_at: input.sweep_queued_at,
        sweep_complete_at: None,
        affected_revision_ids: Vec::new(),
        verification: BTreeMap::new(),
    };
    rmp_serde::to_vec_named(&receipt)
        .map_err(|_| Error::InvariantViolation("redaction audit receipt encode"))
}

pub(crate) fn encode_hard_erase_sweep_job(
    scope: RedactionScope,
    queued_at: u64,
) -> Result<Vec<u8>> {
    let job = HardEraseSweepJob {
        scope: HardEraseSweepScope {
            entity_ids: scope.entity_ids,
            revision_ids: scope.revision_ids,
            carrier_classes: HISTORICAL_CARRIER_CLASSES
                .iter()
                .map(|class| (*class).to_owned())
                .collect(),
        },
        retry_state: HardEraseRetryState {
            attempt_count: 0,
            next_attempt_at: queued_at,
            last_error_code: None,
            queued_at,
            deadline_at: queued_at.saturating_add(HARD_ERASE_SWEEP_SLA_SECS),
        },
    };
    rmp_serde::to_vec_named(&job)
        .map_err(|_| Error::InvariantViolation("hard erase sweep job encode"))
}

pub(crate) fn encode_hard_erase_sweep_key(seq: u64) -> [u8; 10] {
    let mut key = [0_u8; 10];
    key[..2].copy_from_slice(HARD_ERASE_SWEEP_PREFIX);
    key[2..].copy_from_slice(&seq.to_be_bytes());
    key
}

pub(crate) fn decode_hard_erase_sweep_seq(key: &[u8]) -> Option<u64> {
    if key.len() != 10 || !key.starts_with(HARD_ERASE_SWEEP_PREFIX) {
        return None;
    }
    Some(u64::from_be_bytes(key[2..10].try_into().ok()?))
}
