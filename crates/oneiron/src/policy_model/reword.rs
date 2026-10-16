//! An overt owner-policy retry request, not an engine-authored replacement.

use serde::{Deserialize, Serialize};

use crate::error::{Error, RelayError};
use crate::gate::{self, OwnerRowAction};
use crate::store::GATE_SYSTEM_NOTICE_BODY_MAX_LEN;
use crate::{Result, Vault};

use super::{
    PolicyClassifyDecision, PolicyClassifyRequest, PolicyClassifyVerdict, PolicyContentBinding,
    PolicyModelConfig, PolicyVerdictCategory,
};

/// The owner-authored constraint disclosed to the author and the reader. The
/// author generates a new candidate in their own voice and submits it through
/// the same classify/enforce door. No retry bypasses the current policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRewordRequest {
    pub row_ref: String,
    pub constraint: String,
    pub why: Option<String>,
    pub rejected_binding: PolicyContentBinding,
}

pub(super) fn validate_reword_notice(config: &PolicyModelConfig) -> Result<()> {
    if !config.owner_reword_notice.as_deref().is_some_and(|notice| {
        !notice.trim().is_empty() && notice.len() <= GATE_SYSTEM_NOTICE_BODY_MAX_LEN
    }) {
        return Err(Error::InvalidConfig(
            "a reword row requires a bounded owner_reword_notice".into(),
        ));
    }
    Ok(())
}

impl Vault {
    pub(super) fn policy_reword_request_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        request: &PolicyClassifyRequest,
        verdict: &PolicyClassifyVerdict,
        config: &PolicyModelConfig,
    ) -> Result<Option<PolicyRewordRequest>> {
        if verdict.decision != PolicyClassifyDecision::Reword {
            return Ok(None);
        }
        validate_reword_notice(config)?;
        let PolicyVerdictCategory::OwnerPolicy { row_ref } = &verdict.category else {
            return Err(Error::Relay(RelayError::PolicyVerdictNotInForce));
        };
        let policy = gate::resolve_policy_manifest(&self.store, txn)?;
        if policy.read_frontier_hash()? != verdict.binding.read_frontier_hash {
            return Err(Error::Relay(RelayError::PolicyVerdictNotInForce));
        }
        let row = policy
            .active_owner_policy_rows_for_scope(
                request.world_ref.as_deref(),
                request.project_ref.as_deref(),
            )
            .into_iter()
            .find(|row| {
                row.row_ref == *row_ref
                    && row.action == OwnerRowAction::Reword
                    && row.human.is_none()
            })
            .ok_or(Error::Relay(RelayError::PolicyVerdictNotInForce))?;
        Ok(Some(PolicyRewordRequest {
            row_ref: row.row_ref,
            constraint: row.text,
            why: row.why.map(|why| why.text),
            rejected_binding: verdict.binding,
        }))
    }
}
