//! Advisory e-sign ceremony detection thresholds as vault policy values.
//! Resolution is total: an unreadable or fail-closed manifest leaves the
//! shipped thresholds in force and never refuses or holds a ceremony.

use super::policy_values::{PolicyEvaluationScope, PolicyValue, PolicyValueKey};

pub(crate) use oneiron_store::esign_rate_thresholds::EsignRateThresholds;

const SHIPPED_RECIPIENT_THRESHOLD: u64 = 120;
const SHIPPED_DOCUMENT_THRESHOLD: u64 = 1200;

const fn shipped_thresholds() -> EsignRateThresholds {
    EsignRateThresholds {
        recipient: SHIPPED_RECIPIENT_THRESHOLD,
        document: SHIPPED_DOCUMENT_THRESHOLD,
    }
}

impl super::resolution::PolicyManifestResolution {
    pub(crate) fn esign_rate_thresholds(&self) -> EsignRateThresholds {
        if self.is_fail_closed() {
            return shipped_thresholds();
        }
        let recipient = match self
            .resolved_policy_value(
                PolicyValueKey::EsignRateRecipientThreshold,
                &PolicyEvaluationScope::default(),
                PolicyValue::EsignRateRecipientThreshold(SHIPPED_RECIPIENT_THRESHOLD),
            )
            .value
        {
            PolicyValue::EsignRateRecipientThreshold(value) => value,
            _ => SHIPPED_RECIPIENT_THRESHOLD,
        };
        let document = match self
            .resolved_policy_value(
                PolicyValueKey::EsignRateDocumentThreshold,
                &PolicyEvaluationScope::default(),
                PolicyValue::EsignRateDocumentThreshold(SHIPPED_DOCUMENT_THRESHOLD),
            )
            .value
        {
            PolicyValue::EsignRateDocumentThreshold(value) => value,
            _ => SHIPPED_DOCUMENT_THRESHOLD,
        };
        EsignRateThresholds {
            recipient,
            document,
        }
    }
}

/// Resolve both advisory thresholds without making observation fallible.
pub(crate) fn esign_rate_thresholds_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
) -> EsignRateThresholds {
    match super::resolve_policy_manifest(store, txn) {
        Ok(policy) if !policy.is_fail_closed() => policy.esign_rate_thresholds(),
        Ok(_) => {
            tracing::warn!(
                "the policy manifest fails closed: shipped e-sign rate thresholds stand"
            );
            shipped_thresholds()
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                "the policy manifest did not read: shipped e-sign rate thresholds stand"
            );
            shipped_thresholds()
        }
    }
}
