//! Actual cited pack receipts in an archive. Never terminal-stamp authority.
use crate::write_envelope::claim_body::ClaimBody;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptSourceOmission {
    NotStored,
    CredentialRedaction,
}
/// Origin remains data on an untrusted archive, never a replay capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptSourceOrigin {
    CapturedLocalTerminal,
    ImportedArchive,
}

/// Exact owning citation positions, not a recursive scan for arbitrary strings.
pub fn task_receipt_refs(claim: &ClaimBody) -> BTreeSet<String> {
    let citations = if claim.predicate
        == crate::write_envelope::learning_predicate::PREDICATE_LEARNING_RELIABILITY
    {
        claim.evidence.as_ref()
    } else if crate::write_envelope::actor_predicate::is_actor_claim_predicate(&claim.predicate) {
        let Some(Value::Map(entries)) = claim.evidence.as_ref() else {
            return BTreeSet::new();
        };
        if entries
            .iter()
            .filter(|(k, v)| k.as_str() == Some("lane") && v.as_str() == Some("task"))
            .count()
            != 1
        {
            return BTreeSet::new();
        }
        let mut matches = entries
            .iter()
            .filter(|(k, _)| k.as_str() == Some("receipts"));
        let value = matches.next().map(|(_, v)| v);
        if matches.next().is_some() {
            return BTreeSet::new();
        }
        value
    } else {
        None
    };
    let Some(Value::Array(citations)) = citations else {
        return BTreeSet::new();
    };
    citations
        .iter()
        .filter_map(|v| v.as_str())
        .filter(|v| {
            v.strip_prefix("attempt:").is_some_and(|s| {
                oneiron_contracts::entity_id::EntityId::from_hex(s).is_ok_and(|id| id.to_hex() == s)
            })
        })
        .map(str::to_owned)
        .collect()
}
pub fn invalid() -> Error {
    Error::InvalidConfig("invalid archived pack receipt source".into())
}
