//! Actual cited pack receipts in an archive. Never terminal-stamp authority.
use crate::{
    claim::ClaimBody,
    error::{Error, Result},
    receipt::ReceiptRecord,
    serialize::ExportBody,
};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExportReceiptSource {
    Preserved {
        receipt_id: String,
        /// This describes capture location, not authenticated claim grounding.
        origin: ReceiptSourceOrigin,
        body: ExportBody,
    },
    Unavailable {
        receipt_id: String,
        reason: ReceiptSourceOmission,
    },
}
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

impl ExportReceiptSource {
    pub(crate) fn as_imported_archive(&self) -> Self {
        match self {
            Self::Preserved {
                receipt_id, body, ..
            } => Self::Preserved {
                receipt_id: receipt_id.clone(),
                body: body.clone(),
                origin: ReceiptSourceOrigin::ImportedArchive,
            },
            Self::Unavailable { .. } => self.clone(),
        }
    }

    #[must_use]
    pub fn receipt_id(&self) -> &str {
        match self {
            Self::Preserved { receipt_id, .. } | Self::Unavailable { receipt_id, .. } => receipt_id,
        }
    }
    /// Reads untrusted archive evidence; this does not resolve on the local receipt ledger.
    ///
    /// # Errors
    /// Returns an error when the archive source is malformed or has mismatched identity.
    pub fn record(&self) -> Result<Option<ReceiptRecord>> {
        self.validate()?;
        match self {
            Self::Preserved { body, .. } => rmp_serde::from_slice(&body.to_bytes()?)
                .map(Some)
                .map_err(|_| invalid()),
            Self::Unavailable { .. } => Ok(None),
        }
    }
    pub(crate) fn from_record(receipt_id: String, record: Option<&ReceiptRecord>) -> Result<Self> {
        let Some(record) = record else {
            return Ok(Self::Unavailable {
                receipt_id,
                reason: ReceiptSourceOmission::NotStored,
            });
        };
        if record.receipt_id != receipt_id {
            return Err(invalid());
        }
        let bytes = rmp_serde::to_vec_named(record).map_err(|_| invalid())?;
        let body = ExportBody::from_bytes(&bytes, crate::registry::ENTITY_TYPE_ASSET);
        let roundtrip = body
            .to_bytes()
            .ok()
            .and_then(|bytes| rmp_serde::from_slice::<ReceiptRecord>(&bytes).ok());
        // If any field needed nulling, don't misdescribe the result as the
        // actual receipt. The archive makes the precise missing source visible.
        if roundtrip.as_ref() != Some(record) {
            return Ok(Self::Unavailable {
                receipt_id,
                reason: ReceiptSourceOmission::CredentialRedaction,
            });
        }
        Ok(Self::Preserved {
            receipt_id,
            origin: ReceiptSourceOrigin::CapturedLocalTerminal,
            body,
        })
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let Some(id) = self.receipt_id().strip_prefix("attempt:") else {
            return Err(invalid());
        };
        if crate::EntityId::from_hex(id)?.to_hex() != id {
            return Err(invalid());
        }
        if let Self::Preserved {
            receipt_id, body, ..
        } = self
        {
            body.validate(crate::registry::ENTITY_TYPE_ASSET)?;
            let record: ReceiptRecord =
                rmp_serde::from_slice(&body.to_bytes()?).map_err(|_| invalid())?;
            if record.receipt_id != *receipt_id {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
/// Exact owning citation positions, not a recursive scan for arbitrary strings.
pub(crate) fn task_receipt_refs(claim: &ClaimBody) -> BTreeSet<String> {
    let citations = if claim.predicate == crate::skill_reliability::PREDICATE_SKILL_RELIABILITY {
        claim.evidence.as_ref()
    } else if crate::actor_claims::is_actor_claim_predicate(&claim.predicate) {
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
            v.strip_prefix("attempt:")
                .is_some_and(|s| crate::EntityId::from_hex(s).is_ok_and(|id| id.to_hex() == s))
        })
        .map(str::to_owned)
        .collect()
}
fn invalid() -> Error {
    Error::InvalidConfig("invalid archived pack receipt source".into())
}

pub(crate) fn receipt_sources_for_body(
    body: &ExportBody,
    receipts: &std::collections::BTreeMap<String, ReceiptRecord>,
    archived: Option<&std::collections::BTreeMap<String, ExportReceiptSource>>,
) -> Result<Vec<ExportReceiptSource>> {
    task_receipt_refs_from_body(body)
        .into_iter()
        .map(|id| {
            let record = receipts.get(&id);
            if record.is_none()
                && let Some(source) = archived.and_then(|rows| rows.get(&id))
            {
                return Ok(source.clone());
            }
            ExportReceiptSource::from_record(id, record)
        })
        .collect()
}

pub(super) fn task_receipt_refs_from_body(body: &ExportBody) -> BTreeSet<String> {
    body.to_bytes()
        .ok()
        .and_then(|bytes| crate::claim::decode_claim_body(&bytes, true).ok())
        .map_or_else(BTreeSet::new, |claim| task_receipt_refs(&claim))
}
