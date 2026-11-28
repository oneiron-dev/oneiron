//! Actual cited pack receipts in an archive. Never terminal-stamp authority.
use crate::{error::Result, serialize::ExportBody, store::receipt_row::ReceiptRecord};
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
#[doc(hidden)]
use oneiron_records::batch::export::receipt_sources::invalid;
#[doc(hidden)]
pub(crate) use oneiron_records::batch::export::receipt_sources::task_receipt_refs;
#[doc(hidden)]
pub use oneiron_records::batch::export::receipt_sources::{
    ReceiptSourceOmission, ReceiptSourceOrigin,
};

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
/// The receipt sources `body` cites, each as the export reads it: an
/// archived source first, then the native receipt as the snapshot judged it
/// (`receipts`), else not stored.
pub(crate) fn receipt_sources_for_body(
    body: &ExportBody,
    receipts: &std::collections::BTreeMap<String, ExportReceiptSource>,
    archived: Option<&std::collections::BTreeMap<String, ExportReceiptSource>>,
) -> Result<Vec<ExportReceiptSource>> {
    task_receipt_refs_from_body(body)
        .into_iter()
        .map(|id| {
            // Imported history keeps its exact bound source. A coincident local
            // receipt ID cannot silently rewrite the archived claim's trace.
            if let Some(source) = archived
                .and_then(|rows| rows.get(&id))
                .or_else(|| receipts.get(&id))
            {
                return Ok(source.clone());
            }
            ExportReceiptSource::from_record(id, None)
        })
        .collect()
}

pub(super) fn task_receipt_refs_from_body(body: &ExportBody) -> BTreeSet<String> {
    body.to_bytes()
        .ok()
        .and_then(|bytes| crate::write_envelope::claim_body::decode_claim_body(&bytes, true).ok())
        .map_or_else(BTreeSet::new, |claim| task_receipt_refs(&claim))
}
