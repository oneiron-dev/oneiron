//! An owner's purpose answer is authored content, not a label or a grant.

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::store::gate_reason::GateReceiptOutcome;
use crate::store::secret_handle_purpose::{PURPOSE, SecretHandlePurpose};
use crate::store::{GateDecisionId, GateReceipt, PolicyBasis, ReceiptActor};
use crate::{EntityId, Vault};

const PURPOSE_SET: &str = "gate.secret.handle_purpose.set";
const PURPOSE_CLEARED: &str = "gate.secret.handle_purpose.cleared";
const PURPOSE_CONTENT_KIND: &str = "secret_handle_purpose";

/// The actual stored purpose, or a clear, and its owner-act receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretHandlePurposeSet {
    pub purpose: Option<String>,
    pub receipt: String,
}

/// A value-free purpose question derived from a newly found key's notice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretPurposeQuestion {
    pub record: EntityId,
    pub handle: String,
    pub name: String,
    pub label: Option<String>,
    pub suggested_label: Option<String>,
    pub kind: String,
    pub place: String,
    pub found_at: u64,
}

impl Vault {
    /// Reads only purpose metadata under the current owner's proof.
    pub fn secret_handle_purpose(
        &self,
        owner: &AuthenticatedOwner,
        handle: &str,
    ) -> Result<Option<SecretHandlePurposeSet>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let (_, custody) = super::reveal::resolve_handle_in_txn(&self.store, &txn, handle)?;
        Ok(PURPOSE
            .get(&self.store, &txn, &custody)?
            .map(|row| SecretHandlePurposeSet {
                purpose: Some(row.purpose),
                receipt: format!("gate:{}", GateDecisionId::from_bytes(row.receipt).to_hex()),
            }))
    }

    /// Sets freeform purpose text through the authored side-row wall. None
    /// or whitespace-only text clears the answer. Other text is preserved,
    /// including line breaks; no label-size limit applies. The returned text
    /// is what the wall actually stored, never an unmasked input copy.
    /// This does not rename, reveal, grant, or settle a found-key disposition.
    pub fn set_secret_handle_purpose(
        &self,
        owner: &AuthenticatedOwner,
        handle: &str,
        purpose: Option<&str>,
    ) -> Result<SecretHandlePurposeSet> {
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let (handle, custody) = super::reveal::resolve_handle_in_txn(&self.store, txn, handle)?;
            let purpose = purpose.filter(|text| !text.trim().is_empty());
            let decision =
                append_purpose_ruling(self, txn, actor, &handle, &custody, purpose.is_some())?;
            let receipt = format!("gate:{}", decision.to_hex());
            let purpose = if let Some(text) = purpose {
                PURPOSE.put(
                    self,
                    txn,
                    &custody,
                    &SecretHandlePurpose {
                        purpose: text.to_owned(),
                        receipt: decision.as_bytes(),
                    },
                )?;
                Some(
                    PURPOSE
                        .get(&self.store, txn, &custody)?
                        .ok_or(Error::InvariantViolation("stored handle purpose missing"))?
                        .purpose,
                )
            } else {
                crate::store::secret_handle_purpose::erase_secret_handle_purpose_in_txn(
                    self, txn, &custody,
                )?;
                None
            };
            Ok(SecretHandlePurposeSet { purpose, receipt })
        })
    }
}

fn append_purpose_ruling(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    actor: EntityId,
    handle: &str,
    custody: &EntityId,
    set: bool,
) -> Result<GateDecisionId> {
    let mut receipt = GateReceipt::new(
        GateReceiptOutcome::Approved,
        PURPOSE_CONTENT_KIND,
        if set { PURPOSE_SET } else { PURPOSE_CLEARED },
        ReceiptActor::human(actor),
        custody.as_bytes().to_vec(),
        PolicyBasis::NOT_READ,
    );
    receipt.details = vec![
        format!("handle:{handle}"),
        format!("custody:{}", custody.to_hex()),
        if set { "action:set" } else { "action:cleared" }.to_owned(),
    ];
    Ok(vault
        .store
        .record_gate_receipt_in_txn(txn, receipt)?
        .decision_id)
}
