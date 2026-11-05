//! An owner's purpose answer is authored content, not a label or a grant.

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::store::secret_handle_purpose::{PURPOSE, SecretHandlePurpose};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
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
    let decision_id = GateDecisionId::from_bytes(vault.store.clock.ulid()?);
    let record = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id,
        created_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
        outcome: "approved".into(),
        reason_codes: vec![if set { PURPOSE_SET } else { PURPOSE_CLEARED }.into()],
        receipt_reasons: Vec::new(),
        system_notices: crate::store::GateSystemNoticeRecord::receipt_details(
            PURPOSE_CONTENT_KIND,
            vec![
                format!("handle:{handle}"),
                format!("custody:{}", custody.to_hex()),
                if set { "action:set" } else { "action:cleared" }.to_owned(),
            ],
        ),
        actor_class: "human".into(),
        actor_ref: Some(actor.to_hex()),
        content_kind: PURPOSE_CONTENT_KIND.into(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
        claim_id: None,
        grant_ref: None,
        diff_handle: custody.as_bytes().to_vec(),
        read_frontier_hash: [0; 32],
        context: Default::default(),
        redacted_at: None,
    };
    vault.store.append_gate_decision_in_txn(txn, &record)?;
    Ok(decision_id)
}
