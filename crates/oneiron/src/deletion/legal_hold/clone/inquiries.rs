//! An owner's hold on inquiries it sent (ARCH-0038 #company-hold).
//! Each named inquiry contributes its receipt rows, and each kept copy
//! CLAIM's delivery ledger rows. The CLAIMs themselves ride the hold's
//! Records capture. Nothing reads another vault; no transport call.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;
use oneiron_crypto::legal_clone::SourceComponent;

use crate::Vault;
use crate::authority::AuthorityVaultId;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::delivery_record::{DeliveredRow, delivered_rows_in_txn};
use crate::inquiry::{InquiryKeep, inquiry_copy_claim_id, inquiry_receipt_rows_in_txn};

/// One row of an inquiry capture, as stored.
pub(super) struct InquiryRow {
    /// The inquiry the row belongs to.
    pub(super) inquiry: [u8; 16],
    /// The row's component: receipt or delivery ledger.
    pub(super) component: SourceComponent,
    /// The row's native family label.
    pub(super) family: &'static str,
    /// The exact stored key, as sealed.
    pub(super) key: Vec<u8>,
    /// The exact stored bytes, as sealed.
    pub(super) value: Vec<u8>,
}

/// What an owner's hold on inquiries copies (ARCH-0038 #company-hold).
pub(super) struct InquiryScope {
    /// The kept copy CLAIM ids, sorted and distinct.
    pub(super) copy_claims: Vec<[u8; 16]>,
    /// The capture's rows, in inquiry id order.
    pub(super) rows: Vec<InquiryRow>,
}

/// Resolves `inquiries` to their stored rows (ARCH-0038 #company-hold).
/// In inquiry id order, each inquiry's receipts first, then each kept copy
/// CLAIM's delivery rows. A `task` receipt adds its row only, and so does a
/// receipt an actor's erase scrubbed of its member: a hold never reaches
/// past an erase. A copy CLAIM the company deleted is not kept. An inquiry
/// this vault never sent is refused. The ledger reads once.
pub(super) fn resolve_inquiries_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    inquiries: &[EntityId],
) -> Result<InquiryScope> {
    let mut sorted: Vec<EntityId> = inquiries.to_vec();
    sorted.sort();
    sorted.dedup();
    let ledger = delivered_rows_in_txn(&vault.store, txn)?;
    let mut by_record: BTreeMap<EntityId, Vec<usize>> = BTreeMap::new();
    let mut vaults: BTreeSet<AuthorityVaultId> = BTreeSet::new();
    for (index, row) in ledger.iter().enumerate() {
        by_record.entry(row.record).or_default().push(index);
        vaults.insert(row.source_vault);
    }
    let mut copy_claims: BTreeSet<[u8; 16]> = BTreeSet::new();
    let mut rows: Vec<InquiryRow> = Vec::new();
    for inquiry in &sorted {
        let receipts = inquiry_receipt_rows_in_txn(&vault.store, txn, inquiry)?;
        if receipts.is_empty() {
            return Err(Error::InvalidConfig(
                "a legal hold names an inquiry this vault never sent".into(),
            ));
        }
        for receipt in &receipts {
            rows.push(InquiryRow {
                inquiry: *inquiry.as_bytes(),
                component: SourceComponent::InquiryReceipt,
                family: "inquiry_receipt",
                key: receipt.key.clone(),
                value: receipt.value.clone(),
            });
        }
        let members: BTreeSet<EntityId> = receipts
            .iter()
            .filter(|receipt| receipt.keep == InquiryKeep::Copy)
            .filter_map(|receipt| receipt.member)
            .collect();
        // Statement k of a copy lands on CLAIM k, and each CLAIM has its own
        // ledger row, so no ordinal reaches the ledger's row count.
        let mut claims: BTreeSet<EntityId> = BTreeSet::new();
        for member in &members {
            for source_vault in &vaults {
                for ordinal in 0..ledger.len() {
                    let id = inquiry_copy_claim_id(*inquiry, *member, source_vault, ordinal)?;
                    if !by_record.contains_key(&id) {
                        break;
                    }
                    if vault.store.entities.get(txn, id.as_bytes())?.is_some() {
                        claims.insert(id);
                    }
                }
            }
        }
        for claim in &claims {
            copy_claims.insert(*claim.as_bytes());
            let mut ordered: Vec<&DeliveredRow> = by_record
                .get(claim)
                .map(|indices| indices.iter().map(|index| &ledger[*index]).collect())
                .unwrap_or_default();
            ordered.sort_by(|left, right| left.key.cmp(&right.key));
            for row in ordered {
                rows.push(InquiryRow {
                    inquiry: *inquiry.as_bytes(),
                    component: SourceComponent::DeliveryRecord,
                    family: "federation_delivered_record",
                    key: row.key.clone(),
                    value: row.value.clone(),
                });
            }
        }
    }
    Ok(InquiryScope {
        copy_claims: copy_claims.into_iter().collect(),
        rows,
    })
}
