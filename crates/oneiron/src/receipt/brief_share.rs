//! The brief-share projection. Legacy federation and snapshot emitters stay separate.

use std::collections::BTreeMap;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_ACCESS_GRANT;
use crate::share::{Share, ShareAdmission, read_share_in_txn};

use super::grant::scan_entities_by_type;
use super::kernel::{FIELD_BRIEF_REF, ReceiptKind, ReceiptQuery, ReceiptRecord};

pub(super) fn brief_share_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    scan_entities_by_type(
        vault,
        txn,
        ENTITY_TYPE_ACCESS_GRANT,
        "brief share type index",
        |id, _, _| {
            let Some((share, admission)) = read_share_in_txn(&vault.store, txn, &id)? else {
                return Ok(());
            };
            let Some(gate) = vault.store.gate_decision_in_txn(txn, admission.gate_id)? else {
                return Ok(());
            };
            let trace = crate::receipt::gate_decision_receipt(&gate).policy_trace;
            let created =
                brief_share_receipt(id, &share, &admission, &trace, share.created_at, false);
            if query.matches(&created) {
                receipts.push(created);
            }
            if let Some(revoked_at) = share.revoked_at {
                let revoked = brief_share_receipt(id, &share, &admission, &trace, revoked_at, true);
                if query.matches(&revoked) {
                    receipts.push(revoked);
                }
            }
            Ok(())
        },
    )?;
    Ok(receipts)
}

fn brief_share_receipt(
    id: EntityId,
    share: &Share,
    admission: &ShareAdmission,
    trace: &[String],
    occurred_at: u64,
    revoked: bool,
) -> ReceiptRecord {
    let mut fields = BTreeMap::from([
        ("share_id".to_owned(), id.to_hex()),
        (FIELD_BRIEF_REF.to_owned(), share.brief_ref.clone()),
        ("recipient_ref".to_owned(), share.recipient_ref.to_hex()),
        ("scope".to_owned(), "shared_brief".to_owned()),
        ("world_refs".to_owned(), scope_refs(&share.world_refs)),
        ("facet_refs".to_owned(), scope_refs(&share.facet_refs)),
        (
            "include_unscoped".to_owned(),
            share.include_unscoped.to_string(),
        ),
        (
            "redaction_scope_hash".to_owned(),
            share.redaction_scope_hash(),
        ),
    ]);
    let gate_ref = format!("gate:{}", admission.gate_id.to_hex());
    fields.insert("gate_receipt_ref".to_owned(), gate_ref.clone());
    let base = format!("share:brief:{}", id.to_hex());
    ReceiptRecord {
        receipt_id: if revoked {
            format!("{base}:revoked")
        } else {
            base.clone()
        },
        receipt_kind: ReceiptKind::Share,
        occurred_at,
        actor: Some(if revoked {
            admission
                .revoker
                .unwrap_or(admission.issuer)
                .entity_ref()
                .to_hex()
        } else {
            admission.issuer.entity_ref().to_hex()
        }),
        on_behalf_of: None,
        outcome: if revoked { "revoked" } else { "granted" }.to_owned(),
        job_ref: None,
        trigger_ref: Some(base),
        policy_trace: std::iter::once(gate_ref)
            .chain(trace.iter().cloned())
            .collect(),
        fields,
    }
}

fn scope_refs(refs: &std::collections::BTreeSet<EntityId>) -> String {
    refs.iter()
        .map(EntityId::to_hex)
        .collect::<Vec<_>>()
        .join(",")
}
