//! Append-only equal-holder rulings and deterministic newest-wins projection.
use super::{FederationGrantScope, decode_federation_grant_body};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::{EntityId, Vault};
use serde_json::Value;
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRuling {
    pub id: String,
    pub holder: String,
    pub grant_ref: String,
    pub vault_id: u64,
    pub key: String,
    pub value: Value,
    pub learned_at: u64,
    pub ledger_order: u64,
}
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRulingReceipt {
    pub ruling: AdminRuling,
    pub previous_ruling: Option<String>,
    pub previous_holder: Option<String>,
    pub previous_value: Option<Value>,
}
fn prefix(vault_id: u64) -> Vec<u8> {
    format!("shared-ruling:v1:{vault_id:016x}:").into_bytes()
}
fn invalid() -> Error {
    Error::InvalidConfig("invalid shared-vault ruling".into())
}
/// Total ledger order, independent of the order in which concurrent entries are folded.
pub fn fold_admin_rulings<'a>(
    rows: &'a [AdminRuling],
    vault_id: u64,
    key: &str,
) -> Option<&'a AdminRuling> {
    rows.iter()
        .filter(|row| row.vault_id == vault_id && row.key == key)
        .max_by_key(|row| (row.ledger_order, &row.id))
}
impl Vault {
    /// Human authentication and a live stored administrative grant are both required.
    pub fn append_admin_ruling(
        &self,
        holder: &AuthenticatedOwner,
        vault_id: u64,
        key: &str,
        value: Value,
        now: u64,
    ) -> Result<AdminRulingReceipt> {
        if key.trim().is_empty() || key.len() > 1024 {
            return Err(invalid());
        }
        // Rulings are not a secret-storage exception.
        let mut probe = Value::Object(serde_json::Map::from_iter([(
            key.to_owned(),
            value.clone(),
        )]));
        if crate::batch::export::redact_credentials(&mut probe) {
            return Err(invalid());
        }
        let mut txn = self.store.env.write_txn()?;
        holder.revalidate_in_txn(self, &txn)?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        let mut grant_ref = None;
        for row in self
            .store
            .type_index
            .prefix_iter(&txn, &[crate::registry::ENTITY_TYPE_FEDERATION_GRANT])?
        {
            let (index, _) = row?;
            let id = crate::vault::entity_id_from_type_index_key(&index)?;
            let raw = self
                .store
                .entities
                .get(&txn, id.as_bytes())?
                .ok_or_else(invalid)?;
            if EntityMetadataHeader::parse(&raw).is_none_or(|header| {
                header.entity_type != crate::registry::ENTITY_TYPE_FEDERATION_GRANT
            }) {
                return Err(invalid());
            }
            let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if grant.scope == FederationGrantScope::vault(vault_id)
                && grant.member_ref == holder.actor()
                && grant.is_admin()
                && grant.confers_at(now)
                && fold.pact_for_grant(&id).is_none_or(|pact| {
                    pact.status == crate::authority::FederationPactStatus::Active
                })
            {
                grant_ref = Some(id.to_hex());
                break;
            }
        }
        let grant_ref = grant_ref.ok_or_else(invalid)?;
        let rows = self.admin_ruling_receipts_in(&txn, vault_id)?;
        let ruling_rows: Vec<_> = rows.into_iter().map(|receipt| receipt.ruling).collect();
        let previous = fold_admin_rulings(&ruling_rows, vault_id, key);
        let ledger_order = ruling_rows
            .iter()
            .map(|row| row.ledger_order)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(invalid)?;
        let ruling = AdminRuling {
            ledger_order,
            id: EntityId::now().to_hex(),
            holder: holder.actor().to_hex(),
            grant_ref,
            vault_id,
            key: key.to_owned(),
            value,
            learned_at: now,
        };
        let receipt = AdminRulingReceipt {
            ruling,
            previous_ruling: previous.map(|p| p.id.clone()),
            previous_holder: previous.map(|p| p.holder.clone()),
            previous_value: previous.map(|p| p.value.clone()),
        };
        let mut storage_key = prefix(vault_id);
        storage_key.extend_from_slice(receipt.ruling.id.as_bytes());
        self.store.vault_meta.put(
            &mut txn,
            &storage_key,
            &serde_json::to_vec(&receipt).map_err(|_| invalid())?,
        )?;
        txn.commit()?;
        Ok(receipt)
    }
    fn admin_ruling_receipts_in(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
    ) -> Result<Vec<AdminRulingReceipt>> {
        self.store
            .vault_meta
            .prefix_iter(txn, &prefix(vault_id))?
            .map(|row| {
                let (_, raw) = row?;
                serde_json::from_slice(&raw).map_err(|_| invalid())
            })
            .collect()
    }
    pub fn admin_ruling_receipts(&self, vault_id: u64) -> Result<Vec<AdminRulingReceipt>> {
        let txn = self.store.env.read_txn()?;
        self.admin_ruling_receipts_in(&txn, vault_id)
    }
    pub fn live_admin_ruling(&self, vault_id: u64, key: &str) -> Result<Option<AdminRuling>> {
        let rows = self
            .admin_ruling_receipts(vault_id)?
            .into_iter()
            .map(|r| r.ruling)
            .collect::<Vec<_>>();
        Ok(fold_admin_rulings(&rows, vault_id, key).cloned())
    }
}
