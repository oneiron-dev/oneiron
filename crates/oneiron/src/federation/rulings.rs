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
const RULING_PREDICATE: &str = "federation.admin_ruling";
pub(super) fn ruling_anchor_id(vault_id: u64) -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(
        b"oneiron.shared-ruling.anchor.v1",
        &[&vault_id.to_be_bytes()],
    )
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
        let anchor = ruling_anchor_id(vault_id)?;
        if self.store.entities.get(&txn, anchor.as_bytes())?.is_none() {
            self.batch_in()
                .put(
                    &anchor,
                    crate::registry::ENTITY_TYPE_ASSET,
                    crate::TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    b"Shared administrative ruling ledger",
                )
                .apply(&mut txn)?;
        }
        let id = EntityId::from_hex(&receipt.ruling.id)?;
        let candidate = crate::write_envelope::ClaimCandidate::new(
            RULING_PREDICATE,
            crate::claim::ClaimSubject::Entity(anchor),
            rmpv::decode::read_value(&mut std::io::Cursor::new(
                rmp_serde::to_vec_named(&receipt).map_err(|_| invalid())?,
            ))
            .map_err(|_| invalid())?,
            1.0,
        );
        let envelope = crate::write_envelope::WriteEnvelope::new(
            crate::write_envelope::WriteActor::new(
                holder.actor(),
                crate::edge::EdgeActorClass::Human,
            ),
            crate::claim::ClaimSource::UserStated,
            crate::write_envelope::WriteProvenance::new(rmpv::Value::Map(vec![
                (
                    rmpv::Value::from("surface"),
                    rmpv::Value::from("shared_admin_ruling"),
                ),
                (
                    rmpv::Value::from("grant_ref"),
                    rmpv::Value::from(receipt.ruling.grant_ref.as_str()),
                ),
            ]))?,
            crate::claim::ClaimApprovalStatus::Auto,
        );
        self.batch_in()
            .claim_candidate(
                &id,
                candidate,
                &envelope,
                crate::TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .apply_recording_gate_decisions(&mut txn)?;
        if self
            .get_claim_in_txn(&txn, &id)?
            .is_none_or(|body| body.approval != crate::claim::ClaimApprovalStatus::Auto)
        {
            return Err(invalid());
        }
        txn.commit()?;
        Ok(receipt)
    }
    fn admin_ruling_receipts_in(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
    ) -> Result<Vec<AdminRulingReceipt>> {
        let anchor = ruling_anchor_id(vault_id)?;
        let mut rows = Vec::new();
        for id in self.claims_for_subject_in_txn(txn, &anchor)? {
            let body = self.get_claim_in_txn(txn, &id)?.ok_or_else(invalid)?;
            if body.predicate != RULING_PREDICATE
                || body.approval != crate::claim::ClaimApprovalStatus::Auto
            {
                continue;
            }
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, &body.value).map_err(|_| invalid())?;
            let receipt: AdminRulingReceipt =
                rmp_serde::from_slice(&bytes).map_err(|_| invalid())?;
            let holder = EntityId::from_hex(&receipt.ruling.holder)?;
            let actor_matches = body.evidence.as_ref().is_some_and(|evidence| {
                let rmpv::Value::Map(fields) = evidence else { return false; };
                fields.iter().any(|(key, value)| key.as_str() == Some("actor_entity_ref")
                    && matches!(value, rmpv::Value::Binary(bytes) if bytes.as_slice() == holder.as_bytes()))
            });
            if receipt.ruling.id != id.to_hex()
                || receipt.ruling.vault_id != vault_id
                || body.subject != crate::claim::ClaimSubject::Entity(anchor)
                || !actor_matches
            {
                return Err(invalid());
            }
            rows.push(receipt);
        }
        // Lamport order advances after every observed ruling; concurrent ties
        // use the immutable id. Receipts project the same merged history on all replicas.
        rows.sort_by(|a, b| {
            (a.ruling.ledger_order, &a.ruling.id).cmp(&(b.ruling.ledger_order, &b.ruling.id))
        });
        let mut previous = std::collections::BTreeMap::<String, AdminRuling>::new();
        for row in &mut rows {
            let prior = previous.insert(row.ruling.key.clone(), row.ruling.clone());
            row.previous_ruling = prior.as_ref().map(|r| r.id.clone());
            row.previous_holder = prior.as_ref().map(|r| r.holder.clone());
            row.previous_value = prior.map(|r| r.value);
        }
        Ok(rows)
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
