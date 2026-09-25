//! Exact actor-owned keyed facts over canonical CLAIMs. No KV record kind,
//! recall emulation, owner erasure, wildcard scope, or storage bypass.
//!
//! This first surface is explicitly WORLDLESS: it neither reads nor writes
//! world-scoped claims. Actor id AND class are part of the identity. Reads
//! require the canonical claim's envelope to name that actor/class. Namespace
//! prefixes compare whole string segments, never string-prefix approximations.
#[cfg(test)]
mod tests;
mod types;
mod writes;

use super::support::{json_to_rmpv, verify_actor_binding_in_txn};
use super::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::batch::EntityMetadataHeader;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::companion::companion_value_to_json;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::write_envelope::{
    WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub use types::*;

pub(super) const PREDICATE: &str = crate::claim::KEY_VALUE_PREDICATE;
const MAX_ADDRESS_BYTES: usize = 4096;
const MAX_SEGMENTS: usize = 32;
const MAX_OFFSET: usize = 1_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredValue {
    namespace: Vec<String>,
    key: String,
    value: serde_json::Value,
    created_at: u64,
    request_id: String,
}

fn check_namespace(namespace: &[String], empty: bool) -> MemoryResult<()> {
    if (!empty && namespace.is_empty())
        || namespace.len() > MAX_SEGMENTS
        || namespace
            .iter()
            .any(|s| s.is_empty() || s.contains('\0') || s == "*")
        || namespace.iter().map(String::len).sum::<usize>() > MAX_ADDRESS_BYTES
    {
        return Err(MemoryError::bad_request("invalid exact namespace segments"));
    }
    Ok(())
}
fn check_address(address: &KeyValueAddress) -> MemoryResult<()> {
    check_namespace(&address.namespace, false)?;
    if address.key.is_empty() || address.key.len() > MAX_ADDRESS_BYTES || address.key.contains('\0')
    {
        return Err(MemoryError::bad_request(
            "key must be a nonempty bounded string",
        ));
    }
    Ok(())
}
fn check_page(limit: usize, offset: usize) -> MemoryResult<()> {
    super::caps::check_limit(limit)?;
    if offset > MAX_OFFSET {
        return Err(MemoryError::bad_request("offset exceeds 1000000"));
    }
    Ok(())
}
fn conflict(message: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        message,
        &["Read the current key and use a fresh request_id for a new operation."],
    )
}

impl Memory<'_> {
    fn key_value_scope(&self, address: &KeyValueAddress) -> rmpv::Value {
        json_to_rmpv(
            &serde_json::json!({"key_value": {"version": 1, "actor_class": self.actor_class.gate_actor_class(), "namespace": address.namespace, "key": address.key}}),
        )
    }

    fn keyed_value(&self, body: &ClaimBody) -> Option<StoredValue> {
        if body.predicate != PREDICATE
            || body.subject != ClaimSubject::Entity(self.actor)
            || body.world.is_some()
        {
            return None;
        }
        let rmpv::Value::Map(evidence) = body.evidence.as_ref()? else {
            return None;
        };
        let actor_ok = matches!(
            crate::claim::single_map_value(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
            crate::claim::MapValue::Present(rmpv::Value::Binary(bytes))
                if bytes.as_slice() == self.actor.as_bytes()
        );
        let class_ok = matches!(
            crate::claim::single_map_value(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY),
            crate::claim::MapValue::Present(value)
                if value.as_u64() == Some(u64::from(self.actor_class as u8))
        );
        if !actor_ok || !class_ok {
            return None;
        }
        // Malformed rows are not heads. Never repair them, fall back through
        // their history, or let one bad payload deny every key of this actor.
        let value =
            serde_json::from_value::<StoredValue>(companion_value_to_json(&body.value)).ok()?;
        let address = KeyValueAddress {
            namespace: value.namespace.clone(),
            key: value.key.clone(),
        };
        check_address(&address).ok()?;
        // Canonical decay annotates scope without changing the key identity.
        // Validate that annotation, then compare every remaining scope byte.
        crate::claim::claim_demotion_rung(body).ok()?;
        let mut scope = body.scope.clone();
        if let Some(rmpv::Value::Map(entries)) = &mut scope {
            entries.retain(|(key, _)| {
                key.as_str() != Some(crate::claim::CLAIM_SCOPE_DEMOTION_RUNG_KEY)
            });
        }
        if scope.as_ref() != Some(&self.key_value_scope(&address)) {
            return None;
        }
        if !value.value.is_object() {
            return None;
        }
        Some(value)
    }

    fn key_value_rows(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> MemoryResult<BTreeMap<KeyValueAddress, (EntityId, StoredValue)>> {
        verify_actor_binding_in_txn(self.vault, txn, self.actor, self.actor_class)?;
        let mut rows = BTreeMap::new();
        // Existing indexed scan has a hard work ceiling and fails loudly on
        // overflow. Never truncate it into a false negative or a partial page.
        for id in self.vault.claims_for_subject_in_txn(txn, &self.actor)? {
            let Some(raw) = self.vault.get_raw_in(txn, &id)? else {
                continue;
            };
            // Deletion keeps ClaimOf edges for header-only shells. Never
            // decode those as live claims, or walk back to an erased value.
            let Some(header) = EntityMetadataHeader::parse(&raw) else {
                continue;
            };
            if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
                || raw.len() == crate::batch::ENTITY_METADATA_HEADER_LEN
            {
                continue;
            }
            let Ok(body) = crate::claim::decode_claim_body(
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                true,
            ) else {
                continue;
            };
            if body.lifecycle != ClaimLifecycleStatus::Active
                || !matches!(
                    body.approval,
                    ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
                )
            {
                continue;
            }
            let Some(value) = self.keyed_value(&body) else {
                continue;
            };
            let address = KeyValueAddress {
                namespace: value.namespace.clone(),
                key: value.key.clone(),
            };
            // Sync or a generic claim writer may create competing heads. Do
            // not invent a winner or silently delete one on the next write.
            if rows.insert(address, (id, value)).is_some() {
                return Err(conflict("multiple committed heads for one actor-owned key"));
            }
        }
        Ok(rows)
    }

    fn key_value_item(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        value: StoredValue,
    ) -> MemoryResult<KeyValueItem> {
        let raw = self
            .vault
            .get_raw_in(txn, &id)?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("keyed claim header"))?;
        Ok(KeyValueItem {
            namespace: value.namespace,
            key: value.key,
            value: value.value,
            created_at: value.created_at,
            updated_at: header.learned_at,
            revision: id.to_hex(),
        })
    }

    /// Exact get in the bound actor/class's worldless namespace.
    pub fn key_value_get(&self, address: &KeyValueAddress) -> MemoryResult<Option<KeyValueItem>> {
        check_address(address)?;
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        self.key_value_rows(&txn)?
            .remove(address)
            .map(|(id, value)| self.key_value_item(&txn, id, value))
            .transpose()
    }

    /// Exact prefix and equality search, ordered by namespace then key.
    pub fn key_value_search(&self, request: &KeyValueSearch) -> MemoryResult<Vec<KeyValueItem>> {
        check_namespace(&request.namespace_prefix, true)?;
        check_page(request.limit, request.offset)?;
        if let Some(filter) = &request.filter {
            let bytes = serde_json::to_vec(filter)
                .map_err(|_| MemoryError::bad_request("invalid filter"))?;
            super::caps::check_payload_bytes("filter", bytes.len())?;
            if filter.values().any(|value| {
                value
                    .as_object()
                    .is_some_and(|o| o.keys().any(|k| k.starts_with('$')))
            }) {
                return Err(MemoryError::bad_request(
                    "filter operators are not supported; use exact field equality",
                ));
            }
        }
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        self.key_value_rows(&txn)?
            .into_iter()
            .filter(|(address, (_, value))| {
                address.namespace.starts_with(&request.namespace_prefix)
                    && request.filter.as_ref().is_none_or(|filter| {
                        filter.iter().all(|(k, v)| value.value.get(k) == Some(v))
                    })
            })
            .skip(request.offset)
            .take(request.limit)
            .map(|(_, (id, value))| self.key_value_item(&txn, id, value))
            .collect()
    }

    /// Distinct live namespaces, with exact segment prefix/suffix matching.
    pub fn key_value_namespaces(
        &self,
        request: &KeyValueNamespaces,
    ) -> MemoryResult<Vec<Vec<String>>> {
        check_namespace(&request.prefix, true)?;
        check_namespace(&request.suffix, true)?;
        check_page(request.limit, request.offset)?;
        if request
            .max_depth
            .is_some_and(|depth| depth == 0 || depth > MAX_SEGMENTS)
        {
            return Err(MemoryError::bad_request(
                "max_depth must be between 1 and 32",
            ));
        }
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let namespaces: BTreeSet<_> = self
            .key_value_rows(&txn)?
            .into_keys()
            .map(|address| address.namespace)
            .filter(|ns| ns.starts_with(&request.prefix) && ns.ends_with(&request.suffix))
            .map(|mut ns| {
                if let Some(depth) = request.max_depth {
                    ns.truncate(depth);
                }
                ns
            })
            .collect();
        Ok(namespaces
            .into_iter()
            .skip(request.offset)
            .take(request.limit)
            .collect())
    }
}
