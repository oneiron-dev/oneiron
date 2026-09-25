//! Key mutations compose the existing claim gate and lifecycle door in ONE
//! transaction. The public claim_upsert's proposed fallback is deliberately
//! not used: BaseStore cannot truthfully return success for a parked write.
use super::super::support::facade_provenance;
use super::*;
use crate::batch::{ApplyOpsGateMode, BatchOp, apply_ops_with_gate_mode};
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
use std::sync::atomic::Ordering;

impl Memory<'_> {
    /// Synchronous gated replacement. If policy requires review, the complete
    /// transaction aborts: neither a proposed replacement nor a supersession
    /// persists. Use the ordinary claim review workflow for proposed facts.
    /// Retries with the same request_id are accepted only while that exact
    /// revision is still current; a replay never resurrects a deleted value.
    pub fn key_value_put(&self, input: &KeyValuePut) -> MemoryResult<KeyValuePutReceipt> {
        let address = KeyValueAddress {
            namespace: input.namespace.clone(),
            key: input.key.clone(),
        };
        check_address(&address)?;
        if input.request_id.is_empty()
            || input.request_id.len() > 128
            || input.request_id.contains('\0')
        {
            return Err(MemoryError::bad_request(
                "request_id must be a nonempty string of at most 128 bytes",
            ));
        }
        if !input.value.is_object() {
            return Err(MemoryError::bad_request("value must be a JSON object"));
        }
        let source = super::super::claims::parse_claim_source(&input.source)?;
        let identity = serde_json::to_vec(&(
            "oneiron.key_value.v1",
            self.actor.to_hex(),
            self.actor_class.gate_actor_class(),
            &address,
            &input.request_id,
        ))
        .map_err(|_| MemoryError::bad_request("invalid key identity"))?;
        let digest = blake3::hash(&identity);
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest.as_bytes()[..16]);
        // Domain-separated, actor-bound deterministic ID, not an unchecked
        // type byte or caller-selected entity ID. Full identity is rechecked.
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let id = EntityId::from_bytes(bytes)?;
        let now = crate::unix_seconds_now();
        let (item, replayed) = self.with_verified_actor_write_txn(|txn| {
            if self.vault.local_hard_delete_marker_exists_in_txn(txn, &id)? {
                return Err(super::super::support::hard_deleted_refusal(&id));
            }
            let mut rows = self.key_value_rows(txn)?;
            let prior = rows.remove(&address);
            if self.vault.get_raw_in(txn, &id)?.is_some() {
                let body = self.vault.get_claim_in_txn(txn, &id)
                    .map_err(|err| match err {
                        Error::InvalidClaimBody(_) => conflict("request_id names an erased or malformed revision"),
                        other => other.into(),
                    })?
                    .ok_or_else(|| conflict("request_id collides with another record"))?;
                let stored = self.keyed_value(&body).ok_or_else(|| conflict("request_id identity mismatch"))?;
                if stored.namespace != input.namespace || stored.key != input.key
                    || stored.value != input.value || stored.request_id != input.request_id || body.source != Some(source)
                { return Err(conflict("request_id was already used for different input")); }
                if prior.as_ref().is_none_or(|(current, _)| *current != id) {
                    return Err(conflict("request_id names a revision that is no longer current"));
                }
                return Ok((self.key_value_item(txn, id, stored)?, true));
            }
            let stored = StoredValue { namespace: input.namespace.clone(), key: input.key.clone(),
                value: input.value.clone(), created_at: prior.as_ref().map_or(now, |(_, old)| old.created_at),
                request_id: input.request_id.clone() };
            let value = serde_json::to_value(&stored).map_err(|_| MemoryError::bad_request("invalid JSON value"))?;
            super::super::caps::check_payload_bytes("keyed claim", serde_json::to_vec(&value)
                .map_err(|_| MemoryError::bad_request("invalid JSON value"))?.len())?;
            let candidate = ClaimCandidate::new(PREDICATE.to_owned(), ClaimSubject::Entity(self.actor),
                json_to_rmpv(&value), 1.0).with_scope(self.key_value_scope(&address));
            let envelope = WriteEnvelope::new(WriteActor::new(self.actor, self.actor_class), source,
                WriteProvenance::new(facade_provenance("key_value_put"))?, ClaimApprovalStatus::Auto);
            apply_ops_with_gate_mode(&self.vault.store, &self.vault.config, &self.vault.analyzer, txn,
                vec![BatchOp::ClaimCandidate { id, candidate: Box::new(candidate), envelope,
                    occurred: TimeRange { start: now, end: now }, learned_at: now, internal_lexical_query_hint: false }],
                self.vault.text_index_trusted.load(Ordering::Acquire), ApplyOpsGateMode::new(true, true))?;
            let committed = self.vault.get_claim_in_txn(txn, &id)?.ok_or(Error::EntityNotFound)?;
            if !matches!(committed.approval, ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved) {
                return Err(MemoryError::new(super::super::MEMORY_CODE_FORBIDDEN,
                    "keyed write requires review and was not committed",
                    &["Use the canonical claim review workflow; BaseStore writes require an explicit policy that permits this actor and source."]));
            }
            if let Some((prior_id, _)) = prior {
                let prior_body = self.vault.get_claim_in_txn(txn, &prior_id)?
                    .ok_or(Error::EntityNotFound)?;
                crate::Vault::require_source_trust_supersession_rights(&committed, &prior_body)
                    .map_err(|_| MemoryError::new(
                        MEMORY_CODE_INVALID_STATE,
                        format!("source-trust rules forbid replacing keyed address {:?}/{:?}", address.namespace, address.key),
                        &["Keep the true source. Store generated output under a separate key. Only a genuine new user statement may be submitted as user_stated; never relabel generated output."],
                    ))?;
                self.vault.supersede_claim_in_txn(txn, &id, &prior_id, now)?;
            }
            Ok((self.key_value_item(txn, id, stored)?, false))
        })?;
        Ok(KeyValuePutReceipt {
            item,
            replayed,
            receipt_ref: self
                .latest_decision_ref_for(&id)?
                .unwrap_or_else(|| format!("claim:{}", id.to_hex())),
        })
    }

    /// Withdraws only this actor/class's exact current key. Absent is an
    /// idempotent no-op. It is NEVER safe_delete or an owner erasure grant.
    pub fn key_value_delete(
        &self,
        address: &KeyValueAddress,
    ) -> MemoryResult<KeyValueDeleteReceipt> {
        check_address(address)?;
        self.with_verified_actor_write_txn(|txn| {
            let Some((id, _)) = self.key_value_rows(txn)?.remove(address) else {
                return Ok(KeyValueDeleteReceipt {
                    existed: false,
                    receipt_refs: Vec::new(),
                });
            };
            // key_value_rows checked exact subject/scope/envelope authorship
            // in THIS writer snapshot, even for a human-class owner.
            let receipt = self
                .vault
                .retract_claim_in_txn(txn, &id, crate::unix_seconds_now())?;
            Ok(KeyValueDeleteReceipt {
                existed: true,
                receipt_refs: vec![receipt.map_or_else(
                    || format!("retract:{}", id.to_hex()),
                    |r| format!("gate:{}", r.decision_id.to_hex()),
                )],
            })
        })
    }
}
