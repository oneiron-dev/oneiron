use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::batch::{BatchOp, apply_ops};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CONNECTOR_KEY;
use crate::temporal::TimeRange;

use super::charter::{charter_stamped_aggregate, compile_connector_charter};
use super::codec::{decode_connector_key_body, encode_connector_key_body};
use super::meter::delete_charter_usage_rows_in_txn;
use super::record::{
    CONNECTOR_KEY_MAX_BUDGET_ROWS, ConnectorCharterBlock, ConnectorKeyRecord, ConnectorKeyStatus,
    EffectorBudget, PendingConnectorCharter, invalid_body, normalize_connector_key,
    validate_budget_row, validate_suggested_budget_row,
};
use super::txn::{
    append_connector_key_op_record, connector_key_index_entity_id, connector_key_index_key,
    connector_key_index_prefix, governing_connector_key, read_connector_key_in_txn,
    rewrite_connector_key_in_txn, suspend_connector_key_in_txn,
};

// --- Vault registry API -----------------------------------------------------------

impl Vault {
    /// Registers a connector key. Rejects a second non-revoked key for the
    /// same `(connector, actor_entity_ref)` tuple, a non-Active status, and a
    /// pre-stamped charter (a charter must enter via the receipted
    /// propose/approve pair, never via register).
    pub fn register_connector_key(
        &self,
        id: &EntityId,
        record: ConnectorKeyRecord,
    ) -> Result<ConnectorKeyRecord> {
        let mut record = record;
        record.connector = normalize_connector_key(&record.connector);
        for budget in &mut record.budgets {
            if let Some(channel_class) = budget.channel_class.take() {
                budget.channel_class = Some(normalize_connector_key(&channel_class));
            }
        }
        for budget in &mut record.suggested_budgets {
            if let Some(channel_class) = budget.channel_class.take() {
                budget.channel_class = Some(normalize_connector_key(&channel_class));
            }
        }
        record.validate()?;
        if record.status != ConnectorKeyStatus::Active {
            return Err(invalid_body("registration requires status active"));
        }
        if record.charter.is_some() || record.pending_charter.is_some() {
            return Err(invalid_body("registration must not carry a charter"));
        }

        let data = encode_connector_key_body(&record)?;
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some() {
            return Err(Error::ConnectorKeyAlreadyExists);
        }
        let prefix = connector_key_index_prefix(&record.connector)?;
        let mut sibling_ids = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&wtxn, &prefix)? {
            let (key, _) = entry?;
            sibling_ids.push(connector_key_index_entity_id(&key, &record.connector)?);
        }
        for sibling_id in sibling_ids {
            let sibling = read_connector_key_in_txn(&self.store, &wtxn, &sibling_id)?
                .ok_or(Error::CorruptedIndex("connector key index row"))?;
            if sibling.status != ConnectorKeyStatus::Revoked
                && sibling.actor_entity_ref == record.actor_entity_ref
            {
                return Err(Error::ConnectorKeyAlreadyExists);
            }
        }

        self.apply_connector_key_body(&mut wtxn, id, record.registered_at, data)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.register",
            &record,
            policy.read_frontier_hash()?,
            record.registered_at,
        )?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Reads and decodes a connector-key record.
    pub fn get_connector_key(&self, id: &EntityId) -> Result<Option<ConnectorKeyRecord>> {
        let rtxn = self.store.env.read_txn()?;
        read_connector_key_in_txn(&self.store, &rtxn, id)
    }

    /// Resolves the key governing `(connector, actor_entity_ref)` (read-txn
    /// wrapper over the gate's resolution order).
    pub fn connector_key_for(
        &self,
        connector: &str,
        actor_entity_ref: Option<&EntityId>,
    ) -> Result<Option<(EntityId, ConnectorKeyRecord)>> {
        let rtxn = self.store.env.read_txn()?;
        governing_connector_key(
            &self.store,
            &rtxn,
            &normalize_connector_key(connector),
            actor_entity_ref,
        )
    }

    /// Mints an Active connector key whose budget table is necessarily empty.
    /// Optional budget rows can only enter through the owner mutation APIs.
    pub fn mint_unbudgeted_connector_key(
        &self,
        connector: &str,
        actor_entity_ref: Option<EntityId>,
        registered_at: u64,
    ) -> Result<ConnectorKeyRecord> {
        self.register_connector_key(
            &EntityId::now(),
            ConnectorKeyRecord::active(connector, actor_entity_ref, Vec::new(), registered_at),
        )
    }

    /// Appends one owner-supplied budget row to an existing non-revoked key.
    pub fn add_connector_key_budget(
        &self,
        id: &EntityId,
        mut budget: EffectorBudget,
        now: u64,
    ) -> Result<ConnectorKeyRecord> {
        if let Some(channel_class) = budget.channel_class.take() {
            budget.channel_class = Some(normalize_connector_key(&channel_class));
        }
        validate_budget_row(&budget)?;

        let mut wtxn = self.store.env.write_txn()?;
        let mut record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("cannot add budget row to revoked key"));
        }
        if record.budgets.len() >= CONNECTOR_KEY_MAX_BUDGET_ROWS {
            return Err(invalid_body("too many budget rows"));
        }
        record.budgets.push(budget);
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &record)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.budget_add",
            &record,
            policy.read_frontier_hash()?,
            now,
        )?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Stages one advisory budget row. Suggested rows never participate in
    /// charging, and may only carry Refuse semantics.
    pub fn suggest_connector_key_budget(
        &self,
        id: &EntityId,
        mut budget: EffectorBudget,
        now: u64,
    ) -> Result<ConnectorKeyRecord> {
        if let Some(channel_class) = budget.channel_class.take() {
            budget.channel_class = Some(normalize_connector_key(&channel_class));
        }
        validate_suggested_budget_row(&budget)?;

        let mut wtxn = self.store.env.write_txn()?;
        let mut record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("cannot suggest budget row on revoked key"));
        }
        if record.suggested_budgets.len() >= CONNECTOR_KEY_MAX_BUDGET_ROWS {
            return Err(invalid_body("too many suggested budget rows"));
        }
        record.suggested_budgets.push(budget);
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &record)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.budget_suggest",
            &record,
            policy.read_frontier_hash()?,
            now,
        )?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Accepts one staged row into the active budget table. Existing usage is
    /// not consulted or backfilled, so accounting begins at activation.
    pub fn accept_connector_key_budget_suggestion(
        &self,
        id: &EntityId,
        suggestion_index: usize,
        now: u64,
    ) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let mut record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("cannot accept budget row on revoked key"));
        }
        if record.budgets.len() >= CONNECTOR_KEY_MAX_BUDGET_ROWS {
            return Err(invalid_body("too many budget rows"));
        }
        if suggestion_index >= record.suggested_budgets.len() {
            return Err(invalid_body("suggested budget row not found"));
        }
        let budget = record.suggested_budgets.remove(suggestion_index);
        validate_suggested_budget_row(&budget)?;
        record.budgets.push(budget);
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &record)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.budget_accept",
            &record,
            policy.read_frontier_hash()?,
            now,
        )?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Suspends an Active key (owner op).
    pub fn suspend_connector_key(
        &self,
        id: &EntityId,
        reason: &str,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status != ConnectorKeyStatus::Active {
            return Err(invalid_body("illegal status transition"));
        }
        let suspended = suspend_connector_key_in_txn(
            &self.store,
            &mut wtxn,
            id,
            &record,
            reason.to_owned(),
            at,
        )?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.suspend",
            &suspended,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(suspended)
    }

    /// Resumes a Suspended key. Deliberately does NOT clear usage rows: the
    /// window state is truth — if the window has not rolled, the next send
    /// re-exhausts and re-suspends (correct hard-cap behavior).
    pub fn resume_connector_key(&self, id: &EntityId, at: u64) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status != ConnectorKeyStatus::Suspended {
            return Err(invalid_body("illegal status transition"));
        }
        let resumed = ConnectorKeyRecord {
            status: ConnectorKeyStatus::Active,
            status_changed_at: Some(at),
            suspended_reason: None,
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &resumed)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.resume",
            &resumed,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(resumed)
    }

    /// Revokes a key (terminal) from any non-revoked state.
    pub fn revoke_connector_key(&self, id: &EntityId, at: u64) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("illegal status transition"));
        }
        let revoked = ConnectorKeyRecord {
            status: ConnectorKeyStatus::Revoked,
            status_changed_at: Some(at),
            suspended_reason: None,
            // Revocation is terminal: drop any staged proposal so a revoked
            // key carries no mutable charter state (approve/discard also gate
            // on Revoked below).
            pending_charter: None,
            suggested_budgets: Vec::new(),
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &revoked)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.revoke",
            &revoked,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(revoked)
    }

    /// Compiles and STAGES a charter proposal (GOV-10). Never changes
    /// enforcement — that is the human gate. Overwrites a previous pending
    /// proposal; the receipt trail records both.
    pub fn propose_connector_charter(
        &self,
        id: &EntityId,
        text: &str,
        proposed_at: u64,
    ) -> Result<PendingConnectorCharter> {
        let compiled = compile_connector_charter(text)?;
        let normalized = text.replace("\r\n", "\n");
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("charter op on revoked key"));
        }
        let pending = PendingConnectorCharter {
            text: normalized,
            text_hash: compiled.text_hash,
            compiled: compiled.compiled,
            compiled_hash: compiled.compiled_hash,
            proposed_at,
        };
        let proposed = ConnectorKeyRecord {
            pending_charter: Some(pending.clone()),
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &proposed)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.charter_propose",
            &proposed,
            policy.read_frontier_hash()?,
            proposed_at,
        )?;
        wtxn.commit()?;
        Ok(pending)
    }

    /// The human gate (GOV-10): applies the staged compile iff the caller
    /// re-presents its compiled hash out-of-band, and stamps the aggregate
    /// binding text + compiled policy. Clears every compiled-cap usage row
    /// (`0x8000 | *`) in the same txn — compiled-cap usage is keyed
    /// positionally, so a re-stamped charter must never inherit the old
    /// charter's usage at the same indices or leave orphaned rows.
    ///
    /// There is deliberately NO single-call compile-and-activate API; which
    /// callers may invoke `approve` is host-surface policy (the same trust
    /// boundary as every owner Vault op) — in-engine the gate is the
    /// propose/approve split plus the receipt trail.
    pub fn approve_connector_charter(
        &self,
        id: &EntityId,
        expected_compiled_hash: [u8; 32],
        stamped_by: &str,
        stamped_at: u64,
    ) -> Result<ConnectorKeyRecord> {
        if stamped_by.trim().is_empty() {
            return Err(invalid_body("stamped_by must not be blank"));
        }
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("charter op on revoked key"));
        }
        let Some(pending) = record.pending_charter.clone() else {
            return Err(Error::ConnectorCharterMissing);
        };
        if pending.compiled_hash != expected_compiled_hash {
            return Err(Error::ConnectorCharterApprovalMismatch);
        }
        let stamped = ConnectorKeyRecord {
            charter: Some(ConnectorCharterBlock {
                stamped_aggregate: charter_stamped_aggregate(
                    &pending.text_hash,
                    &pending.compiled_hash,
                ),
                text: pending.text,
                text_hash: pending.text_hash,
                compiled: pending.compiled,
                compiled_hash: pending.compiled_hash,
                stamped_by: stamped_by.to_owned(),
                stamped_at,
            }),
            pending_charter: None,
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &stamped)?;
        delete_charter_usage_rows_in_txn(&self.store, &mut wtxn, id)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.charter_approve",
            &stamped,
            policy.read_frontier_hash()?,
            stamped_at,
        )?;
        wtxn.commit()?;
        Ok(stamped)
    }

    /// Owner rejection of a staged charter compile (GOV-10): clears the
    /// pending proposal, receipted. Enforcement was never changed by it.
    pub fn discard_connector_charter(&self, id: &EntityId, at: u64) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("charter op on revoked key"));
        }
        if record.pending_charter.is_none() {
            return Err(Error::ConnectorCharterMissing);
        }
        let discarded = ConnectorKeyRecord {
            pending_charter: None,
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &discarded)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.charter_discard",
            &discarded,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(discarded)
    }

    fn apply_connector_key_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        let new_record = decode_connector_key_body(&data)?;
        let new_index_key = connector_key_index_key(&new_record.connector, id)?;
        let old_index_key = if let Some(raw) = self.store.entities.get(&*wtxn, id.as_bytes())? {
            let Some(header) = EntityMetadataHeader::parse(&raw) else {
                return Err(Error::CorruptedIndex("connector key entity header"));
            };
            if header.entity_type != ENTITY_TYPE_CONNECTOR_KEY {
                return Err(Error::CorruptedIndex("connector key entity type"));
            }
            let old_record = decode_connector_key_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            Some(connector_key_index_key(&old_record.connector, id)?)
        } else {
            None
        };
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_CONNECTOR_KEY,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        if let Some(old_index_key) = old_index_key.as_ref()
            && old_index_key != &new_index_key
        {
            self.store.vault_meta.delete(wtxn, old_index_key)?;
        }
        self.store.vault_meta.put(wtxn, &new_index_key, &[])?;
        Ok(())
    }
}
