//! GOV-10 charter gate: stage proposal, human approve-and-stamp, discard.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::super::charter::{charter_stamped_aggregate, compile_connector_charter};
use super::super::meter::delete_charter_usage_rows_in_txn;
use super::super::record::{
    ConnectorCharterBlock, ConnectorKeyRecord, ConnectorKeyStatus, PendingConnectorCharter,
    invalid_body,
};
use super::super::txn::{
    append_connector_key_op_record, read_connector_key_in_txn, rewrite_connector_key_in_txn,
};

impl Vault {
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
}
