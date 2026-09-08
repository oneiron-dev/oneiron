//! Owner budget-row ops: append active row, stage suggestion, accept suggestion.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::super::record::{
    CONNECTOR_KEY_MAX_BUDGET_ROWS, ConnectorKeyRecord, ConnectorKeyStatus, EffectorBudget,
    invalid_body, normalize_connector_key, validate_budget_row, validate_suggested_budget_row,
};
use super::super::txn::{
    append_connector_key_op_record, read_connector_key_in_txn, rewrite_connector_key_in_txn,
};

impl Vault {
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
}
