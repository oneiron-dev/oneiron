//! Corrections when already-consumed units land after a scope closed.

use crate::error::Result;
use crate::scan_check::EngineScan;
use std::collections::HashSet;

use super::super::AgentDispatcher;
use super::super::spend_record::{SCOPE, SpendScope, SpendScopeId, SpendState};
use super::super::widen_record::invalid;

impl AgentDispatcher<'_> {
    /// Closed ancestors retain their subtree receipts even when soft. Cap
    /// boundaries and the booking host were already tallied by the caller.
    pub(super) fn tally_closed_receipts_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        source: &SpendScope,
        units: u64,
        tallied: &mut Vec<SpendScopeId>,
    ) -> Result<()> {
        let mut seen = HashSet::from([source.scope.clone()]);
        let mut cursor = source.parent.clone();
        let mut rows = 0usize;
        let result = (|| {
            while let Some(id) = cursor {
                if !seen.insert(id.clone()) {
                    return Err(invalid("spend scope ancestor cycle"));
                }
                rows = rows.saturating_add(1);
                let mut row = SCOPE
                    .get(&self.vault.store, txn, &id.0)?
                    .ok_or_else(|| invalid("spend scope ancestor is missing"))?;
                if row.state == SpendState::Open {
                    break;
                }
                cursor = row.parent.clone();
                if !tallied.contains(&row.scope) {
                    row.spent_units = row.spent_units.saturating_add(units);
                    SCOPE.put(&self.vault.store, txn, &row.scope.0, &row)?;
                    tallied.push(row.scope);
                }
            }
            Ok(())
        })();
        super::observe_spend_walk(
            &self.vault.store,
            txn,
            EngineScan::SpendAncestorScopes,
            source.scope.as_str().as_bytes(),
            rows,
        );
        result
    }

    pub(super) fn revise_settled_scope_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &SpendScopeId,
    ) -> Result<()> {
        let scope = SCOPE
            .get(&self.vault.store, txn, &id.0)?
            .ok_or_else(|| invalid("spend scope is missing"))?;
        if scope.state != SpendState::Closed {
            return Ok(());
        }
        if let Some(attempt) = scope.exploration_attempt {
            crate::skill::revise_exploration_route_in_txn(
                self.vault,
                txn,
                attempt,
                &scope.unit,
                scope.spent_units,
            )?;
        }
        self.revise_spend_calibration_in_txn(txn, &scope)
    }
}
