//! The Vault doors that read document limits and the budget guard from the resolved manifest.

use super::*;

impl Vault {
    /// Resolve the live document package limits from trusted policy rows.
    /// A missing or invalid manifest is a refusal, never an organ fallback.
    pub fn docedit_package_limits(&self) -> Result<oneiron_docedit::retained_opc::Limits> {
        let rtxn = self.store.env.read_txn()?;
        let resolution = resolve_policy_manifest(&self.store, &rtxn)?;
        let policy = resolution.docedit_resource_policy().ok_or_else(|| {
            Error::InvalidConfig(
                "document resource policy is unavailable or fail-closed".to_owned(),
            )
        })?;
        Ok(policy.organ_limits())
    }

    /// [`Self::docedit_package_limits`] as `txn` sees the policy rows, for a
    /// reader inside a write transaction.
    pub(crate) fn docedit_package_limits_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<oneiron_docedit::retained_opc::Limits> {
        let resolution = resolve_policy_manifest(&self.store, txn)?;
        let policy = resolution.docedit_resource_policy().ok_or_else(|| {
            Error::InvalidConfig(
                "document resource policy is unavailable or fail-closed".to_owned(),
            )
        })?;
        Ok(policy.organ_limits())
    }

    /// Builds the ONE policy-aware LLM budget meter for one wake pass: the
    /// same `BudgetGuard`, bound at construction to the engine-stamped actor
    /// and to the live manifest's resolved `budget_policy` table.
    ///
    /// The factory resolves the manifest itself and is fail-closed: when the
    /// loaded resolution forces fail-closed (malformed manifest, unsupported
    /// schema version, engine-version floor, unknown axis, row-count
    /// overflow) it refuses with [`Error::InvalidConfig`] and never
    /// substitutes an empty or fabricated table. Production callers keep
    /// admitting with `guard.admit_for_request(&request)` exactly as before.
    pub fn policy_budget_guard(
        &self,
        attempt_id: impl Into<String>,
        limit_units: u64,
        reserve_units: u64,
        on_budget_exhausted: BudgetExhaustionPolicy,
        actor: WriteActor,
    ) -> Result<BudgetGuard> {
        let rtxn = self.store.env.read_txn()?;
        let resolution = resolve_policy_manifest(&self.store, &rtxn)?;
        let table = resolution.budget_policy().ok_or_else(|| {
            Error::InvalidConfig(
                "policy manifest resolution is fail-closed; refusing to build a policy budget guard"
                    .to_owned(),
            )
        })?;
        Ok(BudgetGuard::with_policy_table(
            attempt_id,
            limit_units,
            reserve_units,
            on_budget_exhausted,
            actor,
            table,
        ))
    }
}
