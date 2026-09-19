//! A host-pushed limit converts once. BudgetGuard is the only depletion ladder.
use super::{
    Money, UsageError, UsageLedger,
    keys::{validate_key, vault_rollup_key},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeRate {
    pub from_currency: String,
    pub to_currency: String,
    pub numerator: u64,
    pub denominator: u64,
    pub observed_at: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CachedBudgetLimit {
    pub original: Money,
    pub converted: Money,
    pub rate: ExchangeRate,
    pub refreshed_at: u64,
}
impl CachedBudgetLimit {
    pub fn convert(
        original: Money,
        rate: ExchangeRate,
        refreshed_at: u64,
    ) -> Result<Self, UsageError> {
        original.validate()?;
        if rate.from_currency != original.currency || rate.numerator == 0 || rate.denominator == 0 {
            return Err(UsageError::InvalidField {
                field: "rate",
                message: "invalid conversion rate",
            });
        }
        let amount =
            u128::from(original.amount) * u128::from(rate.numerator) / u128::from(rate.denominator);
        let converted = Money {
            amount: u64::try_from(amount).map_err(|_| UsageError::Overflow)?,
            currency: rate.to_currency.clone(),
            price_table_snapshot: original.price_table_snapshot.clone(),
        };
        converted.validate()?;
        Ok(Self {
            original,
            converted,
            rate,
            refreshed_at,
        })
    }
    /// The host retains this guard for the vault's budget lease lifetime.
    pub fn guard(&self, attempt: impl Into<String>) -> oneiron::BudgetGuard {
        oneiron::BudgetGuard::with_reserve_units(
            attempt,
            self.converted.amount,
            1,
            oneiron::BudgetExhaustionPolicy::Suspend,
        )
    }
}
impl UsageLedger {
    /// Called by the trusted host's cloud-policy refresh, never a wallet route.
    pub fn cache_budget_limit(
        &self,
        owner: &str,
        vault: &str,
        original: Money,
        rate: ExchangeRate,
        now: u64,
    ) -> Result<CachedBudgetLimit, UsageError> {
        let limit = CachedBudgetLimit::convert(original, rate, now)?;
        let key = format!("budget:{}", vault_rollup_key(owner, vault));
        validate_key(&key)?;
        let raw = rmp_serde::to_vec_named(&limit)?;
        self.vault
            .try_with_write_txn(|txn| -> Result<(), UsageError> {
                self.vault.sync_state_put_in_write_txn(txn, &key, &raw)?;
                Ok(())
            })?;
        Ok(limit)
    }
    pub fn cached_budget_limit(
        &self,
        owner: &str,
        vault: &str,
    ) -> Result<Option<CachedBudgetLimit>, UsageError> {
        let key = format!("budget:{}", vault_rollup_key(owner, vault));
        validate_key(&key)?;
        self.vault
            .sync_state_get(&key)?
            .map(|raw| rmp_serde::from_slice(&raw).map_err(UsageError::from))
            .transpose()
    }
}
