//! Vault-local durable reserve/settle/refund ledger for research-loop spend.
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Durable reserve/settle/refund ledger for the RSI research-loop spend budget. Key: ().
const RSI_LINE: SideTable<(), Line, LegacyJson> = SideTable::new(&side_table::BUDGET_RSI_LINE);

/// Loop purpose, kept separate from ordinary interactive LLM budget rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RsiSpendPurpose {
    Experiment,
    Judge,
    HeldOut,
}

/// A share is advisory unless the owner pins its cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsiBudgetShare {
    pub units: u64,
    pub pinned: bool,
}

/// One vault line with a protected exploration slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsiBudgetConfig {
    pub limit: u64,
    pub exploration_units: u64,
    pub shares: BTreeMap<String, RsiBudgetShare>,
}

/// Observable accounting, including reservations that survive reopen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsiBudgetRead {
    pub limit: u64,
    pub spent: u64,
    pub reserved: u64,
    pub suspended: bool,
}

/// The durable receipt of one reservation's terminal outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RsiSettlement {
    Spent(u64),
    Refunded,
}

/// Fail-closed ledger refusals. Nothing is spent or reserved on a refusal.
#[derive(Debug, thiserror::Error)]
pub enum RsiBudgetError {
    #[error("RSI budget is not configured")]
    Unconfigured,
    #[error("RSI budget configuration is invalid or already set")]
    InvalidConfig,
    #[error("RSI reservation already exists")]
    DuplicateReservation,
    #[error("RSI spend requires an open reservation")]
    ReservationRequired,
    #[error("RSI budget capacity exceeded")]
    Exhausted,
    #[error("RSI work is suspended")]
    Suspended,
    #[error(transparent)]
    Engine(#[from] crate::Error),
}
type RsiResult<T> = std::result::Result<T, RsiBudgetError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Reservation {
    units: u64,
    purpose: RsiSpendPurpose,
    share: Option<String>,
    exploration: bool,
    settlement: Option<RsiSettlement>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Line {
    config: RsiBudgetConfig,
    suspended: bool,
    reservations: BTreeMap<String, Reservation>,
}

impl Line {
    fn usage(&self, accepts: impl Fn(&Reservation) -> bool) -> RsiResult<(u64, u64)> {
        let (mut spent, mut reserved) = (0u64, 0u64);
        for row in self.reservations.values().filter(|row| accepts(row)) {
            match row.settlement {
                Some(RsiSettlement::Spent(units)) => {
                    spent = spent.checked_add(units).ok_or(RsiBudgetError::Exhausted)?;
                }
                None => {
                    reserved = reserved
                        .checked_add(row.units)
                        .ok_or(RsiBudgetError::Exhausted)?;
                }
                Some(RsiSettlement::Refunded) => {}
            }
        }
        Ok((spent, reserved))
    }
    fn has_room(
        &self,
        limit: u64,
        units: u64,
        accepts: impl Fn(&Reservation) -> bool,
    ) -> RsiResult<()> {
        let (spent, reserved) = self.usage(accepts)?;
        if spent
            .checked_add(reserved)
            .and_then(|n| n.checked_add(units))
            .is_none_or(|total| total > limit)
        {
            return Err(RsiBudgetError::Exhausted);
        }
        Ok(())
    }
}

fn load(vault: &Vault, txn: &heed::RoTxn<'_>) -> RsiResult<Line> {
    RSI_LINE
        .get(&vault.store, txn, &())?
        .ok_or(RsiBudgetError::Unconfigured)
}
fn save(vault: &Vault, txn: &mut heed::RwTxn<'_>, line: &Line) -> RsiResult<()> {
    RSI_LINE.put(&vault.store, txn, &(), line)?;
    Ok(())
}

impl Vault {
    /// Creates the line once. Reconfiguration cannot erase receipts or spend.
    pub fn configure_rsi_budget(&self, config: RsiBudgetConfig) -> RsiResult<()> {
        if config.exploration_units > config.limit
            || config
                .shares
                .iter()
                .any(|(key, share)| key.is_empty() || share.units > config.limit)
        {
            return Err(RsiBudgetError::InvalidConfig);
        }
        let mut txn = self.store.env.write_txn().map_err(crate::Error::from)?;
        if RSI_LINE.contains(&self.store, &txn, &())? {
            return Err(RsiBudgetError::InvalidConfig);
        }
        save(
            self,
            &mut txn,
            &Line {
                config,
                suspended: false,
                reservations: BTreeMap::new(),
            },
        )?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(())
    }

    /// Admission reserves first. No reservation means no lawful loop spend.
    pub fn reserve_rsi_budget(
        &self,
        id: EntityId,
        units: u64,
        purpose: RsiSpendPurpose,
        share: Option<String>,
        exploration: bool,
    ) -> RsiResult<()> {
        let mut txn = self.store.env.write_txn().map_err(crate::Error::from)?;
        let mut line = load(self, &txn)?;
        if line.suspended {
            return Err(RsiBudgetError::Suspended);
        }
        if line.reservations.contains_key(&id.to_hex()) {
            return Err(RsiBudgetError::DuplicateReservation);
        }
        line.has_room(line.config.limit, units, |_| true)?;
        let slice = if exploration {
            line.config.exploration_units
        } else {
            line.config.limit - line.config.exploration_units
        };
        line.has_room(slice, units, |row| row.exploration == exploration)?;
        if let Some(key) = &share
            && let Some(policy) = line.config.shares.get(key)
            && policy.pinned
        {
            line.has_room(policy.units, units, |row| row.share.as_ref() == Some(key))?;
        }
        line.reservations.insert(
            id.to_hex(),
            Reservation {
                units,
                purpose,
                share,
                exploration,
                settlement: None,
            },
        );
        save(self, &mut txn, &line)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(())
    }

    /// Settles absolute usage once and releases unused reserved capacity.
    /// Repeating the exact terminal response is idempotent; changing it fails.
    pub fn settle_rsi_budget(&self, id: EntityId, spent: u64) -> RsiResult<()> {
        self.finish_rsi_reservation(id, RsiSettlement::Spent(spent))
    }

    /// Refunds an unspent reservation. Settled spend cannot be erased.
    pub fn refund_rsi_budget(&self, id: EntityId) -> RsiResult<()> {
        self.finish_rsi_reservation(id, RsiSettlement::Refunded)
    }

    fn finish_rsi_reservation(&self, id: EntityId, settlement: RsiSettlement) -> RsiResult<()> {
        let mut txn = self.store.env.write_txn().map_err(crate::Error::from)?;
        let mut line = load(self, &txn)?;
        let row = line
            .reservations
            .get_mut(&id.to_hex())
            .ok_or(RsiBudgetError::ReservationRequired)?;
        if let Some(current) = &row.settlement {
            return if *current == settlement {
                Ok(())
            } else {
                Err(RsiBudgetError::ReservationRequired)
            };
        }
        if let RsiSettlement::Spent(units) = settlement
            && units > row.units
        {
            return Err(RsiBudgetError::Exhausted);
        }
        row.settlement = Some(settlement);
        save(self, &mut txn, &line)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(())
    }

    /// A suspension holds new work; admitted work can still settle honestly.
    pub fn suspend_rsi_budget(&self, suspended: bool) -> RsiResult<()> {
        let mut txn = self.store.env.write_txn().map_err(crate::Error::from)?;
        let mut line = load(self, &txn)?;
        line.suspended = suspended;
        save(self, &mut txn, &line)?;
        txn.commit().map_err(crate::Error::from)?;
        Ok(())
    }

    pub fn rsi_budget(&self) -> RsiResult<RsiBudgetRead> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let line = load(self, &txn)?;
        let (spent, reserved) = line.usage(|_| true)?;
        Ok(RsiBudgetRead {
            limit: line.config.limit,
            spent,
            reserved,
            suspended: line.suspended,
        })
    }

    /// Reads the terminal receipt without exposing another vault's key material.
    pub fn rsi_settlement(&self, id: EntityId) -> RsiResult<Option<RsiSettlement>> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let line = load(self, &txn)?;
        Ok(line
            .reservations
            .get(&id.to_hex())
            .and_then(|row| row.settlement.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rsi_line_reserves_settles_refunds_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let config = crate::VaultConfig::device();
        let vault = Vault::open(dir.path(), config.clone()).unwrap();
        vault
            .configure_rsi_budget(RsiBudgetConfig {
                limit: 100,
                exploration_units: 20,
                shares: BTreeMap::new(),
            })
            .unwrap();
        let missing = EntityId::now();
        assert!(matches!(
            vault.settle_rsi_budget(missing, 1),
            Err(RsiBudgetError::ReservationRequired)
        ));
        let first = EntityId::now();
        let second = EntityId::now();
        vault
            .reserve_rsi_budget(first, 70, RsiSpendPurpose::Experiment, None, false)
            .unwrap();
        assert!(matches!(
            vault.reserve_rsi_budget(second, 11, RsiSpendPurpose::Judge, None, false),
            Err(RsiBudgetError::Exhausted)
        ));
        vault
            .reserve_rsi_budget(second, 20, RsiSpendPurpose::HeldOut, None, true)
            .unwrap();
        drop(vault);
        let vault = Vault::open(dir.path(), config).unwrap();
        assert_eq!(vault.rsi_budget().unwrap().reserved, 90);
        vault.suspend_rsi_budget(true).unwrap();
        assert!(matches!(
            vault.reserve_rsi_budget(EntityId::now(), 1, RsiSpendPurpose::Judge, None, true),
            Err(RsiBudgetError::Suspended)
        ));
        vault.settle_rsi_budget(first, 40).unwrap();
        vault.settle_rsi_budget(first, 40).unwrap();
        assert!(vault.settle_rsi_budget(first, 41).is_err());
        vault.refund_rsi_budget(second).unwrap();
        assert_eq!(vault.rsi_budget().unwrap().spent, 40);
        assert_eq!(vault.rsi_budget().unwrap().reserved, 0);
        assert_eq!(
            vault.rsi_settlement(second).unwrap(),
            Some(RsiSettlement::Refunded)
        );
    }
}
