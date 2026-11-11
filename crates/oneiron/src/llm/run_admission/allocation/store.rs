use super::{
    ACCOUNT, AccountRow, AllocationCallKey, AllocationCommit, AllocationRow,
    AllocationServingFence, AllocationStoreError, AllocationTerminal, DurableAllocationHold,
    DurableAllocationRead, VaultAllocationLedger,
};
use crate::llm::VaultResidentLedger;
use crate::llm::run_admission::host::{Unpriced, convert};
use crate::llm::run_admission::{Allocation, AllocationRefusal, LeaseUnit, UnitRate};
use crate::store::Callback;
use crate::{EntityId, Vault};
use std::sync::Arc;

type Result<T> = std::result::Result<T, AllocationStoreError>;

impl VaultAllocationLedger {
    /// Binds once to this real lease acquisition. A reopen keeps all balances
    /// and pending holds; a second handle on the same lease keeps its fence.
    pub fn new(vault: Arc<Vault>) -> Result<AllocationCommit<Arc<Self>>> {
        let lease = vault
            .writer_lease()
            .ok_or(AllocationStoreError::WriterLease)?;
        if !lease.held_by_current_process() || lease.file.is_none() {
            return Err(AllocationStoreError::WriterLease);
        }
        #[cfg(unix)]
        let _ = lease.bind_lock_file()?;
        let ledger = Arc::new(Self {
            fence: AllocationServingFence(lease.acquisition_id()),
            vault,
        });
        let committed = ledger.write(false, |_txn, row| {
            let changed = row.fence != Some(ledger.fence);
            row.fence = Some(ledger.fence);
            Ok(((), changed))
        })?;
        Ok(AllocationCommit {
            value: ledger,
            revision: committed.revision,
            postcommit_error: committed.postcommit_error,
        })
    }

    fn require_lease(&self) -> Result<()> {
        let lease = self
            .vault
            .writer_lease()
            .ok_or(AllocationStoreError::WriterLease)?;
        if !lease.held_by_current_process()
            || lease.file.is_none()
            || AllocationServingFence(lease.acquisition_id()) != self.fence
        {
            return Err(AllocationStoreError::ServingChanged);
        }
        #[cfg(unix)]
        let _ = lease.bind_lock_file()?;
        Ok(())
    }

    // No Host/Run/Budget/Residents mutex is held while acquiring this writer.
    // A callback uses only this supplied transaction and opens no writer of its own.
    fn write<T>(
        &self,
        require_fence: bool,
        change: impl FnOnce(&mut heed::RwTxn<'_>, &mut AccountRow) -> Result<(T, bool)>,
    ) -> Result<AllocationCommit<T>> {
        self.require_lease()?;
        let mut committed = None;
        let result = self.vault.write_txn_door_after_commit(
            Callback::Opaque,
            |txn| {
                self.require_lease()?;
                let mut row = ACCOUNT
                    .get(&self.vault.store, txn, &())?
                    .unwrap_or_default();
                if require_fence && row.fence != Some(self.fence) {
                    return Err(AllocationStoreError::ServingChanged);
                }
                let (value, changed) = change(txn, &mut row)?;
                if changed {
                    row.revision = row
                        .revision
                        .checked_add(1)
                        .ok_or(AllocationStoreError::Overflow)?;
                    ACCOUNT.put(&self.vault.store, txn, &(), &row)?;
                }
                Ok((value, row.revision))
            },
            |value| {
                committed = Some(value);
                Ok(())
            },
        );
        match committed {
            Some((value, revision)) => Ok(AllocationCommit {
                value,
                revision,
                postcommit_error: result.err(),
            }),
            None => {
                result?;
                unreachable!("a successful allocation write publishes after its durable commit")
            }
        }
    }

    /// Installs an explicitly selected fresh grant. Old captured holds keep
    /// their own allocation; closing the old selection releases nothing.
    pub fn grant(&self, allocation: Allocation) -> Result<AllocationCommit<()>> {
        self.write(true, |_txn, row| {
            if row
                .newest_generation
                .is_some_and(|newest| allocation.reference.generation <= newest)
            {
                return Err(AllocationStoreError::StaleGeneration);
            }
            if let Some(current) = &row.current
                && let Some(old) = row
                    .allocations
                    .iter_mut()
                    .find(|old| &old.allocation.reference == current)
            {
                old.accepting = false;
            }
            row.newest_generation = Some(allocation.reference.generation);
            row.current = Some(allocation.reference.clone());
            row.allocations.push(AllocationRow {
                remaining_units: allocation.units,
                allocation,
                accepting: true,
                pending_units: 0,
                used_units: 0,
                holds: Vec::new(),
            });
            Ok(((), true))
        })
    }

    /// Changes only fresh-grant status. Remaining current capacity still works.
    pub fn refuse_fresh(&self, reason: Option<AllocationRefusal>) -> Result<AllocationCommit<()>> {
        self.write(true, |_txn, row| {
            let changed = row.refused != reason;
            row.refused = reason;
            Ok(((), changed))
        })
    }

    /// Stops fresh reservations, keeping every pending original hold intact.
    pub fn close_current(&self) -> Result<AllocationCommit<()>> {
        self.write(true, |_txn, row| {
            let current = current_mut(row)?;
            let changed = current.accepting;
            current.accepting = false;
            Ok(((), changed))
        })
    }

    /// Reserves against the explicit durable current selection. `freeze` must
    /// persist the ORIGINAL producer in this same writer before the hold returns.
    /// A failure aborts both writes. It must not call a void receipt sink or
    /// rebuild prices/owner from a later catalog during recovery.
    pub fn reserve<T>(
        &self,
        key: AllocationCallKey,
        native_units: u128,
        native: &LeaseUnit,
        rates: &[UnitRate],
        resident: Option<EntityId>,
        freeze: impl FnOnce(&mut heed::RwTxn<'_>, &DurableAllocationHold) -> Result<T>,
    ) -> Result<AllocationCommit<(DurableAllocationHold, T)>> {
        self.write(true, |txn, row| {
            if row
                .allocations
                .iter()
                .any(|allocation| allocation.holds.iter().any(|hold| hold.key == key))
            {
                return Err(AllocationStoreError::HoldExists);
            }
            let current = current_mut(row)?;
            if !current.accepting {
                return Err(AllocationStoreError::Closed);
            }
            let units = convert(native_units, native, &current.allocation.unit, rates).map_err(
                |error| match error {
                    Unpriced::NoRate => AllocationStoreError::UnitMismatch,
                    Unpriced::TooLarge => AllocationStoreError::Overflow,
                },
            )?;
            if units > current.remaining_units {
                return Err(AllocationStoreError::Exhausted);
            }
            let (share, committed, overdraft) = match resident {
                Some(resident) => {
                    let standing = VaultResidentLedger::new(Arc::clone(&self.vault))
                        .standing_in_write_txn(
                            txn,
                            resident,
                            &current.allocation.reference,
                            current.allocation.units,
                        )?;
                    let held = current
                        .holds
                        .iter()
                        .filter(|hold| hold.resident == Some(resident) && hold.terminal.is_none())
                        .try_fold(0_u64, |sum, hold| {
                            sum.checked_add(hold.reserved_units)
                                .ok_or(AllocationStoreError::Overflow)
                        })?;
                    let committed = standing
                        .used_units
                        .checked_add(held)
                        .ok_or(AllocationStoreError::Overflow)?;
                    let after = committed
                        .checked_add(units)
                        .ok_or(AllocationStoreError::Overflow)?;
                    let overdraft = after.saturating_sub(standing.share_units.max(committed));
                    if standing.pinned && overdraft > 0 {
                        return Err(AllocationStoreError::ResidentShareSpent { resident });
                    }
                    (standing.share_units, committed, overdraft)
                }
                None => (0, 0, 0),
            };
            let hold = DurableAllocationHold {
                key,
                allocation: current.allocation.reference.clone(),
                unit: current.allocation.unit.clone(),
                reserved_units: units,
                serving_fence: self.fence,
                resident,
                resident_share_units: share,
                resident_committed_units: committed,
                overdraft_units: overdraft,
                dispatched: false,
                terminal: None,
            };
            current.remaining_units -= units;
            current.pending_units = current
                .pending_units
                .checked_add(units)
                .ok_or(AllocationStoreError::Overflow)?;
            let producer = freeze(txn, &hold)?;
            current.holds.push(hold.clone());
            Ok(((hold, producer), true))
        })
    }

    /// The actual physical adapter must commit this BEFORE releasing bytes.
    /// It is not implied by an admitted receipt, a model answer, or a cached bit.
    pub fn begin_dispatch(&self, key: &AllocationCallKey) -> Result<AllocationCommit<()>> {
        self.write(true, |_txn, row| {
            let hold = hold_mut(row, key)?;
            if hold.serving_fence != self.fence {
                return Err(AllocationStoreError::ServingChanged);
            }
            if hold.terminal.is_some() || hold.dispatched {
                return Err(AllocationStoreError::HoldClosed);
            }
            hold.dispatched = true;
            Ok(((), true))
        })
    }

    /// Original terminal + resident charge + `stage` commit together, once.
    /// `stage` uses the original admitted producer and original terminal to feed
    /// existing usage.pending in this writer. The same terminal is idempotent;
    /// a different terminal cannot charge or replace the first. No recovery
    /// infers unsent, releases a hold, or re-clocks from dispatched=false.
    pub fn settle(
        &self,
        key: &AllocationCallKey,
        terminal: AllocationTerminal,
        stage: impl FnOnce(
            &mut heed::RwTxn<'_>,
            &DurableAllocationHold,
            &AllocationTerminal,
        ) -> Result<()>,
    ) -> Result<AllocationCommit<()>> {
        self.write(true, |txn, row| {
            let allocation = row
                .allocations
                .iter_mut()
                .find(|allocation| allocation.holds.iter().any(|hold| &hold.key == key))
                .ok_or(AllocationStoreError::HoldNotFound)?;
            let index = allocation
                .holds
                .iter()
                .position(|hold| &hold.key == key)
                .ok_or(AllocationStoreError::HoldNotFound)?;
            let hold = &allocation.holds[index];
            if let Some(first) = &hold.terminal {
                return if first == &terminal {
                    Ok(((), false))
                } else {
                    Err(AllocationStoreError::TerminalMismatch)
                };
            }
            if terminal.dispatched && !hold.dispatched {
                return Err(AllocationStoreError::DispatchNotRecorded);
            }
            allocation.pending_units = allocation
                .pending_units
                .checked_sub(hold.reserved_units)
                .ok_or(AllocationStoreError::Overflow)?;
            allocation.used_units = allocation
                .used_units
                .checked_add(terminal.units)
                .ok_or(AllocationStoreError::Overflow)?;
            // True overrun remains used even beyond the original grant.
            allocation.remaining_units = allocation
                .allocation
                .units
                .saturating_sub(allocation.used_units)
                .saturating_sub(allocation.pending_units);
            if terminal.units > 0
                && let Some(resident) = hold.resident
            {
                let room = hold
                    .resident_share_units
                    .saturating_sub(hold.resident_committed_units);
                VaultResidentLedger::new(Arc::clone(&self.vault)).charge_in_write_txn(
                    txn,
                    resident,
                    &hold.allocation,
                    terminal.units,
                    terminal.units.saturating_sub(room),
                )?;
            }
            stage(txn, hold, &terminal)?;
            allocation.holds[index].terminal = Some(terminal);
            Ok(((), true))
        })
    }

    /// Explicit current selection and fresh-grant status, read from the store.
    pub fn status(&self) -> Result<crate::llm::run_admission::AccountStatus> {
        self.require_lease()?;
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let row = ACCOUNT
            .get(&self.vault.store, &txn, &())?
            .unwrap_or_default();
        if row.fence != Some(self.fence) {
            return Err(AllocationStoreError::ServingChanged);
        }
        Ok(crate::llm::run_admission::AccountStatus {
            allocation: row.current,
            fresh_allocation_refused: row.refused,
        })
    }

    /// Read-only observation. Never used to rebuild a full-grant BudgetGuard.
    pub fn allocations(&self) -> Result<Vec<DurableAllocationRead>> {
        self.require_lease()?;
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let row = ACCOUNT
            .get(&self.vault.store, &txn, &())?
            .unwrap_or_default();
        if row.fence != Some(self.fence) {
            return Err(AllocationStoreError::ServingChanged);
        }
        Ok(row
            .allocations
            .into_iter()
            .map(|allocation| DurableAllocationRead {
                allocation: allocation.allocation,
                accepting: allocation.accepting,
                remaining_units: allocation.remaining_units,
                pending_units: allocation.pending_units,
                used_units: allocation.used_units,
                revision: row.revision,
                serving_fence: self.fence,
            })
            .collect())
    }

    /// Recovery reads the exact original hold. Reading it changes no capacity.
    pub fn hold(&self, key: &AllocationCallKey) -> Result<Option<DurableAllocationHold>> {
        self.require_lease()?;
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let row = ACCOUNT
            .get(&self.vault.store, &txn, &())?
            .unwrap_or_default();
        if row.fence != Some(self.fence) {
            return Err(AllocationStoreError::ServingChanged);
        }
        Ok(row
            .allocations
            .into_iter()
            .flat_map(|allocation| allocation.holds)
            .find(|hold| &hold.key == key))
    }
}

fn current_mut(row: &mut AccountRow) -> Result<&mut AllocationRow> {
    let current = row
        .current
        .as_ref()
        .ok_or(AllocationStoreError::NoAllocation)?;
    row.allocations
        .iter_mut()
        .find(|allocation| &allocation.allocation.reference == current)
        .ok_or(AllocationStoreError::NoAllocation)
}

fn hold_mut<'a>(
    row: &'a mut AccountRow,
    key: &AllocationCallKey,
) -> Result<&'a mut DurableAllocationHold> {
    row.allocations
        .iter_mut()
        .flat_map(|allocation| &mut allocation.holds)
        .find(|hold| &hold.key == key)
        .ok_or(AllocationStoreError::HoldNotFound)
}
