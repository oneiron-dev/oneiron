use super::{
    ACCOUNT, AccountRow, AllocationCallKey, AllocationCommit, AllocationRow,
    AllocationServingFence, AllocationStoreError, AllocationTerminal, DurableAllocationHold,
    DurableAllocationRead, ReservationParties, VaultAllocationLedger,
};
use crate::federation::WalletRef;
use crate::llm::VaultResidentLedger;
use crate::llm::run_admission::host::{Unpriced, convert};
use crate::llm::run_admission::slot::{Slot, SlotMiss, select};
use crate::llm::run_admission::{
    AccountStatus, Allocation, AllocationRef, AllocationRefusal, LeaseUnit, ResidentShareScope,
    SelectedAllocation, UnitRate, is_gpu_line_allocation,
};
use crate::store::Callback;
use crate::Vault;
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
                fold_legacy_selection(&mut row);
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

    /// Installs an explicitly selected fresh grant in its slot: its unit and
    /// the wallet the host named (row M2-I). It closes and deselects the
    /// allocation selected in that slot and any older generation of its own
    /// id, and nothing else. Old captured holds keep their own allocation;
    /// closing the old selection releases nothing. Its generation must be
    /// newer than every one its own id held; other ids' do not count. A GPU
    /// line's allocation is refused: only its claims draw on it (row M2-I2).
    pub fn grant(&self, allocation: Allocation) -> Result<AllocationCommit<()>> {
        if is_gpu_line_allocation(&allocation.reference) {
            return Err(AllocationStoreError::LineManaged);
        }
        self.write(true, |_txn, row| {
            let reference = &allocation.reference;
            if row.allocations.iter().any(|held| {
                held.allocation.reference.id == reference.id
                    && reference.generation <= held.allocation.reference.generation
            }) {
                return Err(AllocationStoreError::StaleGeneration);
            }
            let replaced: Vec<AllocationRef> = row
                .selected
                .iter()
                .filter(|selected| {
                    row.allocations
                        .iter()
                        .find(|old| &old.allocation.reference == *selected)
                        .is_none_or(|old| {
                            old.allocation.reference.id == reference.id
                                || (old.allocation.unit == allocation.unit
                                    && old.allocation.wallet == allocation.wallet)
                        })
                })
                .cloned()
                .collect();
            for old in &mut row.allocations {
                if replaced.contains(&old.allocation.reference) {
                    old.accepting = false;
                }
            }
            row.selected.retain(|selected| !replaced.contains(selected));
            row.selected.push(reference.clone());
            row.newest_generation = Some(
                row.newest_generation
                    .map_or(reference.generation, |newest| {
                        newest.max(reference.generation)
                    }),
            );
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

    /// Stops fresh reservations on the selected allocation `reference`,
    /// keeping every pending original hold intact. It stays its slot's
    /// selection, so a call in that slot is refused as closed, never moved
    /// to another, until the host grants that slot again.
    pub fn close(&self, reference: &AllocationRef) -> Result<AllocationCommit<()>> {
        self.write(true, |_txn, row| {
            if !row.selected.contains(reference) {
                return Err(AllocationStoreError::NoAllocation);
            }
            let selected = row
                .allocations
                .iter_mut()
                .find(|allocation| &allocation.allocation.reference == reference)
                .ok_or(AllocationStoreError::NoAllocation)?;
            let changed = selected.accepting;
            selected.accepting = false;
            Ok(((), changed))
        })
    }

    /// Reserves against the explicit durable selection: the allocation of the
    /// call's slot (the one rule the in-memory account uses), of the funding
    /// Grant's wallet when `parties.funding` names one (FIX 7766), chosen and
    /// checked inside this writer before anything is held, and on the share
    /// `parties.resident` holds of it (FIX 7767). `freeze` must persist the
    /// ORIGINAL producer in this same writer before the hold returns. A
    /// failure aborts both writes. It must not call a void receipt sink or
    /// rebuild prices/owner from a later catalog during recovery.
    pub fn reserve<T>(
        &self,
        key: AllocationCallKey,
        native_units: u128,
        native: &LeaseUnit,
        rates: &[UnitRate],
        parties: ReservationParties<'_>,
        freeze: impl FnOnce(&mut heed::RwTxn<'_>, &DurableAllocationHold) -> Result<T>,
    ) -> Result<AllocationCommit<(DurableAllocationHold, T)>> {
        let ReservationParties { resident, funding } = parties;
        self.write(true, |txn, row| {
            if row
                .allocations
                .iter()
                .any(|allocation| allocation.holds.iter().any(|hold| hold.key == key))
            {
                return Err(AllocationStoreError::HoldExists);
            }
            let index = selected_index(row, native, rates, funding)?;
            let chosen = &mut row.allocations[index];
            if !chosen.accepting {
                return Err(AllocationStoreError::Closed);
            }
            let units =
                convert(native_units, native, &chosen.allocation.unit, rates).map_err(|error| {
                    match error {
                        Unpriced::NoRate => AllocationStoreError::UnitMismatch,
                        Unpriced::TooLarge => AllocationStoreError::Overflow,
                    }
                })?;
            if units > chosen.remaining_units {
                return Err(AllocationStoreError::Exhausted);
            }
            let (share, committed, overdraft) = match resident {
                Some(resident) => {
                    let standing = VaultResidentLedger::new(Arc::clone(&self.vault))
                        .standing_in_write_txn(
                            txn,
                            resident,
                            &chosen.allocation.reference,
                            chosen.allocation.units,
                            ResidentShareScope::of_wallet(chosen.allocation.wallet.as_ref()),
                        )?;
                    let held = chosen
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
                allocation: chosen.allocation.reference.clone(),
                unit: chosen.allocation.unit.clone(),
                reserved_units: units,
                serving_fence: self.fence,
                resident,
                resident_share_units: share,
                resident_committed_units: committed,
                overdraft_units: overdraft,
                dispatched: false,
                terminal: None,
            };
            chosen.remaining_units -= units;
            chosen.pending_units = chosen
                .pending_units
                .checked_add(units)
                .ok_or(AllocationStoreError::Overflow)?;
            let producer = freeze(txn, &hold)?;
            chosen.holds.push(hold.clone());
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

    /// Every selected allocation, one per slot, and fresh-grant status, read
    /// from the store.
    pub fn status(&self) -> Result<AccountStatus> {
        self.require_lease()?;
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let mut row = ACCOUNT
            .get(&self.vault.store, &txn, &())?
            .unwrap_or_default();
        if row.fence != Some(self.fence) {
            return Err(AllocationStoreError::ServingChanged);
        }
        fold_legacy_selection(&mut row);
        Ok(AccountStatus {
            allocations: row
                .selected
                .iter()
                .filter_map(|reference| {
                    row.allocations
                        .iter()
                        .find(|allocation| &allocation.allocation.reference == reference)
                })
                .map(|selected| SelectedAllocation {
                    reference: selected.allocation.reference.clone(),
                    unit: selected.allocation.unit.clone(),
                    wallet: selected.allocation.wallet.clone(),
                })
                .collect(),
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

/// A row written before allocations by wallet names its one selection in
/// `current` (row M2-I): it is one more selected allocation, closed or not.
fn fold_legacy_selection(row: &mut AccountRow) {
    if let Some(current) = row.current.take()
        && !row.selected.contains(&current)
    {
        row.selected.push(current);
    }
}

/// The index in `row.allocations` of the selected allocation a call in
/// `native` units, priced by `rates`, holds on, for a run funded by
/// `funding`'s wallet or by none: the one rule the in-memory account uses.
fn selected_index(
    row: &AccountRow,
    native: &LeaseUnit,
    rates: &[UnitRate],
    funding: Option<&WalletRef>,
) -> Result<usize> {
    let indices: Vec<usize> = row
        .selected
        .iter()
        .filter_map(|reference| {
            row.allocations
                .iter()
                .position(|allocation| &allocation.allocation.reference == reference)
        })
        .collect();
    let slots: Vec<Slot<'_>> = indices
        .iter()
        .map(|&index| Slot {
            unit: &row.allocations[index].allocation.unit,
            wallet: row.allocations[index].allocation.wallet.as_ref(),
        })
        .collect();
    let chosen = select(&slots, native, rates, funding).map_err(|miss| match miss {
        SlotMiss::Empty => AllocationStoreError::NoAllocation,
        SlotMiss::Wallet { expected, live } => {
            AllocationStoreError::WalletMismatch { expected, live }
        }
        SlotMiss::Unpriced { .. } => AllocationStoreError::UnitMismatch,
        SlotMiss::Ambiguous { units } => AllocationStoreError::Ambiguous { units },
    })?;
    Ok(indices[chosen])
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
