//! Test-only hooks. The REDACTION_AUDIT rematerialization race pin: the
//! armed writes land just before the same-txn recheck+verify+put path starts,
//! so production code must observe mid-flight lease revocation or local
//! divergent receipt bytes before admitting the remote receipt. The
//! device-only races: a settings edit lands, or a machine's standing
//! expires, while a raw verdict inspects a window.

use std::cell::{Cell, RefCell};

use crate::entity_id::EntityId;
use crate::ports::EntityStoreMaintenance;
use crate::{Error, Result, Vault};

thread_local! {
    static RECEIPT_REVOCATION: RefCell<Option<(String, Vec<u8>)>> = const { RefCell::new(None) };
    static RECEIPT_LOCAL_WRITE: RefCell<Option<(EntityId, Vec<u8>)>> = const { RefCell::new(None) };
    static DEVICE_ONLY_RACE: RefCell<Option<DeviceOnlyRace>> = const { RefCell::new(None) };
    static REPLACEMENT_INSTALL_REFUSAL: Cell<bool> = const { Cell::new(false) };
}

/// Refuses the next window replacement's install transaction once, as a disk floor would.
pub fn arm_replacement_install_refusal() {
    REPLACEMENT_INSTALL_REFUSAL.with(|armed| armed.set(true));
}

pub(super) fn refuse_replacement_install() -> Result<()> {
    if REPLACEMENT_INSTALL_REFUSAL.with(|armed| armed.replace(false)) {
        return Err(Error::InvariantViolation("replacement install refused"));
    }
    Ok(())
}

type DeviceOnlyRace = Box<dyn FnOnce(&Vault) -> Result<()>>;

/// Flags `world` device-only once, as a raw verdict opens the window it
/// inspects or a selector export closes its snapshot: a flag committed after
/// the door read the flag set.
pub fn arm_device_only_flag_race(world: EntityId) {
    arm_device_only_race(move |vault| vault.keep_world_on_this_machine_for_test(world, true));
}

/// Runs `race` once, as a raw verdict opens the window it inspects or a
/// selector export closes its snapshot.
pub fn arm_device_only_race(race: impl FnOnce(&Vault) -> Result<()> + 'static) {
    DEVICE_ONLY_RACE.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(race));
    });
}

pub(in crate::sync) fn run_device_only_flag_race(vault: &Vault) -> Result<()> {
    match DEVICE_ONLY_RACE.with(|slot| slot.borrow_mut().take()) {
        Some(race) => race(vault),
        None => Ok(()),
    }
}

pub fn arm_receipt_revocation_race(lease_key: String, revoked_row: Vec<u8>) {
    RECEIPT_REVOCATION.with(|slot| {
        *slot.borrow_mut() = Some((lease_key, revoked_row));
    });
}

pub fn arm_receipt_local_write_race(id: EntityId, local_blob: Vec<u8>) {
    RECEIPT_LOCAL_WRITE.with(|slot| {
        *slot.borrow_mut() = Some((id, local_blob));
    });
}

pub(super) fn run_receipt_revocation_race(vault: &Vault) -> Result<()> {
    let armed = RECEIPT_REVOCATION.with(|slot| slot.borrow_mut().take());
    if let Some((lease_key, revoked_row)) = armed {
        if revoked_row.is_empty() {
            return Err(Error::InvariantViolation("empty revoked lease test row"));
        }
        vault.sync_state_put(&lease_key, &revoked_row)?;
    }
    let armed = RECEIPT_LOCAL_WRITE.with(|slot| slot.borrow_mut().take());
    if let Some((id, local_blob)) = armed {
        if local_blob.is_empty() {
            return Err(Error::InvariantViolation("empty local receipt test row"));
        }
        vault.with_write_txn_grouped(|wtxn| {
            EntityStoreMaintenance::port_raw_record_seed(&vault.store, wtxn, &id, &local_blob)
        })?;
    }
    Ok(())
}
