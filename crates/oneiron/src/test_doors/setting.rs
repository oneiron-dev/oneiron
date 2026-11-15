//! Doors for the Setting primitive's tests (DESIGN 15-setting-primitive, stage 0.1).

#[cfg(feature = "test-support")]
use crate::Vault;
#[cfg(feature = "test-support")]
use crate::consent::AuthenticatedOwner;
#[cfg(feature = "test-support")]
use crate::entity_id::EntityId;
#[cfg(feature = "test-support")]
use crate::error::{Error, Result};
#[cfg(feature = "test-support")]
use crate::setting::{
    EngineSetting, FitCell, Resolved, SetSetting, SetSettingOutcome, SettingCaller, SettingMode,
    SettingScope,
};

pub use super::setting_keys::{after_commit_seen, after_commits, hooked_changes};

/// Plants bytes no row encodes to as `key`'s value row at `scope`: a damaged store.
///
/// # Errors
///
/// An unknown key; storage errors.
#[cfg(feature = "test-support")]
pub fn plant_undecodable_row(vault: &Vault, key: &str, scope: SettingScope) -> Result<()> {
    crate::setting::put_stored_bytes(vault, key, SettingMode::Value, scope, &[0xc1, 0xc1])
}

/// Makes each of `requests` as the owner through `Vault::set_setting_in_txn`, all in one write,
/// then fails that write when `fail` is set: the changes commit together or not at all. Once the
/// write commits, it runs the changes' after-commit hooks, as every such caller does.
///
/// # Errors
///
/// A change's refusal; `InvalidConfig` when `fail` is set; storage errors.
#[cfg(feature = "test-support")]
pub fn set_settings_in_one_write(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    requests: &[SetSetting],
    fail: bool,
) -> Result<Vec<SetSettingOutcome>> {
    vault
        .with_write_txn_grouped(|txn| {
            let mut outcomes = Vec::with_capacity(requests.len());
            for request in requests {
                outcomes.push(vault.set_setting_in_txn(
                    txn,
                    SettingCaller::Owner(owner),
                    request,
                )?);
            }
            if fail {
                return Err(Error::InvalidConfig(
                    "the caller's write fails after its changes".into(),
                ));
            }
            Ok(outcomes)
        })
        .inspect(|outcomes| {
            let changes: Vec<_> = requests.iter().zip(outcomes).collect();
            crate::setting::run_after_commit(vault, &changes);
        })
}

/// Makes `request` as the engine: applying the owner's answer to `ask`, or, with none, as an
/// engine path's own change.
///
/// # Errors
///
/// As `Vault::set_setting`.
#[cfg(feature = "test-support")]
pub fn set_setting_as_engine(
    vault: &Vault,
    ask: Option<EntityId>,
    request: SetSetting,
) -> Result<SetSettingOutcome> {
    let engine = ask.map_or_else(EngineSetting::own, EngineSetting::answer);
    vault.set_setting(SettingCaller::Engine(engine), request)
}

/// Makes `request` as the person `person` proves, on their own behalf.
///
/// # Errors
///
/// As `Vault::set_setting`.
#[cfg(feature = "test-support")]
pub fn set_setting_as_person(
    vault: &Vault,
    person: &AuthenticatedOwner,
    request: SetSetting,
) -> Result<SetSettingOutcome> {
    vault.set_setting(SettingCaller::Person(person), request)
}

/// `test.owner_number` read twice in one read: through the vault, and below it over the store's
/// tables (`Setting::read_in_dbs_txn`).
///
/// # Errors
///
/// As `Setting::read_in_txn`.
#[cfg(feature = "test-support")]
pub fn owner_number_read_both_ways(
    vault: &Vault,
    known: &[SettingScope],
) -> Result<(Resolved<u64>, Resolved<u64>)> {
    let key = &super::setting_keys::TEST_OWNER_NUMBER;
    let txn = vault.store.env.read_txn()?;
    Ok((
        key.read_in_txn(vault, &txn, known, None)?,
        key.read_in_dbs_txn(&vault.store, &txn, known, None)?,
    ))
}

/// Runs the setting tables' scrub for the erased entity `id` in a write of its own, as the
/// delete pipeline's eraser line does when `id` is erased.
///
/// # Errors
///
/// Storage errors.
#[cfg(feature = "test-support")]
pub fn erase_entity_from_settings(vault: &Vault, id: EntityId) -> Result<()> {
    let mut txn = vault.store.env.write_txn()?;
    crate::setting::erase_setting_entity_in_txn(&vault.store, &mut txn, &id)?;
    txn.commit()?;
    Ok(())
}

/// Whether a leave of a shared vault keeps the value row of `key` at `scope` in the live setting
/// table.
#[cfg(all(feature = "test-support", feature = "sync"))]
#[must_use]
pub fn leave_keeps_setting_row(key: &str, scope: SettingScope) -> bool {
    let row = oneiron_setting_contract::RowKey {
        name: key.to_owned(),
        item: None,
        mode: SettingMode::Value,
        scope,
    };
    let full = [crate::side_table::SETTING.prefix, row.encode().as_slice()].concat();
    crate::setting::leave_keeps_row(&full)
}

/// Caches `value`, learned from `runs` runs, as the fit of `key` in `cell`, as the learning
/// projector does: the fit a learned key's read finds there.
///
/// # Errors
///
/// Storage errors.
#[cfg(feature = "test-support")]
pub fn put_setting_fit(
    vault: &Vault,
    key: &str,
    cell: &FitCell,
    value: f64,
    runs: f64,
) -> Result<()> {
    let fit_key = crate::learning_setting::setting_fit_key(
        key,
        cell.project,
        cell.goal,
        cell.task_type.as_deref(),
    );
    let mut txn = vault.store.env.write_txn()?;
    crate::learning::project::SETTING_FIT.put(
        &vault.store,
        &mut txn,
        &fit_key,
        &crate::learning::project::SettingFit { value, runs, at: 0 },
    )?;
    txn.commit()?;
    Ok(())
}

/// The seed a fit of `test.learned_rate` starts from at the places `known`, with its weight in
/// runs (`Setting::seed_in_txn`).
///
/// # Errors
///
/// A place the key does not admit; storage errors.
#[cfg(feature = "test-support")]
pub fn learned_rate_seed(vault: &Vault, known: &[SettingScope]) -> Result<Option<(f64, f64)>> {
    let txn = vault.store.env.read_txn()?;
    super::setting_keys::TEST_LEARNED_RATE.seed_in_txn(&vault.store, &txn, known)
}

/// The setting change of sequence `sequence`, as the change stream stores it.
///
/// # Errors
///
/// A change row that does not decode; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_change(
    vault: &Vault,
    sequence: u64,
) -> Result<Option<crate::setting::SettingChange>> {
    let txn = vault.store.env.read_txn()?;
    crate::setting::change_in_txn(&vault.store, &txn, sequence)
}

/// `test.ordered_cap` read where the reader knows `known`, and `ask`, one call's request, met
/// with it: the request layer of the typed read (stage 6.0).
///
/// # Errors
///
/// As `Setting::read_in_txn` and `Setting::narrowed`.
#[cfg(feature = "test-support")]
pub fn ordered_cap_requested(
    vault: &Vault,
    known: &[SettingScope],
    ask: u64,
) -> Result<crate::setting::Requested<u64>> {
    let key = &super::setting_keys::TEST_ORDERED_CAP;
    let txn = vault.store.env.read_txn()?;
    key.narrowed(key.read_in_txn(vault, &txn, known, None)?, &ask)
}

/// The same request of `test.custom_window`, a key whose order has no meet.
///
/// # Errors
///
/// `InvalidConfig`: a request never reaches a key with no meet.
#[cfg(feature = "test-support")]
pub fn custom_window_requested(vault: &Vault, ask: u64) -> Result<crate::setting::Requested<u64>> {
    let key = &super::setting_keys::TEST_CUSTOM_WINDOW;
    let txn = vault.store.env.read_txn()?;
    key.narrowed(key.read_in_txn(vault, &txn, &[], None)?, &ask)
}
