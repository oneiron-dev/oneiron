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

/// Runs the pack door for `pack` over `defaults` (each key's name and its default as JSON), in its
/// own write, as a new build or a pack's update would: every key not listed keeps its row. The
/// whole list is the pack's layer.
///
/// # Errors
///
/// An unknown key or a default its key does not take; as the pack door.
#[cfg(feature = "test-support")]
pub fn apply_pack_defaults(
    vault: &Vault,
    pack: &str,
    defaults: &[(&str, serde_json::Value)],
) -> Result<Option<crate::setting::PackApplied>> {
    let defaults = defaults
        .iter()
        .map(|(key, value)| {
            let spec = crate::setting::spec_named(key)?;
            Ok((spec, spec.kind.from_json(value.clone())?))
        })
        .collect::<Result<Vec<_>>>()?;
    vault.apply_pack_defaults(pack, &defaults, None)
}

/// The `engine` pack's run, as the vault's open makes it.
///
/// # Errors
///
/// As the pack door.
#[cfg(feature = "test-support")]
pub fn apply_engine_pack(vault: &Vault) -> Result<Option<crate::setting::PackApplied>> {
    vault.apply_engine_pack()
}

/// The revision of `key`'s row in `pack`'s layer: the sequence of the change that wrote it, 0
/// for a first default; `None` with no readable row.
///
/// # Errors
///
/// An unknown key; storage errors.
#[cfg(feature = "test-support")]
pub fn pack_row_revision(vault: &Vault, key: &str, pack: &str) -> Result<Option<u64>> {
    crate::setting::layer_row_revision(vault, key, pack)
}

/// Loses `key`'s row in `pack`'s layer, as a damaged store would.
///
/// # Errors
///
/// An unknown key; storage errors.
#[cfg(feature = "test-support")]
pub fn lose_pack_row(vault: &Vault, key: &str, pack: &str) -> Result<()> {
    crate::setting::delete_layer_row(vault, key, pack)
}

/// Runs the move hook for `project` in its own write, as a door that moved it would, with its
/// lines either side of the move named: `before` and `after`, each the project and then its
/// ancestors nearest first. Returns how many carried rows it wrote.
///
/// # Errors
///
/// A key's `on_change` refusal; storage errors.
#[cfg(feature = "test-support")]
pub fn carry_settings_between(
    vault: &Vault,
    project: EntityId,
    before: &[EntityId],
    after: &[EntityId],
) -> Result<usize> {
    vault.with_write_txn_grouped(|txn| {
        crate::setting::carry_between_in_txn(vault, txn, project, before, after)
    })
}

/// The lines of `project` a setting read walks: the project, then its ancestors over the stored
/// parents, nearest first.
///
/// # Errors
///
/// A stored parent that is not an id; storage errors.
#[cfg(feature = "test-support")]
pub fn project_lines(vault: &Vault, project: EntityId) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    vault.project_lines_in_txn(&txn, project)
}

/// Another machine of the vault's owner (stage 7a-2): enrolled as the owner's own, its install
/// key held by the test, so it signs setting acts as its own door would.
#[cfg(feature = "test-support")]
pub struct EnrolledMachine {
    machine: EntityId,
    key: ed25519_dalek::SigningKey,
}

/// Enrols a machine whose install key is derived from `seed` as one of the owner's own
/// machines, by the owner's answer on this install.
///
/// # Errors
///
/// A vault with no authority root; the enrolment's refusal; storage errors.
#[cfg(feature = "test-support")]
pub fn enroll_machine_with_key(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    seed: u8,
) -> Result<EnrolledMachine> {
    use crate::authority::{
        ActSurface, MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        MachineDeviceClass, MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership,
        MachineRole, machine_profile_proof_transcript,
    };
    use ed25519_dalek::Signer;

    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let machine = EntityId::now();
    let vault_id = vault
        .authority_vault_id()?
        .ok_or(Error::InvariantViolation(
            "a peer machine needs a rooted vault",
        ))?;
    let machine_key = key.verifying_key().to_bytes();
    let device_class = MachineDeviceClass::Computer;
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = key
        .sign(&machine_profile_proof_transcript(
            &vault_id,
            machine,
            &machine_key,
            device_class,
            &encryption_key,
        ))
        .to_bytes();
    vault.enroll_machine(
        owner,
        ActSurface::ThisInstall,
        &MachineEnrolmentRequest {
            vault_id,
            machine,
            machine_key,
            device_class,
            encryption_key,
            machine_proof,
        },
        MachineRole::Owned(MachineOwnership::Yours),
        None,
    )?;
    Ok(EnrolledMachine { machine, key })
}

/// Where the acts on `key`'s row (`item`, `mode`, `scope`) stand now: an act a peer signs on
/// it later did not see any act appended since.
#[cfg(feature = "test-support")]
pub struct SettingFrontier(crate::authority::SettingFrontier);

/// The frontier of `key`'s row `mode` at `scope`, for `item`.
///
/// # Errors
///
/// A key name of another shape; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_frontier(
    vault: &Vault,
    key: &str,
    item: Option<&str>,
    mode: SettingMode,
    scope: SettingScope,
) -> Result<SettingFrontier> {
    vault
        .setting_frontier(&[row_key(key, item, mode, scope)])
        .map(SettingFrontier)
}

/// One setting row as a test names it: its key, item, mode and scope.
#[cfg(feature = "test-support")]
pub type SlotName<'a> = (&'a str, Option<&'a str>, SettingMode, SettingScope);

/// The frontier of the rows `slots` together (stage 7a-3): a batch signed on it names each row's
/// revision as it stood.
///
/// # Errors
///
/// A key name of another shape; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_frontier_of(vault: &Vault, slots: &[SlotName<'_>]) -> Result<SettingFrontier> {
    let slots: Vec<_> = slots
        .iter()
        .map(|(key, item, mode, scope)| row_key(key, *item, *mode, scope.clone()))
        .collect();
    vault.setting_frontier(&slots).map(SettingFrontier)
}

#[cfg(feature = "test-support")]
fn row_key(
    key: &str,
    item: Option<&str>,
    mode: SettingMode,
    scope: SettingScope,
) -> oneiron_setting_contract::RowKey {
    oneiron_setting_contract::RowKey {
        name: key.to_owned(),
        item: item.map(str::to_owned),
        mode,
        scope,
    }
}

/// The owner `owner`'s change of `key`'s row (`item`, `mode`, `scope`) to `value` (`None`
/// clears), as `signer`'s own door signs it on `frontier` at `ts`, landed here as a peer's entry
/// lands: through the authority log's write door, whose commit runs the setting projection.
///
/// # Errors
///
/// The log's refusal of the entry; storage errors.
#[cfg(feature = "test-support")]
#[allow(clippy::too_many_arguments)]
pub fn land_setting_act_from(
    vault: &Vault,
    signer: &EnrolledMachine,
    owner: EntityId,
    frontier: &SettingFrontier,
    (key, item, mode, scope): (&str, Option<&str>, SettingMode, SettingScope),
    value: Option<serde_json::Value>,
    ts: u64,
) -> Result<()> {
    land_setting_batch_from(
        vault,
        signer,
        owner,
        frontier,
        &[((key, item, mode, scope), value)],
        ts,
    )
    .map(|_| ())
}

/// The owner `owner`'s change of each row of `rows` to its value (`None` clears) as ONE act
/// (a batch, stage 7a-3), signed as `signer`'s own door signs it on `frontier` at `ts`, landed
/// here as a peer's entry lands. A row `frontier` did not read names `seen` zero. Whether the
/// fold here counts the entry (valid, and not held back).
///
/// # Errors
///
/// The log's refusal of the entry; storage errors.
#[cfg(feature = "test-support")]
pub fn land_setting_batch_from(
    vault: &Vault,
    signer: &EnrolledMachine,
    owner: EntityId,
    frontier: &SettingFrontier,
    rows: &[(SlotName<'_>, Option<serde_json::Value>)],
    ts: u64,
) -> Result<bool> {
    let rows = rows
        .iter()
        .map(|((key, item, mode, scope), value)| {
            let inline = value
                .as_ref()
                .map(serde_json::to_vec)
                .transpose()
                .map_err(|_| Error::InvariantViolation("a setting value's JSON"))?;
            Ok((row_key(key, *item, *mode, scope.clone()), inline))
        })
        .collect::<Result<Vec<_>>>()?;
    let entry =
        vault.sign_setting_act_as((signer.machine, &signer.key), owner, &frontier.0, rows, ts)?;
    let hash = oneiron_authority::authority::authority_entry_hash(&entry)?;
    let at = crate::temporal::TimeRange { start: ts, end: ts };
    vault.put_authority_log_entries(&[(entry, at, ts)])?;
    let fold = vault.authority_fold()?;
    Ok(fold.valid_entries.contains(&hash) && !fold.held_back_entries().contains(&hash))
}

/// Whether the setting publish pass ran in this vault (stage 7a-3).
///
/// # Errors
///
/// Storage errors.
#[cfg(feature = "test-support")]
pub fn settings_published(vault: &Vault) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    crate::setting::settings_published_in_txn(vault, &txn)
}

/// Forgets every setting row the projection wrote from signed acts, and its record (stage
/// 7a-3): the install then holds the log and none of those rows, as a machine that took the log
/// from another, until its next projection pass. The rows forgotten.
///
/// # Errors
///
/// Storage errors.
#[cfg(feature = "test-support")]
pub fn forget_projected_setting_rows(vault: &Vault) -> Result<usize> {
    let mut txn = vault.store.env.write_txn()?;
    let forgotten = crate::setting::forget_projected_rows_in_txn(vault, &mut txn)?;
    txn.commit()?;
    Ok(forgotten)
}

/// `test.ordered_cap` as a read at the places `known` resolves it: the value, its source and
/// how the acts behind it stand.
///
/// # Errors
///
/// As `Setting::read_in_txn`.
#[cfg(feature = "test-support")]
pub fn ordered_cap_read(vault: &Vault, known: &[SettingScope]) -> Result<Resolved<u64>> {
    let txn = vault.store.env.read_txn()?;
    super::setting_keys::TEST_ORDERED_CAP.read_in_txn(vault, &txn, known, None)
}
