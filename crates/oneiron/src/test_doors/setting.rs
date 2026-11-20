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
/// whole list is the pack's layer, and the door runs as this build's version of the pack.
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
    apply_pack_defaults_at(vault, pack, crate::setting::ENGINE_PACK_VERSION, defaults)
}

/// [`apply_pack_defaults`] as a build that ships `version` of the pack runs it (stage 7c-3a): the
/// door does not act when the pack's head holds a newer version.
///
/// # Errors
///
/// As [`apply_pack_defaults`].
#[cfg(feature = "test-support")]
pub fn apply_pack_defaults_at(
    vault: &Vault,
    pack: &str,
    version: &str,
    defaults: &[(&str, serde_json::Value)],
) -> Result<Option<crate::setting::PackApplied>> {
    let defaults = defaults
        .iter()
        .map(|(key, value)| {
            let spec = crate::setting::spec_named(key)?;
            Ok((spec, spec.kind.from_json(value.clone())?))
        })
        .collect::<Result<Vec<_>>>()?;
    vault.apply_pack_defaults(pack, (version, &defaults), None)
}

/// The version `pack`'s head row keeps (stage 7c-3a); `None` when the door never ran for it.
///
/// # Errors
///
/// Storage errors.
#[cfg(feature = "test-support")]
pub fn pack_head_version(vault: &Vault, pack: &str) -> Result<Option<String>> {
    Ok(crate::setting::head_version_and_digest(vault, pack)?.map(|(version, _)| version))
}

/// The digest (hex) of the defaults `pack`'s door last weighed here (stage 7c-3a); `None` when the
/// door never ran for it.
///
/// # Errors
///
/// Storage errors.
#[cfg(feature = "test-support")]
pub fn pack_head_digest(vault: &Vault, pack: &str) -> Result<Option<String>> {
    Ok(crate::setting::head_version_and_digest(vault, pack)?.map(|(_, digest)| digest))
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
            let value = match value {
                Some(value) => crate::authority::SlotValue::Inline(json_bytes(value)?),
                None => crate::authority::SlotValue::Clear,
            };
            Ok((row_key(key, *item, *mode, scope.clone()), value))
        })
        .collect::<Result<Vec<_>>>()?;
    land_slot_values_from(vault, (signer, owner), frontier, rows, ts)
}

/// `rows`, as `signer`'s own door signs them for the owner `owner` on `frontier` at `ts`, landed
/// here as a peer's entry lands. Whether the fold here counts the entry.
#[cfg(feature = "test-support")]
fn land_slot_values_from(
    vault: &Vault,
    (signer, owner): (&EnrolledMachine, EntityId),
    frontier: &SettingFrontier,
    rows: Vec<(
        oneiron_setting_contract::RowKey,
        crate::authority::SlotValue,
    )>,
    ts: u64,
) -> Result<bool> {
    let entry =
        vault.sign_setting_act_as((signer.machine, &signer.key), owner, &frontier.0, rows, ts)?;
    let hash = oneiron_authority::authority::authority_entry_hash(&entry)?;
    let at = crate::temporal::TimeRange { start: ts, end: ts };
    vault.put_authority_log_entries(&[(entry, at, ts)])?;
    let fold = vault.authority_fold()?;
    Ok(fold.valid_entries.contains(&hash) && !fold.held_back_entries().contains(&hash))
}

/// A setting value's JSON bytes, as a door writes them.
#[cfg(feature = "test-support")]
fn json_bytes(value: &serde_json::Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error::InvariantViolation("a setting value's JSON"))
}

/// The owner `owner`'s change of the row `slot` to `value` with its value beside the act (stage
/// 7c-1): the act keeps only BLAKE3 over the value's JSON bytes, as `signer`'s own door signs it
/// on `frontier` at `ts`, landed here as a peer's entry lands, without the row that holds the
/// value ([`land_setting_beside_value`] lands that). Whether the fold here counts the entry.
///
/// # Errors
///
/// The log's refusal of the entry; storage errors.
#[cfg(feature = "test-support")]
pub fn land_setting_beside_act_from(
    vault: &Vault,
    (signer, owner): (&EnrolledMachine, EntityId),
    frontier: &SettingFrontier,
    (key, item, mode, scope): SlotName<'_>,
    value: &serde_json::Value,
    ts: u64,
) -> Result<bool> {
    let digest = oneiron_authority::authority::setting_value_digest(&json_bytes(value)?);
    let rows = vec![(
        row_key(key, item, mode, scope),
        crate::authority::SlotValue::Beside(digest),
    )];
    land_slot_values_from(vault, (signer, owner), frontier, rows, ts)
}

/// The ASSET row that holds `value` beside an act on the row `slot` (stage 7c-1).
///
/// # Errors
///
/// A key name of another shape.
#[cfg(feature = "test-support")]
pub fn setting_beside_row(
    (key, item, mode, scope): SlotName<'_>,
    value: &serde_json::Value,
) -> Result<EntityId> {
    crate::setting::beside_row_of(&row_key(key, item, mode, scope), &json_bytes(value)?)
}

/// Lands the row that holds `value` beside an act on the row `slot`, in a write of its own, as a
/// peer's row lands: through the batch door, whose commit runs the setting projection (stage
/// 7c-1).
///
/// # Errors
///
/// The put's refusal; storage errors.
#[cfg(feature = "test-support")]
pub fn land_setting_beside_value(
    vault: &Vault,
    (key, item, mode, scope): SlotName<'_>,
    value: &serde_json::Value,
) -> Result<()> {
    let json = json_bytes(value)?;
    crate::setting::land_beside_row(vault, &row_key(key, item, mode, scope), &json, &json)
}

/// Lands at the row for `value` beside an act on the row `slot` a row that holds `held`'s JSON
/// bytes instead: a row that does not match its digest (stage 7c-1).
///
/// # Errors
///
/// The put's refusal; storage errors.
#[cfg(feature = "test-support")]
pub fn land_setting_beside_value_holding(
    vault: &Vault,
    (key, item, mode, scope): SlotName<'_>,
    value: &serde_json::Value,
    held: &serde_json::Value,
) -> Result<()> {
    crate::setting::land_beside_row(
        vault,
        &row_key(key, item, mode, scope),
        &json_bytes(value)?,
        &json_bytes(held)?,
    )
}

/// The JSON the row for `value` beside an act on the row `slot` holds here; `None` when no such
/// row is readable here (stage 7c-1).
///
/// # Errors
///
/// A row whose bytes are not JSON; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_beside_value_here(
    vault: &Vault,
    (key, item, mode, scope): SlotName<'_>,
    value: &serde_json::Value,
) -> Result<Option<serde_json::Value>> {
    crate::setting::beside_row_json(vault, &row_key(key, item, mode, scope), &json_bytes(value)?)?
        .map(|json| {
            serde_json::from_slice(&json)
                .map_err(|_| Error::InvariantViolation("a beside row's JSON"))
        })
        .transpose()
}

/// The live acts on `key`'s row (`item`, `mode`, `scope`), a move's copy among them (stage
/// 7a-4): what a copy of the row names. Empty when no act names the row.
///
/// # Errors
///
/// A key name of another shape; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_slot_heads(
    vault: &Vault,
    (key, item, mode, scope): SlotName<'_>,
) -> Result<Vec<oneiron_authority::authority::AuthorityEntryHash>> {
    let target =
        oneiron_authority::authority::setting_slot_target(&row_key(key, item, mode, scope))?;
    let txn = vault.store.env.read_txn()?;
    vault.setting_slot_live_in_txn(&txn, target)
}

/// One carried row a copy lists, with the acts it names, each by its own row.
#[cfg(feature = "test-support")]
pub type CopiedRow<'a> = (
    SlotName<'a>,
    Vec<(
        SlotName<'a>,
        oneiron_authority::authority::AuthorityEntryHash,
    )>,
);

/// A move's copy of each carried row of `rows` (stage 7a-4), as `signer`'s own carry signs it on
/// `frontier` at `ts`, landed here as a peer's entry lands. A row `frontier` did not read names
/// `seen` zero. The entry's hash, and whether the fold here counts it (valid, and not held back).
///
/// # Errors
///
/// The log's refusal of the entry; storage errors.
#[cfg(feature = "test-support")]
pub fn land_setting_copy_from(
    vault: &Vault,
    signer: &EnrolledMachine,
    frontier: &SettingFrontier,
    rows: &[CopiedRow<'_>],
    ts: u64,
) -> Result<(oneiron_authority::authority::AuthorityEntryHash, bool)> {
    let rows = rows
        .iter()
        .map(|((key, item, mode, scope), names)| {
            let names = names
                .iter()
                .map(|((key, item, mode, scope), act)| {
                    oneiron_authority::authority::SettingCopyName {
                        slot: row_key(key, *item, *mode, scope.clone()),
                        act: *act,
                    }
                })
                .collect::<Vec<_>>();
            (row_key(key, *item, *mode, scope.clone()), names)
        })
        .collect::<Vec<_>>();
    let entry = vault.sign_setting_copy_as((signer.machine, &signer.key), &frontier.0, rows, ts)?;
    let hash = oneiron_authority::authority::authority_entry_hash(&entry)?;
    let at = crate::temporal::TimeRange { start: ts, end: ts };
    vault.put_authority_log_entries(&[(entry, at, ts)])?;
    let fold = vault.authority_fold()?;
    Ok((
        hash,
        fold.valid_entries.contains(&hash) && !fold.held_back_entries().contains(&hash),
    ))
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

/// `test.born_depth` as a read at the places `known` resolves it (stage 7c-2): the value, its
/// source and how it stands.
///
/// # Errors
///
/// As `Setting::read_in_txn`.
#[cfg(feature = "test-support")]
pub fn born_depth_read(vault: &Vault, known: &[SettingScope]) -> Result<Resolved<u64>> {
    let txn = vault.store.env.read_txn()?;
    super::setting_keys::TEST_BORN_DEPTH.read_in_txn(vault, &txn, known, None)
}

/// `test.permit_list` at the vault, read through its typed handle (stage 7c-1: a list that
/// travels beside its act).
///
/// # Errors
///
/// As `Setting::read_in_txn`.
#[cfg(feature = "test-support")]
pub fn permit_list_read(vault: &Vault) -> Result<Resolved<Vec<String>>> {
    let txn = vault.store.env.read_txn()?;
    super::setting_keys::TEST_PERMIT_LIST.read_in_txn(vault, &txn, &[], None)
}

/// `test.member_banner` at the vault, read through its typed handle (stage 7c-1: free text that
/// travels beside its act).
///
/// # Errors
///
/// As `Setting::read_in_txn`.
#[cfg(feature = "test-support")]
pub fn member_banner_read(vault: &Vault) -> Result<Resolved<String>> {
    let txn = vault.store.env.read_txn()?;
    super::setting_keys::TEST_MEMBER_BANNER.read_in_txn(vault, &txn, &[], None)
}

/// One setting act a peer signed that this install has not landed yet (stage 7b-3 tests).
#[cfg(feature = "test-support")]
pub struct SignedSettingAct(oneiron_authority::authority::AuthorityLogEntry);

/// The owner `owner`'s change of the row `slot` to `value` (`None` clears), signed as `signer`'s
/// own door signs it on `frontier` at `ts`, `ahead` sequences past the signer's next one here,
/// and not landed ([`land_signed_setting_act`]). Landed before an act its signer signs after it
/// at the next sequence, it puts that act past the signer's sequence floor on this install,
/// which then counts that act restriction only (stage 7b-3 tests).
///
/// # Errors
///
/// A key name of another shape; a value with no JSON; storage errors.
#[cfg(feature = "test-support")]
pub fn sign_setting_act_ahead(
    vault: &Vault,
    (signer, owner): (&EnrolledMachine, EntityId),
    frontier: &SettingFrontier,
    ((key, item, mode, scope), value): (SlotName<'_>, Option<serde_json::Value>),
    (ts, ahead): (u64, u64),
) -> Result<SignedSettingAct> {
    let inline = value
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|_| Error::InvariantViolation("a setting value's JSON"))?;
    vault
        .sign_setting_act_ahead_as(
            (signer.machine, &signer.key),
            (owner, &frontier.0),
            vec![(row_key(key, item, mode, scope), inline)],
            (ts, ahead),
        )
        .map(SignedSettingAct)
}

/// Lands `act` here at `ts`, as a peer's entry lands (stage 7b-3 tests). The entry's hash.
///
/// # Errors
///
/// The log's refusal of the entry; storage errors.
#[cfg(feature = "test-support")]
pub fn land_signed_setting_act(
    vault: &Vault,
    act: &SignedSettingAct,
    ts: u64,
) -> Result<oneiron_authority::authority::AuthorityEntryHash> {
    let hash = oneiron_authority::authority::authority_entry_hash(&act.0)?;
    let at = crate::temporal::TimeRange { start: ts, end: ts };
    vault.put_authority_log_entries(&[(act.0.clone(), at, ts)])?;
    Ok(hash)
}

/// The frontier of `pack`'s head acts now (stage 7c-3a).
///
/// # Errors
///
/// A pack target that does not encode; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_pack_frontier_of(vault: &Vault, pack: &str) -> Result<SettingFrontier> {
    vault.setting_pack_frontier(pack).map(SettingFrontier)
}

/// A pack's head, as `signer`'s own pack door signs it on `frontier` at `ts`, landed here as a
/// peer's entry lands (stage 7c-3a). The digest is 64 hex digits. Whether the fold here counts
/// the entry (valid, and not held back).
///
/// # Errors
///
/// `InvalidConfig` for a bad digest; the log's refusal of the entry; storage errors.
#[cfg(feature = "test-support")]
pub fn land_setting_pack_head_from(
    vault: &Vault,
    signer: &EnrolledMachine,
    frontier: &SettingFrontier,
    (pack, version, digest, held): (&str, &str, &str, &[&str]),
    ts: u64,
) -> Result<bool> {
    let digest = oneiron_hex::decode_any_case::<32>(digest)
        .ok_or_else(|| Error::InvalidConfig("a pack digest must be 64 hex digits".into()))?;
    let held = held.iter().map(|name| (*name).to_owned()).collect();
    let entry = vault.sign_setting_pack_head_as(
        (signer.machine, &signer.key),
        &frontier.0,
        (pack, version, digest, held),
        ts,
    )?;
    let hash = oneiron_authority::authority::authority_entry_hash(&entry)?;
    let at = crate::temporal::TimeRange { start: ts, end: ts };
    vault.put_authority_log_entries(&[(entry, at, ts)])?;
    let fold = vault.authority_fold()?;
    Ok(fold.valid_entries.contains(&hash) && !fold.held_back_entries().contains(&hash))
}

/// One live head act of a pack, as a test reads it (stage 7c-3a).
#[cfg(feature = "test-support")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackHeadView {
    /// The carrier whose pack door weighed the defaults.
    pub machine: EntityId,
    /// The version of the pack the door's build ships.
    pub version: String,
    /// The digest of the pack's table of defaults, as lowercase hex.
    pub digest: String,
    /// The keys held at their earlier accepted value, in name order.
    pub held: Vec<String>,
}

/// `pack`'s live head acts, read back from the log and sorted by version and digest (stage 7c-3a).
///
/// # Errors
///
/// A pack target that does not encode; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_pack_heads(vault: &Vault, pack: &str) -> Result<Vec<PackHeadView>> {
    let txn = vault.store.env.read_txn()?;
    let mut heads: Vec<_> = vault
        .setting_pack_heads_in_txn(&txn, pack)?
        .into_iter()
        .map(|(_, head)| PackHeadView {
            machine: head.machine,
            version: head.version,
            digest: oneiron_hex::encode(&head.digest),
            held: head.held,
        })
        .collect();
    heads.sort_by(|a, b| (&a.version, &a.digest).cmp(&(&b.version, &b.digest)));
    Ok(heads)
}
