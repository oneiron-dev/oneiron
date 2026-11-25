//! Doors for the Setting primitive's tests (DESIGN 15-setting-primitive, stage 0.1).

#[cfg(feature = "test-support")]
use crate::Vault;
#[cfg(feature = "test-support")]
use crate::authority::OwnerProofGround;
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

#[cfg(feature = "test-support")]
mod peer_acts;
#[cfg(feature = "test-support")]
pub use peer_acts::{
    CopiedRow, EnrolledMachine, SettingFrontier, SignedSettingAct, SlotName,
    enroll_machine_with_key, land_setting_act_from, land_setting_batch_from,
    land_setting_beside_act_from, land_setting_beside_untagged, land_setting_beside_value,
    land_setting_beside_value_before, land_setting_beside_value_holding, land_setting_copy_from,
    land_setting_pack_accept_from, land_setting_pack_head_from, land_signed_pack_act,
    land_signed_setting_act, land_signed_setting_acts, setting_beside_row,
    setting_beside_value_here, setting_copy_names, setting_frontier, setting_frontier_of,
    setting_pack_accept_frontier_of, setting_pack_frontier_of, setting_slot_heads,
    sign_setting_act_ahead, sign_setting_beside_act_from, sign_setting_pack_accept_from,
};

/// Lands here, as a window's sync carries it, another machine's copy of the stored notice `id`
/// that holds no seen or acknowledged mark: the copy of a notice both machines raised alone
/// (row SETTING-PROJECTED-ROW-REFUSING-HOOKS, REVIEW-10294 round 2).
///
/// # Errors
///
/// No notice row at `id`; a copy the ingest does not land; storage errors.
#[cfg(all(feature = "test-support", feature = "sync"))]
pub fn land_notification_copy_without_receipts(vault: &Vault, id: EntityId) -> Result<()> {
    let held = {
        let rtxn = vault.store.env.read_txn()?;
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &rtxn, &id)?
    }
    .ok_or(Error::CorruptedIndex("notice copy door: no notice row"))?;
    let header_len = crate::batch::ENTITY_METADATA_HEADER_LEN;
    let (header, body) = held
        .split_at_checked(header_len)
        .ok_or(Error::CorruptedIndex("notice copy door: row header"))?;
    let mut body = crate::inbox::decode_notification_body(body)?;
    body.seen_by.clear();
    body.acked_by.clear();
    let mut blob = header.to_vec();
    blob.extend_from_slice(&crate::inbox::encode_notification_body(&body)?);
    let window = crate::sync::types::WindowKey::from_timestamp(body.created_at);
    crate::sync::ingest_carried_entity_for_test(vault, &window.0, &id, &blob)
}

/// Plants bytes no row encodes to as `key`'s value row at `scope`: a damaged store.
///
/// # Errors
///
/// An unknown key; storage errors.
#[cfg(feature = "test-support")]
pub fn plant_undecodable_row(vault: &Vault, key: &str, scope: SettingScope) -> Result<()> {
    crate::setting::put_stored_bytes(vault, key, SettingMode::Value, scope, &[0xc1, 0xc1])
}

/// Plants `value` as `key`'s value row at the vault for `item`, written by `by` in the capacity
/// `setter` (an agent through its Grant, say), on an install where the fixture cannot act as that
/// writer.
///
/// # Errors
///
/// An unknown key; an item the key does not admit; a value it does not take; storage errors.
#[cfg(feature = "test-support")]
pub fn plant_setting_row(
    vault: &Vault,
    key: &str,
    item: Option<&str>,
    value: serde_json::Value,
    (setter, by): (crate::setting::Setter, Option<EntityId>),
) -> Result<()> {
    crate::setting::put_stored_row(vault, key, item, value, (setter, by))
}

/// Plants `digest` as the defaults digest `pack`'s head row keeps: a damaged store.
///
/// # Errors
///
/// A pack with no head; storage errors.
#[cfg(feature = "test-support")]
pub fn plant_pack_head_digest(vault: &Vault, pack: &str, digest: &str) -> Result<()> {
    crate::setting::put_head_digest(vault, pack, digest)
}

/// What a fresh emergency reschedule plan of `proposals` live replacement times meets under the
/// owner's proposal count and floor in force: `Err` with the refusal's words where it refuses (row
/// SETTING-PROJECTED-ROW-REFUSING-HOOKS, SETTING-PROJECTED-EMERGENCY-PAIR = A).
///
/// # Errors
///
/// Storage errors.
#[cfg(feature = "test-support")]
pub fn emergency_plan_admission(
    vault: &Vault,
    proposals: usize,
) -> Result<std::result::Result<(), String>> {
    let policy =
        crate::booking::emergency_reschedule::setting_keys::emergency_proposal_policy(vault)?;
    Ok(policy.admit(proposals))
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
                    Some(&OwnerProofGround::test_door()),
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

/// Every change the setting change stream holds, oldest first (stage 7c-1 tests).
///
/// # Errors
///
/// A change row that does not decode; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_changes(vault: &Vault) -> Result<Vec<crate::setting::SettingChange>> {
    let txn = vault.store.env.read_txn()?;
    Ok(crate::setting::settings_after_in_txn(&vault.store, &txn, None, usize::MAX)?.0)
}

/// Waits for, then holds, the turn a change of `key` takes before its write opens, until the
/// returned guard drops (stage 7c-1 tests): a holder of the calendar admission turn.
///
/// # Errors
///
/// An unknown key, or one that names no turn; the turn's refusal.
#[cfg(feature = "test-support")]
pub fn hold_setting_write_turn(vault: &Vault, key: &str) -> Result<Box<dyn std::any::Any>> {
    let turn = crate::setting::spec_named(key)?
        .write_turn
        .ok_or(Error::InvariantViolation("the key names no write turn"))?;
    (turn.take)(vault)
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

/// Forgets every record of a setting projection and leaves the rows it wrote (row
/// SETTING-PROJECTED-ROW-REFUSING-HOOKS): each row then holds its value while its acts read as
/// moved, as a row does once a peer's act arrived and before the projection pass read it. The
/// records forgotten.
///
/// # Errors
///
/// Storage errors.
#[cfg(feature = "test-support")]
pub fn forget_setting_projection_records(vault: &Vault) -> Result<usize> {
    let mut txn = vault.store.env.write_txn()?;
    let forgotten = crate::setting::forget_projection_records_in_txn(vault, &mut txn)?;
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

/// `pack`'s table of `defaults` (each key's name and its default as JSON): its digest, as
/// lowercase hex, and the bytes that travel beside its head acts (stage 7c-3c).
///
/// # Errors
///
/// An unknown key or a default its key does not take.
#[cfg(feature = "test-support")]
pub fn pack_table_of(
    pack: &str,
    defaults: &[(&str, serde_json::Value)],
) -> Result<(String, Vec<u8>)> {
    let defaults = defaults
        .iter()
        .map(|(key, value)| {
            let spec = crate::setting::spec_named(key)?;
            Ok((spec, spec.kind.from_json(value.clone())?))
        })
        .collect::<Result<Vec<_>>>()?;
    let (digest, bytes) = crate::setting::table_digest_and_bytes(pack, &defaults)?;
    Ok((oneiron_hex::encode(&digest), bytes))
}

/// Puts the row of `pack`'s table whose digest is `digest` (64 hex digits) beside the act `act`
/// holding `held`, in a write of its own, as a peer's row lands: through the batch door, whose
/// commit runs the setting projection (stage 7c-3c; a row per act, stage 7c-3c review). The
/// row's id.
///
/// # Errors
///
/// `InvalidConfig` for a bad digest; the put's refusal; storage errors.
#[cfg(feature = "test-support")]
pub fn land_pack_table(
    vault: &Vault,
    (pack, digest): (&str, &str),
    act: &oneiron_authority::authority::AuthorityEntryHash,
    held: &[u8],
) -> Result<EntityId> {
    let digest = oneiron_hex::decode_any_case::<32>(digest)
        .ok_or_else(|| Error::InvalidConfig("a pack digest must be 64 hex digits".into()))?;
    crate::setting::land_pack_table(vault, (pack, &digest, act), held)
}

/// Puts the row of `pack`'s table whose digest is `digest` (64 hex digits) beside the act `act`
/// holding `held`, in a write of its own, as a sync pass stores a peer's row: a replicated put,
/// which a row erased here refuses (stage 7c-3c review). The row's id.
///
/// # Errors
///
/// `InvalidConfig` for a bad digest; the put's refusal; storage errors.
#[cfg(all(feature = "test-support", feature = "sync"))]
pub fn land_pack_table_from_peer(
    vault: &Vault,
    (pack, digest): (&str, &str),
    act: &oneiron_authority::authority::AuthorityEntryHash,
    held: &[u8],
) -> Result<EntityId> {
    let digest = oneiron_hex::decode_any_case::<32>(digest)
        .ok_or_else(|| Error::InvalidConfig("a pack digest must be 64 hex digits".into()))?;
    crate::setting::land_pack_table_from_peer(vault, (pack, &digest, act), held)
}

/// Puts `pack`'s table whose digest is `digest` (64 hex digits) holding `held` in the one row per
/// pack and digest that builds before rows per act wrote, in a write of its own, through the
/// batch door (stage 7c-3c review).
///
/// # Errors
///
/// `InvalidConfig` for a bad digest; the put's refusal; storage errors.
#[cfg(feature = "test-support")]
pub fn land_pack_table_shared_row(
    vault: &Vault,
    (pack, digest): (&str, &str),
    held: &[u8],
) -> Result<()> {
    let digest = oneiron_hex::decode_any_case::<32>(digest)
        .ok_or_else(|| Error::InvalidConfig("a pack digest must be 64 hex digits".into()))?;
    crate::setting::land_pack_table_shared_row(vault, (pack, &digest), held)
}

/// The bytes the row of `pack`'s table whose digest is `digest` (64 hex digits) beside the act
/// `act` holds here; `None` when no row is here (stage 7c-3c).
///
/// # Errors
///
/// `InvalidConfig` for a bad digest; storage errors.
#[cfg(feature = "test-support")]
pub fn pack_table_here(
    vault: &Vault,
    (pack, digest): (&str, &str),
    act: &oneiron_authority::authority::AuthorityEntryHash,
) -> Result<Option<Vec<u8>>> {
    let digest = oneiron_hex::decode_any_case::<32>(digest)
        .ok_or_else(|| Error::InvalidConfig("a pack digest must be 64 hex digits".into()))?;
    crate::setting::pack_table_bytes(vault, (pack, &digest, act))
}

/// One live head act of a pack, as a test reads it (stage 7c-3a).
#[cfg(feature = "test-support")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackHeadView {
    /// The head act's entry (stage 7c-3c review): what a change row a yes landed names.
    pub act: oneiron_authority::authority::AuthorityEntryHash,
    /// The carrier whose pack door weighed the defaults.
    pub machine: EntityId,
    /// The version of the pack the door's build ships.
    pub version: String,
    /// The digest of the pack's table of defaults, as lowercase hex.
    pub digest: String,
    /// The keys held at their earlier accepted value, in name order.
    pub held: Vec<String>,
    /// The owner whose yes the head is (stage 7c-3c); `None` for a pack door's head.
    pub owner: Option<EntityId>,
    /// The keys the owner's yes accepts, in name order; empty for a pack door's head.
    pub accepted: Vec<String>,
}

/// `pack`'s live head acts, read back from the log and sorted by version and digest (stage 7c-3a).
///
/// # Errors
///
/// A pack target that does not encode; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_pack_heads(vault: &Vault, pack: &str) -> Result<Vec<PackHeadView>> {
    let txn = vault.store.env.read_txn()?;
    pack_head_views(vault.setting_pack_heads_in_txn(&txn, pack)?)
}

/// The owner's live yeses to defaults of `pack`'s table `digest` (64 hex digits), read back from
/// the log and sorted by version and digest (stage 7c-3c).
///
/// # Errors
///
/// `InvalidConfig` for a bad digest; a target that does not encode; storage errors.
#[cfg(feature = "test-support")]
pub fn setting_pack_accepts(
    vault: &Vault,
    (pack, digest): (&str, &str),
) -> Result<Vec<PackHeadView>> {
    let digest = oneiron_hex::decode_any_case::<32>(digest)
        .ok_or_else(|| Error::InvalidConfig("a pack digest must be 64 hex digits".into()))?;
    let txn = vault.store.env.read_txn()?;
    pack_head_views(vault.setting_pack_accepts_in_txn(&txn, pack, &digest)?)
}

#[cfg(feature = "test-support")]
fn pack_head_views(
    heads: Vec<(
        oneiron_authority::authority::AuthorityEntryHash,
        oneiron_authority::authority::SettingPackHead,
    )>,
) -> Result<Vec<PackHeadView>> {
    let mut heads: Vec<_> = heads
        .into_iter()
        .map(|(act, head)| PackHeadView {
            act,
            machine: head.machine,
            version: head.version,
            digest: oneiron_hex::encode(&head.digest),
            held: head.held,
            owner: head.accept.as_ref().map(|accept| accept.act.owner),
            accepted: head
                .accept
                .map(|accept| accept.accepted)
                .unwrap_or_default(),
        })
        .collect();
    heads.sort_by(|a, b| (&a.version, &a.digest).cmp(&(&b.version, &b.digest)));
    Ok(heads)
}
