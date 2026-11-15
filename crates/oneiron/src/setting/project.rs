//! The act is the write (stage 7a-2; DESIGN 1.6 "What travels", "The fold and the projection").
//!
//! In a vault with an authority root, an owner's change of a row that travels
//! ([`travels`]: a `sync: vault` key whose value type is closed, not learned, never a carried
//! row) appends its signed act in the change's own write, naming its row and carrying its value
//! ([`append_act_in_txn`]). The act is no longer best effort: a machine that cannot carry it
//! refuses the change, with the append's typed reason, and nothing is written.
//!
//! The projection writes such a row from the acts the fold counts ([`project_target_in_txn`]):
//! - the heads agree: their value, or no row for a clear;
//! - on a key whose order has a meet, the heads that differ meet (a clear of the vault value row
//!   gives the accepted default, a clear of any other row no bound);
//! - on any other key, heads that differ conflict, and the last act every head descends from
//!   stays in force (no row when none does), [`SettingStanding::Conflict`];
//! - a value this build cannot decode or check reads the key's strictest value:
//!   [`SettingStanding::Quarantined`].
//!
//! It writes the row and one change row only when the row the acts give differs from the one
//! stored, or the stored one is not the owner's, and runs the key's hook. It records the
//! revision it projected ([`super::tables::SETTING_PROJECTION`]), so a pass over the same
//! revision writes nothing, and a row a person, an agent or the engine changed on this install
//! alone stays as they left it until an act names the row again (RULING SETTING-7A-2-DECIDERS =
//! A). It runs in the door's own write, after every commit that stored an authority row
//! ([`Vault::project_settings_after_authority_ingest`]), and at open. A key this build does not
//! know, a head whose value is only a digest, and a head the log here does not hold leave the
//! row as it is.

use serde::{Deserialize, Serialize};

use oneiron_authority::authority::{
    ActSurface, AuthorityEntryHash, OwnerActKind, POLICY_SETTING_INLINE_MAX, setting_slot_target,
    setting_value_digest,
};
use oneiron_setting_contract::{RowKey, SettingStanding};

use super::change::{record_change_in_txn, record_signed_entry_in_txn};
use super::pack::layer_default_in_txn;
use super::read::{StoredRow, table_of};
use super::{
    EncodedValue, Setter, SettingChange, SettingMode, SettingScope, SettingSpec, SettingSync,
    spec_named,
};
use crate::Vault;
use crate::authority::{SettingSlotAct, SettingSlotFold, SettingSlotHead, SettingSlotRow};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable, SideTableDbs};

/// One projected row per act target.
const PROJECTIONS: SideTable<Vec<u8>, Projection, Named> =
    SideTable::new(&side_table::SETTING_PROJECTION);

/// A value no MessagePack decoder reads (the format's one unused byte): the row a quarantined
/// slot keeps, so every read of it takes the key's strictest value as for any row that does not
/// decode.
const UNREADABLE_VALUE: u8 = 0xc1;

/// What the projection last wrote for one act target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Projection {
    /// The row's stored key ([`RowKey::encode`]); empty where the target's acts name no row this
    /// build writes (a digest-only act, an older setting's act, a free-time policy).
    slot: Vec<u8>,
    /// The target's act revision the row was projected from.
    basis: [u8; 32],
    /// How the acts stood.
    standing: SettingStanding,
}

/// What a projection pass did ([`Vault::project_settings`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SettingsProjected {
    /// Act targets whose revision moved since their last projection.
    pub moved: usize,
    /// Rows the pass wrote or removed.
    pub rows_changed: usize,
}

/// Whether an owner's change of a `mode` row of `spec` travels as its signed act (stage 7a-2):
/// a `sync: vault` key whose value type is closed ([`super::ValueKind::travels_inline`]), and
/// not a learned key, whose seed weight does not travel yet. A carried row stays on its install
/// until a move's rows travel as one copy (stage 7a-3).
pub(super) fn travels(spec: &SettingSpec, mode: SettingMode) -> bool {
    spec.sync == SettingSync::Vault
        && spec.kind.travels_inline()
        && !spec.is_learned()
        && mode != SettingMode::Carried
}

/// Whether the vault has an authority root, a conflicted one included: a vault without one is
/// one machine, and its door writes the row alone, as before stage 7 (the cut
/// `project_depth/fold.rs` makes).
pub(super) fn rooted_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    let view = vault.authority_view_readonly_in_txn(txn)?;
    Ok(view.vault_id.is_some() || view.vault_root_is_conflicted())
}

/// Appends the owner `owner`'s applied change `recorded` of a row of `spec` that travels as its
/// signed act, in the change's write `txn`, from `surface`; names the entry on the change row;
/// and projects the row from the fold in the same write. Returns `false` and writes nothing when
/// the value's JSON is longer than an act carries: that change keeps the digest-only act of
/// stage 7a-1 until values travel beside their acts (stage 7c).
///
/// # Errors
///
/// The append's typed refusal (no live machine profile to carry the act, a fold that does not
/// count it, more heads than one entry names), or a storage error: the change fails with it.
pub(super) fn append_act_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    spec: &'static SettingSpec,
    (owner, surface): (EntityId, ActSurface),
    recorded: &SettingChange,
) -> Result<bool> {
    let inline = recorded
        .value
        .as_ref()
        .map(|value| json_bytes(spec, value))
        .transpose()?;
    if inline
        .as_ref()
        .is_some_and(|bytes| bytes.len() > POLICY_SETTING_INLINE_MAX)
    {
        return Ok(false);
    }
    let slot = RowKey {
        name: recorded.key.clone(),
        item: recorded.item.clone(),
        mode: recorded.mode,
        scope: recorded.scope.clone(),
    };
    let target = setting_slot_target(&slot)?;
    let prior = setting_value_digest(&match &recorded.prior {
        Some(prior) => json_bytes(spec, prior)?,
        None => b"null".to_vec(),
    });
    let signed = vault.append_setting_slot_act_in_txn(
        txn,
        SettingSlotAct {
            owner,
            surface,
            rows: vec![SettingSlotRow {
                slot,
                prior,
                inline,
            }],
        },
    )?;
    record_signed_entry_in_txn(&vault.store, txn, recorded, signed)?;
    let now = recorded.at;
    project_target_in_txn(vault, txn, target, now)?;
    Ok(true)
}

/// The value's JSON bytes: what an act carries inline, and what its digest is over (the digest
/// stage 7a-1's acts keep).
pub(super) fn json_bytes(spec: &SettingSpec, value: &EncodedValue) -> Result<Vec<u8>> {
    let json = spec.kind.to_json(value).unwrap_or(serde_json::Value::Null);
    serde_json::to_vec(&json).map_err(|_| Error::InvariantViolation("setting act encoding"))
}

fn target_key(target: EntityId) -> Vec<u8> {
    target.as_bytes().to_vec()
}

/// One head as the projection reads it.
struct Head {
    act: AuthorityEntryHash,
    owner: EntityId,
    surface: ActSurface,
    slot: RowKey,
    /// The value's JSON bytes; `None` for a clear.
    inline: Option<Vec<u8>>,
}

impl Head {
    fn credit(&self) -> Credit {
        Credit {
            act: self.act,
            owner: self.owner,
            surface: self.surface,
        }
    }
}

/// The act a projected row is credited to: its change row's `signed`, `by` and `surface`.
#[derive(Clone, Copy)]
struct Credit {
    act: AuthorityEntryHash,
    owner: EntityId,
    surface: ActSurface,
}

/// Why a target leaves its row as it is.
enum Inert {
    /// Its acts name no row this build writes, now or under a later build: recorded, so a later
    /// pass reads them again only once the revision moves.
    ForGood,
    /// Its acts name a row this build cannot write yet (a key it does not know, one that does
    /// not travel here, a head the log here does not hold): not recorded, so the open pass of a
    /// later build reads them again.
    ForNow,
}

/// The head `head` reads as, or why it leaves the row as it is.
fn head_of(head: &SettingSlotHead) -> std::result::Result<Head, Inert> {
    let Some(set) = &head.set else {
        return Err(Inert::ForNow);
    };
    if set.value.is_some() && set.inline.is_none() {
        return Err(Inert::ForGood);
    }
    let slot = match &set.slot {
        Some(slot) => slot.clone(),
        None => RowKey {
            name: set.setting.clone(),
            item: None,
            mode: SettingMode::Value,
            scope: SettingScope::Vault,
        },
    };
    if set.act.act != OwnerActKind::PolicySetting {
        return Err(Inert::ForGood);
    }
    Ok(Head {
        act: head.act,
        owner: set.act.owner,
        surface: set.act.surface,
        slot,
        inline: set.inline.clone(),
    })
}

/// A head's value under `spec`: `None` for a clear; `Err` for a value this build cannot decode
/// or whose check refuses it.
fn value_of(spec: &SettingSpec, head: &Head) -> std::result::Result<Option<EncodedValue>, ()> {
    let Some(bytes) = &head.inline else {
        return Ok(None);
    };
    let json: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    spec.kind.from_json(json).map(Some).map_err(|_| ())
}

/// The row the acts give, and how they stand.
struct Projected {
    /// The row's value; `None` for no row.
    value: Option<EncodedValue>,
    /// The row stays as it is: a quarantined value of a key that names no strictest value, so
    /// no row could read as one (its read would fail).
    keep: bool,
    standing: SettingStanding,
    /// The act the row is credited to.
    deciding: Credit,
}

/// Combines the live heads of one row (module doc).
fn combine(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &'static SettingSpec,
    heads: &[Head],
    fold: &SettingSlotFold,
) -> Result<std::result::Result<Projected, Inert>> {
    let Some(newest) = heads.first() else {
        return Ok(Err(Inert::ForNow));
    };
    let strictest = spec.kind.strictest_value()?.is_some();
    let quarantined = || Projected {
        value: Some(EncodedValue(vec![UNREADABLE_VALUE])),
        keep: !strictest,
        standing: SettingStanding::Quarantined,
        deciding: newest.credit(),
    };
    let mut values = Vec::with_capacity(heads.len());
    for head in heads {
        match value_of(spec, head) {
            Ok(value) => values.push(value),
            Err(()) => return Ok(Ok(quarantined())),
        }
    }
    if !fold.conflict {
        return Ok(Ok(Projected {
            value: values.swap_remove(0),
            keep: false,
            standing: SettingStanding::Settled,
            deciding: newest.credit(),
        }));
    }
    if spec.kind.order().has_meet() {
        let clear_gives = if is_vault_value_row(&newest.slot) {
            Some(layer_default_in_txn(&vault.store, txn, spec)?.value)
        } else {
            None
        };
        let mut met: Option<EncodedValue> = None;
        for value in values
            .into_iter()
            .map(|value| value.or_else(|| clear_gives.clone()))
        {
            let Some(value) = value else { continue };
            met = Some(match met {
                None => value,
                Some(so_far) => match spec.kind.meet(&so_far, &value) {
                    Some(meet) => meet,
                    None => return Ok(Ok(quarantined())),
                },
            });
        }
        return Ok(Ok(Projected {
            value: met,
            keep: false,
            standing: SettingStanding::Settled,
            deciding: newest.credit(),
        }));
    }
    // No order, a neutral or a custom key: nothing is safer than anything else, so the last value
    // every head descends from stays (owner_choice.rs `in_force`), or no row.
    let Some(agreed) = &fold.in_force else {
        return Ok(Ok(Projected {
            value: None,
            keep: false,
            standing: SettingStanding::Conflict,
            deciding: newest.credit(),
        }));
    };
    let agreed = match head_of(agreed) {
        Ok(head) if head.slot == newest.slot => head,
        Ok(_) | Err(Inert::ForGood) => return Ok(Err(Inert::ForGood)),
        Err(Inert::ForNow) => return Ok(Err(Inert::ForNow)),
    };
    Ok(Ok(match value_of(spec, &agreed) {
        Ok(value) => Projected {
            value,
            keep: false,
            standing: SettingStanding::Conflict,
            deciding: agreed.credit(),
        },
        Err(()) => quarantined(),
    }))
}

fn is_vault_value_row(slot: &RowKey) -> bool {
    slot.item.is_none() && slot.mode == SettingMode::Value && slot.scope == SettingScope::Vault
}

/// Projects the row the acts on `target` name, in `txn`, at `now`, when the target's revision
/// moved since its last projection. Returns the key whose row changed.
fn project_target_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    target: EntityId,
    now: u64,
) -> Result<Option<&'static SettingSpec>> {
    let Some(fold) = vault.setting_slot_fold_in_txn(txn, target)? else {
        return Ok(None);
    };
    if PROJECTIONS
        .get(&vault.store, txn, &target_key(target))?
        .is_some_and(|projection| projection.basis == fold.revision)
    {
        return Ok(None);
    }
    let inert = |why: Inert| (target, fold.revision, why);
    let heads = match fold
        .live
        .iter()
        .map(head_of)
        .collect::<std::result::Result<Vec<Head>, Inert>>()
    {
        Ok(heads) => heads,
        Err(why) => return leave_in_txn(vault, txn, inert(why)),
    };
    let Some(slot) = heads.first().map(|head| head.slot.clone()) else {
        return Ok(None);
    };
    if heads.iter().any(|head| head.slot != slot) {
        return leave_in_txn(vault, txn, inert(Inert::ForGood));
    }
    let Ok(spec) = spec_named(&slot.name) else {
        return leave_in_txn(vault, txn, inert(Inert::ForNow));
    };
    if !travels(spec, slot.mode)
        || !spec.admits_scope(slot.scope.kind())
        || spec.check_item(slot.item.as_deref()).is_err()
    {
        // Acts that carry no value were only ever digests (stage 7a-1): no build writes a row
        // from them. One that carries a value waits for a build where its key travels.
        let carried = heads.iter().any(|head| head.inline.is_some());
        let why = if carried {
            Inert::ForNow
        } else {
            Inert::ForGood
        };
        return leave_in_txn(vault, txn, inert(why));
    }
    let projected = match combine(vault, txn, spec, &heads, &fold)? {
        Ok(projected) => projected,
        Err(why) => return leave_in_txn(vault, txn, inert(why)),
    };
    let changed = write_row_in_txn(vault, txn, spec, &slot, &projected, now)?;
    PROJECTIONS.put(
        &vault.store,
        txn,
        &target_key(target),
        &Projection {
            slot: slot.encode(),
            basis: fold.revision,
            standing: projected.standing,
        },
    )?;
    Ok(changed.then_some(spec))
}

/// Leaves the row of `target` as it is (`Inert`), recording its `revision` when no build writes a
/// row from those acts. Returns no changed key.
fn leave_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    (target, revision, why): (EntityId, [u8; 32], Inert),
) -> Result<Option<&'static SettingSpec>> {
    if matches!(why, Inert::ForGood) {
        PROJECTIONS.put(
            &vault.store,
            txn,
            &target_key(target),
            &Projection {
                slot: Vec::new(),
                basis: revision,
                standing: SettingStanding::Settled,
            },
        )?;
    }
    Ok(None)
}

/// Writes `projected` as the row `slot` of `spec` when it differs from the stored row, or the
/// stored row is not the owner's: the row, one change row credited to the deciding act, and the
/// key's hook. Whether it wrote.
fn write_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    spec: &'static SettingSpec,
    slot: &RowKey,
    projected: &Projected,
    now: u64,
) -> Result<bool> {
    let deciding = projected.deciding;
    if projected.keep {
        return Ok(false);
    }
    let table = table_of(spec);
    let key = slot.encode();
    let stored = table
        .get_bytes(&vault.store, txn, &key)?
        .map(|bytes| rmp_serde::from_slice::<StoredRow>(&bytes).ok());
    let owners = |row: &StoredRow| row.setter == Setter::Owner && row.by == Some(deciding.owner);
    let same = match (&stored, &projected.value) {
        (None, None) => true,
        (Some(Some(row)), Some(value)) => row.value == *value && owners(row),
        _ => false,
    };
    if same {
        return Ok(false);
    }
    let prior = stored.flatten().map(|row| row.value);
    let recorded = record_change_in_txn(
        &vault.store,
        txn,
        SettingChange {
            id: vault.store.clock.entity_id()?,
            sequence: 0,
            key: spec.name.to_owned(),
            item: slot.item.clone(),
            scope: slot.scope.clone(),
            mode: slot.mode,
            by: Some(deciding.owner),
            setter: Setter::Owner,
            prior,
            value: projected.value.clone(),
            at: now,
            why: None,
            weight_runs: None,
            direction: None,
            surface: Some(deciding.surface),
            signed: Some(deciding.act),
        },
    )?;
    match &projected.value {
        Some(value) => table.put(
            &vault.store,
            txn,
            &key,
            &StoredRow {
                value: value.clone(),
                by: Some(deciding.owner),
                setter: Setter::Owner,
                set_at: now,
                change: recorded.sequence,
                weight_runs: None,
            },
        )?,
        None => table.delete(&vault.store, txn, &key)?,
    }
    if let Some(on_change) = spec.on_change {
        on_change(vault, txn, &recorded)?;
    }
    Ok(true)
}

/// Forgets every row the projection wrote, and its record (stage 7a-3 tests): this install then
/// holds the log and none of those rows, as a machine that took the log from another holds it
/// until its next pass. The rows forgotten.
///
/// # Errors
///
/// Storage errors.
#[cfg(all(oneiron_test_support, feature = "test-support"))]
pub(crate) fn forget_projected_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
) -> Result<usize> {
    let mut forgotten = 0;
    for (target, projection) in PROJECTIONS.scan(&vault.store, txn)? {
        if let Some(slot) = RowKey::decode(&projection.slot)
            && let Ok(spec) = spec_named(&slot.name)
            && table_of(spec).delete(&vault.store, txn, &projection.slot)?
        {
            forgotten += 1;
        }
        PROJECTIONS.delete(&vault.store, txn, &target)?;
    }
    Ok(forgotten)
}

/// How the acts behind the rows of `spec` a read walks stand: the least settled of the pin and
/// value rows on `chain`, for `item` and the item-less rows (stage 7a-2). A key that does not
/// travel is always settled.
///
/// # Errors
///
/// Storage errors.
pub(super) fn standing_in_txn(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    chain: &[SettingScope],
    item: Option<&str>,
) -> Result<SettingStanding> {
    if spec.sync != SettingSync::Vault || !spec.kind.travels_inline() {
        return Ok(SettingStanding::Settled);
    }
    let items: Vec<Option<&str>> = match item {
        Some(_) => vec![item, None],
        None => vec![None],
    };
    let mut standing = SettingStanding::Settled;
    for scope in chain {
        for row_item in &items {
            for mode in [SettingMode::Pin, SettingMode::Value] {
                let slot = RowKey {
                    name: spec.name.to_owned(),
                    item: row_item.map(str::to_owned),
                    mode,
                    scope: scope.clone(),
                };
                if let Some(projection) =
                    PROJECTIONS.get(dbs, txn, &target_key(setting_slot_target(&slot)?))?
                {
                    standing = standing.max(projection.standing);
                }
            }
        }
    }
    Ok(standing)
}

impl Vault {
    /// Projects every setting row whose signed acts moved since it was last projected, in one
    /// write, and runs the `after_commit` of each key whose row changed (stage 7a-2). A vault
    /// with no authority root, or with no setting act, writes nothing.
    ///
    /// First, in its own write, the owner's rows no act backs are published as batch acts, once
    /// per vault (stage 7a-3, [`Self::publish_settings`]); a fault there is logged, and the
    /// projection goes on.
    ///
    /// # Errors
    ///
    /// Storage errors; a key's hook's error.
    pub fn project_settings(&self) -> Result<SettingsProjected> {
        match self.publish_settings() {
            Ok(Some(published)) if published.acts > 0 => tracing::info!(
                acts = published.acts,
                rows = published.rows,
                "the owner's setting rows no act backed were published as batch acts"
            ),
            Ok(_) => {}
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "the owner's setting rows no act backs were not published; the next authority commit or open tries again"
            ),
        }
        let moved: Vec<EntityId> = {
            let txn = self.store.env.read_txn()?;
            if !rooted_in_txn(self, &txn)? {
                return Ok(SettingsProjected::default());
            }
            let mut moved = Vec::new();
            for (target, revision) in self.policy_setting_revisions_in_txn(&txn)? {
                let projected = PROJECTIONS.get(&self.store, &txn, &target_key(target))?;
                if projected.is_none_or(|projection| projection.basis != revision) {
                    moved.push(target);
                }
            }
            moved
        };
        if moved.is_empty() {
            return Ok(SettingsProjected::default());
        }
        let changed = self.with_write_txn_grouped(|txn| {
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let mut changed = Vec::new();
            for target in &moved {
                if let Some(spec) = project_target_in_txn(self, txn, *target, now)? {
                    changed.push(spec);
                }
            }
            Ok(changed)
        })?;
        for spec in &changed {
            if let Some(after_commit) = spec.after_commit {
                after_commit(self);
            }
        }
        Ok(SettingsProjected {
            moved: moved.len(),
            rows_changed: changed.len(),
        })
    }

    /// [`Self::project_settings`] once a commit stored an authority row (`noted`), whichever
    /// door stored it: a peer's acts, an import, a machine's standing or a Grant changed. A no-op
    /// otherwise; a failure is logged, and the next such commit or the next open tries again.
    pub(crate) fn project_settings_after_authority_ingest(&self, noted: bool) {
        if !noted {
            return;
        }
        if let Err(error) = self.project_settings() {
            tracing::warn!(
                kind = ?error.kind(),
                "the setting rows were not projected from their signed acts; the next authority commit or open tries again"
            );
        }
    }
}
