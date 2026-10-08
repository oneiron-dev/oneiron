//! Learned settings (ARCH-0003 #learning-settings): the catalog of learned
//! knobs, the owner's seed and pin rows over them, and the one read that
//! resolves the value in force.
//!
//! A new learned knob is a CATALOG ROW here, never a constant in the module
//! that reads it: the catalog names its key, its bounds and its shipped seed,
//! and every reader asks [`setting_value`]. The owner steers a row with a
//! [`SettingRow`] — a SEED replaces the shipped value, a PIN fixes the value
//! in force — and nobody hand-writes the value itself.
//!
//! The fitted half (`learning.setting`, refit from audit receipts) is not
//! built yet: with no fit, a seed is the estimate, so the value in force is
//! the pin, else the owner's seed, else the catalog seed.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::write_envelope::WriteActor;

/// One learned knob: its key, its bounds and the value it ships with.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SettingSpec {
    /// The catalog key, the `setting_key` a seed or pin row targets.
    pub key: &'static str,
    /// Lowest admissible value, inclusive.
    pub min: f64,
    /// Highest admissible value, inclusive.
    pub max: f64,
    /// The shipped seed: the value in force until the owner seeds or pins one.
    pub seed: f64,
}

/// The attribution judge's confidence floor (ARCH-0056 §5 #unclear-floor):
/// below it, a hunk's verdict is recorded as `unclear` and charges nobody.
pub const ATTRIBUTION_UNCLEAR_FLOOR: SettingSpec = SettingSpec {
    key: "attribution_unclear_floor",
    min: 0.0,
    max: 1.0,
    seed: 0.6,
};

/// Every learned knob the engine reads.
pub const SETTING_CATALOG: &[SettingSpec] = &[ATTRIBUTION_UNCLEAR_FLOOR];

/// The catalog row named `key`, if the engine knows it.
#[must_use]
pub fn setting_spec(key: &str) -> Option<&'static SettingSpec> {
    SETTING_CATALOG.iter().find(|spec| spec.key == key)
}

/// How an owner row steers its setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SettingMode {
    /// Replaces the shipped seed; a fit, once built, keeps learning from it.
    Seed,
    /// Fixes the value in force; a fit may propose a change, never apply it.
    Pin,
}

impl SettingMode {
    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::Pin => "pin",
        }
    }
}

/// One owner seed or pin over a vault-scoped setting. The setter is the owner
/// who writes it ([`put_setting_row`]), never a field the caller fills in.
///
/// Canon scopes a row `spawn | goal | project | vault`; every reader the
/// engine has today asks at the vault, so the vault is the only scope stored.
#[derive(Debug, Clone, PartialEq)]
pub struct SettingRow {
    /// The catalog key this row steers.
    pub key: String,
    pub mode: SettingMode,
    pub value: f64,
    /// The seed's weight in runs; `None` for a pin, whose weight is unbounded.
    pub weight_runs: Option<f64>,
    /// Unix seconds the row was set.
    pub at: u64,
    /// The owner's own reason, kept as written.
    pub why: String,
}

/// Owner rows, keyed by `setting_key "\0" mode`, so a seed and a pin over one
/// key stand side by side.
const SETTING: SideTable<String, StoredSettingRow, Raw> =
    SideTable::new(&side_table::LEARNING_SETTING);

const ROW_VERSION: u8 = 1;
const ROW_LABEL: &str = "learning setting row";

/// Longest reason a row keeps, in bytes: a sentence for the record, not a
/// document.
const MAX_WHY_BYTES: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSettingRow {
    v: u8,
    value: f64,
    weight_runs: Option<f64>,
    by: String,
    at: u64,
    why: String,
}

impl RawValue for StoredSettingRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| CodecError::Value(Error::InvariantViolation(ROW_LABEL)))
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let row: Self = rmp_serde::from_slice(bytes)
            .map_err(|_| CodecError::Value(Error::CorruptedIndex(ROW_LABEL)))?;
        if row.v != ROW_VERSION {
            return Err(CodecError::Value(Error::CorruptedIndex(ROW_LABEL)));
        }
        Ok(row)
    }
}

fn row_key(key: &str, mode: SettingMode) -> String {
    format!("{key}\0{}", mode.as_str())
}

const fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

/// Records an owner seed or pin, replacing the row of the same key and mode.
///
/// Seeds and pins are the owner's (ARCH-0003 #learning-settings): `owner` must
/// pass the owner-write check in the transaction that writes the row, and the
/// row records that owner as its setter.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for a key outside the catalog, a value outside
/// the row's bounds, a pin carrying a weight or a seed without a positive one,
/// or a reason over 1 KiB; the owner-write refusal when `owner` is not the
/// vault's owner; storage errors.
pub fn put_setting_row(vault: &Vault, owner: &WriteActor, row: &SettingRow) -> Result<()> {
    let spec = setting_spec(&row.key).ok_or(invalid("no learned setting has this key"))?;
    if row.why.len() > MAX_WHY_BYTES {
        return Err(invalid(
            "a setting row's reason is a sentence, not a document",
        ));
    }
    if !row.value.is_finite() || row.value < spec.min || row.value > spec.max {
        return Err(invalid(
            "a setting value must lie within its catalog bounds",
        ));
    }
    match (row.mode, row.weight_runs) {
        (SettingMode::Pin, None) => {}
        (SettingMode::Seed, Some(weight)) if weight.is_finite() && weight > 0.0 => {}
        _ => {
            return Err(invalid(
                "a seed carries a positive weight in runs and a pin carries none",
            ));
        }
    }
    let stored = StoredSettingRow {
        v: ROW_VERSION,
        value: row.value,
        weight_runs: row.weight_runs,
        by: owner.entity_ref().to_hex(),
        at: row.at,
        why: row.why.clone(),
    };
    vault.with_write_txn(|wtxn| {
        vault.verify_owner_write_actor_in_txn(wtxn, owner)?;
        SETTING.put(&vault.store, wtxn, &row_key(spec.key, row.mode), &stored)?;
        Ok(())
    })
}

/// Withdraws the owner's seed or pin over `key`, returning the setting to
/// whatever stands beneath it. Only the owner may.
///
/// # Errors
///
/// The owner-write refusal when `owner` is not the vault's owner; storage
/// errors.
pub fn clear_setting_row(
    vault: &Vault,
    owner: &WriteActor,
    key: &str,
    mode: SettingMode,
) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        vault.verify_owner_write_actor_in_txn(wtxn, owner)?;
        SETTING.delete(&vault.store, wtxn, &row_key(key, mode))?;
        Ok(())
    })
}

/// The value in force for `spec`: the owner's pin, else the owner's seed,
/// else the catalog seed.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn setting_value(vault: &Vault, spec: &SettingSpec) -> Result<f64> {
    let rtxn = vault.store.env.read_txn()?;
    for mode in [SettingMode::Pin, SettingMode::Seed] {
        if let Some(row) = SETTING.get(&vault.store, &rtxn, &row_key(spec.key, mode))?
            // A row written under wider bounds than today's catalog is not a
            // value this reader can stand behind; the next row down is.
            && (spec.min..=spec.max).contains(&row.value)
        {
            return Ok(row.value);
        }
    }
    Ok(spec.seed)
}
