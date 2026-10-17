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
//! The fitted half is `learning.setting` ([`crate::learning`]): fitting checks
//! enter through [`record_setting_check`], the projector folds them over the
//! seed (the owner's, else the catalog's at the shipped weight) and caches the
//! vault-scope fit beside its claim. The value in force is the pin, else the
//! fit once it has own runs, else the owner's seed, else the catalog seed. A
//! pin fixes the value used while the fit keeps learning underneath it.

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

/// How long a group commit at the vault's single writer may wait, with its
/// queue empty, for writes already on their way, in milliseconds counted from
/// when the group opened (ARCH-0019 group-commit invariant, OF-536). It bounds
/// that idle wait only: writes already queued join regardless, up to
/// [`GROUP_COMMIT_MAX_WRITES`], until one that runs alone (a host's callback)
/// or holds a session-overlay segment closes the group. A group never waits
/// when no write is on its way, so a lone writer pays nothing; zero closes
/// every group as soon as its queue is empty.
pub const GROUP_COMMIT_WINDOW_MS: SettingSpec = SettingSpec {
    key: "group_commit_window_ms",
    min: 0.0,
    max: 50.0,
    seed: 2.0,
};

/// The most logical writes one group commit carries before it closes. One
/// gives every logical write its own transaction and fsync.
pub const GROUP_COMMIT_MAX_WRITES: SettingSpec = SettingSpec {
    key: "group_commit_max_writes",
    min: 1.0,
    max: 4096.0,
    seed: 256.0,
};

/// The share of credit a used lineage hop passes up (ARCH-0003
/// #learning-settings `credit_decay`): halving per hop by default.
pub const CREDIT_DECAY: SettingSpec = SettingSpec {
    key: "credit_decay",
    min: 0.0,
    max: 1.0,
    seed: 0.5,
};

/// Whether used lineage hops pass late credit up at all (ARCH-0037
/// #lineage-credit, the power user's off switch): on at one half or more.
pub const CREDIT_ENABLED: SettingSpec = SettingSpec {
    key: "credit_enabled",
    min: 0.0,
    max: 1.0,
    seed: 1.0,
};

/// The most used hops late credit climbs from an outcome (ARCH-0037
/// #lineage-credit); at its maximum, the full used chain, canon's default.
pub const CREDIT_DEPTH_CAP: SettingSpec = SettingSpec {
    key: "credit_depth_cap",
    min: 0.0,
    max: 1024.0,
    seed: 1024.0,
};

/// Whether late credit crosses only hops a contribution check measured
/// (ARCH-0037 #lineage-credit): on at one half or more; off by default, so
/// an unchecked used hop passes credit.
pub const CREDIT_CHECK_EVERY_HOP: SettingSpec = SettingSpec {
    key: "credit_check_every_hop",
    min: 0.0,
    max: 1.0,
    seed: 0.0,
};

/// The probability of a random audit (`audit_rate`). Its floor is strictly
/// above zero: the honesty floor never samples nothing.
pub const AUDIT_RATE: SettingSpec = SettingSpec {
    key: "audit_rate",
    min: 0.001,
    max: 1.0,
    seed: 0.05,
};

/// The `learning.*` window: old runs halve in weight every this many days, so
/// a silent vendor update under one model id shows up in the estimate.
pub const LEARNING_WINDOW_HALF_LIFE_DAYS: SettingSpec = SettingSpec {
    key: "learning_window_half_life_days",
    min: 1.0,
    max: 3650.0,
    seed: 90.0,
};

/// The weight in runs a catalog seed carries as a `learning.setting` prior
/// when the owner has seeded nothing.
pub const LEARNING_SHIPPED_PRIOR_RUNS: SettingSpec = SettingSpec {
    key: "learning_shipped_prior_runs",
    min: 0.0,
    max: 100.0,
    seed: 2.0,
};

/// The most runs a borrowed reading (a parent type's, another executor's)
/// counts as: carried weakly, so a cell's own runs soon outweigh it.
pub const LEARNING_BORROWED_PRIOR_RUNS: SettingSpec = SettingSpec {
    key: "learning_borrowed_prior_runs",
    min: 0.0,
    max: 100.0,
    seed: 2.0,
};

/// The spawn planner's solo-first gate floor (ARCH-0079 #planner, OF-541):
/// when solo's measured success rate for a task type is at or above this,
/// a team must clear [`PLANNER_SOLO_MARGIN`] past solo to displace it.
pub const PLANNER_SOLO_SUCCESS_FLOOR: SettingSpec = SettingSpec {
    key: "planner_solo_success_floor",
    min: 0.0,
    max: 1.0,
    seed: 0.7,
};

/// How far past solo's success rate a team shape must project before the
/// planner prefers it once the solo-first gate is engaged.
pub const PLANNER_SOLO_MARGIN: SettingSpec = SettingSpec {
    key: "planner_solo_margin",
    min: 0.0,
    max: 1.0,
    seed: 0.05,
};

/// The spawn width at which a plan counts as big and the planner ladder
/// climbs to its strong rung regardless of care.
pub const PLANNER_BIG_PLAN_WIDTH: SettingSpec = SettingSpec {
    key: "planner_big_plan_width",
    min: 1.0,
    max: 10000.0,
    seed: 16.0,
};

/// Every learned knob the engine reads.
pub const SETTING_CATALOG: &[SettingSpec] = &[
    ATTRIBUTION_UNCLEAR_FLOOR,
    GROUP_COMMIT_WINDOW_MS,
    GROUP_COMMIT_MAX_WRITES,
    CREDIT_DECAY,
    CREDIT_ENABLED,
    CREDIT_DEPTH_CAP,
    CREDIT_CHECK_EVERY_HOP,
    AUDIT_RATE,
    LEARNING_WINDOW_HALF_LIFE_DAYS,
    LEARNING_SHIPPED_PRIOR_RUNS,
    LEARNING_BORROWED_PRIOR_RUNS,
    PLANNER_SOLO_SUCCESS_FLOOR,
    PLANNER_SOLO_MARGIN,
    PLANNER_BIG_PLAN_WIDTH,
    crate::dreamer_runner::maintenance::agent_health::HEALTH_REVIEW,
    crate::dreamer_runner::maintenance::agent_health::HEALTH_LOOP_REPEATS,
    crate::dreamer_runner::maintenance::agent_health::HEALTH_CHECK_FAILS,
    crate::dreamer_runner::maintenance::agent_health::HEALTH_WAIT_SHARE,
    crate::dreamer_runner::maintenance::agent_health::HEALTH_WAIT_MINUTES,
    crate::dreamer_runner::maintenance::agent_health::HEALTH_SILENT_MINUTES,
    crate::dreamer_runner::maintenance::agent_health::HEALTH_WIDEN_DENIALS,
    crate::dreamer_runner::maintenance::agent_health::HEALTH_COST_SPIKE,
    crate::dreamer_runner::maintenance::agent_health::HEALTH_ESCALATE_TTL_HOURS,
    crate::dreamer_runner::maintenance::agent_health::HEALTH_CARD_FLOOR,
    crate::dreamer_runner::maintenance::agent_health::HEALTH_DUP_MIN_COST,
    crate::skill::EXPLORATION_ASK_CLIMB_HOURS,
    crate::skill::EXPLORATION_ASK_LAPSE_HOURS,
    crate::blob_artifact::esign::ESIGN_ASK_CLIMB_HOURS,
    crate::llm::decision::questions::QUESTION_CALL_BUDGET_MS,
];

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
/// Canon scopes a row `spawn | goal | project | vault`. This row is the
/// vault's; [`put_scoped_setting_row`] lays one over a project or a task
/// type.
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

/// Where an owner row applies. A project or task-type row steers only the
/// reads that name that project or type ([`setting_value_scoped`]); every
/// other read sees the vault's row.
#[derive(Debug, Clone, PartialEq)]
pub enum SettingScope {
    Vault,
    Project(crate::entity_id::EntityId),
    /// A task type's node, at whatever tree version the read names.
    Type(crate::learning::TypeRef),
}

/// Owner rows, keyed by `setting_key "\0" mode`, so a seed and a pin over one
/// key stand side by side; a project or type row appends its scope.
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

fn scoped_row_key(key: &str, mode: SettingMode, scope: &SettingScope) -> String {
    match scope {
        SettingScope::Vault => row_key(key, mode),
        SettingScope::Project(project) => {
            format!("{}\0project\0{}", row_key(key, mode), project.to_hex())
        }
        SettingScope::Type(type_ref) => {
            format!("{}\0type\0{}", row_key(key, mode), type_ref.node_id)
        }
    }
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
    put_scoped_setting_row(vault, owner, &SettingScope::Vault, row)
}

/// [`put_setting_row`] over `scope`: a project's or a task type's own seed
/// or pin, under the same owner rule and bounds. Only a vault seed is the
/// vault fit's prior, so only it refolds the fit.
///
/// # Errors
///
/// As [`put_setting_row`], and [`Error::InvalidClaimBody`] for a malformed
/// type reference.
pub fn put_scoped_setting_row(
    vault: &Vault,
    owner: &WriteActor,
    scope: &SettingScope,
    row: &SettingRow,
) -> Result<()> {
    if let SettingScope::Type(type_ref) = scope {
        type_ref.validate()?;
    }
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
    vault.with_write_txn_grouped(|wtxn| {
        vault.verify_owner_write_actor_in_txn(wtxn, owner)?;
        SETTING.put(
            &vault.store,
            wtxn,
            &scoped_row_key(spec.key, row.mode, scope),
            &stored,
        )?;
        // A seed is the fit's prior: every fit over this knob refolds from it.
        if *scope == SettingScope::Vault {
            crate::learning::project::reproject_setting_cells_in_txn(
                vault, wtxn, spec.key, row.at,
            )?;
        }
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
    clear_scoped_setting_row(vault, owner, &SettingScope::Vault, key, mode)
}

/// [`clear_setting_row`] over `scope`.
///
/// # Errors
///
/// As [`clear_setting_row`].
pub fn clear_scoped_setting_row(
    vault: &Vault,
    owner: &WriteActor,
    scope: &SettingScope,
    key: &str,
    mode: SettingMode,
) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        vault.verify_owner_write_actor_in_txn(wtxn, owner)?;
        SETTING.delete(&vault.store, wtxn, &scoped_row_key(key, mode, scope))?;
        if mode == SettingMode::Seed && *scope == SettingScope::Vault {
            let now = crate::unix_seconds_now();
            crate::learning::project::reproject_setting_cells_in_txn(vault, wtxn, key, now)?;
        }
        Ok(())
    })
}

/// The value in force for `spec`: the owner's pin, else the vault-scope fit
/// once it has own runs, else the owner's seed, else the catalog seed.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn setting_value(vault: &Vault, spec: &SettingSpec) -> Result<f64> {
    let rtxn = vault.store.env.read_txn()?;
    setting_value_in_txn(&vault.store, &rtxn, spec)
}

/// [`setting_value`] inside a transaction the caller already holds.
pub(crate) fn setting_value_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
) -> Result<f64> {
    setting_value_scoped_in_txn(store, txn, spec, None, None)
}

/// The value in force for `spec` where `project` and `type_ref` apply: the
/// narrowest pin (the project's, then the type's, then the vault's), else the
/// narrower seed (the project's, then the type's), else the vault-scope fit
/// once it has own runs, else the vault's seed, else the catalog seed. The
/// vault's seed is the vault fit's own prior, so the fit outranks it; a
/// project or type seed is the owner's word for that scope alone, which no
/// fit learned from the whole vault overrides. With neither named it is
/// [`setting_value`].
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn setting_value_scoped(
    vault: &Vault,
    spec: &SettingSpec,
    project: Option<crate::entity_id::EntityId>,
    type_ref: Option<&crate::learning::TypeRef>,
) -> Result<f64> {
    let rtxn = vault.store.env.read_txn()?;
    setting_value_scoped_in_txn(&vault.store, &rtxn, spec, project, type_ref)
}

/// [`setting_value_scoped`] inside a transaction the caller already holds.
pub(crate) fn setting_value_scoped_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    project: Option<crate::entity_id::EntityId>,
    type_ref: Option<&crate::learning::TypeRef>,
) -> Result<f64> {
    let scopes: Vec<SettingScope> = project
        .map(SettingScope::Project)
        .into_iter()
        .chain(type_ref.cloned().map(SettingScope::Type))
        .chain([SettingScope::Vault])
        .collect();
    for scope in &scopes {
        if let Some(value) = scoped_row_value(store, txn, spec, SettingMode::Pin, scope)? {
            return Ok(value);
        }
    }
    for scope in scopes.iter().filter(|scope| **scope != SettingScope::Vault) {
        if let Some(value) = scoped_row_value(store, txn, spec, SettingMode::Seed, scope)? {
            return Ok(value);
        }
    }
    if let Some(fit) =
        crate::learning::project::SETTING_FIT.get(store, txn, &spec.key.to_owned())?
        && fit.runs > 0.0
        && fit.value.is_finite()
    {
        // A fit never leaves the catalog's bounds, so it never widens a floor.
        return Ok(fit.value.clamp(spec.min, spec.max));
    }
    let seed = scoped_row_value(store, txn, spec, SettingMode::Seed, &SettingScope::Vault)?;
    Ok(seed.unwrap_or(spec.seed))
}

/// Every owner row as stored, in key order: its scope, the row, and the
/// owner who set it (32 hex), for the owner's list doors. A type row's key
/// names its node only, so its scope reads `tree_version` 0: a type row
/// matches its node at any tree version.
///
/// # Errors
///
/// A row that does not decode; storage errors.
pub fn list_setting_rows(vault: &Vault) -> Result<Vec<(SettingScope, SettingRow, String)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for (stored_key, stored) in SETTING.scan(&vault.store, &rtxn)? {
        let parts: Vec<&str> = stored_key.split('\0').collect();
        let mode = match parts.get(1).copied() {
            Some("seed") => SettingMode::Seed,
            Some("pin") => SettingMode::Pin,
            _ => continue,
        };
        let scope = match parts.as_slice() {
            [_, _] => SettingScope::Vault,
            [_, _, "project", hex] => match crate::entity_id::EntityId::from_hex(hex) {
                Ok(project) => SettingScope::Project(project),
                Err(_) => continue,
            },
            [_, _, "type", node] => SettingScope::Type(crate::learning::TypeRef {
                node_id: (*node).to_owned(),
                tree_version: 0,
            }),
            _ => continue,
        };
        out.push((
            scope,
            SettingRow {
                key: parts[0].to_owned(),
                mode,
                value: stored.value,
                weight_runs: stored.weight_runs,
                at: stored.at,
                why: stored.why,
            },
            stored.by,
        ));
    }
    Ok(out)
}

pub(crate) fn owner_row_value(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    mode: SettingMode,
) -> Result<Option<f64>> {
    scoped_row_value(store, txn, spec, mode, &SettingScope::Vault)
}

fn scoped_row_value(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    mode: SettingMode,
    scope: &SettingScope,
) -> Result<Option<f64>> {
    Ok(SETTING
        .get(store, txn, &scoped_row_key(spec.key, mode, scope))?
        // A row written under wider bounds than today's catalog is not a
        // value this reader can stand behind; the next row down is.
        .filter(|row| (spec.min..=spec.max).contains(&row.value))
        .map(|row| row.value))
}

/// The owner's seed over `spec` and its weight in runs, if one stands: the
/// prior a `learning.setting` fit starts from.
pub(crate) fn owner_seed_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
) -> Result<Option<(f64, f64)>> {
    Ok(SETTING
        .get(store, txn, &row_key(spec.key, SettingMode::Seed))?
        .filter(|row| (spec.min..=spec.max).contains(&row.value))
        .and_then(|row| row.weight_runs.map(|weight| (row.value, weight))))
}

/// One check that fits a named knob: the value the check found best, on the
/// receipt that ran it.
#[derive(Debug, Clone, PartialEq)]
pub struct SettingCheck {
    /// The skill that uses the knob, or the project.
    pub subject: crate::entity_id::EntityId,
    /// The catalog key.
    pub key: String,
    /// The task type the check ran under; the vault-scope fit is the root.
    pub type_ref: crate::learning::TypeRef,
    pub observed: f64,
    pub receipt: String,
    pub at: u64,
    /// A fitting check, an audit (with its rate) or a held-out run.
    pub anchor: crate::learning::Anchor,
}

/// Records one fitting check into `learning.setting` and refits.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for a key outside the catalog, an observed
/// value outside its bounds, or an anchor that does not fit settings; the
/// evidence door's errors.
pub fn record_setting_check(
    vault: &Vault,
    check: &SettingCheck,
    now: u64,
) -> Result<Option<crate::learning::Estimate>> {
    let spec = setting_spec(&check.key).ok_or(invalid("no learned setting has this key"))?;
    if !check.observed.is_finite() || check.observed < spec.min || check.observed > spec.max {
        return Err(invalid(
            "a fitting check's value lies within its catalog bounds",
        ));
    }
    let cell = crate::learning::LearningCell::new(
        crate::learning::LearningPredicate::Setting,
        check.subject,
    )
    .setting_key(spec.key)
    .type_ref(check.type_ref.clone());
    let evidence = crate::learning::LearningEvidence::anchored(
        check.receipt.clone(),
        check.at,
        check.anchor,
        crate::learning::Observation::Magnitude(check.observed),
    );
    crate::learning::record_evidence(vault, &cell, &evidence, now)
}

/// The one subject `key`'s vault-wide fit is learned on: an id derived from
/// the key, since a vault-wide knob has no one skill that uses it. Only a
/// root-typed check on this subject fits the vault (OF-542); a project's or
/// a skill's check fits that subject alone.
///
/// # Errors
///
/// The derivation's refusal of a reserved id.
pub fn global_setting_subject(key: &str) -> Result<crate::entity_id::EntityId> {
    crate::entity_id::EntityId::derive(
        crate::entity_id::derived_domains::GLOBAL_SETTING_SUBJECT,
        &[key.as_bytes()],
    )
}

/// [`record_setting_check`] inside `wtxn`, for a writer whose own row and
/// the check commit together: a random audit's outcome and the audit rate it
/// fits (OF-542).
///
/// # Errors
///
/// As [`record_setting_check`].
pub(crate) fn record_setting_check_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    check: &SettingCheck,
    now: u64,
) -> Result<Option<crate::learning::Estimate>> {
    let spec = setting_spec(&check.key).ok_or(invalid("no learned setting has this key"))?;
    if !check.observed.is_finite() || check.observed < spec.min || check.observed > spec.max {
        return Err(invalid(
            "a fitting check's value lies within its catalog bounds",
        ));
    }
    let cell = crate::learning::LearningCell::new(
        crate::learning::LearningPredicate::Setting,
        check.subject,
    )
    .setting_key(spec.key)
    .type_ref(check.type_ref.clone());
    let evidence = crate::learning::LearningEvidence::anchored(
        check.receipt.clone(),
        check.at,
        check.anchor,
        crate::learning::Observation::Magnitude(check.observed),
    );
    crate::learning::record_evidence_in_txn(vault, wtxn, &cell, &evidence, now)
}
