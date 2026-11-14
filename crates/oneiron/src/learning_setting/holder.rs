//! The learning dials a holder of `engine.controls` may tune (untangle 6.6b;
//! S66-MAP = A): a closed list of catalog keys, each with its class. Every
//! change runs through the one check and writes its receipt in the writer
//! that stores the row. The owner's rows stand over a holder's: a holder
//! never replaces or clears a pin the owner set, since a pin fixes the value
//! until its setter changes it; a holder's pin at a narrower scope never
//! stands over the owner's (the read walks the owner's pins first, and the
//! door refuses a holder's pin under the owner's pin for the whole vault);
//! and a work budget's holder value never exceeds the owner's own row for
//! that knob and scope, which it never replaces or clears. Every other
//! catalog key stays the owner's to set.

use super::{
    SETTING, Setter, SettingMode, SettingRow, SettingScope, SettingSpec, StoredSettingRow,
    checked_spec, clear_row_in_txn, invalid, put_row_in_txn, scoped_row_key, setting_spec, witness,
};
use crate::Vault;
use crate::dreamer_runner::maintenance::agent_health::{
    HEALTH_CARD_FLOOR, HEALTH_CHECK_FAILS, HEALTH_COST_MIN_RUNS, HEALTH_COST_SPIKE,
    HEALTH_DUP_MIN_COST, HEALTH_ESCALATE_TTL_HOURS, HEALTH_LOOP_REPEATS, HEALTH_REVIEW,
    HEALTH_REVIEW_WINDOW_HOURS, HEALTH_SILENT_MINUTES, HEALTH_TREND_PERIOD_DAYS,
    HEALTH_WAIT_MINUTES, HEALTH_WAIT_SHARE, HEALTH_WIDEN_DENIALS,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{EngineControlActor, EngineControlClass};
use crate::store::setting_seed::{
    AUDIT_RATE, CONTRIBUTION_CHECK_RATE, CREDIT_CHECK_EVERY_HOP, CREDIT_DEPTH_CAP,
    LEARNING_BORROWED_PRIOR_RUNS, LEARNING_SHIPPED_PRIOR_RUNS, LEARNING_WINDOW_HALF_LIFE_DAYS,
};

use EngineControlClass::{MaintenanceCadence, WakeCadence, WorkBudget};

/// The learning dials a holder of `engine.controls` may tune, each with its
/// class: the learned maintenance and check sampling rates (maintenance
/// cadence), the Coach's health and review triggers and the self-heal
/// trigger thresholds (wake cadence), and the question call's time budget
/// (work budget). `health.card.owner_copy` is not here: it routes the
/// Coach's cards to the owner, which is no trigger, so it stays the owner's.
pub const ENGINE_CONTROL_SETTINGS: [(&str, EngineControlClass); 25] = [
    (CREDIT_DEPTH_CAP.key, MaintenanceCadence),
    (CREDIT_CHECK_EVERY_HOP.key, MaintenanceCadence),
    (AUDIT_RATE.key, MaintenanceCadence),
    (LEARNING_WINDOW_HALF_LIFE_DAYS.key, MaintenanceCadence),
    (LEARNING_SHIPPED_PRIOR_RUNS.key, MaintenanceCadence),
    (LEARNING_BORROWED_PRIOR_RUNS.key, MaintenanceCadence),
    (CONTRIBUTION_CHECK_RATE.key, MaintenanceCadence),
    (HEALTH_REVIEW.key, WakeCadence),
    (HEALTH_LOOP_REPEATS.key, WakeCadence),
    (HEALTH_CHECK_FAILS.key, WakeCadence),
    (HEALTH_WAIT_SHARE.key, WakeCadence),
    (HEALTH_WAIT_MINUTES.key, WakeCadence),
    (HEALTH_SILENT_MINUTES.key, WakeCadence),
    (HEALTH_WIDEN_DENIALS.key, WakeCadence),
    (HEALTH_COST_SPIKE.key, WakeCadence),
    (HEALTH_ESCALATE_TTL_HOURS.key, WakeCadence),
    (HEALTH_CARD_FLOOR.key, WakeCadence),
    (HEALTH_DUP_MIN_COST.key, WakeCadence),
    (HEALTH_REVIEW_WINDOW_HOURS.key, WakeCadence),
    (HEALTH_COST_MIN_RUNS.key, WakeCadence),
    (HEALTH_TREND_PERIOD_DAYS.key, WakeCadence),
    (
        crate::dreamer_runner::maintenance::coach::TRADEOFF_REMINDER_HOURS.key,
        WakeCadence,
    ),
    (
        crate::self_heal::DETECTOR_CENTROID_MIN_SIMILARITY.key,
        WakeCadence,
    ),
    (
        crate::dreamer_runner::maintenance::attribution_labels::ATTRIBUTION_LABEL_RECEIPTS.key,
        WakeCadence,
    ),
    (
        crate::llm::decision::questions::QUESTION_CALL_BUDGET_MS.key,
        WorkBudget,
    ),
];

/// The class of the learning dial `key`, when a holder may tune it.
fn holder_class(key: &str) -> Option<EngineControlClass> {
    ENGINE_CONTROL_SETTINGS
        .iter()
        .find(|(listed, _)| *listed == key)
        .map(|(_, class)| *class)
}

/// Whether `key` is a work budget a holder may tune: a holder's row on it
/// stays within the owner's own seed or pin for that knob and scope, at the
/// holder's door ([`owner_rows_admit`]) and at every read after
/// (`resolution::capped_row_in_txn`).
pub(super) fn is_work_budget(key: &str) -> bool {
    matches!(holder_class(key), Some(WorkBudget))
}

/// The receipt's rendering of a holder's change.
fn rendered(scope: &SettingScope, mode: SettingMode, value: Option<f64>) -> String {
    let scope = match scope {
        SettingScope::Vault => "vault".to_owned(),
        SettingScope::Goal(id) => format!("goal:{}", id.to_hex()),
        SettingScope::Project(id) => format!("project:{}", id.to_hex()),
        SettingScope::Type(_) => "type".to_owned(),
    };
    serde_json::json!({"scope": scope, "mode": mode.as_str(), "value": value}).to_string()
}

/// The row over `spec`, `mode` and `scope` when the owner's door wrote it:
/// every row but a holder's. It stays the owner's when its setter was since
/// erased, or holds the vault no more.
fn owner_row_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    mode: SettingMode,
    scope: &SettingScope,
) -> Result<Option<StoredSettingRow>> {
    Ok(SETTING
        .get(&vault.store, txn, &scoped_row_key(spec.key, mode, scope))?
        .filter(|row| !row.by_holder))
}

/// Refuses a holder's change the owner's rows stand over: a pin the owner
/// set, a new pin under the owner's pin for the whole vault, any row the
/// owner set over a work budget, and a work-budget value above the owner's
/// own row for that knob and scope.
fn owner_rows_admit(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    scope: &SettingScope,
    mode: SettingMode,
    class: EngineControlClass,
    value: Option<f64>,
) -> Result<()> {
    if owner_row_in_txn(vault, txn, spec, mode, scope)?.is_some()
        && (mode == SettingMode::Pin || class == WorkBudget)
    {
        return Err(invalid("the owner set this row; only the owner changes it"));
    }
    // The read gives the owner's vault pin precedence over a holder's pin at
    // any narrower scope, so that pin would never be in force: the door says
    // so, where a stored row and its receipt would claim a change.
    if value.is_some()
        && mode == SettingMode::Pin
        && *scope != SettingScope::Vault
        && owner_row_in_txn(vault, txn, spec, SettingMode::Pin, &SettingScope::Vault)?.is_some()
    {
        return Err(invalid(
            "the owner pinned this setting for the whole vault; only the owner changes it",
        ));
    }
    if class == WorkBudget
        && let Some(value) = value
    {
        for owner_mode in [SettingMode::Pin, SettingMode::Seed] {
            if let Some(cap) = owner_row_in_txn(vault, txn, spec, owner_mode, scope)?
                && value > cap.value
            {
                return Err(invalid(
                    "a holder's work budget stays within the owner's cap",
                ));
            }
        }
    }
    Ok(())
}

impl Vault {
    /// A holder of `engine.controls` sets a seed or pin on one learning dial
    /// it may tune ([`ENGINE_CONTROL_SETTINGS`]), under the same bounds and
    /// row terms as the owner's door. The row records the holder as its
    /// setter; its act is witnessed as the engine observed it; the receipt
    /// names the holder, the class and the value. Returns the receipt.
    ///
    /// # Errors
    ///
    /// [`crate::Error::InvalidClaimBody`] for a key a holder may not tune, a
    /// value outside its catalog bounds, broken row terms, a pin or work
    /// budget the owner set, a pin under the owner's pin for the whole
    /// vault, or a work budget above the owner's cap;
    /// `InvalidConfig` when `holder` holds no live `engine.controls`; store
    /// failures.
    pub fn put_setting_row_as_holder(
        &self,
        holder: EntityId,
        scope: &SettingScope,
        row: &SettingRow,
    ) -> Result<EntityId> {
        let class =
            holder_class(&row.key).ok_or(invalid("this learning setting is the owner's to set"))?;
        let spec = checked_spec(scope, row)?;
        self.apply_engine_control(
            EngineControlActor::Holder(holder),
            class,
            spec.key,
            &rendered(scope, row.mode, Some(row.value)),
            |wtxn| {
                owner_rows_admit(self, &*wtxn, spec, scope, row.mode, class, Some(row.value))?;
                let witness = witness::holder_put_in_txn(self, wtxn, scope, row)?;
                let setter = Setter::Holder(holder);
                put_row_in_txn(self, wtxn, spec, scope, row, setter, witness)
            },
        )
    }

    /// A holder of `engine.controls` withdraws a seed or pin on one learning
    /// dial it may tune; the owner's pins and work-budget rows stand.
    /// Returns the receipt.
    ///
    /// # Errors
    ///
    /// As [`Self::put_setting_row_as_holder`].
    pub fn clear_setting_row_as_holder(
        &self,
        holder: EntityId,
        scope: &SettingScope,
        key: &str,
        mode: SettingMode,
    ) -> Result<EntityId> {
        let class =
            holder_class(key).ok_or(invalid("this learning setting is the owner's to set"))?;
        let spec = setting_spec(key).ok_or(invalid("no learned setting has this key"))?;
        self.apply_engine_control(
            EngineControlActor::Holder(holder),
            class,
            spec.key,
            &rendered(scope, mode, None),
            |wtxn| {
                owner_rows_admit(self, &*wtxn, spec, scope, mode, class, None)?;
                clear_row_in_txn(self, wtxn, scope, spec.key, mode)
            },
        )
    }
}
