//! Effector-budget rows: dimension/window/exhaust/reserve enums, EffectorBudget constructors, row and spend-unit validators.

use crate::error::Result;

use super::{invalid_body, normalize_connector_key};

const CALENDAR_TZ_UTC: &str = "UTC";

/// Budget dimension per OF-277 §3.3 (ticket prose "rate_limit" = `Rate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EffectorBudgetDimension {
    Sends,
    Spend,
    Rate,
}

impl EffectorBudgetDimension {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sends => "sends",
            Self::Spend => "spend",
            Self::Rate => "rate",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "sends" => Some(Self::Sends),
            "spend" => Some(Self::Spend),
            "rate" => Some(Self::Rate),
            _ => None,
        }
    }
}

/// Calendar bucket period for calendar budget windows (UTC-only in v1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CalendarPeriod {
    Day,
    Week,
    Month,
}

impl CalendarPeriod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "day" => Some(Self::Day),
            "week" => Some(Self::Week),
            "month" => Some(Self::Month),
            _ => None,
        }
    }
}

/// Accounting window for one budget row.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EffectorBudgetWindow {
    /// Sliding window: a debit is live while `ts + duration_s > now`.
    Rolling { duration_s: u64 },
    /// Calendar bucket (UTC-only in v1: `tz` must be absent or `"UTC"`).
    Calendar {
        period: CalendarPeriod,
        tz: Option<String>,
    },
}

/// What happens when a budget row would be exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EffectorBudgetOnExhaust {
    /// Deny the effect; the key stays active.
    Refuse,
    /// Deny the effect AND flip the whole key to Suspended (hard cap).
    Suspend,
}

impl EffectorBudgetOnExhaust {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Refuse => "refuse",
            Self::Suspend => "suspend",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "refuse" => Some(Self::Refuse),
            "suspend" => Some(Self::Suspend),
            _ => None,
        }
    }
}

/// Spend reserve policy. `PreauthorizeEstimateThenSettle` round-trips through
/// the schema but enforces as `SettleOnly` in v1 (documented limitation,
/// ratified OF-277 §7 item 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EffectorBudgetReservePolicy {
    SettleOnly,
    PreauthorizeEstimateThenSettle,
}

impl EffectorBudgetReservePolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SettleOnly => "settle_only",
            Self::PreauthorizeEstimateThenSettle => "preauthorize_estimate_then_settle",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "settle_only" => Some(Self::SettleOnly),
            "preauthorize_estimate_then_settle" => Some(Self::PreauthorizeEstimateThenSettle),
            _ => None,
        }
    }
}

/// One effector-budget row (OF-277 §3.3 schema, ratified names).
///
/// `limit` units: `sends`/`rate` count gate-admitted effector dispatches;
/// `spend` is the connector's DECLARED denomination (M8 resolution
/// 2026-07-10): ISO-4217 currencies in minor units, provider units
/// (credits/tokens/requests) as opaque integers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EffectorBudget {
    pub dimension: EffectorBudgetDimension,
    /// Optional narrowing; matched against the normalized effect channel.
    pub channel_class: Option<String>,
    pub limit: u64,
    /// Required iff `dimension == Spend`: a 3-ASCII-uppercase ISO-4217 code or
    /// a connector-declared provider-unit token.
    pub unit: Option<String>,
    pub window: EffectorBudgetWindow,
    pub on_exhaust: EffectorBudgetOnExhaust,
    /// Spend only; `None` ⇒ `SettleOnly`.
    pub reserve_policy: Option<EffectorBudgetReservePolicy>,
}

impl EffectorBudget {
    /// Sends-dimension row.
    #[must_use]
    pub fn sends(
        limit: u64,
        window: EffectorBudgetWindow,
        on_exhaust: EffectorBudgetOnExhaust,
    ) -> Self {
        Self {
            dimension: EffectorBudgetDimension::Sends,
            channel_class: None,
            limit,
            unit: None,
            window,
            on_exhaust,
            reserve_policy: None,
        }
    }

    /// Rate-dimension row: rolling window, refuse on exhaust.
    #[must_use]
    pub fn rate(limit: u64, duration_s: u64) -> Self {
        Self {
            dimension: EffectorBudgetDimension::Rate,
            channel_class: None,
            limit,
            unit: None,
            window: EffectorBudgetWindow::Rolling { duration_s },
            on_exhaust: EffectorBudgetOnExhaust::Refuse,
            reserve_policy: None,
        }
    }

    /// Spend-dimension row (settle-only reserve policy).
    #[must_use]
    pub fn spend(
        limit: u64,
        unit: &str,
        window: EffectorBudgetWindow,
        on_exhaust: EffectorBudgetOnExhaust,
    ) -> Self {
        Self {
            dimension: EffectorBudgetDimension::Spend,
            channel_class: None,
            limit,
            unit: Some(unit.to_owned()),
            window,
            on_exhaust,
            reserve_policy: None,
        }
    }
}

pub(in crate::connector_key) fn validate_budget_row(budget: &EffectorBudget) -> Result<()> {
    if budget.limit == 0 {
        return Err(invalid_body("budget limit must be at least 1"));
    }
    match (budget.dimension, budget.unit.as_deref()) {
        (EffectorBudgetDimension::Spend, Some(unit)) => validate_spend_unit(unit)?,
        (EffectorBudgetDimension::Spend, None) => {
            return Err(invalid_body("spend rows require a unit"));
        }
        (_, Some(_)) => return Err(invalid_body("unit only allowed on spend rows")),
        (_, None) => {}
    }
    if budget.reserve_policy.is_some() && budget.dimension != EffectorBudgetDimension::Spend {
        return Err(invalid_body("reserve_policy only allowed on spend rows"));
    }
    match &budget.window {
        EffectorBudgetWindow::Rolling { duration_s } => {
            if *duration_s == 0 {
                return Err(invalid_body("rolling window duration must be at least 1s"));
            }
        }
        EffectorBudgetWindow::Calendar { tz, .. } => {
            if let Some(tz) = tz.as_deref()
                && tz != CALENDAR_TZ_UTC
            {
                return Err(invalid_body("calendar tz must be UTC"));
            }
        }
    }
    if let Some(channel_class) = budget.channel_class.as_deref() {
        if normalize_connector_key(channel_class).is_empty() {
            return Err(invalid_body("channel_class must not be blank"));
        }
        // Same stored-form == index-form invariant as the connector token:
        // row matching compares against the normalized effect channel, so a
        // non-canonical stored narrowing would never match any dispatch.
        if channel_class != normalize_connector_key(channel_class) {
            return Err(invalid_body("channel_class must be stored normalized"));
        }
    }
    Ok(())
}

pub(in crate::connector_key) fn validate_suggested_budget_row(
    budget: &EffectorBudget,
) -> Result<()> {
    validate_budget_row(budget)?;
    if budget.dimension == EffectorBudgetDimension::Spend {
        return Err(invalid_body("suggested budget rows must be sends or rate"));
    }
    if budget.on_exhaust != EffectorBudgetOnExhaust::Refuse {
        return Err(invalid_body("suggested budget rows must refuse on exhaust"));
    }
    Ok(())
}

/// The connector-declared denomination (M8 resolution 2026-07-10): a
/// 3-ASCII-uppercase ISO-4217 code, or a provider-unit token
/// (`[a-z0-9_]{1,32}`). A 3-letter alphabetic unit is the ISO namespace and
/// must be uppercase — `"usd"` is a malformed currency, not a provider token.
pub(in crate::connector_key) fn validate_spend_unit(unit: &str) -> Result<()> {
    let bytes = unit.as_bytes();
    if bytes.len() == 3 && bytes.iter().all(u8::is_ascii_alphabetic) {
        if bytes.iter().all(u8::is_ascii_uppercase) {
            return Ok(());
        }
        return Err(invalid_body("spend unit currency code must be uppercase"));
    }
    if !bytes.is_empty()
        && bytes.len() <= 32
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Ok(());
    }
    Err(invalid_body(
        "spend unit must be an ISO-4217 code or provider-unit token",
    ))
}

/// Maximum number of budget rows on one key (and compiled caps on one charter).
pub const CONNECTOR_KEY_MAX_BUDGET_ROWS: usize = 16;
