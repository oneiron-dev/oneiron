//! Moved from `crates/oneiron/src/connector_key/record/budgets.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::connector_key::record::key_record::invalid_body;
use oneiron_base::error::Result;
pub use oneiron_verb_wire::connector_key::record::budgets::ConnectorSpendEstimate;

pub const CALENDAR_TZ_UTC: &str = "UTC";

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

/// What happens when a budget row would be exceeded. A sends or rate row is a
/// count, so its crossing never suspends a key, whatever the row says
/// ([`EffectorBudget::exhaust_policy`], FIX 8753): `Suspend` binds spend rows
/// only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EffectorBudgetOnExhaust {
    /// Deny the effect; the key stays active. A count row's effect waits for
    /// its window at every door that paces (FIX 8686).
    Refuse,
    /// Spend rows: deny the effect AND flip the whole key to Suspended (hard
    /// cap). On a sends or rate row it acts as [`Self::Refuse`].
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

/// Spend reserve policy. `PreauthorizeEstimateThenSettle` reserves the
/// verb's declared price before the call and keeps it as the call's charge
/// (FIX 8689, `connector_key::meter::spend_reserve`); `SettleOnly` records a
/// cost only once it settled.
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

/// What a send's preauthorized spend stood on (FIX 8689): the verb's
/// declared price, reserved before the call and kept as its charge unless a
/// provider reports the actual cost; or no price in the row's unit, so the
/// call was measured and not refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorSpendBasis {
    Estimated(ConnectorSpendEstimate),
    Unpriced,
    /// The delivered send's provider reported its actual cost (FIX 11662):
    /// the estimate's entries, when one was reserved, came out and the
    /// actual went in on the preauthorizing rows in its unit. An actual
    /// above `estimated` is the overspend, written as it is, since the
    /// effect already occurred.
    Reconciled {
        estimated: Option<ConnectorSpendEstimate>,
        actual: ConnectorSpendEstimate,
    },
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
    /// What exhausting this row does (FIX 8753). A sends or rate crossing is a
    /// count, a health signal rather than a cap on authority, so it never
    /// suspends the key: it refuses, and waits for its window at every door
    /// that paces. Only a spend row honours its `Suspend`.
    #[must_use]
    pub const fn exhaust_policy(&self) -> EffectorBudgetOnExhaust {
        match self.dimension {
            EffectorBudgetDimension::Spend => self.on_exhaust,
            EffectorBudgetDimension::Sends | EffectorBudgetDimension::Rate => {
                EffectorBudgetOnExhaust::Refuse
            }
        }
    }

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

/// The connector-declared denomination (M8 resolution 2026-07-10): a
/// 3-ASCII-uppercase ISO-4217 code, or a provider-unit token
/// (`[a-z0-9_]{1,32}`). A 3-letter alphabetic unit is the ISO namespace and
/// must be uppercase — `"usd"` is a malformed currency, not a provider token.
pub fn validate_spend_unit(unit: &str) -> Result<()> {
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
