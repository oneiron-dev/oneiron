//! Connector-key registry records with effector budgets for OF-277 GOV-01.
//!
//! A CONNECTOR_KEY (entity type byte 135) is an engine-authored, vault-resident
//! maintenance record that governs external-effect dispatch for one outbound
//! connector, optionally narrowed to one acting entity. Budgets (sends / spend
//! / rate) live on the record; live usage counters live in `vault_meta` rows
//! debited inside the gate's write transaction, so debit + decision + (on
//! exhaust-suspend) the key-status flip commit atomically. The `charter` /
//! `pending_charter` slots are pinned in the v1 body so GOV-10 (ONE-1417) can
//! fill them without re-versioning the schema.

use std::io::Cursor;

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::batch::EntityMetadataHeader;
use crate::batch::{BatchOp, apply_ops};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::llm::{
    BudgetLadderEvent, BudgetSignalDeliveryChannel, BudgetSteeringSignal, BudgetThreshold,
};
use crate::registry::ENTITY_TYPE_CONNECTOR_KEY;
use crate::store::{GateDecisionId, GateDecisionRecord, Store};
use crate::temporal::TimeRange;

/// Current ConnectorKeyRecord body schema version.
pub const CONNECTOR_KEY_SCHEMA_VERSION: u64 = 1;

/// Pinned on-disk MessagePack key set for ConnectorKeyRecord bodies.
pub const CONNECTOR_KEY_BODY_KEYS: [&str; 10] = [
    "schema_version",
    "connector",
    "actor_entity_ref",
    "status",
    "budgets",
    "registered_at",
    "status_changed_at",
    "suspended_reason",
    "charter",
    "pending_charter",
];

const KEY_SCHEMA_VERSION: &str = CONNECTOR_KEY_BODY_KEYS[0];
const KEY_CONNECTOR: &str = CONNECTOR_KEY_BODY_KEYS[1];
const KEY_ACTOR_ENTITY_REF: &str = CONNECTOR_KEY_BODY_KEYS[2];
const KEY_STATUS: &str = CONNECTOR_KEY_BODY_KEYS[3];
const KEY_BUDGETS: &str = CONNECTOR_KEY_BODY_KEYS[4];
const KEY_REGISTERED_AT: &str = CONNECTOR_KEY_BODY_KEYS[5];
const KEY_STATUS_CHANGED_AT: &str = CONNECTOR_KEY_BODY_KEYS[6];
const KEY_SUSPENDED_REASON: &str = CONNECTOR_KEY_BODY_KEYS[7];
const KEY_CHARTER: &str = CONNECTOR_KEY_BODY_KEYS[8];
const KEY_PENDING_CHARTER: &str = CONNECTOR_KEY_BODY_KEYS[9];

const BUDGET_KEYS: [&str; 7] = [
    "dimension",
    "channel_class",
    "limit",
    "unit",
    "window",
    "on_exhaust",
    "reserve_policy",
];
const ROLLING_WINDOW_KEYS: [&str; 2] = ["kind", "duration_s"];
const CALENDAR_WINDOW_KEYS: [&str; 3] = ["kind", "period", "tz"];
const WINDOW_KIND_ROLLING: &str = "rolling";
const WINDOW_KIND_CALENDAR: &str = "calendar";
const CALENDAR_TZ_UTC: &str = "UTC";

const CHARTER_BLOCK_KEYS: [&str; 7] = [
    "text",
    "text_hash",
    "compiled",
    "compiled_hash",
    "stamped_aggregate",
    "stamped_by",
    "stamped_at",
];
const PENDING_CHARTER_KEYS: [&str; 5] = [
    "text",
    "text_hash",
    "compiled",
    "compiled_hash",
    "proposed_at",
];
const COMPILED_POLICY_KEYS: [&str; 2] = ["never_list", "channel_caps"];

/// Maximum number of budget rows on one key (and compiled caps on one charter).
pub const CONNECTOR_KEY_MAX_BUDGET_ROWS: usize = 16;

/// Compiled-charter cap usage rows live at `0x8000 | i` (GOV-10); key budget
/// rows live at `0..=15`.
pub const CONNECTOR_KEY_CHARTER_ROW_BASE: u16 = 0x8000;

/// vault_meta connector lookup index: prefix ++ normalized connector bytes ++
/// `\0` ++ key id (16 bytes) -> `[]`.
pub(crate) const CONNECTOR_KEY_CONNECTOR_INDEX_PREFIX: &[u8] = b"connector_key/connector/v1\0";

/// vault_meta usage rows: prefix ++ key id (16 bytes) ++ row_index u16 BE ->
/// canonical msgpack `{window_start, entries, fired}`.
pub(crate) const CONNECTOR_KEY_USAGE_PREFIX: &[u8] = b"connector_key/usage/v1\0";

/// vault_meta spend-settlement idempotency rows: prefix ++ key id (16 bytes)
/// ++ event_ref bytes -> row_index u16 BE ++ minor_units u64 BE ++
/// cost_occurred_at u64 BE. One row per settlement event id. Replay
/// IDENTITY is the (row_index, minor_units) prefix — the settlement's
/// actual content; the trailing declared cost time is first-writer-wins
/// recorded data. A matching replay settles nothing (even with a drifted
/// declared time between honest retries); a same-id replay with different
/// content fails closed (a pre-claimed event_ref cannot force a silent
/// no-op for a different settlement).
pub(crate) const CONNECTOR_KEY_SETTLE_EVENT_PREFIX: &[u8] = b"connector_key/settle_event/v1\0";

const CONNECTOR_KEY_SETTLE_EVENT_REF_MAX_LEN: usize = 128;

const CONNECTOR_KEY_OP_DIFF_DOMAIN: &[u8] = b"oneiron.connector_key.op.v0";

const SECONDS_PER_DAY: u64 = 86_400;

/// Template id for the effector-meter ~80% wrap-up notice (GOV-02, ONE-1418).
/// The LADDER and the delivery CHANNEL are the ARCHPASS-A3 shared vocabulary
/// from `llm::budget`; only the message text is meter-specific.
pub const EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE_ID: &str = "effector_budget.plan.80";
/// Template id for the effector-meter 95% LAND / graceful-wrap signal.
pub const EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE_ID: &str = "effector_budget.land.95";
/// Steering message injected at the 80% effector-budget threshold.
pub const EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE: &str = "\
Effector budget is at or above 80%. Prioritize the sends that still matter, \
defer the rest, and plan to finish within the remaining allowance.";
/// Steering message injected at the 95% effector-budget threshold.
pub const EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE: &str = "\
Effector budget is at or above 95%. Enter LAND: start no new outreach, finish \
or checkpoint in-flight sends, and treat the remaining allowance as a \
graceful-wrap window before the hard cut.";

/// Mirror of `llm::budget::steering_signal` for the effector meter: same
/// ladder, same one delivery channel, meter-specific texts. `Silent50`
/// carries no steering (same as the LLM meter).
fn effector_steering_signal(threshold: BudgetThreshold) -> Option<BudgetSteeringSignal> {
    let (template_id, message) = match threshold {
        BudgetThreshold::Silent50 => return None,
        BudgetThreshold::Plan80 => (
            EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE_ID,
            EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE,
        ),
        BudgetThreshold::Land95 => (
            EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE_ID,
            EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE,
        ),
    };
    Some(BudgetSteeringSignal {
        threshold,
        channel: BudgetSignalDeliveryChannel::SteeringQueueNextTurn,
        template_id: template_id.to_owned(),
        message: message.to_owned(),
    })
}

/// Pinned usage-row `fired` names (serde snake_case of `BudgetThreshold`).
const fn budget_threshold_fired_name(threshold: BudgetThreshold) -> &'static str {
    match threshold {
        BudgetThreshold::Silent50 => "silent50",
        BudgetThreshold::Plan80 => "plan80",
        BudgetThreshold::Land95 => "land95",
    }
}

/// Suspension reason for an exhausted budget row: key rows report the row
/// index; compiled-charter rows report the charter-local index.
pub(crate) fn budget_exhausted_reason(row_index: u16) -> String {
    if row_index & CONNECTOR_KEY_CHARTER_ROW_BASE == 0 {
        format!("budget_exhausted:row:{row_index}")
    } else {
        format!(
            "budget_exhausted:charter_row:{}",
            row_index & !CONNECTOR_KEY_CHARTER_ROW_BASE
        )
    }
}

// --- Charter compiler (GOV-10, ONE-1417) --------------------------------------

/// Domain tag for the compiled-policy hash.
const CONNECTOR_CHARTER_COMPILED_DOMAIN: &[u8] = b"oneiron.connector_charter.compiled.v1";
/// Domain tag for the human-stamped aggregate binding text + compiled policy.
pub(crate) const CONNECTOR_CHARTER_STAMP_DOMAIN: &[u8] = b"oneiron.connector_charter.stamp.v1";

/// ISO-4217 currencies with exponent 0 (major unit == minor unit); every
/// other currency compiles major → minor with the default exponent 2.
/// Pinned by the M8 / R7 resolution (2026-07-10).
const ISO_4217_ZERO_EXPONENT_CURRENCIES: [&str; 3] = ["JPY", "KRW", "VND"];

/// Output of one deterministic charter compile: same text ⇒ same struct ⇒
/// same hashes. The compiler is a mechanical parser — no model in the loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledCharter {
    pub text_hash: [u8; 32],
    pub compiled: CompiledConnectorPolicy,
    pub compiled_hash: [u8; 32],
}

/// A fail-closed charter compile error: 1-based line number over the
/// CRLF-normalized text. Maps into [`Error::ConnectorCharterCompile`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorCharterCompileIssue {
    pub line_number: u32,
    pub message: String,
}

impl From<ConnectorCharterCompileIssue> for Error {
    fn from(issue: ConnectorCharterCompileIssue) -> Self {
        Error::ConnectorCharterCompile {
            line_number: issue.line_number,
            message: issue.message,
        }
    }
}

fn sha256_bytes(chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

/// Canonical msgpack bytes for a compiled policy (the hash input).
fn encode_compiled_policy_bytes(compiled: &CompiledConnectorPolicy) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &encode_compiled_policy(compiled)).map_err(|_| {
        Error::InvariantViolation("compiled connector policy MessagePack encode failed")
    })?;
    Ok(out)
}

pub(crate) fn compiled_policy_hash(compiled: &CompiledConnectorPolicy) -> Result<[u8; 32]> {
    Ok(sha256_bytes(&[
        CONNECTOR_CHARTER_COMPILED_DOMAIN,
        &encode_compiled_policy_bytes(compiled)?,
    ]))
}

/// The human stamp binds text and compiled policy as ONE aggregate.
pub(crate) fn charter_stamped_aggregate(
    text_hash: &[u8; 32],
    compiled_hash: &[u8; 32],
) -> [u8; 32] {
    sha256_bytes(&[CONNECTOR_CHARTER_STAMP_DOMAIN, text_hash, compiled_hash])
}

/// Recomputes the stamped aggregate from the STORED text and compiled policy
/// and compares it to the stamp. Any mismatch degrades enforcement to
/// proposed-only (`gate.pending.charter_drift`) until a human re-stamps.
pub(crate) fn charter_block_drifted(block: &ConnectorCharterBlock) -> Result<bool> {
    let text_hash = sha256_bytes(&[block.text.as_bytes()]);
    let compiled_hash = compiled_policy_hash(&block.compiled)?;
    Ok(charter_stamped_aggregate(&text_hash, &compiled_hash) != block.stamped_aggregate)
}

/// Never-list matching: an entry `"{c}:{v}"` matches iff (`c == "*"` or
/// `c ==` the normalized effect channel) and (`v == "*"` or `v ==` the
/// trimmed, lowercased effect verb).
pub(crate) fn charter_never_list_matches(
    block: &ConnectorCharterBlock,
    normalized_channel: &str,
    verb: &str,
) -> bool {
    let verb = verb.trim().to_ascii_lowercase();
    block.compiled.never_list.iter().any(|entry| {
        let Some((channel_part, verb_part)) = entry.split_once(':') else {
            return false;
        };
        (channel_part == "*" || channel_part == normalized_channel)
            && (verb_part == "*" || verb_part == verb)
    })
}

/// Compiles a natural-language charter (the pinned 6-form constrained-English
/// grammar) into a deterministic policy. Fail-closed: any unrecognized or
/// malformed non-empty line aborts the whole compile with its 1-based line
/// number — no partial output.
pub fn compile_connector_charter(
    text: &str,
) -> std::result::Result<CompiledCharter, ConnectorCharterCompileIssue> {
    let normalized = text.replace("\r\n", "\n");
    let text_hash = sha256_bytes(&[normalized.as_bytes()]);

    let mut never_list: Vec<String> = Vec::new();
    let mut channel_caps: Vec<EffectorBudget> = Vec::new();
    for (index, line) in normalized.lines().enumerate() {
        let line_number = u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1);
        let issue = |message: &str| ConnectorCharterCompileIssue {
            line_number,
            message: message.to_owned(),
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match parse_charter_directive(trimmed).map_err(|message| issue(&message))? {
            CharterDirective::Never(entry) => never_list.push(entry),
            CharterDirective::Cap(budget) => {
                if channel_caps.len() >= CONNECTOR_KEY_MAX_BUDGET_ROWS {
                    return Err(issue("too many charter channel caps"));
                }
                validate_budget_row(&budget).map_err(|error| match error {
                    Error::InvalidConnectorKeyBody(reason) => issue(reason),
                    _ => issue("invalid charter cap"),
                })?;
                channel_caps.push(budget);
            }
        }
    }

    never_list.sort();
    never_list.dedup();
    let compiled = CompiledConnectorPolicy {
        never_list,
        channel_caps,
    };
    let compiled_hash =
        compiled_policy_hash(&compiled).map_err(|_| ConnectorCharterCompileIssue {
            line_number: 0,
            message: "compiled policy encode failed".to_owned(),
        })?;
    Ok(CompiledCharter {
        text_hash,
        compiled,
        compiled_hash,
    })
}

enum CharterDirective {
    Never(String),
    Cap(EffectorBudget),
}

fn parse_charter_directive(line: &str) -> std::result::Result<CharterDirective, String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let keyword = tokens[0].to_ascii_lowercase();
    match keyword.as_str() {
        // `never <verb>` | `never <verb> on <channel>`
        "never" => match tokens.len() {
            2 => Ok(CharterDirective::Never(format!(
                "*:{}",
                parse_charter_verb(tokens[1])?
            ))),
            4 if tokens[2].eq_ignore_ascii_case("on") => {
                let verb = parse_charter_verb(tokens[1])?;
                let channel = parse_charter_channel(tokens[3])?;
                Ok(CharterDirective::Never(format!("{channel}:{verb}")))
            }
            _ => Err("unrecognized charter directive".to_owned()),
        },
        // `cap <n> sends per <day|week|month|<m>s> on <channel>`
        // `cap spend <n> <unit> per <day|week|month> on <channel>`
        "cap" => {
            if tokens.len() == 8 && tokens[1].eq_ignore_ascii_case("spend") {
                if !tokens[4].eq_ignore_ascii_case("per") || !tokens[6].eq_ignore_ascii_case("on") {
                    return Err("unrecognized charter directive".to_owned());
                }
                let major_units = parse_charter_number(tokens[2], "invalid spend cap amount")?;
                let unit = tokens[3];
                let limit = charter_spend_limit(major_units, unit)?;
                let period = parse_calendar_period(tokens[5])
                    .ok_or_else(|| "invalid calendar period".to_owned())?;
                let channel = parse_charter_cap_channel(tokens[7])?;
                Ok(CharterDirective::Cap(EffectorBudget {
                    dimension: EffectorBudgetDimension::Spend,
                    channel_class: Some(channel),
                    limit,
                    unit: Some(unit.to_owned()),
                    window: EffectorBudgetWindow::Calendar { period, tz: None },
                    on_exhaust: EffectorBudgetOnExhaust::Suspend,
                    reserve_policy: None,
                }))
            } else if tokens.len() == 7 && tokens[2].eq_ignore_ascii_case("sends") {
                if !tokens[3].eq_ignore_ascii_case("per") || !tokens[5].eq_ignore_ascii_case("on") {
                    return Err("unrecognized charter directive".to_owned());
                }
                let limit = parse_charter_number(tokens[1], "invalid sends cap limit")?;
                let window = parse_charter_window(tokens[4])?;
                let channel = parse_charter_cap_channel(tokens[6])?;
                Ok(CharterDirective::Cap(EffectorBudget {
                    dimension: EffectorBudgetDimension::Sends,
                    channel_class: Some(channel),
                    limit,
                    unit: None,
                    window,
                    on_exhaust: EffectorBudgetOnExhaust::Suspend,
                    reserve_policy: None,
                }))
            } else {
                Err("unrecognized charter directive".to_owned())
            }
        }
        // `rate <n> per <m>s on <channel>`
        "rate" => {
            if tokens.len() != 6
                || !tokens[2].eq_ignore_ascii_case("per")
                || !tokens[4].eq_ignore_ascii_case("on")
            {
                return Err("unrecognized charter directive".to_owned());
            }
            let limit = parse_charter_number(tokens[1], "invalid rate limit")?;
            let duration_s = parse_rolling_duration(tokens[3])?;
            let channel = parse_charter_cap_channel(tokens[5])?;
            Ok(CharterDirective::Cap(EffectorBudget {
                dimension: EffectorBudgetDimension::Rate,
                channel_class: Some(channel),
                limit,
                unit: None,
                window: EffectorBudgetWindow::Rolling { duration_s },
                on_exhaust: EffectorBudgetOnExhaust::Refuse,
                reserve_policy: None,
            }))
        }
        _ => Err("unrecognized charter directive".to_owned()),
    }
}

fn parse_charter_verb(token: &str) -> std::result::Result<String, String> {
    if token == "*" {
        return Ok("*".to_owned());
    }
    let verb = token.to_ascii_lowercase();
    if !verb.is_empty()
        && verb
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        Ok(verb)
    } else {
        Err("invalid verb".to_owned())
    }
}

fn parse_charter_channel(token: &str) -> std::result::Result<String, String> {
    let channel = normalize_connector_key(token);
    if channel.is_empty() {
        return Err("invalid channel".to_owned());
    }
    Ok(channel)
}

/// Cap/rate channel narrowing. The gate matches a cap row's `channel_class`
/// by EXACT equality (`load_budget_row_states`), so a stored `"*"` would never
/// match a real channel (slack/email) — a `cap 10 sends per day on *` would
/// compile into a row that debits 0 forever (fail-OPEN). Reject the wildcard
/// here. `never <verb> on <channel>` keeps `"*"` as a legitimate wildcard via
/// `parse_charter_channel`, so this narrowing is cap/rate-only.
fn parse_charter_cap_channel(token: &str) -> std::result::Result<String, String> {
    let channel = parse_charter_channel(token)?;
    if channel == "*" {
        return Err("cap channel must not be the wildcard '*'".to_owned());
    }
    Ok(channel)
}

fn parse_charter_number(token: &str, message: &str) -> std::result::Result<u64, String> {
    match token.parse::<u64>() {
        Ok(value) if value >= 1 => Ok(value),
        _ => Err(message.to_owned()),
    }
}

fn parse_calendar_period(token: &str) -> Option<CalendarPeriod> {
    CalendarPeriod::parse(token.to_ascii_lowercase().as_str())
}

fn parse_rolling_duration(token: &str) -> std::result::Result<u64, String> {
    token
        .strip_suffix(['s', 'S'])
        .ok_or_else(|| "invalid window duration".to_owned())
        .and_then(|digits| parse_charter_number(digits, "invalid window duration"))
}

fn parse_charter_window(token: &str) -> std::result::Result<EffectorBudgetWindow, String> {
    if let Some(period) = parse_calendar_period(token) {
        return Ok(EffectorBudgetWindow::Calendar { period, tz: None });
    }
    Ok(EffectorBudgetWindow::Rolling {
        duration_s: parse_rolling_duration(token)?,
    })
}

/// M8 / R7 (2026-07-10): the cap unit MUST equal the connector's declared
/// denomination — no conversion in the gate, ever. ISO-4217 currencies
/// compile MAJOR → minor units via the pinned exponent table (default 2;
/// explicit exponent-0 list JPY/KRW/VND); provider units pass through as
/// opaque integers.
fn charter_spend_limit(major_units: u64, unit: &str) -> std::result::Result<u64, String> {
    validate_spend_unit(unit).map_err(|error| match error {
        Error::InvalidConnectorKeyBody(reason) => reason.to_owned(),
        _ => "invalid spend unit".to_owned(),
    })?;
    let bytes = unit.as_bytes();
    let is_iso_currency = bytes.len() == 3 && bytes.iter().all(u8::is_ascii_uppercase);
    if !is_iso_currency {
        return Ok(major_units);
    }
    let exponent: u32 = if ISO_4217_ZERO_EXPONENT_CURRENCIES.contains(&unit) {
        0
    } else {
        2
    };
    major_units
        .checked_mul(10_u64.pow(exponent))
        .ok_or_else(|| "spend cap overflows minor units".to_owned())
}

/// ConnectorKeyRecord lifecycle status.
///
/// v1 reachable states: `Active ⇄ Suspended`, `→ Revoked` (terminal).
/// `Pending` is accepted by decode for forward-compat with the ARCH-0028
/// qualification suite but is never minted by v1 registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectorKeyStatus {
    Pending,
    Active,
    Suspended,
    Revoked,
}

impl ConnectorKeyStatus {
    /// Returns the pinned on-disk status string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
        }
    }

    /// Parses a pinned on-disk status string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

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

/// Compiled connector policy (GOV-10 fills; pinned now so the v1 body encoding
/// is stable). v1 carries only what the gate can enforce today.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CompiledConnectorPolicy {
    /// Sorted, deduped `"channel:verb"` entries; `"*"` wildcard on either side.
    pub never_list: Vec<String>,
    /// Extra budget rows, enforced identically to key budgets.
    pub channel_caps: Vec<EffectorBudget>,
}

/// Human-stamped charter block (GOV-10). Enforcement reads only `compiled`,
/// never `text`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectorCharterBlock {
    pub text: String,
    pub text_hash: [u8; 32],
    pub compiled: CompiledConnectorPolicy,
    pub compiled_hash: [u8; 32],
    /// `sha256(STAMP_DOMAIN ‖ text_hash ‖ compiled_hash)`.
    pub stamped_aggregate: [u8; 32],
    pub stamped_by: String,
    pub stamped_at: u64,
}

/// Staged (compiled but not yet human-approved) charter (GOV-10).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PendingConnectorCharter {
    pub text: String,
    pub text_hash: [u8; 32],
    pub compiled: CompiledConnectorPolicy,
    pub compiled_hash: [u8; 32],
    pub proposed_at: u64,
}

/// Vault-resident connector-key registry record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorKeyRecord {
    /// Stable outbound connector key (same string space as
    /// `OutboundCapabilityManifest.connector`), stored normalized.
    pub connector: String,
    /// `None` = any actor on this connector.
    pub actor_entity_ref: Option<EntityId>,
    pub status: ConnectorKeyStatus,
    pub budgets: Vec<EffectorBudget>,
    pub registered_at: u64,
    pub status_changed_at: Option<u64>,
    /// `"budget_exhausted:row:{i}"` | `"budget_exhausted:charter_row:{i}"`
    /// (GOV-10) | an owner-supplied reason.
    pub suspended_reason: Option<String>,
    /// GOV-10 fills; GOV-01 encodes Nil.
    pub charter: Option<ConnectorCharterBlock>,
    /// GOV-10 fills; GOV-01 encodes Nil.
    pub pending_charter: Option<PendingConnectorCharter>,
}

impl ConnectorKeyRecord {
    /// Constructs an active record with no charter, ready for registration.
    #[must_use]
    pub fn active(
        connector: impl Into<String>,
        actor_entity_ref: Option<EntityId>,
        budgets: Vec<EffectorBudget>,
        registered_at: u64,
    ) -> Self {
        Self {
            connector: connector.into(),
            actor_entity_ref,
            status: ConnectorKeyStatus::Active,
            budgets,
            registered_at,
            status_changed_at: None,
            suspended_reason: None,
            charter: None,
            pending_charter: None,
        }
    }

    /// Validates structural invariants shared by encode, decode, and register.
    ///
    /// Registration-only checks (status must be Active, no pre-stamped
    /// charter) deliberately do NOT live here: decode must accept every
    /// status and any stored charter block.
    pub fn validate(&self) -> Result<()> {
        validate_connector_token(&self.connector)?;
        if self.budgets.len() > CONNECTOR_KEY_MAX_BUDGET_ROWS {
            return Err(invalid_body("too many budget rows"));
        }
        for budget in &self.budgets {
            validate_budget_row(budget)?;
        }
        if let Some(reason) = self.suspended_reason.as_deref() {
            if reason.trim().is_empty() {
                return Err(invalid_body("suspended_reason must not be blank"));
            }
            if self.status != ConnectorKeyStatus::Suspended {
                return Err(invalid_body("suspended_reason requires suspended status"));
            }
        }
        if let Some(status_changed_at) = self.status_changed_at
            && status_changed_at < self.registered_at
        {
            return Err(invalid_body("status_changed_at before registered_at"));
        }
        if let Some(charter) = self.charter.as_ref() {
            if charter.text.trim().is_empty() {
                return Err(invalid_body("charter text must not be blank"));
            }
            if charter.stamped_by.trim().is_empty() {
                return Err(invalid_body("charter stamped_by must not be blank"));
            }
            validate_compiled_policy(&charter.compiled)?;
        }
        if let Some(pending) = self.pending_charter.as_ref() {
            if pending.text.trim().is_empty() {
                return Err(invalid_body("pending charter text must not be blank"));
            }
            validate_compiled_policy(&pending.compiled)?;
        }
        Ok(())
    }
}

/// Normalizes an outbound connector/channel key (duplicate of the private
/// `outbound.rs::normalize_key` on the shared string space).
#[must_use]
pub(crate) fn normalize_connector_key(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn validate_connector_token(connector: &str) -> Result<()> {
    if normalize_connector_key(connector).is_empty() {
        return Err(invalid_body("connector must not be blank"));
    }
    if connector.as_bytes().contains(&0) {
        return Err(invalid_body("connector must not contain NUL"));
    }
    // The stored form MUST be the canonical (normalized) form: the connector
    // index key and the gate's governing-key lookup are both derived from
    // the normalized channel, so a record stored non-canonical would exist
    // but never match — a budget key that silently fails to govern. Vault
    // write doors normalize before validate; this makes the invariant hold
    // for every encode/decode, including replicated or imported bodies.
    if connector != normalize_connector_key(connector) {
        return Err(invalid_body("connector must be stored normalized"));
    }
    Ok(())
}

fn validate_budget_row(budget: &EffectorBudget) -> Result<()> {
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

/// The connector-declared denomination (M8 resolution 2026-07-10): a
/// 3-ASCII-uppercase ISO-4217 code, or a provider-unit token
/// (`[a-z0-9_]{1,32}`). A 3-letter alphabetic unit is the ISO namespace and
/// must be uppercase — `"usd"` is a malformed currency, not a provider token.
fn validate_spend_unit(unit: &str) -> Result<()> {
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

fn validate_compiled_policy(compiled: &CompiledConnectorPolicy) -> Result<()> {
    if compiled.channel_caps.len() > CONNECTOR_KEY_MAX_BUDGET_ROWS {
        return Err(invalid_body("too many charter channel caps"));
    }
    for cap in &compiled.channel_caps {
        validate_budget_row(cap)?;
    }
    for entry in &compiled.never_list {
        if entry.trim().is_empty() {
            return Err(invalid_body("never_list entry must not be blank"));
        }
    }
    Ok(())
}

fn invalid_body(reason: &'static str) -> Error {
    Error::InvalidConnectorKeyBody(reason)
}

// --- Encoding ---------------------------------------------------------------

/// Encodes a ConnectorKeyRecord body in canonical MessagePack field order.
pub fn encode_connector_key_body(record: &ConnectorKeyRecord) -> Result<Vec<u8>> {
    record.validate()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(CONNECTOR_KEY_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_CONNECTOR),
            Value::from(record.connector.clone()),
        ),
        (
            Value::from(KEY_ACTOR_ENTITY_REF),
            record
                .actor_entity_ref
                .as_ref()
                .map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec())),
        ),
        (Value::from(KEY_STATUS), Value::from(record.status.as_str())),
        (
            Value::from(KEY_BUDGETS),
            Value::Array(record.budgets.iter().map(encode_budget_row).collect()),
        ),
        (
            Value::from(KEY_REGISTERED_AT),
            Value::from(record.registered_at),
        ),
        (
            Value::from(KEY_STATUS_CHANGED_AT),
            record.status_changed_at.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_SUSPENDED_REASON),
            option_string_value(record.suspended_reason.as_deref()),
        ),
        (
            Value::from(KEY_CHARTER),
            record
                .charter
                .as_ref()
                .map_or(Value::Nil, encode_charter_block),
        ),
        (
            Value::from(KEY_PENDING_CHARTER),
            record
                .pending_charter
                .as_ref()
                .map_or(Value::Nil, encode_pending_charter),
        ),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("connector key body MessagePack encode failed"))?;
    Ok(out)
}

fn encode_budget_row(budget: &EffectorBudget) -> Value {
    Value::Map(vec![
        (
            Value::from(BUDGET_KEYS[0]),
            Value::from(budget.dimension.as_str()),
        ),
        (
            Value::from(BUDGET_KEYS[1]),
            option_string_value(budget.channel_class.as_deref()),
        ),
        (Value::from(BUDGET_KEYS[2]), Value::from(budget.limit)),
        (
            Value::from(BUDGET_KEYS[3]),
            option_string_value(budget.unit.as_deref()),
        ),
        (Value::from(BUDGET_KEYS[4]), encode_window(&budget.window)),
        (
            Value::from(BUDGET_KEYS[5]),
            Value::from(budget.on_exhaust.as_str()),
        ),
        (
            Value::from(BUDGET_KEYS[6]),
            budget
                .reserve_policy
                .map_or(Value::Nil, |policy| Value::from(policy.as_str())),
        ),
    ])
}

fn encode_window(window: &EffectorBudgetWindow) -> Value {
    match window {
        EffectorBudgetWindow::Rolling { duration_s } => Value::Map(vec![
            (
                Value::from(ROLLING_WINDOW_KEYS[0]),
                Value::from(WINDOW_KIND_ROLLING),
            ),
            (
                Value::from(ROLLING_WINDOW_KEYS[1]),
                Value::from(*duration_s),
            ),
        ]),
        EffectorBudgetWindow::Calendar { period, tz } => Value::Map(vec![
            (
                Value::from(CALENDAR_WINDOW_KEYS[0]),
                Value::from(WINDOW_KIND_CALENDAR),
            ),
            (
                Value::from(CALENDAR_WINDOW_KEYS[1]),
                Value::from(period.as_str()),
            ),
            (
                Value::from(CALENDAR_WINDOW_KEYS[2]),
                option_string_value(tz.as_deref()),
            ),
        ]),
    }
}

fn encode_compiled_policy(compiled: &CompiledConnectorPolicy) -> Value {
    Value::Map(vec![
        (
            Value::from(COMPILED_POLICY_KEYS[0]),
            Value::Array(
                compiled
                    .never_list
                    .iter()
                    .map(|entry| Value::from(entry.clone()))
                    .collect(),
            ),
        ),
        (
            Value::from(COMPILED_POLICY_KEYS[1]),
            Value::Array(
                compiled
                    .channel_caps
                    .iter()
                    .map(encode_budget_row)
                    .collect(),
            ),
        ),
    ])
}

fn encode_charter_block(charter: &ConnectorCharterBlock) -> Value {
    Value::Map(vec![
        (
            Value::from(CHARTER_BLOCK_KEYS[0]),
            Value::from(charter.text.clone()),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[1]),
            Value::Binary(charter.text_hash.to_vec()),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[2]),
            encode_compiled_policy(&charter.compiled),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[3]),
            Value::Binary(charter.compiled_hash.to_vec()),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[4]),
            Value::Binary(charter.stamped_aggregate.to_vec()),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[5]),
            Value::from(charter.stamped_by.clone()),
        ),
        (
            Value::from(CHARTER_BLOCK_KEYS[6]),
            Value::from(charter.stamped_at),
        ),
    ])
}

fn encode_pending_charter(pending: &PendingConnectorCharter) -> Value {
    Value::Map(vec![
        (
            Value::from(PENDING_CHARTER_KEYS[0]),
            Value::from(pending.text.clone()),
        ),
        (
            Value::from(PENDING_CHARTER_KEYS[1]),
            Value::Binary(pending.text_hash.to_vec()),
        ),
        (
            Value::from(PENDING_CHARTER_KEYS[2]),
            encode_compiled_policy(&pending.compiled),
        ),
        (
            Value::from(PENDING_CHARTER_KEYS[3]),
            Value::Binary(pending.compiled_hash.to_vec()),
        ),
        (
            Value::from(PENDING_CHARTER_KEYS[4]),
            Value::from(pending.proposed_at),
        ),
    ])
}

// --- Decoding ---------------------------------------------------------------

/// Decodes a ConnectorKeyRecord body after fail-closed structural validation.
pub fn decode_connector_key_body(bytes: &[u8]) -> Result<ConnectorKeyRecord> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| malformed())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(malformed());
    }
    decode_connector_key_value(&value)
}

fn malformed() -> Error {
    invalid_body("body failed validation")
}

fn decode_connector_key_value(value: &Value) -> Result<ConnectorKeyRecord> {
    let Value::Map(entries) = value else {
        return Err(malformed());
    };
    validate_keys(entries, &CONNECTOR_KEY_BODY_KEYS)?;

    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64() != Some(CONNECTOR_KEY_SCHEMA_VERSION) {
        return Err(invalid_body("unsupported schema version"));
    }

    let record = ConnectorKeyRecord {
        connector: decode_non_empty_string(required_value(entries, KEY_CONNECTOR)?)?,
        actor_entity_ref: decode_optional_entity_id(required_value(
            entries,
            KEY_ACTOR_ENTITY_REF,
        )?)?,
        status: required_value(entries, KEY_STATUS)?
            .as_str()
            .and_then(ConnectorKeyStatus::parse)
            .ok_or_else(malformed)?,
        budgets: decode_budget_rows(required_value(entries, KEY_BUDGETS)?)?,
        registered_at: required_value(entries, KEY_REGISTERED_AT)?
            .as_u64()
            .ok_or_else(malformed)?,
        status_changed_at: decode_optional_u64(required_value(entries, KEY_STATUS_CHANGED_AT)?)?,
        suspended_reason: decode_optional_string(required_value(entries, KEY_SUSPENDED_REASON)?)?,
        charter: decode_optional_charter_block(required_value(entries, KEY_CHARTER)?)?,
        pending_charter: decode_optional_pending_charter(required_value(
            entries,
            KEY_PENDING_CHARTER,
        )?)?,
    };
    record.validate()?;
    Ok(record)
}

fn decode_budget_rows(value: &Value) -> Result<Vec<EffectorBudget>> {
    let Value::Array(rows) = value else {
        return Err(malformed());
    };
    rows.iter().map(decode_budget_row).collect()
}

fn decode_budget_row(value: &Value) -> Result<EffectorBudget> {
    let Value::Map(entries) = value else {
        return Err(malformed());
    };
    validate_keys(entries, &BUDGET_KEYS)?;
    let reserve_policy = match required_value(entries, BUDGET_KEYS[6])? {
        Value::Nil => None,
        value => Some(
            value
                .as_str()
                .and_then(EffectorBudgetReservePolicy::parse)
                .ok_or_else(malformed)?,
        ),
    };
    Ok(EffectorBudget {
        dimension: required_value(entries, BUDGET_KEYS[0])?
            .as_str()
            .and_then(EffectorBudgetDimension::parse)
            .ok_or_else(malformed)?,
        channel_class: decode_optional_string(required_value(entries, BUDGET_KEYS[1])?)?,
        limit: required_value(entries, BUDGET_KEYS[2])?
            .as_u64()
            .ok_or_else(malformed)?,
        unit: decode_optional_string(required_value(entries, BUDGET_KEYS[3])?)?,
        window: decode_window(required_value(entries, BUDGET_KEYS[4])?)?,
        on_exhaust: required_value(entries, BUDGET_KEYS[5])?
            .as_str()
            .and_then(EffectorBudgetOnExhaust::parse)
            .ok_or_else(malformed)?,
        reserve_policy,
    })
}

fn decode_window(value: &Value) -> Result<EffectorBudgetWindow> {
    let Value::Map(entries) = value else {
        return Err(malformed());
    };
    let kind = required_value(entries, "kind")?
        .as_str()
        .ok_or_else(malformed)?;
    match kind {
        WINDOW_KIND_ROLLING => {
            validate_keys(entries, &ROLLING_WINDOW_KEYS)?;
            Ok(EffectorBudgetWindow::Rolling {
                duration_s: required_value(entries, ROLLING_WINDOW_KEYS[1])?
                    .as_u64()
                    .ok_or_else(malformed)?,
            })
        }
        WINDOW_KIND_CALENDAR => {
            validate_keys(entries, &CALENDAR_WINDOW_KEYS)?;
            Ok(EffectorBudgetWindow::Calendar {
                period: required_value(entries, CALENDAR_WINDOW_KEYS[1])?
                    .as_str()
                    .and_then(CalendarPeriod::parse)
                    .ok_or_else(malformed)?,
                tz: decode_optional_string(required_value(entries, CALENDAR_WINDOW_KEYS[2])?)?,
            })
        }
        _ => Err(malformed()),
    }
}

fn decode_compiled_policy(value: &Value) -> Result<CompiledConnectorPolicy> {
    let Value::Map(entries) = value else {
        return Err(malformed());
    };
    validate_keys(entries, &COMPILED_POLICY_KEYS)?;
    let Value::Array(never_entries) = required_value(entries, COMPILED_POLICY_KEYS[0])? else {
        return Err(malformed());
    };
    let never_list = never_entries
        .iter()
        .map(|entry| entry.as_str().map(str::to_owned).ok_or_else(malformed))
        .collect::<Result<Vec<_>>>()?;
    Ok(CompiledConnectorPolicy {
        never_list,
        channel_caps: decode_budget_rows(required_value(entries, COMPILED_POLICY_KEYS[1])?)?,
    })
}

fn decode_optional_charter_block(value: &Value) -> Result<Option<ConnectorCharterBlock>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let Value::Map(entries) = value else {
        return Err(malformed());
    };
    validate_keys(entries, &CHARTER_BLOCK_KEYS)?;
    Ok(Some(ConnectorCharterBlock {
        text: decode_non_empty_string(required_value(entries, CHARTER_BLOCK_KEYS[0])?)?,
        text_hash: decode_hash32(required_value(entries, CHARTER_BLOCK_KEYS[1])?)?,
        compiled: decode_compiled_policy(required_value(entries, CHARTER_BLOCK_KEYS[2])?)?,
        compiled_hash: decode_hash32(required_value(entries, CHARTER_BLOCK_KEYS[3])?)?,
        stamped_aggregate: decode_hash32(required_value(entries, CHARTER_BLOCK_KEYS[4])?)?,
        stamped_by: decode_non_empty_string(required_value(entries, CHARTER_BLOCK_KEYS[5])?)?,
        stamped_at: required_value(entries, CHARTER_BLOCK_KEYS[6])?
            .as_u64()
            .ok_or_else(malformed)?,
    }))
}

fn decode_optional_pending_charter(value: &Value) -> Result<Option<PendingConnectorCharter>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let Value::Map(entries) = value else {
        return Err(malformed());
    };
    validate_keys(entries, &PENDING_CHARTER_KEYS)?;
    Ok(Some(PendingConnectorCharter {
        text: decode_non_empty_string(required_value(entries, PENDING_CHARTER_KEYS[0])?)?,
        text_hash: decode_hash32(required_value(entries, PENDING_CHARTER_KEYS[1])?)?,
        compiled: decode_compiled_policy(required_value(entries, PENDING_CHARTER_KEYS[2])?)?,
        compiled_hash: decode_hash32(required_value(entries, PENDING_CHARTER_KEYS[3])?)?,
        proposed_at: required_value(entries, PENDING_CHARTER_KEYS[4])?
            .as_u64()
            .ok_or_else(malformed)?,
    }))
}

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(malformed)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(malformed());
        };
        if seen[index] {
            return Err(malformed());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(malformed())
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(malformed)
}

fn decode_non_empty_string(value: &Value) -> Result<String> {
    let value = value.as_str().ok_or_else(malformed)?;
    if value.trim().is_empty() {
        return Err(malformed());
    }
    Ok(value.to_owned())
}

fn decode_optional_string(value: &Value) -> Result<Option<String>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    decode_non_empty_string(value).map(Some)
}

fn decode_optional_u64(value: &Value) -> Result<Option<u64>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    value.as_u64().ok_or_else(malformed).map(Some)
}

fn decode_optional_entity_id(value: &Value) -> Result<Option<EntityId>> {
    match value {
        Value::Nil => Ok(None),
        Value::Binary(bytes) => {
            let raw: [u8; ENTITY_ID_LEN] = bytes.as_slice().try_into().map_err(|_| malformed())?;
            EntityId::from_bytes(raw).map(Some).map_err(|_| malformed())
        }
        _ => Err(malformed()),
    }
}

fn decode_hash32(value: &Value) -> Result<[u8; 32]> {
    let Value::Binary(bytes) = value else {
        return Err(malformed());
    };
    bytes.as_slice().try_into().map_err(|_| malformed())
}

fn option_string_value(value: Option<&str>) -> Value {
    value.map_or(Value::Nil, Value::from)
}

// --- Window math ------------------------------------------------------------

/// Returns the UTC bucket start for a calendar window at `now` (Unix seconds).
///
/// Day: midnight UTC. Week: Monday-start UTC (saturating — for `now` before
/// 1970-01-05 the Monday-start would be negative, so the bucket clamps to the
/// epoch instead of underflowing u64). Month: first-of-month 00:00:00 UTC via
/// the Hinnant civil-date algorithm.
#[must_use]
pub(crate) fn calendar_window_start(period: CalendarPeriod, now: u64) -> u64 {
    match period {
        CalendarPeriod::Day => now - now % SECONDS_PER_DAY,
        CalendarPeriod::Week => {
            let days = now / SECONDS_PER_DAY;
            days.saturating_sub((days + 3) % 7) * SECONDS_PER_DAY
        }
        CalendarPeriod::Month => {
            let days = i64::try_from(now / SECONDS_PER_DAY).unwrap_or(i64::MAX);
            let (year, month, _day) = civil_from_days(days);
            let month_start_days = days_from_civil(year, month, 1);
            u64::try_from(month_start_days).unwrap_or(0) * SECONDS_PER_DAY
        }
    }
}

/// Hinnant `civil_from_days`: days since 1970-01-01 → (year, month, day).
const fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Hinnant `days_from_civil`: (year, month, day) → days since 1970-01-01.
const fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

// --- Usage rows -------------------------------------------------------------

/// Live usage state for one (key, budget row) pair, stored in `vault_meta`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ConnectorKeyUsage {
    /// Current calendar bucket start; 0 for rolling windows.
    pub(crate) window_start: u64,
    /// `(ts, amount)` debit log, pruned on every touch.
    pub(crate) entries: Vec<(u64, u64)>,
    /// Ladder thresholds fired this window (GOV-01 writes it empty; GOV-02
    /// populates it): `"silent50" | "plan80" | "land95"`.
    pub(crate) fired: Vec<String>,
}

impl ConnectorKeyUsage {
    pub(crate) fn used(&self) -> u64 {
        self.entries
            .iter()
            .fold(0_u64, |sum, (_, amount)| sum.saturating_add(*amount))
    }

    /// Prunes entries to window liveness at `now`. Calendar rollover resets
    /// `entries` and `fired` (fresh bucket ⇒ fresh ladder). Rolling windows
    /// have no discrete rollover, so the ladder re-arms per the M5a rule
    /// (resolved 2026-07-10): on each touch, drop `fired` entries whose
    /// threshold percent exceeds the current `percent_used` — full expiry
    /// re-arms everything, partial expiry re-arms exactly the thresholds no
    /// longer satisfied.
    pub(crate) fn touch(&mut self, window: &EffectorBudgetWindow, limit: u64, now: u64) {
        match window {
            EffectorBudgetWindow::Rolling { duration_s } => {
                self.window_start = 0;
                self.entries
                    .retain(|(ts, _)| ts.saturating_add(*duration_s) > now);
                let percent = percent_used(self.used(), limit);
                self.fired.retain(|name| {
                    parse_fired_threshold(name)
                        .is_none_or(|threshold| threshold.percent() <= percent)
                });
            }
            EffectorBudgetWindow::Calendar { period, .. } => {
                let bucket = calendar_window_start(*period, now);
                if self.window_start != bucket {
                    self.window_start = bucket;
                    self.entries.clear();
                    self.fired.clear();
                } else {
                    self.entries.retain(|(ts, _)| *ts >= bucket);
                }
            }
        }
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let value = Value::Map(vec![
            (Value::from("window_start"), Value::from(self.window_start)),
            (
                Value::from("entries"),
                Value::Array(
                    self.entries
                        .iter()
                        .map(|(ts, amount)| {
                            Value::Array(vec![Value::from(*ts), Value::from(*amount)])
                        })
                        .collect(),
                ),
            ),
            (
                Value::from("fired"),
                Value::Array(
                    self.fired
                        .iter()
                        .map(|name| Value::from(name.clone()))
                        .collect(),
                ),
            ),
        ]);
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &value)
            .map_err(|_| Error::InvariantViolation("connector key usage encode failed"))?;
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let corrupted = || Error::CorruptedIndex("connector key usage row");
        let mut cursor = Cursor::new(bytes);
        let value = rmpv::decode::read_value(&mut cursor).map_err(|_| corrupted())?;
        if cursor.position() != bytes.len() as u64 {
            return Err(corrupted());
        }
        let Value::Map(entries) = value else {
            return Err(corrupted());
        };
        let field = |key: &str| {
            entries
                .iter()
                .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
                .ok_or_else(corrupted)
        };
        let window_start = field("window_start")?.as_u64().ok_or_else(corrupted)?;
        let Value::Array(raw_entries) = field("entries")? else {
            return Err(corrupted());
        };
        let debit_entries = raw_entries
            .iter()
            .map(|entry| {
                let Value::Array(pair) = entry else {
                    return Err(corrupted());
                };
                if pair.len() != 2 {
                    return Err(corrupted());
                }
                Ok((
                    pair[0].as_u64().ok_or_else(corrupted)?,
                    pair[1].as_u64().ok_or_else(corrupted)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let Value::Array(raw_fired) = field("fired")? else {
            return Err(corrupted());
        };
        let fired = raw_fired
            .iter()
            .map(|name| name.as_str().map(str::to_owned).ok_or_else(corrupted))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            window_start,
            entries: debit_entries,
            fired,
        })
    }
}

// --- vault_meta keys ---------------------------------------------------------

pub(crate) fn connector_key_index_prefix(connector: &str) -> Result<Vec<u8>> {
    validate_connector_token(connector)?;
    let mut key = Vec::with_capacity(
        CONNECTOR_KEY_CONNECTOR_INDEX_PREFIX.len() + connector.len() + 1 + ENTITY_ID_LEN,
    );
    key.extend_from_slice(CONNECTOR_KEY_CONNECTOR_INDEX_PREFIX);
    key.extend_from_slice(connector.as_bytes());
    key.push(0);
    Ok(key)
}

pub(crate) fn connector_key_index_key(connector: &str, id: &EntityId) -> Result<Vec<u8>> {
    let mut key = connector_key_index_prefix(connector)?;
    key.extend_from_slice(id.as_bytes());
    Ok(key)
}

pub(crate) fn connector_key_index_entity_id(key: &[u8], connector: &str) -> Result<EntityId> {
    let prefix = connector_key_index_prefix(connector)?;
    if key.len() != prefix.len() + ENTITY_ID_LEN || !key.starts_with(&prefix) {
        return Err(Error::CorruptedIndex("connector key connector index key"));
    }
    let mut raw_id = [0; ENTITY_ID_LEN];
    raw_id.copy_from_slice(&key[prefix.len()..]);
    EntityId::from_bytes(raw_id)
        .map_err(|_| Error::CorruptedIndex("connector key connector index key"))
}

/// Length of the settlement-event IDENTITY prefix (row_index ++ minor_units
/// — the settlement's actual content). The declared `cost_occurred_at`
/// trails as first-writer-wins RECORDED data and is deliberately NOT part
/// of the identity: an honest retry whose declared cost time drifted
/// between attempts must stay idempotent, never fail closed into a
/// fresh-event_ref retry that double-debits.
const SETTLE_EVENT_IDENTITY_LEN: usize = size_of::<u16>() + size_of::<u64>();

/// The stored settlement-event value: identity prefix, then the declared
/// cost time from the FIRST successful write.
fn settle_event_value(row_index: u16, minor_units: u64, cost_occurred_at: u64) -> Vec<u8> {
    let mut value = Vec::with_capacity(SETTLE_EVENT_IDENTITY_LEN + size_of::<u64>());
    value.extend_from_slice(&row_index.to_be_bytes());
    value.extend_from_slice(&minor_units.to_be_bytes());
    value.extend_from_slice(&cost_occurred_at.to_be_bytes());
    value
}

pub(crate) fn connector_key_settle_event_key(id: &EntityId, event_ref: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        CONNECTOR_KEY_SETTLE_EVENT_PREFIX.len() + ENTITY_ID_LEN + event_ref.len(),
    );
    key.extend_from_slice(CONNECTOR_KEY_SETTLE_EVENT_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key.extend_from_slice(event_ref.as_bytes());
    key
}

/// Deletes every compiled-cap usage row (`0x8000 | *`) for one key. Called
/// by charter approve so a re-stamped charter never inherits positional
/// usage from the previous charter's caps.
fn delete_charter_usage_rows_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let mut prefix = Vec::with_capacity(CONNECTOR_KEY_USAGE_PREFIX.len() + ENTITY_ID_LEN);
    prefix.extend_from_slice(CONNECTOR_KEY_USAGE_PREFIX);
    prefix.extend_from_slice(id.as_bytes());
    let mut doomed = Vec::new();
    for entry in store.vault_meta.prefix_iter(wtxn, &prefix)? {
        let (key, _) = entry?;
        if key.len() != prefix.len() + size_of::<u16>() {
            return Err(Error::CorruptedIndex("connector key usage row key"));
        }
        let row_index = u16::from_be_bytes([key[prefix.len()], key[prefix.len() + 1]]);
        if row_index & CONNECTOR_KEY_CHARTER_ROW_BASE != 0 {
            doomed.push(key.to_vec());
        }
    }
    for key in doomed {
        store.vault_meta.delete(wtxn, &key)?;
    }
    Ok(())
}

pub(crate) fn connector_key_usage_row_key(id: &EntityId, row_index: u16) -> Vec<u8> {
    let mut key =
        Vec::with_capacity(CONNECTOR_KEY_USAGE_PREFIX.len() + ENTITY_ID_LEN + size_of::<u16>());
    key.extend_from_slice(CONNECTOR_KEY_USAGE_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key.extend_from_slice(&row_index.to_be_bytes());
    key
}

// --- Reads and charges --------------------------------------------------------

/// Post-debit read of one budget row (the `self.*` echo shape; GOV-02 wires
/// the meter read around it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectorBudgetRowRead {
    /// `0..=15` key rows; `0x8000 | i` compiled-cap rows (GOV-10).
    pub row_index: u16,
    pub dimension: EffectorBudgetDimension,
    pub channel_class: Option<String>,
    pub limit: u64,
    pub unit: Option<String>,
    /// Live usage in the current window.
    pub used: u64,
    pub remaining: u64,
    /// `used*100/limit`, capped 100 (`limit == 0` ⇒ 100).
    pub percent_used: u64,
    pub on_exhaust: EffectorBudgetOnExhaust,
    /// Calendar bucket start; 0 for rolling.
    pub window_start: u64,
    /// Thresholds the current window's usage has crossed, ascending — the
    /// TRUE ladder state, computed from live usage rather than parsed from
    /// the stored event-emission memory (which lags when usage advances
    /// without incremental firing: spend settlements, pre-ladder rows).
    pub fired_thresholds: Vec<BudgetThreshold>,
}

/// The `self.*` effector-meter read (ARCHPASS A3): the response-borne budget
/// is an ECHO of this read, never a second delivery lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectorBudgetRead {
    pub key_ref: EntityId,
    pub connector: String,
    pub status: ConnectorKeyStatus,
    /// Key budget rows and, when a charter is stamped, the compiled-cap rows
    /// at `0x8000 | i` (GOV-10) — ascending row index.
    pub rows: Vec<EffectorBudgetRowRead>,
}

/// The budget outcome the gate hands back to dispatch when a governing key's
/// budget stage ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectorBudgetCharge {
    pub key_ref: EntityId,
    /// 1 iff ≥1 Sends-dimension row actually debited this dispatch, else 0
    /// (`NoRows`/`Exhausted` paths return 0).
    pub sends_debit: u64,
    /// Post-debit meter read over EVERY row of the governing key.
    pub read: EffectorBudgetRead,
    /// `row_index` values matched by this dispatch (the binding constraint
    /// set for the receipt `"budget"` field — M4 resolution 2026-07-10).
    pub matched_rows: Vec<u16>,
    /// Threshold events fired by this charge, for the host steering queue
    /// (same contract as `BudgetAdmission.ladder_events`).
    pub ladder_events: Vec<BudgetLadderEvent>,
}

/// Outcome of one budget-stage evaluation over a key's matched rows.
pub(crate) enum EffectorBudgetChargeOutcome {
    /// No budget row matched this effect.
    NoRows(EffectorBudgetCharge),
    /// All matched rows passed; debits applied.
    Charged(EffectorBudgetCharge),
    /// A matched row would exceed (or a spend row is already exhausted);
    /// NO debits were applied. `row_index` is the first exceeding row in
    /// ascending row-index order.
    Exhausted {
        row_index: u16,
        on_exhaust: EffectorBudgetOnExhaust,
        charge: EffectorBudgetCharge,
    },
}

fn percent_used(used: u64, limit: u64) -> u64 {
    if limit == 0 {
        return 100;
    }
    let percent = (u128::from(used) * 100) / u128::from(limit);
    u64::try_from(percent.min(100)).unwrap_or(100)
}

fn parse_fired_threshold(name: &str) -> Option<BudgetThreshold> {
    match name {
        "silent50" => Some(BudgetThreshold::Silent50),
        "plan80" => Some(BudgetThreshold::Plan80),
        "land95" => Some(BudgetThreshold::Land95),
        _ => None,
    }
}

/// Thresholds the given usage percentage has crossed, ascending.
fn crossed_thresholds(percent: u64) -> Vec<BudgetThreshold> {
    [
        BudgetThreshold::Silent50,
        BudgetThreshold::Plan80,
        BudgetThreshold::Land95,
    ]
    .into_iter()
    .filter(|threshold| percent >= threshold.percent())
    .collect()
}

fn budget_row_read(
    row_index: u16,
    budget: &EffectorBudget,
    usage: &ConnectorKeyUsage,
) -> EffectorBudgetRowRead {
    let used = usage.used();
    let percent = percent_used(used, budget.limit);
    EffectorBudgetRowRead {
        row_index,
        dimension: budget.dimension,
        channel_class: budget.channel_class.clone(),
        limit: budget.limit,
        unit: budget.unit.clone(),
        used,
        remaining: budget.limit.saturating_sub(used),
        percent_used: percent,
        on_exhaust: budget.on_exhaust,
        window_start: usage.window_start,
        // The read reports the TRUE ladder state — every threshold the live
        // usage has crossed — not the event-emission memory. Usage can
        // advance without incremental firing (spend settlements never emit
        // per M3b; pre-ladder upgrade rows carry entries with an empty
        // `fired`), and the Exhausted path deliberately emits nothing (M5b
        // carry-read-only), so a denial's history must be computed from the
        // usage itself or a jump-to-exhausted row would read as
        // signal-silent. Post-touch, the stored `fired` (the single-fire
        // memory) is always a subset of this per the M5a re-arm rule, so for
        // incrementally-fired rows the two coincide exactly.
        fired_thresholds: crossed_thresholds(percent),
    }
}

fn budget_debit_amount(dimension: EffectorBudgetDimension, send_like: bool) -> u64 {
    match dimension {
        // Sends count gate-admitted sends; lifecycle intents (send_ref None)
        // never eat a sends budget.
        EffectorBudgetDimension::Sends => u64::from(send_like),
        // Rate is a verb-agnostic limiter on effector calls.
        EffectorBudgetDimension::Rate => 1,
        // Spend debits 0 at admission; actual costs settle post-hoc.
        EffectorBudgetDimension::Spend => 0,
    }
}

/// Every budget row of a record in ascending row-index order: key rows at
/// base 0, then (when a charter is stamped — GOV-10) compiled-cap rows at
/// `0x8000 | i`. One row-set union so evaluate-all-then-apply-all atomicity
/// spans key AND compiled rows.
fn record_budget_rows(record: &ConnectorKeyRecord) -> Result<Vec<(u16, &EffectorBudget)>> {
    let index = |base: u16, offset: usize| {
        u16::try_from(offset)
            .ok()
            .filter(|offset| *offset < CONNECTOR_KEY_CHARTER_ROW_BASE)
            .map(|offset| base | offset)
            .ok_or(Error::InvariantViolation(
                "connector key budget row index overflow",
            ))
    };
    let mut rows = Vec::with_capacity(record.budgets.len());
    for (offset, budget) in record.budgets.iter().enumerate() {
        rows.push((index(0, offset)?, budget));
    }
    if let Some(charter) = record.charter.as_ref() {
        for (offset, budget) in charter.compiled.channel_caps.iter().enumerate() {
            rows.push((index(CONNECTOR_KEY_CHARTER_ROW_BASE, offset)?, budget));
        }
    }
    Ok(rows)
}

struct BudgetRowState<'a> {
    row_index: u16,
    budget: &'a EffectorBudget,
    usage: ConnectorKeyUsage,
    amount: u64,
    matched: bool,
}

fn load_budget_row_states<'a>(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
    record: &'a ConnectorKeyRecord,
    effect_channel: Option<&str>,
    send_like: bool,
    now: u64,
) -> Result<Vec<BudgetRowState<'a>>> {
    let mut states = Vec::new();
    for (row_index, budget) in record_budget_rows(record)? {
        let usage_key = connector_key_usage_row_key(key_id, row_index);
        let mut usage = match store.vault_meta.get(txn, &usage_key)? {
            Some(bytes) => ConnectorKeyUsage::decode(bytes)?,
            None => ConnectorKeyUsage::default(),
        };
        usage.touch(&budget.window, budget.limit, now);
        let matched = effect_channel.is_some_and(|channel| {
            budget
                .channel_class
                .as_deref()
                .is_none_or(|channel_class| channel_class == channel)
        });
        let amount = if matched {
            budget_debit_amount(budget.dimension, send_like)
        } else {
            0
        };
        states.push(BudgetRowState {
            row_index,
            budget,
            usage,
            amount,
            matched,
        });
    }
    Ok(states)
}

fn budget_read_from_states(
    key_id: &EntityId,
    record: &ConnectorKeyRecord,
    states: &[BudgetRowState<'_>],
) -> EffectorBudgetRead {
    EffectorBudgetRead {
        key_ref: *key_id,
        connector: record.connector.clone(),
        status: record.status,
        rows: states
            .iter()
            .map(|state| budget_row_read(state.row_index, state.budget, &state.usage))
            .collect(),
    }
}

/// Evaluates and (only when every matched row passes) debits a key's budget
/// rows for one admitted external effect. Evaluate-all-then-apply-all across
/// the key/compiled union: an exhausted outcome applies NO debits. The charge
/// carries the full post-debit meter read, the matched row indices, and the
/// ladder events fired by this charge (GOV-02, ONE-1418).
pub(crate) fn charge_effector_budgets(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    key_id: &EntityId,
    key: &mut ConnectorKeyRecord,
    effect_channel: &str,
    send_like: bool,
    now: u64,
) -> Result<EffectorBudgetChargeOutcome> {
    let mut states = load_budget_row_states(
        store,
        wtxn,
        key_id,
        key,
        Some(effect_channel),
        send_like,
        now,
    )?;
    let matched_rows: Vec<u16> = states
        .iter()
        .filter(|state| state.matched)
        .map(|state| state.row_index)
        .collect();

    if matched_rows.is_empty() {
        let read = budget_read_from_states(key_id, key, &states);
        return Ok(EffectorBudgetChargeOutcome::NoRows(EffectorBudgetCharge {
            key_ref: *key_id,
            sends_debit: 0,
            read,
            matched_rows,
            ladder_events: Vec::new(),
        }));
    }

    // Evaluate ALL matched rows before applying ANY debit; report the first
    // exceeding row in ascending row-index order (key rows before compiled).
    let exhausted = states.iter().find(|state| {
        if !state.matched {
            return false;
        }
        let used = state.usage.used();
        match state.budget.dimension {
            // Spend debits 0 at admission and refuses when already exhausted.
            EffectorBudgetDimension::Spend => used >= state.budget.limit,
            _ => used.saturating_add(state.amount) > state.budget.limit,
        }
    });
    if let Some(state) = exhausted {
        let row_index = state.row_index;
        let on_exhaust = state.budget.on_exhaust;
        // Carry-read-only (M5b resolution 2026-07-10): the exhaustion path
        // fires NO new ladder events and persists nothing — the signal
        // history rides the read's `fired_thresholds`.
        let read = budget_read_from_states(key_id, key, &states);
        return Ok(EffectorBudgetChargeOutcome::Exhausted {
            row_index,
            on_exhaust,
            charge: EffectorBudgetCharge {
                key_ref: *key_id,
                sends_debit: 0,
                read,
                matched_rows,
                ladder_events: Vec::new(),
            },
        });
    }

    let mut sends_debit = 0;
    let mut ladder_events = Vec::new();
    for state in states.iter_mut().filter(|state| state.matched) {
        if state.amount > 0 {
            state.usage.entries.push((now, state.amount));
            if state.budget.dimension == EffectorBudgetDimension::Sends {
                sends_debit = 1;
            }
        }
        // Fire ladder thresholds crossed by the post-debit usage, once per
        // window per row (persisted in `fired`). Spend rows advance only via
        // settlement — spend-ladder signals are an explicit v1 non-goal (M3b).
        if state.budget.dimension != EffectorBudgetDimension::Spend {
            let percent = percent_used(state.usage.used(), state.budget.limit);
            for threshold in [
                BudgetThreshold::Silent50,
                BudgetThreshold::Plan80,
                BudgetThreshold::Land95,
            ] {
                let name = budget_threshold_fired_name(threshold);
                if percent >= threshold.percent()
                    && !state.usage.fired.iter().any(|fired| fired == name)
                {
                    state.usage.fired.push(name.to_owned());
                    // Each event carries the row that fired it: a dispatch
                    // matching several rows can cross the same threshold on
                    // more than one, and the consumer must be able to tell
                    // "sends at 80%" from "rate at 80%".
                    ladder_events.push(BudgetLadderEvent {
                        threshold,
                        steering: effector_steering_signal(threshold),
                        row_index: Some(state.row_index),
                    });
                }
            }
        }
        let usage_key = connector_key_usage_row_key(key_id, state.row_index);
        store
            .vault_meta
            .put(wtxn, &usage_key, &state.usage.encode()?)?;
    }

    let read = budget_read_from_states(key_id, key, &states);
    Ok(EffectorBudgetChargeOutcome::Charged(EffectorBudgetCharge {
        key_ref: *key_id,
        sends_debit,
        read,
        matched_rows,
        ladder_events,
    }))
}

// --- Resolution ---------------------------------------------------------------

fn read_connector_key_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ConnectorKeyRecord>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CONNECTOR_KEY {
        return Err(Error::InvalidEntityType(header.entity_type));
    }
    decode_connector_key_body(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

/// Resolves the connector key governing one effect: within a `(connector,
/// actor_entity_ref)` tuple the non-revoked record wins; the exact actor
/// tuple wins over the actor-agnostic tuple; a revoked-only tuple still
/// resolves (the status wall reports `connector_key_revoked` instead of
/// silently un-governing the connector). `connector` must be normalized.
pub(crate) fn governing_connector_key(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    connector: &str,
    actor_entity_ref: Option<&EntityId>,
) -> Result<Option<(EntityId, ConnectorKeyRecord)>> {
    let Ok(prefix) = connector_key_index_prefix(connector) else {
        // A blank/invalid connector token can never have a registered key.
        return Ok(None);
    };
    let mut candidate_ids = Vec::new();
    for entry in store.vault_meta.prefix_iter(txn, &prefix)? {
        let (key, _) = entry?;
        candidate_ids.push(connector_key_index_entity_id(key, connector)?);
    }

    let mut exact: Vec<(EntityId, ConnectorKeyRecord)> = Vec::new();
    let mut agnostic: Vec<(EntityId, ConnectorKeyRecord)> = Vec::new();
    for id in candidate_ids {
        let record = read_connector_key_in_txn(store, txn, &id)?
            .ok_or(Error::CorruptedIndex("connector key index row"))?;
        match (record.actor_entity_ref.as_ref(), actor_entity_ref) {
            (Some(bound), Some(actor)) if bound == actor => exact.push((id, record)),
            (None, _) => agnostic.push((id, record)),
            _ => {}
        }
    }

    let pick = |hits: Vec<(EntityId, ConnectorKeyRecord)>| {
        let mut revoked_only = None;
        for hit in hits {
            if hit.1.status != ConnectorKeyStatus::Revoked {
                return Some(hit);
            }
            if revoked_only.is_none() {
                revoked_only = Some(hit);
            }
        }
        revoked_only
    };
    if let Some(hit) = pick(exact) {
        return Ok(Some(hit));
    }
    Ok(pick(agnostic))
}

// --- In-txn rewrites -----------------------------------------------------------

/// Rewrites a connector-key entity body in place, preserving the entity
/// header (the `touch_standing_outbound_grant_in_txn` pattern — the connector
/// never changes, so the connector index needs no maintenance).
pub(crate) fn rewrite_connector_key_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    record: &ConnectorKeyRecord,
) -> Result<()> {
    let Some(raw) = store.entities.get(wtxn, id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(raw)
        .ok_or(Error::CorruptedIndex("connector key entity header"))?;
    if header.entity_type != ENTITY_TYPE_CONNECTOR_KEY {
        return Err(Error::CorruptedIndex("connector key entity type"));
    }
    let body = encode_connector_key_body(record)?;
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
    payload.push(ENTITY_TYPE_CONNECTOR_KEY);
    payload.extend_from_slice(&header.occurred_start.to_be_bytes());
    payload.extend_from_slice(&header.occurred_end.to_be_bytes());
    payload.extend_from_slice(&header.learned_at.to_be_bytes());
    payload.extend_from_slice(&body);
    store.entities.put(wtxn, id.as_bytes(), &payload)?;
    Ok(())
}

/// Flips a key to Suspended inside the caller's transaction (used by the gate
/// on exhaust-suspend and by `Vault::suspend_connector_key`).
pub(crate) fn suspend_connector_key_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    record: &ConnectorKeyRecord,
    reason: String,
    at: u64,
) -> Result<ConnectorKeyRecord> {
    let suspended = ConnectorKeyRecord {
        status: ConnectorKeyStatus::Suspended,
        status_changed_at: Some(at),
        suspended_reason: Some(reason),
        ..record.clone()
    };
    rewrite_connector_key_in_txn(store, wtxn, id, &suspended)?;
    Ok(suspended)
}

// --- Receipted lifecycle ops -----------------------------------------------------

fn append_connector_key_op_record(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    op_reason: &'static str,
    record: &ConnectorKeyRecord,
    policy_frontier: [u8; 32],
    at: u64,
) -> Result<()> {
    let body = encode_connector_key_body(record)?;
    let mut hasher = Sha256::new();
    hasher.update(CONNECTOR_KEY_OP_DIFF_DOMAIN);
    hasher.update(&body);
    store.append_gate_decision_in_txn(
        wtxn,
        &GateDecisionRecord {
            version: 0,
            decision_id: GateDecisionId::now(),
            created_at: at,
            outcome: "allow".to_owned(),
            reason_codes: vec![op_reason.to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: "first_party".to_owned(),
            actor_ref: None,
            content_kind: "connector_key_op".to_owned(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            claim_id: None,
            grant_ref: Some(format!("ckey:{}", id.to_hex())),
            diff_handle: hasher.finalize().to_vec(),
            read_frontier_hash: policy_frontier,
        },
    )
}

// --- Vault registry API -----------------------------------------------------------

impl Vault {
    /// Registers a connector key. Rejects a second non-revoked key for the
    /// same `(connector, actor_entity_ref)` tuple, a non-Active status, and a
    /// pre-stamped charter (a charter must enter via the receipted
    /// propose/approve pair, never via register).
    pub fn register_connector_key(
        &self,
        id: &EntityId,
        record: ConnectorKeyRecord,
    ) -> Result<ConnectorKeyRecord> {
        let mut record = record;
        record.connector = normalize_connector_key(&record.connector);
        for budget in &mut record.budgets {
            if let Some(channel_class) = budget.channel_class.take() {
                budget.channel_class = Some(normalize_connector_key(&channel_class));
            }
        }
        record.validate()?;
        if record.status != ConnectorKeyStatus::Active {
            return Err(invalid_body("registration requires status active"));
        }
        if record.charter.is_some() || record.pending_charter.is_some() {
            return Err(invalid_body("registration must not carry a charter"));
        }

        let data = encode_connector_key_body(&record)?;
        let mut wtxn = self.store.env.write_txn()?;
        if self.store.entities.get(&wtxn, id.as_bytes())?.is_some() {
            return Err(Error::ConnectorKeyAlreadyExists);
        }
        let prefix = connector_key_index_prefix(&record.connector)?;
        let mut sibling_ids = Vec::new();
        for entry in self.store.vault_meta.prefix_iter(&wtxn, &prefix)? {
            let (key, _) = entry?;
            sibling_ids.push(connector_key_index_entity_id(key, &record.connector)?);
        }
        for sibling_id in sibling_ids {
            let sibling = read_connector_key_in_txn(&self.store, &wtxn, &sibling_id)?
                .ok_or(Error::CorruptedIndex("connector key index row"))?;
            if sibling.status != ConnectorKeyStatus::Revoked
                && sibling.actor_entity_ref == record.actor_entity_ref
            {
                return Err(Error::ConnectorKeyAlreadyExists);
            }
        }

        self.apply_connector_key_body(&mut wtxn, id, record.registered_at, data)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.register",
            &record,
            policy.read_frontier_hash()?,
            record.registered_at,
        )?;
        wtxn.commit()?;
        Ok(record)
    }

    /// Reads and decodes a connector-key record.
    pub fn get_connector_key(&self, id: &EntityId) -> Result<Option<ConnectorKeyRecord>> {
        let rtxn = self.store.env.read_txn()?;
        read_connector_key_in_txn(&self.store, &rtxn, id)
    }

    /// The `self.*` effector-meter read (ARCHPASS A3): resolves the governing
    /// key and computes each row's live usage at `now` — no debit, no
    /// threshold firing, no usage-row writes. Liveness (window rollover,
    /// rolling prune/re-arm) is computed on the read, never stored. Rows
    /// include the key budget rows and, when a charter is stamped (GOV-10),
    /// the compiled-cap rows at `0x8000 | i`.
    pub fn effector_budget_read(
        &self,
        connector: &str,
        actor_entity_ref: Option<&EntityId>,
    ) -> Result<Option<EffectorBudgetRead>> {
        let rtxn = self.store.env.read_txn()?;
        let Some((key_id, record)) = governing_connector_key(
            &self.store,
            &rtxn,
            &normalize_connector_key(connector),
            actor_entity_ref,
        )?
        else {
            return Ok(None);
        };
        let now = crate::unix_seconds_now();
        let states =
            load_budget_row_states(&self.store, &rtxn, &key_id, &record, None, false, now)?;
        Ok(Some(budget_read_from_states(&key_id, &record, &states)))
    }

    /// Resolves the key governing `(connector, actor_entity_ref)` (read-txn
    /// wrapper over the gate's resolution order).
    pub fn connector_key_for(
        &self,
        connector: &str,
        actor_entity_ref: Option<&EntityId>,
    ) -> Result<Option<(EntityId, ConnectorKeyRecord)>> {
        let rtxn = self.store.env.read_txn()?;
        governing_connector_key(
            &self.store,
            &rtxn,
            &normalize_connector_key(connector),
            actor_entity_ref,
        )
    }

    /// Suspends an Active key (owner op).
    pub fn suspend_connector_key(
        &self,
        id: &EntityId,
        reason: &str,
        at: u64,
    ) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status != ConnectorKeyStatus::Active {
            return Err(invalid_body("illegal status transition"));
        }
        let suspended = suspend_connector_key_in_txn(
            &self.store,
            &mut wtxn,
            id,
            &record,
            reason.to_owned(),
            at,
        )?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.suspend",
            &suspended,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(suspended)
    }

    /// Resumes a Suspended key. Deliberately does NOT clear usage rows: the
    /// window state is truth — if the window has not rolled, the next send
    /// re-exhausts and re-suspends (correct hard-cap behavior).
    pub fn resume_connector_key(&self, id: &EntityId, at: u64) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status != ConnectorKeyStatus::Suspended {
            return Err(invalid_body("illegal status transition"));
        }
        let resumed = ConnectorKeyRecord {
            status: ConnectorKeyStatus::Active,
            status_changed_at: Some(at),
            suspended_reason: None,
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &resumed)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.resume",
            &resumed,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(resumed)
    }

    /// Revokes a key (terminal) from any non-revoked state.
    pub fn revoke_connector_key(&self, id: &EntityId, at: u64) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("illegal status transition"));
        }
        let revoked = ConnectorKeyRecord {
            status: ConnectorKeyStatus::Revoked,
            status_changed_at: Some(at),
            suspended_reason: None,
            // Revocation is terminal: drop any staged proposal so a revoked
            // key carries no mutable charter state (approve/discard also gate
            // on Revoked below).
            pending_charter: None,
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &revoked)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.revoke",
            &revoked,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(revoked)
    }

    /// Settles actual engine-recorded spend into a Spend row (v1 settle-only
    /// accounting; costs are never client-asserted). If the settle crosses
    /// the limit on an `on_exhaust: Suspend` row and the key is Active, the
    /// key flips Suspended in the same transaction. No retroactive refusal —
    /// the effect already occurred; the NEXT admission refuses.
    ///
    /// Two different times are deliberately kept apart. `cost_occurred_at`
    /// is the DECLARED fact — when the provider cost happened, legitimately
    /// lagging, recorded first-writer-wins in the settlement-event row and
    /// never consulted for accounting (nor for replay identity). Which budget window the debit lands in, the
    /// usage-entry chronology, and any suspension stamp all take the ENGINE
    /// clock at settle time, unconditionally: the record says when the cost
    /// happened; the ledger says when we learned of it. A caller-picked
    /// timestamp therefore cannot select, roll, or clear any window.
    pub fn settle_connector_spend(
        &self,
        id: &EntityId,
        row_index: u16,
        minor_units: u64,
        cost_occurred_at: u64,
        event_ref: &str,
    ) -> Result<EffectorBudgetRowRead> {
        if event_ref.trim().is_empty() {
            return Err(invalid_body("settle event_ref must not be blank"));
        }
        if event_ref.len() > CONNECTOR_KEY_SETTLE_EVENT_REF_MAX_LEN {
            return Err(invalid_body("settle event_ref too long"));
        }
        if event_ref.as_bytes().contains(&0) {
            return Err(invalid_body("settle event_ref must not contain NUL"));
        }
        // A zero-amount settlement records nothing and would only grow the
        // usage entry log; entry counts stay bounded by the row limit.
        if minor_units == 0 {
            return Err(invalid_body("settle amount must be at least 1"));
        }
        let settled_at = crate::unix_seconds_now();

        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        let budget = if row_index & CONNECTOR_KEY_CHARTER_ROW_BASE == 0 {
            record.budgets.get(usize::from(row_index))
        } else {
            record.charter.as_ref().and_then(|charter| {
                charter
                    .compiled
                    .channel_caps
                    .get(usize::from(row_index & !CONNECTOR_KEY_CHARTER_ROW_BASE))
            })
        };
        let Some(budget) = budget.cloned() else {
            return Err(invalid_body("spend settle on missing row"));
        };
        if budget.dimension != EffectorBudgetDimension::Spend {
            return Err(invalid_body("spend settle on non-spend row"));
        }

        let usage_key = connector_key_usage_row_key(id, row_index);
        let mut usage = match self.store.vault_meta.get(&wtxn, &usage_key)? {
            Some(bytes) => ConnectorKeyUsage::decode(bytes)?,
            None => ConnectorKeyUsage::default(),
        };

        // Idempotency keyed on the settlement's CONTENT (row, amount): a
        // replayed event id with the same content settles nothing — even
        // when the declared cost time drifted between honest retry attempts
        // (the first write's recorded time stands) — while the same event id
        // with a DIFFERENT (row, amount) fails closed, so a pre-claimed
        // event_ref cannot force a silent no-op for a different settlement.
        let event_key = connector_key_settle_event_key(id, event_ref);
        let event_value = settle_event_value(row_index, minor_units, cost_occurred_at);
        if let Some(stored) = self.store.vault_meta.get(&wtxn, &event_key)? {
            if stored.len() < SETTLE_EVENT_IDENTITY_LEN
                || stored[..SETTLE_EVENT_IDENTITY_LEN] != event_value[..SETTLE_EVENT_IDENTITY_LEN]
            {
                return Err(invalid_body(
                    "settle event replay with different settlement",
                ));
            }
            // Read-only echo of the row's current state; nothing is written.
            usage.touch(&budget.window, budget.limit, settled_at);
            return Ok(budget_row_read(row_index, &budget, &usage));
        }

        usage.touch(&budget.window, budget.limit, settled_at);
        usage.entries.push((settled_at, minor_units));
        self.store
            .vault_meta
            .put(&mut wtxn, &event_key, &event_value)?;
        self.store
            .vault_meta
            .put(&mut wtxn, &usage_key, &usage.encode()?)?;

        let mut settled_record = record;
        if usage.used() >= budget.limit
            && budget.on_exhaust == EffectorBudgetOnExhaust::Suspend
            && settled_record.status == ConnectorKeyStatus::Active
        {
            let reason = budget_exhausted_reason(row_index);
            settled_record = suspend_connector_key_in_txn(
                &self.store,
                &mut wtxn,
                id,
                &settled_record,
                reason,
                settled_at,
            )?;
        }

        let row_read = budget_row_read(row_index, &budget, &usage);
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.spend_settle",
            &settled_record,
            policy.read_frontier_hash()?,
            settled_at,
        )?;
        wtxn.commit()?;
        Ok(row_read)
    }

    /// Compiles and STAGES a charter proposal (GOV-10). Never changes
    /// enforcement — that is the human gate. Overwrites a previous pending
    /// proposal; the receipt trail records both.
    pub fn propose_connector_charter(
        &self,
        id: &EntityId,
        text: &str,
        proposed_at: u64,
    ) -> Result<PendingConnectorCharter> {
        let compiled = compile_connector_charter(text).map_err(Error::from)?;
        let normalized = text.replace("\r\n", "\n");
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("charter op on revoked key"));
        }
        let pending = PendingConnectorCharter {
            text: normalized,
            text_hash: compiled.text_hash,
            compiled: compiled.compiled,
            compiled_hash: compiled.compiled_hash,
            proposed_at,
        };
        let proposed = ConnectorKeyRecord {
            pending_charter: Some(pending.clone()),
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &proposed)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.charter_propose",
            &proposed,
            policy.read_frontier_hash()?,
            proposed_at,
        )?;
        wtxn.commit()?;
        Ok(pending)
    }

    /// The human gate (GOV-10): applies the staged compile iff the caller
    /// re-presents its compiled hash out-of-band, and stamps the aggregate
    /// binding text + compiled policy. Clears every compiled-cap usage row
    /// (`0x8000 | *`) in the same txn — compiled-cap usage is keyed
    /// positionally, so a re-stamped charter must never inherit the old
    /// charter's usage at the same indices or leave orphaned rows.
    ///
    /// There is deliberately NO single-call compile-and-activate API; which
    /// callers may invoke `approve` is host-surface policy (the same trust
    /// boundary as every owner Vault op) — in-engine the gate is the
    /// propose/approve split plus the receipt trail.
    pub fn approve_connector_charter(
        &self,
        id: &EntityId,
        expected_compiled_hash: [u8; 32],
        stamped_by: &str,
        stamped_at: u64,
    ) -> Result<ConnectorKeyRecord> {
        if stamped_by.trim().is_empty() {
            return Err(invalid_body("stamped_by must not be blank"));
        }
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("charter op on revoked key"));
        }
        let Some(pending) = record.pending_charter.clone() else {
            return Err(Error::ConnectorCharterMissing);
        };
        if pending.compiled_hash != expected_compiled_hash {
            return Err(Error::ConnectorCharterApprovalMismatch);
        }
        let stamped = ConnectorKeyRecord {
            charter: Some(ConnectorCharterBlock {
                stamped_aggregate: charter_stamped_aggregate(
                    &pending.text_hash,
                    &pending.compiled_hash,
                ),
                text: pending.text,
                text_hash: pending.text_hash,
                compiled: pending.compiled,
                compiled_hash: pending.compiled_hash,
                stamped_by: stamped_by.to_owned(),
                stamped_at,
            }),
            pending_charter: None,
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &stamped)?;
        delete_charter_usage_rows_in_txn(&self.store, &mut wtxn, id)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.charter_approve",
            &stamped,
            policy.read_frontier_hash()?,
            stamped_at,
        )?;
        wtxn.commit()?;
        Ok(stamped)
    }

    /// Owner rejection of a staged charter compile (GOV-10): clears the
    /// pending proposal, receipted. Enforcement was never changed by it.
    pub fn discard_connector_charter(&self, id: &EntityId, at: u64) -> Result<ConnectorKeyRecord> {
        let mut wtxn = self.store.env.write_txn()?;
        let record =
            read_connector_key_in_txn(&self.store, &wtxn, id)?.ok_or(Error::EntityNotFound)?;
        if record.status == ConnectorKeyStatus::Revoked {
            return Err(invalid_body("charter op on revoked key"));
        }
        if record.pending_charter.is_none() {
            return Err(Error::ConnectorCharterMissing);
        }
        let discarded = ConnectorKeyRecord {
            pending_charter: None,
            ..record
        };
        rewrite_connector_key_in_txn(&self.store, &mut wtxn, id, &discarded)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &wtxn)?;
        append_connector_key_op_record(
            &self.store,
            &mut wtxn,
            id,
            "gate.connector_key.charter_discard",
            &discarded,
            policy.read_frontier_hash()?,
            at,
        )?;
        wtxn.commit()?;
        Ok(discarded)
    }

    fn apply_connector_key_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        learned_at: u64,
        data: Vec<u8>,
    ) -> Result<()> {
        let new_record = decode_connector_key_body(&data)?;
        let new_index_key = connector_key_index_key(&new_record.connector, id)?;
        let old_index_key = if let Some(raw) = self.store.entities.get(&*wtxn, id.as_bytes())? {
            let Some(header) = EntityMetadataHeader::parse(raw) else {
                return Err(Error::CorruptedIndex("connector key entity header"));
            };
            if header.entity_type != ENTITY_TYPE_CONNECTOR_KEY {
                return Err(Error::CorruptedIndex("connector key entity type"));
            }
            let old_record = decode_connector_key_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            Some(connector_key_index_key(&old_record.connector, id)?)
        } else {
            None
        };
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_CONNECTOR_KEY,
                occurred: TimeRange {
                    start: learned_at,
                    end: learned_at,
                },
                learned_at,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        if let Some(old_index_key) = old_index_key.as_ref()
            && old_index_key != &new_index_key
        {
            self.store.vault_meta.delete(wtxn, old_index_key)?;
        }
        self.store.vault_meta.put(wtxn, &new_index_key, &[])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
