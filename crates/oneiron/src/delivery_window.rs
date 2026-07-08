//! Delivery-window policy claims and evaluator for OF-327 O3.
//!
//! The `delivery_window.*` family is deliberately interrupt-only: async writes
//! stay deliverable, while interrupt-class verbs are held or reshaped.

use rmpv::Value;

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    claim_generated_origin,
};
use crate::error::{Error, Result};

pub const DELIVERY_WINDOW_SCHEMA_VERSION: u64 = 1;

pub const PREDICATE_DELIVERY_WINDOW_QUIET: &str = "delivery_window.quiet";
pub const PREDICATE_DELIVERY_WINDOW_CONTEXT: &str = "delivery_window.context";
pub const PREDICATE_DELIVERY_WINDOW_CHANNEL: &str = "delivery_window.channel";

pub const DELIVERY_WINDOW_CLAIM_PREDICATES: [&str; 3] = [
    PREDICATE_DELIVERY_WINDOW_QUIET,
    PREDICATE_DELIVERY_WINDOW_CONTEXT,
    PREDICATE_DELIVERY_WINDOW_CHANNEL,
];

const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_APPLIES_TO: &str = "applies_to";
const KEY_WINDOW: &str = "window";
const KEY_START_MINUTE: &str = "start_minute";
const KEY_END_MINUTE: &str = "end_minute";
const KEY_TZ: &str = "tz";
const KEY_WHEN: &str = "when";
const KEY_CHANNEL: &str = "channel";
const KEY_REASON: &str = "reason";

const MAX_REASON_BYTES: usize = 128;
const MAX_CHANNEL_BYTES: usize = 128;
const MINUTES_PER_DAY: u16 = 24 * 60;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum DeliveryWindowDecision {
    #[default]
    DeliverNow,
    DeliverNowWithApnsCap {
        reason: String,
        from: String,
        to: String,
    },
    Hold {
        reason: String,
        retry_at: Option<u64>,
    },
    Degrade {
        reason: String,
        from: String,
        to: String,
    },
    LetGo {
        reason: String,
    },
}

impl DeliveryWindowDecision {
    pub(crate) fn policy_trace(&self) -> String {
        match self {
            Self::DeliverNow => "delivery_window.no_restriction".to_owned(),
            Self::DeliverNowWithApnsCap { reason, .. } => {
                format!("delivery_window.apns_cap:{reason}")
            }
            Self::Hold { reason, .. } => format!("delivery_window.hold:{reason}"),
            Self::Degrade { reason, .. } => format!("delivery_window.degrade:{reason}"),
            Self::LetGo { reason } => format!("delivery_window.let_go:{reason}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryWindowVerbClass {
    Ambient,
    Interrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryWindowAppliesTo {
    Interrupt,
}

impl DeliveryWindowAppliesTo {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "interrupt" => Some(Self::Interrupt),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryWindowContextCondition {
    CalendarBusy,
    FocusOn,
    Driving,
    Asleep,
}

impl DeliveryWindowContextCondition {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CalendarBusy => "calendar_busy",
            Self::FocusOn => "focus_on",
            Self::Driving => "driving",
            Self::Asleep => "asleep",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "calendar_busy" => Some(Self::CalendarBusy),
            "focus_on" => Some(Self::FocusOn),
            "driving" => Some(Self::Driving),
            "asleep" => Some(Self::Asleep),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryWindowApnsInterruptionLevel {
    Passive,
    Active,
    TimeSensitive,
    Critical,
}

impl DeliveryWindowApnsInterruptionLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passive => "passive",
            Self::Active => "active",
            Self::TimeSensitive => "time_sensitive",
            Self::Critical => "critical",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "passive" => Some(Self::Passive),
            "active" => Some(Self::Active),
            "time_sensitive" | "time-sensitive" => Some(Self::TimeSensitive),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    #[must_use]
    pub const fn companion_ceiling(self) -> Self {
        match self {
            Self::Critical => Self::TimeSensitive,
            other => other,
        }
    }

    #[must_use]
    pub const fn quiet_window_degrade(self) -> Self {
        match self.companion_ceiling() {
            Self::TimeSensitive => Self::Active,
            Self::Active => Self::Passive,
            Self::Passive => Self::Passive,
            Self::Critical => Self::Active,
        }
    }

    #[must_use]
    pub fn push_label(self) -> String {
        format!("push:{}", self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryWindowTimeWindow {
    pub start_minute: u16,
    pub end_minute: u16,
}

impl DeliveryWindowTimeWindow {
    pub fn new(start_minute: u16, end_minute: u16) -> Result<Self> {
        if start_minute >= MINUTES_PER_DAY || end_minute >= MINUTES_PER_DAY {
            return Err(invalid_claim(
                "delivery_window window minutes must be < 1440",
            ));
        }
        if start_minute == end_minute {
            return Err(invalid_claim(
                "delivery_window window start and end must differ",
            ));
        }
        Ok(Self {
            start_minute,
            end_minute,
        })
    }

    #[must_use]
    pub fn contains(self, local_minute_of_day: u16) -> bool {
        if local_minute_of_day >= MINUTES_PER_DAY {
            return false;
        }
        if self.start_minute < self.end_minute {
            local_minute_of_day >= self.start_minute && local_minute_of_day < self.end_minute
        } else {
            local_minute_of_day >= self.start_minute || local_minute_of_day < self.end_minute
        }
    }

    #[must_use]
    pub fn retry_at_after(self, delivery_epoch_secs: u64, local_minute_of_day: u16) -> Option<u64> {
        if !self.contains(local_minute_of_day) {
            return None;
        }
        let minutes_until_end = if self.start_minute < self.end_minute {
            self.end_minute.saturating_sub(local_minute_of_day)
        } else if local_minute_of_day >= self.start_minute {
            MINUTES_PER_DAY
                .saturating_sub(local_minute_of_day)
                .saturating_add(self.end_minute)
        } else {
            self.end_minute.saturating_sub(local_minute_of_day)
        };
        Some(delivery_epoch_secs.saturating_add(u64::from(minutes_until_end) * 60))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryWindowPolicyClaim {
    pub predicate: String,
    pub applies_to: DeliveryWindowAppliesTo,
    pub channel: Option<String>,
    pub window: Option<DeliveryWindowTimeWindow>,
    pub context: Option<DeliveryWindowContextCondition>,
    pub reason: String,
    pub approval: ClaimApprovalStatus,
    pub lifecycle: ClaimLifecycleStatus,
    pub source: Option<ClaimSource>,
    pub generated_origin: bool,
    pub valid_from: Option<u64>,
    pub valid_to: Option<u64>,
    pub stale: bool,
}

impl DeliveryWindowPolicyClaim {
    pub fn from_claim_body(body: &ClaimBody) -> Result<Self> {
        validate_delivery_window_claim_structure(body)?;
        let entries = value_map(&body.value)?;
        let applies_to = DeliveryWindowAppliesTo::parse(required_str(entries, KEY_APPLIES_TO)?)
            .ok_or_else(|| invalid_claim("delivery_window applies_to must be interrupt"))?;
        let reason = optional_str(entries, KEY_REASON)?
            .map(str::to_owned)
            .unwrap_or_else(|| default_reason(&body.predicate).to_owned());
        let (channel, window, context) = match body.predicate.as_str() {
            PREDICATE_DELIVERY_WINDOW_QUIET => (
                None,
                Some(decode_time_window(required_value(entries, KEY_WINDOW)?)?),
                None,
            ),
            PREDICATE_DELIVERY_WINDOW_CONTEXT => (
                None,
                None,
                Some(
                    DeliveryWindowContextCondition::parse(required_str(entries, KEY_WHEN)?)
                        .ok_or_else(|| invalid_claim("delivery_window when value is unknown"))?,
                ),
            ),
            PREDICATE_DELIVERY_WINDOW_CHANNEL => (
                Some(normalize_channel_key(required_str(entries, KEY_CHANNEL)?)),
                optional_value(entries, KEY_WINDOW)?
                    .map(decode_time_window)
                    .transpose()?,
                None,
            ),
            _ => unreachable!("predicate membership checked above"),
        };

        Ok(Self {
            predicate: body.predicate.clone(),
            applies_to,
            channel,
            window,
            context,
            reason,
            approval: body.approval,
            lifecycle: body.lifecycle,
            source: body.source,
            generated_origin: claim_generated_origin(body),
            valid_from: body.valid_from,
            valid_to: body.valid_to,
            stale: body.stale,
        })
    }

    fn restriction_at(&self, context: &DeliveryWindowEvaluationContext) -> Option<Restriction> {
        if !matches!(
            self.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        ) || self.lifecycle != ClaimLifecycleStatus::Active
            || self.stale
        {
            return None;
        }
        if self.approval == ClaimApprovalStatus::Auto && self.generated_origin {
            return None;
        }
        if self.applies_to != DeliveryWindowAppliesTo::Interrupt {
            return None;
        }
        if context.verb_class != DeliveryWindowVerbClass::Interrupt {
            return None;
        }
        if let Some(valid_from) = self.valid_from
            && context.delivery_epoch_secs < valid_from
        {
            return None;
        }
        if let Some(valid_to) = self.valid_to
            && context.delivery_epoch_secs >= valid_to
        {
            return None;
        }
        if let Some(channel) = self.channel.as_deref()
            && context.channel.as_deref() != Some(channel)
        {
            return None;
        }
        if let Some(condition) = self.context
            && !context.active_contexts.contains(&condition)
        {
            return None;
        }
        let retry_at = if let Some(window) = self.window {
            window.retry_at_after(context.delivery_epoch_secs, context.local_minute_of_day)?
        } else {
            0
        };
        Some(Restriction {
            predicate: self.predicate.clone(),
            reason: self.reason.clone(),
            retry_at: if self.window.is_some() {
                Some(retry_at)
            } else {
                None
            },
            source: self.source,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryWindowEvaluationContext {
    pub delivery_epoch_secs: u64,
    local_minute_of_day: u16,
    pub verb_class: DeliveryWindowVerbClass,
    pub channel: Option<String>,
    pub active_contexts: Vec<DeliveryWindowContextCondition>,
    pub interrupt_surface: Option<String>,
    pub degrade_to: Option<String>,
    pub apns_interruption_level: Option<DeliveryWindowApnsInterruptionLevel>,
}

impl DeliveryWindowEvaluationContext {
    pub fn new(
        delivery_epoch_secs: u64,
        local_minute_of_day: u16,
        verb_class: DeliveryWindowVerbClass,
    ) -> Result<Self> {
        if local_minute_of_day >= MINUTES_PER_DAY {
            return Err(invalid_claim(
                "delivery_window local minute of day must be < 1440",
            ));
        }
        Ok(Self {
            delivery_epoch_secs,
            local_minute_of_day,
            verb_class,
            channel: None,
            active_contexts: Vec::new(),
            interrupt_surface: None,
            degrade_to: None,
            apns_interruption_level: None,
        })
    }

    #[must_use]
    pub const fn local_minute_of_day(&self) -> u16 {
        self.local_minute_of_day
    }

    #[must_use]
    pub fn channel(mut self, channel: impl Into<String>) -> Self {
        let channel = channel.into();
        self.channel = Some(normalize_channel_key(&channel));
        self
    }

    #[must_use]
    pub fn active_context(mut self, condition: DeliveryWindowContextCondition) -> Self {
        if !self.active_contexts.contains(&condition) {
            self.active_contexts.push(condition);
        }
        self
    }

    #[must_use]
    pub fn interrupt_surface(mut self, surface: impl Into<String>) -> Self {
        self.interrupt_surface = Some(surface.into());
        self
    }

    #[must_use]
    pub fn degrade_to(mut self, surface: impl Into<String>) -> Self {
        self.degrade_to = Some(surface.into());
        self
    }

    #[must_use]
    pub fn apns_interruption_level(mut self, level: DeliveryWindowApnsInterruptionLevel) -> Self {
        self.apns_interruption_level = Some(level);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Restriction {
    predicate: String,
    reason: String,
    retry_at: Option<u64>,
    source: Option<ClaimSource>,
}

pub struct DeliveryWindowEvaluator;

impl DeliveryWindowEvaluator {
    #[must_use]
    pub fn evaluate(
        context: &DeliveryWindowEvaluationContext,
        claims: &[DeliveryWindowPolicyClaim],
    ) -> DeliveryWindowDecision {
        if context.local_minute_of_day >= MINUTES_PER_DAY {
            return invalid_context_decision(context);
        }

        let restrictions = claims
            .iter()
            .filter_map(|claim| claim.restriction_at(context))
            .collect::<Vec<_>>();

        if restrictions.is_empty() {
            return apns_ceiling_decision(context).unwrap_or(DeliveryWindowDecision::DeliverNow);
        }

        let selected = most_restrictive_restriction(&restrictions)
            .expect("non-empty restrictions have a selected restriction");
        if let Some(level) = context.apns_interruption_level {
            let to = level.quiet_window_degrade();
            if level != to {
                return DeliveryWindowDecision::Degrade {
                    reason: selected.reason.clone(),
                    from: level.push_label(),
                    to: to.push_label(),
                };
            }
            if selected.retry_at.is_some() {
                return DeliveryWindowDecision::DeliverNow;
            }
        }
        if let Some(to) = context.degrade_to.as_ref() {
            return DeliveryWindowDecision::Degrade {
                reason: selected.reason.clone(),
                from: context
                    .interrupt_surface
                    .clone()
                    .unwrap_or_else(|| "interrupt".to_owned()),
                to: to.clone(),
            };
        }

        DeliveryWindowDecision::Hold {
            reason: selected.reason.clone(),
            retry_at: selected.retry_at,
        }
    }
}

fn invalid_context_decision(context: &DeliveryWindowEvaluationContext) -> DeliveryWindowDecision {
    if context.verb_class == DeliveryWindowVerbClass::Interrupt {
        DeliveryWindowDecision::Hold {
            reason: "invalid_local_minute".to_owned(),
            retry_at: None,
        }
    } else {
        DeliveryWindowDecision::DeliverNow
    }
}

#[must_use]
pub fn is_delivery_window_claim_predicate(predicate: &str) -> bool {
    DELIVERY_WINDOW_CLAIM_PREDICATES.contains(&predicate)
}

pub(crate) fn validate_delivery_window_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(invalid_claim(
            "delivery_window claim subject must be an entity",
        ));
    }
    if !is_delivery_window_claim_predicate(&body.predicate) {
        return Err(invalid_claim("unknown delivery_window claim predicate"));
    }
    let entries = value_map(&body.value)?;
    require_schema_version(entries)?;
    let applies_to = required_str(entries, KEY_APPLIES_TO)?;
    if DeliveryWindowAppliesTo::parse(applies_to) != Some(DeliveryWindowAppliesTo::Interrupt) {
        return Err(invalid_claim(
            "delivery_window applies_to must be interrupt",
        ));
    }
    if let Some(reason) = optional_str(entries, KEY_REASON)?
        && (reason.is_empty() || reason.len() > MAX_REASON_BYTES)
    {
        return Err(invalid_claim("delivery_window reason is invalid"));
    }

    match body.predicate.as_str() {
        PREDICATE_DELIVERY_WINDOW_QUIET => {
            validate_keys_for_predicate(
                entries,
                &[
                    KEY_SCHEMA_VERSION,
                    KEY_APPLIES_TO,
                    KEY_WINDOW,
                    KEY_TZ,
                    KEY_REASON,
                ],
            )?;
            let window = required_value(entries, KEY_WINDOW)?;
            decode_time_window(window)?;
            if let Some(tz) = optional_str(entries, KEY_TZ)?
                && tz != "user-local"
            {
                return Err(invalid_claim("delivery_window tz is invalid"));
            }
            Ok(())
        }
        PREDICATE_DELIVERY_WINDOW_CONTEXT => {
            validate_keys_for_predicate(
                entries,
                &[KEY_SCHEMA_VERSION, KEY_APPLIES_TO, KEY_WHEN, KEY_REASON],
            )?;
            let when = required_str(entries, KEY_WHEN)?;
            DeliveryWindowContextCondition::parse(when)
                .map(|_| ())
                .ok_or_else(|| invalid_claim("delivery_window when value is unknown"))
        }
        PREDICATE_DELIVERY_WINDOW_CHANNEL => {
            validate_keys_for_predicate(
                entries,
                &[
                    KEY_SCHEMA_VERSION,
                    KEY_APPLIES_TO,
                    KEY_CHANNEL,
                    KEY_WINDOW,
                    KEY_REASON,
                ],
            )?;
            let channel = required_str(entries, KEY_CHANNEL)?;
            let normalized_channel = normalize_channel_key(channel);
            if normalized_channel.is_empty() || normalized_channel.len() > MAX_CHANNEL_BYTES {
                return Err(invalid_claim("delivery_window channel is invalid"));
            }
            if let Some(window) = optional_value(entries, KEY_WINDOW)? {
                decode_time_window(window)?;
            }
            Ok(())
        }
        _ => unreachable!("predicate membership checked above"),
    }
}

fn apns_ceiling_decision(
    context: &DeliveryWindowEvaluationContext,
) -> Option<DeliveryWindowDecision> {
    let level = context.apns_interruption_level?;
    let capped = level.companion_ceiling();
    (level != capped).then(|| DeliveryWindowDecision::DeliverNowWithApnsCap {
        reason: "apns_time_sensitive_ceiling".to_owned(),
        from: level.push_label(),
        to: capped.push_label(),
    })
}

fn most_restrictive_restriction(restrictions: &[Restriction]) -> Option<&Restriction> {
    restrictions
        .iter()
        .max_by(|left, right| restriction_rank(left).cmp(&restriction_rank(right)))
}

fn restriction_rank(restriction: &Restriction) -> (bool, u64, u8, &str, &str) {
    (
        restriction.retry_at.is_none(),
        restriction.retry_at.unwrap_or(0),
        source_priority(restriction.source),
        restriction.predicate.as_str(),
        restriction.reason.as_str(),
    )
}

const fn source_priority(source: Option<ClaimSource>) -> u8 {
    match source {
        Some(ClaimSource::UserStated) => 2,
        Some(_) => 1,
        None => 0,
    }
}

fn default_reason(predicate: &str) -> &'static str {
    match predicate {
        PREDICATE_DELIVERY_WINDOW_QUIET => "quiet_window",
        PREDICATE_DELIVERY_WINDOW_CONTEXT => "context_window",
        PREDICATE_DELIVERY_WINDOW_CHANNEL => "channel_window",
        _ => "restricted",
    }
}

fn normalize_channel_key(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn decode_time_window(value: &Value) -> Result<DeliveryWindowTimeWindow> {
    let entries = value_map(value)?;
    validate_window_keys(entries)?;
    let start = required_u16(entries, KEY_START_MINUTE)?;
    let end = required_u16(entries, KEY_END_MINUTE)?;
    DeliveryWindowTimeWindow::new(start, end)
}

fn value_map(value: &Value) -> Result<&[(Value, Value)]> {
    match value {
        Value::Map(entries) => {
            for (key, _) in entries {
                if key.as_str().is_none() {
                    return Err(invalid_claim("delivery_window value keys must be strings"));
                }
            }
            Ok(entries)
        }
        _ => Err(invalid_claim("delivery_window value must be a map")),
    }
}

fn validate_window_keys(entries: &[(Value, Value)]) -> Result<()> {
    for (key, _) in entries {
        let key = key
            .as_str()
            .expect("delivery_window value_map validates string keys");
        if ![KEY_START_MINUTE, KEY_END_MINUTE].contains(&key) {
            return Err(invalid_claim("delivery_window window has unsupported key"));
        }
    }
    Ok(())
}

fn validate_keys_for_predicate(entries: &[(Value, Value)], allowed: &[&str]) -> Result<()> {
    for (key, _) in entries {
        let key = key
            .as_str()
            .expect("delivery_window value_map validates string keys");
        if !allowed.contains(&key) {
            return Err(invalid_claim(
                "delivery_window value has key outside predicate variant",
            ));
        }
    }
    Ok(())
}

fn require_schema_version(entries: &[(Value, Value)]) -> Result<()> {
    match required_value(entries, KEY_SCHEMA_VERSION)?.as_u64() {
        Some(DELIVERY_WINDOW_SCHEMA_VERSION) => Ok(()),
        _ => Err(invalid_claim(
            "delivery_window schema_version is unsupported",
        )),
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    optional_value(entries, key)?.ok_or_else(|| invalid_claim("delivery_window value missing key"))
}

fn optional_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<Option<&'a Value>> {
    let mut found = None;
    for (entry_key, value) in entries {
        if entry_key.as_str() == Some(key) {
            if found.is_some() {
                return Err(invalid_claim("delivery_window value has duplicate key"));
            }
            found = Some(value);
        }
    }
    Ok(found)
}

fn required_str<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    optional_str(entries, key)?
        .ok_or_else(|| invalid_claim("delivery_window value missing string key"))
}

fn optional_str<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<Option<&'a str>> {
    optional_value(entries, key)?
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid_claim("delivery_window value key must be string"))
        })
        .transpose()
}

fn required_u16(entries: &[(Value, Value)], key: &str) -> Result<u16> {
    required_value(entries, key)?
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| invalid_claim("delivery_window minute value is invalid"))
}

fn invalid_claim(message: &'static str) -> Error {
    Error::InvalidClaimBody(message)
}

#[cfg(test)]
mod tests;
