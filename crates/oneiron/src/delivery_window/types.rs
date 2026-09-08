//! Claim predicates, key consts, decision/ladder enums and resolution structs.

use serde::{Deserialize, Serialize};

pub const DELIVERY_WINDOW_SCHEMA_VERSION: u64 = 1;

pub const PREDICATE_DELIVERY_WINDOW_QUIET: &str = "delivery_window.quiet";

pub const PREDICATE_DELIVERY_WINDOW_CONTEXT: &str = "delivery_window.context";

pub const PREDICATE_DELIVERY_WINDOW_CHANNEL: &str = "delivery_window.channel";

pub const DELIVERY_WINDOW_CLAIM_PREDICATES: [&str; 3] = [
    PREDICATE_DELIVERY_WINDOW_QUIET,
    PREDICATE_DELIVERY_WINDOW_CONTEXT,
    PREDICATE_DELIVERY_WINDOW_CHANNEL,
];

pub(super) const KEY_SCHEMA_VERSION: &str = "schema_version";

pub(super) const KEY_APPLIES_TO: &str = "applies_to";

pub(super) const KEY_WINDOW: &str = "window";

pub(super) const KEY_START_MINUTE: &str = "start_minute";

pub(super) const KEY_END_MINUTE: &str = "end_minute";

pub(super) const KEY_TZ: &str = "tz";

pub(super) const KEY_WHEN: &str = "when";

pub(super) const KEY_CHANNEL: &str = "channel";

pub(super) const KEY_REASON: &str = "reason";

pub(super) const MAX_REASON_BYTES: usize = 128;

pub(super) const MAX_CHANNEL_BYTES: usize = 128;

pub(super) const MINUTES_PER_DAY: u16 = 24 * 60;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

/// Host-resolved delivery level for a compatibility verb whose manifest name
/// alone cannot decide the class.
///
/// A connector-level `send` on telegram/line/imessage may resolve either to a
/// plain chat message (ambient: it lands in a thread and interrupts nobody) or
/// to a push (interrupt-class). The ruled contract is "do not guess ambient
/// from the string alone", and [`DeliveryWindowApnsInterruptionLevel`] only
/// carries APNs pushes, so this is the non-APNs carrier the schedule context
/// freezes onto the TASK. Absent, the manifest's interrupt class stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryWindowResolvedLevel {
    /// Resolved to a plain in-thread chat message.
    PlainChat,
    /// Resolved to a push/interrupting surface.
    Push,
}

impl DeliveryWindowResolvedLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlainChat => "plain_chat",
            Self::Push => "push",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "plain_chat" | "plain-chat" => Some(Self::PlainChat),
            "push" => Some(Self::Push),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_plain_chat(self) -> bool {
        matches!(self, Self::PlainChat)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DeliveryWindowLadderRung {
    HumanExplicitInstant,
    Ambient,
    InterruptDegraded,
    InterruptHeld,
    MissingLocalMinute,
}

impl DeliveryWindowLadderRung {
    /// The stable receipt string for this rung. Receipts render rungs ONLY
    /// through this map, so no out-of-enum rung name can reach an audit row.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HumanExplicitInstant => "human_explicit_instant",
            Self::Ambient => "ambient",
            Self::InterruptDegraded => "interrupt_degraded",
            Self::InterruptHeld => "interrupt_held",
            Self::MissingLocalMinute => "missing_local_minute",
        }
    }
}

/// Evidence retained from every live policy match, even when execution takes a higher rung.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeliveryWindowMatch {
    pub predicate: String,
    pub reason: String,
    pub retry_at: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeliveryWindowResolution {
    pub observed: DeliveryWindowDecision,
    pub effective: DeliveryWindowDecision,
    pub matched: Vec<DeliveryWindowMatch>,
    pub rung: DeliveryWindowLadderRung,
}

impl DeliveryWindowResolution {
    /// The fail-closed resolution for an interrupt-class send whose local
    /// wall-clock minute is unknown (hostless schedule): the live window
    /// claims cannot be evaluated, so the send holds rather than guessing.
    /// The unevaluable claims still ride along as retained evidence.
    #[must_use]
    pub fn missing_local_minute(matched: Vec<DeliveryWindowMatch>) -> Self {
        let hold = DeliveryWindowDecision::Hold {
            reason: MISSING_LOCAL_MINUTE_REASON.to_owned(),
            retry_at: None,
        };
        Self {
            effective: hold.clone(),
            observed: hold,
            matched,
            rung: DeliveryWindowLadderRung::MissingLocalMinute,
        }
    }
}

/// Receipt/hold reason for a send whose local minute never reached the door.
pub const MISSING_LOCAL_MINUTE_REASON: &str = "local_minute_unavailable";
