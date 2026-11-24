//! The AFTER slot's default rule, `typed_retry@1` (pass 34, 4.7): what follows an attempt's end.
//! A retry is a new attempt of the same order under a new key; the old key is never sent again
//! (I1). The end cause cuts the options, and the counts and the backoff come from the setting
//! `jobs.retry`. A backoff waits as the blocker `RetryNotBefore`, like any waiting order.
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::setting::SettingValue;

use super::record::{EndKind, SlotDecision, SlotName, WorkOrder};

/// The AFTER rule's name and version, as a decision records it.
pub const AFTER_RULE: &str = "typed_retry@1";

/// The most retries one rule of `jobs.retry` may allow.
pub const RETRY_COUNT_MAX: u8 = 32;

/// How many times one class of end is retried, and how long the loop waits first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetryRule {
    /// Retries after the first attempt of this class; 0 never retries.
    pub count: u8,
    /// The wait before the first retry, in milliseconds.
    pub backoff_ms: u64,
    /// Whether each further retry waits twice as long as the one before.
    pub doubling: bool,
}

/// The value of `jobs.retry`: per class of end, its count and backoff. Every class not named
/// here gives up or is decided by the end itself (a success is done, a cancel gives up, a
/// closed attempt continues).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicy {
    /// Ends of zero seconds that never started: a refusal, a busy device, a node restart before
    /// launch. The queue working.
    pub never_started: RetryRule,
    /// The start window passed with nothing accepted.
    pub expired: RetryRule,
    /// Started, seconds unknown (a lost machine). The engine default never retries it: the
    /// lead or the owner decides.
    pub lost: RetryRule,
    /// A failure the order's own `retry_on` lists (a nonzero exit, a limit).
    pub on_request: RetryRule,
}

impl Default for RetryPolicy {
    /// Pass 34's table 4.7: 3 retries of a zero-second end, 30 s then doubling; one retry of an
    /// expired window; no retry of a lost machine; one retry of a failure the order lists.
    fn default() -> Self {
        Self {
            never_started: RetryRule {
                count: 3,
                backoff_ms: 30_000,
                doubling: true,
            },
            expired: RetryRule {
                count: 1,
                backoff_ms: 30_000,
                doubling: false,
            },
            lost: RetryRule {
                count: 0,
                backoff_ms: 30_000,
                doubling: false,
            },
            on_request: RetryRule {
                count: 1,
                backoff_ms: 30_000,
                doubling: false,
            },
        }
    }
}

impl SettingValue for RetryPolicy {
    const CLOSED: bool = true;

    fn check(self) -> Result<Self> {
        for (name, rule) in [
            ("never_started", self.never_started),
            ("expired", self.expired),
            ("lost", self.lost),
            ("on_request", self.on_request),
        ] {
            if rule.count > RETRY_COUNT_MAX {
                return Err(Error::InvalidConfig(format!(
                    "jobs.retry.{name}.count is at most {RETRY_COUNT_MAX}"
                )));
            }
        }
        Ok(self)
    }
}

/// What the AFTER slot decided for an order whose last attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterPick {
    Done,
    RetryNow,
    /// Retry once this time has passed.
    RetryAt(u64),
    GiveUp,
}

impl AfterPick {
    const fn option(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::RetryNow => "retry_now",
            Self::RetryAt(_) => "retry_at",
            Self::GiveUp => "give_up",
        }
    }
}

/// Which retry rule an end draws on, when any.
fn retry_class(end: EndKind, order: &WorkOrder, policy: &RetryPolicy) -> Option<RetryRule> {
    match end {
        EndKind::NeverStarted => Some(policy.never_started),
        EndKind::Expired => Some(policy.expired),
        EndKind::Lost => Some(policy.lost),
        EndKind::Exited { code } if code != 0 && order.retry_on.contains(&end) => {
            Some(policy.on_request)
        }
        EndKind::MemoryLimit | EndKind::DiskLimit | EndKind::TimeLimit
            if order.retry_on.contains(&end) =>
        {
            Some(policy.on_request)
        }
        _ => None,
    }
}

/// Whether two ends draw on the same retry rule, so they count against one count.
fn same_class(a: EndKind, b: EndKind) -> bool {
    let class = |end: EndKind| match end {
        EndKind::NeverStarted => 0,
        EndKind::Expired => 1,
        EndKind::Lost => 2,
        EndKind::Exited { .. } | EndKind::MemoryLimit | EndKind::DiskLimit | EndKind::TimeLimit => 3,
        _ => 4,
    };
    class(a) == class(b)
}

/// `typed_retry@1` on the end `end` of `order`'s last attempt at `now_ms`: the lawful options
/// the end allows and the rule's pick, recorded as the slot's decision.
#[must_use]
pub fn after_rule(
    order: &WorkOrder,
    end: EndKind,
    policy: &RetryPolicy,
    now_ms: u64,
) -> (AfterPick, SlotDecision) {
    let (options, pick, why): (&[&str], AfterPick, String) = match end {
        EndKind::Exited { code: 0 } => (&["done"], AfterPick::Done, "it succeeded".to_owned()),
        EndKind::Closed => (
            &["retry_now", "give_up"],
            AfterPick::RetryNow,
            "a closed attempt continues as the next attempt".to_owned(),
        ),
        EndKind::WrittenOff => (
            &["give_up"],
            AfterPick::GiveUp,
            "the owner wrote it off: nothing starts again unless somebody orders again"
                .to_owned(),
        ),
        EndKind::LaunchRefusedChanged | EndKind::Revoked | EndKind::Stopped => (
            &["give_up"],
            AfterPick::GiveUp,
            "this end is never retried".to_owned(),
        ),
        _ => {
            let options: &[&str] = match end {
                EndKind::NeverStarted => &["retry_now", "retry_at", "give_up"],
                _ => &["retry_at", "give_up"],
            };
            match retry_class(end, order, policy) {
                None => (
                    &["give_up"],
                    AfterPick::GiveUp,
                    "a deterministic failure is not retried unless the order lists it".to_owned(),
                ),
                Some(rule) => {
                    // The ends of this class before the last one.
                    let earlier = order
                        .attempts
                        .iter()
                        .rev()
                        .skip(1)
                        .filter_map(|attempt| attempt.end.as_ref())
                        .filter(|ended| same_class(ended.kind, end))
                        .count();
                    let earlier = u32::try_from(earlier).unwrap_or(u32::MAX);
                    if earlier >= u32::from(rule.count) {
                        (
                            options,
                            AfterPick::GiveUp,
                            format!("{} retries of this end are used", rule.count),
                        )
                    } else {
                        let factor = if rule.doubling {
                            1_u64.checked_shl(earlier).unwrap_or(u64::MAX)
                        } else {
                            1
                        };
                        let wait = rule.backoff_ms.saturating_mul(factor);
                        (
                            options,
                            AfterPick::RetryAt(now_ms.saturating_add(wait)),
                            format!("retry {} of {} after {wait} ms", earlier + 1, rule.count),
                        )
                    }
                }
            }
        }
    };
    let decision = SlotDecision::by_rule(
        SlotName::After,
        AFTER_RULE,
        options.iter().map(|option| (*option).to_owned()).collect(),
        pick.option().to_owned(),
        &why,
    );
    (pick, decision)
}
