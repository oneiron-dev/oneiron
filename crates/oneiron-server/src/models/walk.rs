//! What one call met on the rungs of its ladder before an answer: each rung
//! it passed over and why, the receipt's `passed_over`.
use std::collections::BTreeMap;

use oneiron::LlmError;
use serde_json::{Value as JsonValue, json};

use super::cooldown::Rest;
use super::ladder::LadderRung;

/// Why a call did not answer from a rung it passed: the receipt's
/// `passed_over`. `sent` says the rung went out: one its backend refused
/// before sending was never charged.
pub(super) enum Passed {
    /// It refused for a quota or a limit, and rests until its reset (none
    /// when nothing keeps rests).
    Refused {
        kind: &'static str,
        rest: Option<Rest>,
        sent: bool,
    },
    /// It failed another way, of this closed class.
    Failed { kind: &'static str, sent: bool },
    /// It rests from an earlier refusal until then.
    Resting { until: u64 },
    /// A fallback to it would take the work off the device, and the call's
    /// world stays on it.
    KeptOnDevice,
}

/// What one call met on the rungs it passed before an answer.
#[derive(Default)]
pub(super) struct Walk {
    pub(super) passed: Vec<(usize, Passed)>,
    pub(super) last: Option<LlmError>,
    /// When a call that waited for its first offer back woke: that offer is
    /// back then, whatever the clock reads. Zero until it waits.
    pub(super) woke: u64,
}

impl Walk {
    /// Records what the call met on the rung at `index`, unless that is the
    /// state the rung was last found in.
    pub(super) fn note(&mut self, index: usize, passed: Passed) {
        let same = self
            .latest()
            .get(&index)
            .is_some_and(|last| last.same_state(&passed));
        if !same {
            self.passed.push((index, passed));
        }
    }

    /// The state each rung was last found in.
    fn latest(&self) -> BTreeMap<usize, &Passed> {
        self.passed
            .iter()
            .map(|(index, passed)| (*index, passed))
            .collect()
    }

    /// The rungs that went out and failed: each was charged on its own permit.
    pub(super) fn went_out(&self) -> usize {
        self.passed
            .iter()
            .filter(|(_, passed)| {
                matches!(
                    passed,
                    Passed::Refused { sent: true, .. } | Passed::Failed { sent: true, .. }
                )
            })
            .count()
    }

    /// The earliest time a rung the call may use is back from its rest, and
    /// the first rung back then. Each rung counts as it was last found: a
    /// later refusal supersedes an earlier reset, and a rung the call has
    /// since kept the work from counts no more.
    pub(super) fn back(&self) -> Option<(usize, u64)> {
        self.latest()
            .into_iter()
            .filter_map(|(index, passed)| Some((index, passed.back()?)))
            .min_by_key(|(_, back)| *back)
    }

    /// Each rung the call passed before its answer, and why: the offer it
    /// refused and the end of its rest, one it found resting, one it kept the
    /// work from. Config names and closed codes only.
    pub(super) fn passed_over(&self, rungs: &[LadderRung]) -> JsonValue {
        self.passed
            .iter()
            .map(|(index, passed)| {
                let rung = &rungs[*index];
                let mut row = json!({
                    "rung": rung.position,
                    "provider": rung.provider,
                    "model": rung.wire_model,
                });
                match passed {
                    Passed::Refused { kind, rest, .. } => {
                        row["passed"] = json!("refused");
                        row["class"] = json!(kind);
                        if let Some(rest) = rest {
                            row["cooldown_until"] = json!(rest.until);
                            row["reset"] = json!(rest.source.as_str());
                        }
                    }
                    Passed::Failed { kind, .. } => {
                        row["passed"] = json!("failed");
                        row["class"] = json!(kind);
                    }
                    Passed::Resting { until } => {
                        row["passed"] = json!("cooling_down");
                        row["cooldown_until"] = json!(until);
                    }
                    Passed::KeptOnDevice => row["passed"] = json!("kept_on_device"),
                }
                row
            })
            .collect()
    }

    /// Whether every rung the call could use rests: none it passed failed
    /// but by a limit refusal.
    pub(super) fn limited(&self) -> bool {
        !self
            .passed
            .iter()
            .any(|(_, passed)| matches!(passed, Passed::Failed { .. }))
    }
}

impl Passed {
    /// When a rung passed for a limit is back in rotation.
    pub(super) fn back(&self) -> Option<u64> {
        match self {
            Self::Resting { until } => Some(*until),
            Self::Refused {
                rest: Some(rest), ..
            } => Some(rest.until),
            _ => None,
        }
    }

    /// Whether a rung passed unsent as `found` is as the call last found
    /// it: kept from the work, or resting until the same end. A rung that
    /// was sent is always news.
    fn same_state(&self, found: &Self) -> bool {
        match found {
            Self::KeptOnDevice => matches!(self, Self::KeptOnDevice),
            Self::Resting { until } => self.back() == Some(*until),
            Self::Refused { .. } | Self::Failed { .. } => false,
        }
    }
}
