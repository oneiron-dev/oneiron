//! What one call met on the rungs of its ladder before an answer: each rung
//! it passed over and why, the receipt's `passed_over`, and the closed class
//! of each failure it met.
use std::collections::BTreeMap;

use oneiron::{FatalLlmError, LlmError};
use serde_json::{Value as JsonValue, json};

use super::cooldown::{ResetSource, Rest};
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
    /// Its provider was down (a server error, a timeout, a cut stream, an
    /// empty answer), and it rests for its health until then (none when
    /// nothing keeps rests).
    Down {
        kind: &'static str,
        rest: Option<Rest>,
        sent: bool,
    },
    /// It failed another way, of this closed class.
    Failed { kind: &'static str, sent: bool },
    /// It rests from an earlier refusal, as kept.
    Resting { rest: Rest },
    /// A fallback to it would take the work off the device, and the call's
    /// world stays on it.
    KeptOnDevice,
    /// It does not hold the call's voice (FIX 1746): its target held no live
    /// binding of the banked voice when the call was admitted, or holds it
    /// no more, or the call's stock or raw voice is another rung's.
    VoiceNotHeld,
    /// It is on probation after its provider was down, and its one
    /// probation request is out (OF-305), seen at health version `seen`.
    ProbeInFlight { seen: u64 },
}

/// What one call met on the rungs it passed before an answer.
#[derive(Default)]
pub(super) struct Walk {
    pub(super) passed: Vec<(usize, Passed)>,
    pub(super) last: Option<LlmError>,
}

impl Walk {
    /// Records what the call met on the rung at `index`, unless that is the
    /// state the rung was last found in, which it then refreshes. Whether it
    /// was news.
    pub(super) fn note(&mut self, index: usize, passed: Passed) -> bool {
        if let Some((_, last)) = self.passed.iter_mut().rev().find(|(at, _)| *at == index)
            && last.same_state(&passed)
        {
            *last = passed;
            return false;
        }
        self.passed.push((index, passed));
        true
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
                    Passed::Refused { sent: true, .. }
                        | Passed::Down { sent: true, .. }
                        | Passed::Failed { sent: true, .. }
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
                    Passed::Down { kind, rest, .. } => {
                        row["passed"] = json!("failed");
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
                    Passed::Resting { rest } => {
                        row["passed"] = json!("cooling_down");
                        row["cooldown_until"] = json!(rest.until);
                    }
                    Passed::KeptOnDevice => row["passed"] = json!("kept_on_device"),
                    Passed::VoiceNotHeld => row["passed"] = json!("voice_not_held"),
                    Passed::ProbeInFlight { .. } => row["passed"] = json!("probation_busy"),
                }
                row
            })
            .collect()
    }

    /// Whether the call was ever kept from the rung at `index`.
    pub(super) fn held_from(&self, index: usize) -> bool {
        self.passed
            .iter()
            .any(|(at, passed)| *at == index && matches!(passed, Passed::KeptOnDevice))
    }

    /// Whether the call was last kept from some rung: a fallback to it would
    /// have taken the work off the device.
    pub(super) fn kept(&self) -> bool {
        self.latest()
            .values()
            .any(|passed| matches!(passed, Passed::KeptOnDevice))
    }

    /// Each rung of `rungs` with the rest it was last found in, when every
    /// one is parked: resting, or refused for a limit and resting since. A
    /// rung the call kept the work from, or one that does not hold its
    /// voice, counts as neither; one it never reached, or one that failed
    /// another way, means not every rung parked. `None` too when none
    /// rests.
    pub(super) fn parked(&self, rungs: usize) -> Option<Vec<(usize, Rest)>> {
        let latest = self.latest();
        let mut parked = Vec::new();
        for index in 0..rungs {
            match latest.get(&index)? {
                Passed::Refused {
                    rest: Some(rest), ..
                }
                | Passed::Down {
                    rest: Some(rest), ..
                }
                | Passed::Resting { rest } => parked.push((index, *rest)),
                Passed::KeptOnDevice | Passed::VoiceNotHeld => {}
                Passed::Refused { rest: None, .. }
                | Passed::Down { rest: None, .. }
                | Passed::Failed { .. }
                | Passed::ProbeInFlight { .. } => return None,
            }
        }
        (!parked.is_empty()).then_some(parked)
    }

    /// Whether every rung the call last found resting rests for its health
    /// alone, or is on probation with its request out: an outage, not a
    /// limit, so the call ends with the provider's own failure rather than a
    /// rate refusal. False when none rests or probes.
    pub(super) fn outage(&self) -> bool {
        let mut any = false;
        for passed in self.latest().into_values() {
            let health = match passed {
                Passed::Down {
                    rest: Some(rest), ..
                }
                | Passed::Refused {
                    rest: Some(rest), ..
                }
                | Passed::Resting { rest } => rest.source == ResetSource::Unhealthy,
                Passed::ProbeInFlight { .. } => true,
                _ => continue,
            };
            if !health {
                return false;
            }
            any = true;
        }
        any
    }

    /// The first rung the call last found with its probation request out,
    /// and the earliest health version any such rung was seen at: a wait for
    /// that request's end starts from there.
    pub(super) fn probing(&self) -> Option<(usize, u64)> {
        let latest = self.latest();
        let mut found = latest.iter().filter_map(|(index, passed)| match passed {
            Passed::ProbeInFlight { seen } => Some((*index, *seen)),
            _ => None,
        });
        let first = found.next()?;
        Some(found.fold(first, |(index, low), (_, seen)| (index, low.min(seen))))
    }

    /// Whether every rung the call could use rests: none it passed failed
    /// but by a limit refusal or an outage it rests for.
    pub(super) fn limited(&self) -> bool {
        !self.passed.iter().any(|(_, passed)| {
            matches!(
                passed,
                Passed::Failed { .. } | Passed::Down { rest: None, .. }
            )
        })
    }
}

impl Passed {
    /// When a rung passed for a limit is back in rotation.
    pub(super) fn back(&self) -> Option<u64> {
        match self {
            Self::Resting { rest } => Some(rest.until),
            Self::Refused {
                rest: Some(rest), ..
            }
            | Self::Down {
                rest: Some(rest), ..
            } => Some(rest.until),
            _ => None,
        }
    }

    /// Whether a rung passed unsent as `found` is as the call last found
    /// it: kept from the work, without the call's voice, or resting until
    /// the same end. A rung that
    /// was sent is always news.
    fn same_state(&self, found: &Self) -> bool {
        match found {
            Self::KeptOnDevice => matches!(self, Self::KeptOnDevice),
            Self::VoiceNotHeld => matches!(self, Self::VoiceNotHeld),
            Self::ProbeInFlight { .. } => matches!(self, Self::ProbeInFlight { .. }),
            Self::Resting { rest } => self.back() == Some(rest.until),
            Self::Refused { .. } | Self::Down { .. } | Self::Failed { .. } => false,
        }
    }
}

/// The closed class of a rung failure. An unsupported capability's reason is
/// a provider's own words, so the log carries the class and not the error.
pub(super) fn failure_kind(error: &LlmError) -> &'static str {
    use oneiron::RetryableLlmError;
    use oneiron::llm::BudgetDenied;
    match error {
        LlmError::Retryable(RetryableLlmError::RateLimited { .. }) => "rate_limited",
        LlmError::Retryable(RetryableLlmError::QuotaSpent { .. }) => "quota_spent",
        LlmError::Retryable(RetryableLlmError::ServerError) => "server_error",
        LlmError::Retryable(RetryableLlmError::Timeout) => "timeout",
        LlmError::Retryable(RetryableLlmError::StreamCut) => "stream_cut",
        LlmError::Retryable(RetryableLlmError::KeptOnDevice { .. }) => "kept_on_device",
        LlmError::Fatal(FatalLlmError::InvalidRequest) => "invalid_request",
        LlmError::Fatal(FatalLlmError::Auth) => "auth",
        LlmError::Fatal(FatalLlmError::ContentFiltered) => "content_filtered",
        LlmError::Fatal(FatalLlmError::EmptyResponse) => "empty_response",
        LlmError::Fatal(FatalLlmError::Unsupported(_)) => "unsupported",
        LlmError::Fatal(FatalLlmError::LabelRead(_)) => "label_read",
        LlmError::BudgetDenied(BudgetDenied::Exhausted) => "budget_exhausted",
        LlmError::BudgetDenied(BudgetDenied::LeaseInvalid) => "lease_invalid",
        LlmError::BudgetDenied(BudgetDenied::AdmissionDenied) => "admission_denied",
    }
}

/// Whether a rung failure says its provider is down, not that the request
/// or its credentials are wrong: a server error, a timeout, a cut stream or
/// an empty answer. Its offer rests for its health (OF-305).
pub(super) fn provider_down(error: &LlmError) -> bool {
    error.is_provider_unavailable()
}

/// A failure that ends the call as it came: the request itself failed (a
/// 400, filtered content, a capability it needs), so the next offer would
/// fail it too, or the run refused it, so the next rung's admission meets the
/// same line. Every other failure hands the call on.
pub(super) fn ends_call(error: &LlmError) -> bool {
    matches!(
        error,
        LlmError::Fatal(
            FatalLlmError::InvalidRequest
                | FatalLlmError::ContentFiltered
                | FatalLlmError::Unsupported(_)
        ) | LlmError::BudgetDenied(_)
    )
}
