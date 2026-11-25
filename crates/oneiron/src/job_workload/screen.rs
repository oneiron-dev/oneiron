//! The screen of an agent's pin (pass 34, `34-compute-general/DESIGN.md`
//! section 6.5): rung 1 of the pin's check-in, in mode `auto`, for a pin no
//! `compute.pin` grant covers. It puts one typed question to the host's
//! decision ladder, the path `ai.verdict` takes, and it only chooses between
//! go and ask: it never grants. It runs before the pin door's writer, so no
//! transaction spans a model call.
//!
//! With no decision model on the host, R2's deterministic fallback decides
//! ([`fallback_is_sure`]); a model that fails or abstains is unsure, so the
//! pin asks. A network pin outside a grant always asks; the screen's verdict
//! rides on its record as a recommendation.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::EntityId;

use super::record::{JOB_WORKLOADS, JobWorkload, PinCheckInOutcome};
use super::{DeviceClaim, NetworkMode, ResourceRequest, ScopeKind, WorkloadPin};

/// What the screen reads about one pin: the pin's own facts and the signals
/// the owner named, against the earlier pins of the same Grant (its family)
/// that were let go and not revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PinSignals {
    pub template: String,
    pub network: NetworkMode,
    /// `host` or `container`.
    pub scope: String,
    pub request: ResourceRequest,
    /// How many of the family's pins were let go and are not revoked.
    pub family_pins: u32,
    /// The family's pins name this template at this commit.
    pub template_and_commit_pinned_before: bool,
    /// The family pinned this template before under another template digest:
    /// the template changed.
    pub template_changed: bool,
    /// An earlier pin of this template and commit asked at least as much on
    /// every axis.
    pub within_earlier_request: bool,
}

/// What the screen answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenVerdict {
    /// Sure: the pin goes. Unsure: it asks.
    pub sure: bool,
    /// P(sure), in thousandths, where the ladder gave one.
    pub probability_permille: Option<u16>,
    /// The rung that answered.
    pub rung: Option<String>,
    /// The decision's receipt: its question id (hex).
    pub receipt: Option<String>,
}

/// What the screen answered, or why it gave no verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScreenAnswer {
    /// The ladder answered: sure goes, unsure asks.
    Verdict(ScreenVerdict),
    /// No decision model on this host takes the question (none is bound, or
    /// none answers its contract): the deterministic fallback decides.
    NoModel { why: String },
    /// A model was asked and gave no verdict (an error, a refusal, the
    /// deadline): the pin asks.
    Failed { why: String },
}

/// The screen: the host's decision ladder behind one question.
pub trait WorkloadScreen {
    /// The ladder's answer for a pin with `signals`.
    fn screen(&self, signals: &PinSignals) -> ScreenAnswer;
}

/// No decision model on the host: the deterministic fallback decides every
/// screen.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoScreenModel;

impl WorkloadScreen for NoScreenModel {
    fn screen(&self, _signals: &PinSignals) -> ScreenAnswer {
        ScreenAnswer::NoModel {
            why: "no decision model screens workload pins here".to_owned(),
        }
    }
}

/// Who answered a pin's screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScreenSource {
    /// The host's decision ladder.
    Model,
    /// The deterministic fallback, when no model on the host takes the
    /// question.
    Fallback,
}

/// A pin's screen, as its record keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PinScreen {
    pub sure: bool,
    pub by: ScreenSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probability_permille: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rung: Option<String>,
    /// The `ai.verdict` receipt: the decision's question id (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
    /// Why no model gave a verdict: none on the host takes the question (the
    /// fallback decided), or the one asked failed (the pin asks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_failure: Option<String>,
}

impl PinScreen {
    /// The record of `answer`: the model's verdict; the fallback's decision
    /// on `signals` when no model takes the question; unsure when the model
    /// asked failed.
    #[must_use]
    pub(super) fn of(answer: ScreenAnswer, signals: &PinSignals) -> Self {
        let unanswered = |sure, by, why| Self {
            sure,
            by,
            probability_permille: None,
            rung: None,
            receipt: None,
            model_failure: Some(why),
        };
        match answer {
            ScreenAnswer::Verdict(verdict) => Self {
                sure: verdict.sure,
                by: ScreenSource::Model,
                probability_permille: verdict.probability_permille,
                rung: verdict.rung,
                receipt: verdict.receipt,
                model_failure: None,
            },
            ScreenAnswer::NoModel { why } => {
                unanswered(fallback_is_sure(signals), ScreenSource::Fallback, why)
            }
            ScreenAnswer::Failed { why } => unanswered(false, ScreenSource::Model, why),
        }
    }
}

/// R2's deterministic fallback (DESIGN 6.5): sure only when the pin has no
/// network, the family pinned this template at this commit before, the
/// template did not change, and an earlier pin asked at least as much. The
/// pin is inside the agent's own Grant already: the door checked the power.
#[must_use]
pub fn fallback_is_sure(signals: &PinSignals) -> bool {
    signals.network == NetworkMode::None
        && signals.template_and_commit_pinned_before
        && !signals.template_changed
        && signals.within_earlier_request
}

/// Whether `asked` asks no more than `earlier` on any axis: threads, memory,
/// disk, maximum, and its devices ([`devices_within`]).
fn request_within(asked: &ResourceRequest, earlier: &ResourceRequest) -> bool {
    asked.cpu_threads <= earlier.cpu_threads
        && asked.memory_mib <= earlier.memory_mib
        && asked.disk_mib <= earlier.disk_mib
        && asked.maximum_secs <= earlier.maximum_secs
        && devices_within(&asked.devices, &earlier.devices)
}

/// Whether each device `asked` claims takes its own device of `earlier`: of
/// the same kind, features and sharing, with at least its memory (0, any
/// device, counts as the most), no earlier device serving two.
fn devices_within(asked: &[DeviceClaim], earlier: &[DeviceClaim]) -> bool {
    asked.iter().all(|claim| {
        let same = |other: &&DeviceClaim| same_device_class(other, claim);
        memory_fits(
            &device_runs(asked.iter().filter(same)),
            &device_runs(earlier.iter().filter(same)),
        )
    })
}

/// Whether two claims ask for the same class of device: kind, features (as
/// a set) and sharing.
fn same_device_class(one: &DeviceClaim, other: &DeviceClaim) -> bool {
    let features = |claim: &DeviceClaim| {
        claim
            .features
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
    };
    one.kind == other.kind && one.sharing == other.sharing && features(one) == features(other)
}

/// The devices of `claims` as runs of (memory per device, how many), most
/// memory first; a claim of any device (0) counts as the most.
fn device_runs<'a>(claims: impl Iterator<Item = &'a DeviceClaim>) -> Vec<(u64, u64)> {
    let mut runs: Vec<(u64, u64)> = claims
        .map(|claim| {
            let memory = if claim.memory_mib == 0 {
                u64::MAX
            } else {
                claim.memory_mib
            };
            (memory, u64::from(claim.count))
        })
        .collect();
    runs.sort_unstable_by_key(|run| std::cmp::Reverse(run.0));
    runs
}

/// Whether the asked devices, most memory first, each take the next earlier
/// device, most memory first, with at least as much memory: a matching of
/// each asked device to its own earlier one exists exactly then.
fn memory_fits(asked: &[(u64, u64)], earlier: &[(u64, u64)]) -> bool {
    let mut earlier = earlier.iter().copied();
    let mut held: Option<(u64, u64)> = None;
    for &(needed, mut count) in asked {
        while count > 0 {
            let (memory, left) = match held.take() {
                Some(run) if run.1 > 0 => run,
                _ => match earlier.next() {
                    Some(run) => run,
                    None => return false,
                },
            };
            if memory < needed {
                return false;
            }
            let taken = left.min(count);
            count -= taken;
            held = Some((memory, left - taken));
        }
    }
    true
}

/// Whether `row`'s pin was let go (by its check-in or the owner's approval)
/// and is not revoked: an earlier pin the family may lean on.
fn let_go(row: &JobWorkload) -> bool {
    row.revoked.is_none()
        && (row.approval.is_some()
            || matches!(
                row.check_in.as_ref().map(|check_in| &check_in.outcome),
                Some(PinCheckInOutcome::Went { .. })
            ))
}

/// The screen's signals for `pin`, a new pin under `grant`, read in `txn`.
///
/// # Errors
///
/// Storage errors.
pub(super) fn pin_signals_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    grant: EntityId,
    pin: &WorkloadPin,
) -> crate::Result<PinSignals> {
    let mut signals = PinSignals {
        template: pin.template.clone(),
        network: pin.network,
        scope: match pin.scope {
            ScopeKind::Host => "host",
            ScopeKind::Container { .. } => "container",
        }
        .to_owned(),
        request: pin.request.clone(),
        family_pins: 0,
        template_and_commit_pinned_before: false,
        template_changed: false,
        within_earlier_request: false,
    };
    for (_, row) in JOB_WORKLOADS.scan(&vault.store, txn)? {
        if row.pinned_under != Some(grant) || !let_go(&row) {
            continue;
        }
        signals.family_pins = signals.family_pins.saturating_add(1);
        if row.pin.template != pin.template {
            continue;
        }
        if row.pin.template_digest != pin.template_digest {
            signals.template_changed = true;
            continue;
        }
        if row.pin.commit == pin.commit {
            signals.template_and_commit_pinned_before = true;
            if request_within(&pin.request, &row.pin.request) {
                signals.within_earlier_request = true;
            }
        }
    }
    Ok(signals)
}
