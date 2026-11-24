//! The screen of an agent's pin (pass 34, `34-compute-general/DESIGN.md`
//! section 6.5): rung 1 of the pin's check-in, in mode `auto`, for a pin no
//! `compute.pin` grant covers. It puts one typed question to the host's
//! decision ladder, the path `ai.verdict` takes, and it only chooses between
//! go and ask: it never grants. It runs before the pin door's writer, so no
//! transaction spans a model call.
//!
//! With no model, or on a model error, R2's deterministic fallback decides
//! ([`fallback_is_sure`]). A network pin outside a grant always asks; the
//! screen's verdict rides on its record as a recommendation.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::EntityId;

use super::record::{JOB_WORKLOADS, JobWorkload, PinCheckInOutcome};
use super::{NetworkMode, ResourceRequest, ScopeKind, WorkloadPin};

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

/// The screen: the host's decision ladder behind one question.
pub trait WorkloadScreen {
    /// The ladder's answer for a pin with `signals`.
    ///
    /// # Errors
    ///
    /// Any failure, including "no model available": the deterministic
    /// fallback decides then.
    fn screen(&self, signals: &PinSignals) -> crate::Result<ScreenVerdict>;
}

/// No decision model: every screen fails, so the deterministic fallback
/// decides.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoScreenModel;

impl WorkloadScreen for NoScreenModel {
    fn screen(&self, _signals: &PinSignals) -> crate::Result<ScreenVerdict> {
        Err(crate::Error::InvalidConfig(
            "no decision model screens workload pins here".into(),
        ))
    }
}

/// Who answered a pin's screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScreenSource {
    /// The host's decision ladder.
    Model,
    /// The deterministic fallback, when no model answered.
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
    /// Why no model answered, when the fallback decided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_failure: Option<String>,
}

impl PinScreen {
    /// The record of `answer`, or of the fallback's decision on `signals`
    /// when the screen failed.
    #[must_use]
    pub(super) fn of(answer: crate::Result<ScreenVerdict>, signals: &PinSignals) -> Self {
        match answer {
            Ok(verdict) => Self {
                sure: verdict.sure,
                by: ScreenSource::Model,
                probability_permille: verdict.probability_permille,
                rung: verdict.rung,
                receipt: verdict.receipt,
                model_failure: None,
            },
            Err(error) => Self {
                sure: fallback_is_sure(signals),
                by: ScreenSource::Fallback,
                probability_permille: None,
                rung: None,
                receipt: None,
                model_failure: Some(error.to_string()),
            },
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
/// disk, maximum, the number of devices, and each device's memory against
/// the largest an earlier claim named (0, any device, is the largest).
fn request_within(asked: &ResourceRequest, earlier: &ResourceRequest) -> bool {
    let count = |request: &ResourceRequest| -> u64 {
        request
            .devices
            .iter()
            .map(|claim| u64::from(claim.count))
            .sum()
    };
    let largest =
        earlier
            .devices
            .iter()
            .map(|claim| claim.memory_mib)
            .fold(Some(0), |most, mib| match (most, mib) {
                (None, _) | (_, 0) => None,
                (Some(most), mib) => Some(most.max(mib)),
            });
    asked.cpu_threads <= earlier.cpu_threads
        && asked.memory_mib <= earlier.memory_mib
        && asked.disk_mib <= earlier.disk_mib
        && asked.maximum_secs <= earlier.maximum_secs
        && count(asked) <= count(earlier)
        && asked.devices.iter().all(|claim| match largest {
            None => true,
            Some(largest) => claim.memory_mib != 0 && claim.memory_mib <= largest,
        })
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
