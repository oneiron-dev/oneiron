//! `vault.consolidation.wake.status` (DOOR-144 B): the typed wake read beside
//! `vault.consolidation.status`. One page of what one wake pass recorded of
//! itself ([`Vault::dreamer_wake_observation`]), addressed by an attempt or by
//! a pass, in wire shapes: ids as hex, node ids as decimal strings, step
//! hashes as 64 hex, a lease id as the diagnostic it is (never a capability).
//! The read is the caller's own Memory read, as its sibling's is; it names no
//! owner proof and scans nothing it was not addressed to.

use serde::{Deserialize, Serialize};

use super::support::hex_string;
use super::{Memory, MemoryError, MemoryResult, parse_job_ref};
use crate::dreamer_wake::{
    WAKE_OBSERVATION_PAGE_MAX, WakeCallState, WakeObservation, WakeObservationCursor,
    WakeObservationRequest, WakeObservationSelector, WakeObservedCall, WakeObservedCheckpoint,
    WakeObservedGeneration, WakeRef,
};
use crate::entity_id::EntityId;
use crate::llm::BudgetLeaseState;

/// The input: an attempt's observation (`job_ref`, with `wake_ref` naming
/// the pass whose generation to read, else its latest), or one pass's
/// (`wake_ref` alone). A page carries 50 rows unless `limit` names others,
/// and never more than 500; `cursor` is the previous page's `next_cursor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationWakeStatusRequest {
    /// The attempt, as 32 hex (`vault.consolidation.enqueue`'s `job_ref`).
    #[serde(default)]
    pub job_ref: Option<String>,
    /// The wake pass, as 32 hex.
    #[serde(default)]
    pub wake_ref: Option<String>,
    /// Rows on this page: 50 when absent, at most 500.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Where the previous page stopped: its `next_cursor`.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// One page of what one wake pass recorded, read on one snapshot, and the
/// pass as it runs now, sampled after.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeView {
    /// The pass, as 32 hex.
    pub wake_ref: String,
    pub header: DreamerWakeHeaderView,
    /// On an attempt's read: the addressed generation.
    #[serde(default)]
    pub generation: Option<DreamerWakeGenerationView>,
    /// On a pass's read: the attempt generations it admitted, in attempt
    /// order.
    #[serde(default)]
    pub members: Vec<DreamerWakeGenerationView>,
    /// On an attempt's read: its model calls in that pass, in call order.
    #[serde(default)]
    pub calls: Vec<DreamerWakeCallView>,
    /// The next page's `cursor`; absent once this page reached the end.
    #[serde(default)]
    pub next_cursor: Option<String>,
    /// The pass as this host runs it now, sampled after the page and never
    /// atomically with it; absent when nothing here runs it.
    #[serde(default)]
    pub live: Option<DreamerWakeLiveView>,
}

/// One pass's clock and where it ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeHeaderView {
    /// What woke the pass.
    pub trigger: String,
    pub scope: String,
    /// The worker label the pass leases its attempts under.
    pub worker: String,
    /// The node that ran it, as a decimal string.
    pub node_id: String,
    /// The pass's wake-budget line, a diagnostic name.
    pub budget_id: String,
    /// Unix ms at the deadline's origin; absent under an injected clock.
    pub origin_unix_ms: Option<u64>,
    /// The pass's wall-clock ceiling, ms on its own clock.
    pub ceiling_ms: u64,
    /// The ceiling anchored to the wall origin, Unix ms.
    pub ceiling_unix_ms: Option<u64>,
    /// When its hooks allowed the pass: Unix ms, and ms on its clock.
    pub entered_unix_ms: u64,
    pub entered_elapsed_ms: u64,
    /// How it ended; absent while it runs, and for good when its process
    /// died first.
    pub ended: Option<DreamerWakeEndView>,
}

/// How a pass ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeEndView {
    pub unix_ms: u64,
    pub elapsed_ms: u64,
    /// Why it stopped; absent when it returned an error.
    pub stop: Option<String>,
}

/// One attempt generation a pass admitted, with the Checkpoint park that
/// pass cut, once it parked, and the earlier cut it continues as the same
/// try.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeGenerationView {
    /// The attempt, as 32 hex.
    pub job_ref: String,
    /// The queue generation its admission leased.
    pub attempt_count: u32,
    /// The pass that admitted it, as 32 hex.
    pub wake_ref: String,
    pub worker: String,
    pub run_id: Option<String>,
    /// Ms on the pass's clock when its admission was observed.
    pub admitted_elapsed_ms: u64,
    pub checkpoint: Option<DreamerWakeCheckpointView>,
    pub after_cut: Option<DreamerWakeCheckpointView>,
}

/// One Checkpoint park a pass cut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeCheckpointView {
    /// The park, as 32 hex.
    pub park_ref: String,
    pub job_ref: String,
    pub attempt_count: u32,
    /// The pass that cut it, as 32 hex.
    pub wake_ref: String,
    /// Unix seconds.
    pub parked_at: u64,
    /// The steps the cutting pass recorded, each as its 64-hex request hash:
    /// what the same try replays from its memo once resumed.
    pub saved_steps: Vec<String>,
    /// The later pass that resumed it.
    pub resumed: Option<DreamerWakeResumeView>,
}

/// The later pass that resumed a Checkpoint park.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeResumeView {
    pub wake_ref: String,
    /// Unix seconds.
    pub at: u64,
    pub worker: String,
}

/// One model call a pass admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeCallView {
    /// The call, as 32 hex.
    pub call_ref: String,
    pub job_ref: String,
    pub attempt_count: u32,
    /// The logical step's canonical request hash, as 64 hex.
    pub step_hash: String,
    /// 0 for the step's own call, n for its nth schema correction.
    pub ordinal: u32,
    /// The lease its guard issued: a diagnostic, not a capability.
    pub lease_id: String,
    /// Ms on the pass's clock just after its guard admitted it.
    pub admitted_elapsed_ms: u64,
    pub end: Option<DreamerWakeCallEndView>,
}

/// How one call closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeCallEndView {
    pub state: DreamerWakeCallStateView,
    pub at_unix_ms: u64,
    pub used_units: Option<u64>,
    /// The terminal step claim that recorded its step, as 32 hex.
    pub claim_ref: Option<String>,
}

/// A call's last recorded state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DreamerWakeCallStateView {
    /// Its step's terminal claim recorded the response.
    Claimed,
    /// Its lease settled the units it charged; no claim recorded a response.
    Settled,
    /// Its lease was released untouched.
    Aborted,
    /// It closed with its lease still open, or one its guard no longer knows.
    Unsettled,
}

/// A running pass as its clock and its calls' guards read now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeLiveView {
    pub elapsed_ms: u64,
    pub remaining_ms: u64,
    /// Its calls still running.
    pub calls: Vec<DreamerWakeLiveCallView>,
}

/// One running call and its lease as the guard that issued it holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DreamerWakeLiveCallView {
    pub call_ref: String,
    pub lease_id: String,
    /// Absent once that guard holds no lease by this id.
    pub lease: Option<DreamerWakeLeaseView>,
}

/// A live lease's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DreamerWakeLeaseView {
    /// Admitted and not yet closed; `dispatched` once bytes may have left.
    Open {
        reserve_units: u64,
        dispatched: bool,
    },
    /// Closed with the units it charged.
    Settled { used_units: u64 },
    /// Released untouched.
    Aborted,
}

impl Memory<'_> {
    /// One page of the wake observation `input` addresses (DOOR-144 B).
    /// `None` for an attempt or a pass no observed wake recorded: no
    /// observation, which is not the same as no work.
    pub fn dreamer_wake_status(
        &self,
        input: &ConsolidationWakeStatusRequest,
    ) -> MemoryResult<Option<DreamerWakeView>> {
        let request = wake_request(input)?;
        let Some(observation) = self.vault.dreamer_wake_observation(&request)? else {
            return Ok(None);
        };
        Ok(Some(wake_view(observation)))
    }
}

fn wake_request(input: &ConsolidationWakeStatusRequest) -> MemoryResult<WakeObservationRequest> {
    let wake = input.wake_ref.as_deref().map(wake_ref).transpose()?;
    let selector = match (&input.job_ref, wake) {
        (Some(job_ref), wake) => WakeObservationSelector::Attempt {
            attempt: parse_job_ref(job_ref)?,
            wake,
        },
        (None, Some(wake)) => WakeObservationSelector::Wake { wake },
        (None, None) => {
            return Err(MemoryError::bad_request_with(
                "a wake read names an attempt or a wake pass",
                &["Send job_ref for an attempt's observation, or wake_ref for a pass's."],
            ));
        }
    };
    let cursor = input
        .cursor
        .as_deref()
        .map(|cursor| parse_cursor(cursor, &selector))
        .transpose()?;
    Ok(WakeObservationRequest {
        selector,
        limit: input
            .limit
            .map(|limit| usize::try_from(limit).unwrap_or(WAKE_OBSERVATION_PAGE_MAX)),
        cursor,
    })
}

fn wake_ref(text: &str) -> MemoryResult<WakeRef> {
    EntityId::from_hex(text.trim())
        .map(WakeRef::from_entity_id)
        .map_err(|_| MemoryError::bad_request(format!("wake ref {text:?} is not a 32-hex id")))
}

/// A cursor as the previous page spelled it: `call:<32 hex>` on an
/// attempt's page, `member:<32 hex>:<count>` on a pass's.
fn parse_cursor(
    text: &str,
    selector: &WakeObservationSelector,
) -> MemoryResult<WakeObservationCursor> {
    let refused = || {
        MemoryError::bad_request_with(
            format!("cursor {text:?} is not this read's next_cursor"),
            &["Send the next_cursor the previous page of the same read answered."],
        )
    };
    match selector {
        WakeObservationSelector::Attempt { .. } => {
            let call = text.strip_prefix("call:").ok_or_else(refused)?;
            EntityId::from_hex(call)
                .map(WakeObservationCursor::Call)
                .map_err(|_| refused())
        }
        WakeObservationSelector::Wake { .. } => {
            let member = text.strip_prefix("member:").ok_or_else(refused)?;
            let (attempt, count) = member.split_once(':').ok_or_else(refused)?;
            Ok(WakeObservationCursor::Member {
                attempt: parse_job_ref(attempt).map_err(|_| refused())?,
                attempt_count: count.parse().map_err(|_| refused())?,
            })
        }
    }
}

fn cursor_text(cursor: WakeObservationCursor) -> String {
    match cursor {
        WakeObservationCursor::Call(call) => format!("call:{}", call.to_hex()),
        WakeObservationCursor::Member {
            attempt,
            attempt_count,
        } => format!("member:{}:{attempt_count}", hex_string(attempt.as_bytes())),
    }
}

fn wake_view(observation: WakeObservation) -> DreamerWakeView {
    let header = &observation.header;
    DreamerWakeView {
        wake_ref: observation.wake.entity_id().to_hex(),
        header: DreamerWakeHeaderView {
            trigger: header.trigger.clone(),
            scope: header.scope.clone(),
            worker: header.worker.clone(),
            node_id: header.node_id.to_string(),
            budget_id: header.budget_id.clone(),
            origin_unix_ms: header.origin_unix_ms,
            ceiling_ms: header.ceiling_ms,
            ceiling_unix_ms: header.ceiling_unix_ms(),
            entered_unix_ms: header.entered_unix_ms,
            entered_elapsed_ms: header.entered_elapsed_ms,
            ended: header.ended.as_ref().map(|end| DreamerWakeEndView {
                unix_ms: end.unix_ms,
                elapsed_ms: end.elapsed_ms,
                stop: end.stop.clone(),
            }),
        },
        generation: observation.generation.as_ref().map(generation_view),
        members: observation.members.iter().map(generation_view).collect(),
        calls: observation.calls.iter().map(call_view).collect(),
        next_cursor: observation.next.map(cursor_text),
        live: observation.live.map(|live| DreamerWakeLiveView {
            elapsed_ms: live.elapsed_ms,
            remaining_ms: live.remaining_ms,
            calls: live
                .calls
                .into_iter()
                .map(|call| DreamerWakeLiveCallView {
                    call_ref: call.call.to_hex(),
                    lease_id: call.lease_id,
                    lease: call.lease.map(|lease| match lease {
                        BudgetLeaseState::Open {
                            reserve_units,
                            dispatched,
                        } => DreamerWakeLeaseView::Open {
                            reserve_units,
                            dispatched,
                        },
                        BudgetLeaseState::Settled { used_units } => {
                            DreamerWakeLeaseView::Settled { used_units }
                        }
                        BudgetLeaseState::Aborted => DreamerWakeLeaseView::Aborted,
                    }),
                })
                .collect(),
        }),
    }
}

fn generation_view(generation: &WakeObservedGeneration) -> DreamerWakeGenerationView {
    let attempt = &generation.attempt;
    DreamerWakeGenerationView {
        job_ref: hex_string(attempt.attempt.as_bytes()),
        attempt_count: attempt.attempt_count,
        wake_ref: attempt.wake.entity_id().to_hex(),
        worker: attempt.worker.clone(),
        run_id: attempt.run_id.clone(),
        admitted_elapsed_ms: attempt.admitted_elapsed_ms,
        checkpoint: attempt
            .park
            .zip(generation.checkpoint.as_ref())
            .map(|(park, cut)| checkpoint_view(park, cut)),
        after_cut: attempt
            .after_cut
            .zip(generation.after_cut.as_ref())
            .map(|(park, cut)| checkpoint_view(park, cut)),
    }
}

fn checkpoint_view(park: EntityId, cut: &WakeObservedCheckpoint) -> DreamerWakeCheckpointView {
    DreamerWakeCheckpointView {
        park_ref: park.to_hex(),
        job_ref: hex_string(cut.attempt.as_bytes()),
        attempt_count: cut.attempt_count,
        wake_ref: cut.wake.entity_id().to_hex(),
        parked_at: cut.parked_at,
        saved_steps: cut
            .saved_steps
            .iter()
            .map(|step| hex_string(step))
            .collect(),
        resumed: cut.resumed.as_ref().map(|resumed| DreamerWakeResumeView {
            wake_ref: resumed.wake.entity_id().to_hex(),
            at: resumed.at,
            worker: resumed.worker.clone(),
        }),
    }
}

fn call_view(call: &WakeObservedCall) -> DreamerWakeCallView {
    DreamerWakeCallView {
        call_ref: call.call.to_hex(),
        job_ref: hex_string(call.attempt.as_bytes()),
        attempt_count: call.attempt_count,
        step_hash: hex_string(&call.step_hash),
        ordinal: call.ordinal,
        lease_id: call.lease_id.clone(),
        admitted_elapsed_ms: call.admitted_elapsed_ms,
        end: call.end.as_ref().map(|end| DreamerWakeCallEndView {
            state: match end.state {
                WakeCallState::Claimed => DreamerWakeCallStateView::Claimed,
                WakeCallState::Settled => DreamerWakeCallStateView::Settled,
                WakeCallState::Aborted => DreamerWakeCallStateView::Aborted,
                WakeCallState::Unsettled => DreamerWakeCallStateView::Unsettled,
            },
            at_unix_ms: end.at_unix_ms,
            used_units: end.used_units,
            claim_ref: end.claim.map(|claim| claim.to_hex()),
        }),
    }
}
