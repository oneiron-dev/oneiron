//! The request a code fix replays exactly (FIX 1662): the one the failing
//! call sent, as the vault kept it before the call, rather than one rebuilt
//! from the failure's instructions, briefing and task. A failure-ladder case
//! reads its failing attempt's last kept call: its replay capsule (an
//! executor or workflow step's), else a durable step's row. A blocked report
//! reads the request its row keeps, or the call of its run that the row
//! names by its hash. A request that no longer reads as the copy kept, or
//! that was never kept, leaves the replay to rebuild the call, and the
//! replay says so. A capsule the wall withheld its request from keeps no
//! copy, and says why (FIX 6348). An erased capsule's call is replayed by
//! no copy and no rebuild (FIX 6251).

use serde::{Deserialize, Serialize};

use super::{CodeFixSource, failed_case_in};
use crate::attempt_queue::AttemptId;
use crate::code_run::{CapsuleRequest, CapsuleRungBinding, capsule_request, step_replay_capsules};
use crate::self_heal::blocked_reports::{SentRequest, blocked_source_in, step_sources_in};
use crate::{EntityId, LlmRequest, Result, Vault};

/// The request a failing call sent, as the vault kept it, for a replay that
/// sends it again inside the vault.
#[derive(Debug, Clone, PartialEq)]
pub struct ExactReplayRequest {
    /// The request, canonical, with its tool declarations: a replay keeps
    /// them, and runs no tool the answer names.
    pub request: LlmRequest,
    /// The rung that answered the call, when one did; a call no provider
    /// answered has none.
    pub rung: Option<CapsuleRungBinding>,
    /// Whether the copy is the request as sent. `false` when the side-row
    /// wall masked a secret in it: the replay sends the custody handle,
    /// never the secret.
    pub as_sent: bool,
}

impl ExactReplayRequest {
    /// How a replay that sends it runs the failure.
    #[must_use]
    pub const fn fidelity(&self) -> ReplayFidelity {
        if self.as_sent {
            ReplayFidelity::Exact
        } else {
            ReplayFidelity::ExactMasked
        }
    }
}

/// How a code fix's replay ran the real failure (FIX 1662).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayFidelity {
    /// The request the failing call sent, as it was sent.
    Exact,
    /// That request, with each secret in it masked into its custody handle.
    ExactMasked,
    /// Rebuilt from the failure's instructions, briefing and task: not the
    /// request the call sent.
    Rebuilt,
}

/// What the vault kept of the request a failing call sent (FIX 1662).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ExactReplay {
    /// The request as kept.
    Kept(Box<ExactReplayRequest>),
    /// None was kept, or the copy no longer reads as kept: the replay
    /// rebuilds the call.
    NotKept,
    /// The call's capsule keeps no copy: the side-row wall withheld its
    /// request at capture, for `reasons` (FIX 6254, 6348). A durable step's
    /// row of the call, when one reads, is `fallback`; with none the replay
    /// rebuilds the call, as for `NotKept`.
    Withheld {
        reasons: Vec<String>,
        fallback: Option<Box<ExactReplayRequest>>,
    },
    /// The call's replay capsule was erased with its actor (FIX 6144): no
    /// replay of the call runs, rebuilt or not.
    Erased,
}

impl ExactReplay {
    fn of(copy: Option<ExactReplayRequest>) -> Self {
        copy.map_or(Self::NotKept, |copy| Self::Kept(Box::new(copy)))
    }

    /// The request a replay sends: the copy kept, or a withheld capsule's
    /// step-row copy. `None` leaves the replay to rebuild the call, or once
    /// erased, to run none.
    pub(crate) fn request(&self) -> Option<&ExactReplayRequest> {
        match self {
            Self::Kept(request)
            | Self::Withheld {
                fallback: Some(request),
                ..
            } => Some(request),
            Self::NotKept | Self::Withheld { fallback: None, .. } | Self::Erased => None,
        }
    }
}

/// What the vault kept of the request the failure `source` names. A request
/// the report's own row keeps is read there, under that row's own erase.
pub(crate) fn exact_replay(vault: &Vault, source: &CodeFixSource) -> Result<ExactReplay> {
    let txn = vault.store.env.read_txn()?;
    // The attempt whose kept calls hold it, and the hash of the one a report
    // names, when it names one.
    let (attempt, digest) = match source {
        CodeFixSource::Case { case_ref } => match failed_case_in(vault, &txn, case_ref)? {
            Some((case, _)) => (
                EntityId::from_bytes(*case.failing_attempt_id.as_bytes())?,
                None,
            ),
            None => return Ok(ExactReplay::NotKept),
        },
        CodeFixSource::Blocked { receipt, run } => {
            let sent = blocked_source_in(vault, &txn, receipt)?
                .and_then(|source| source.request)
                .and_then(|request| request.sent);
            match (sent, run) {
                // The report's own row keeps it.
                (
                    Some(SentRequest {
                        digest,
                        kept: Some(kept),
                    }),
                    _,
                ) => {
                    let copy = as_kept(kept.request, None, digest, kept.stored);
                    return Ok(ExactReplay::of(copy));
                }
                (sent, Some(run)) => (*run, sent.map(|sent| sent.digest)),
                (_, None) => return Ok(ExactReplay::NotKept),
            }
        }
    };
    drop(txn);
    let replay = attempt_request(vault, attempt, digest)?;
    if let ExactReplay::Withheld { reasons, fallback } = &replay {
        // Local only (FIX 6348): why the capsule keeps no copy.
        tracing::debug!(
            ?reasons,
            step_copy = fallback.is_some(),
            "the failing call's capsule withheld its request"
        );
    }
    Ok(replay)
}

/// `request` while it still reads as the copy kept, whose hash is `stored`;
/// it is the request as sent when that is `sent` too.
fn as_kept(
    request: LlmRequest,
    rung: Option<CapsuleRungBinding>,
    sent: [u8; 32],
    stored: [u8; 32],
) -> Option<ExactReplayRequest> {
    if request.canonical_hash().ok()? != stored {
        return None;
    }
    Some(ExactReplayRequest {
        request,
        rung,
        as_sent: stored == sent,
    })
}

/// The failing call among `attempt`'s kept calls: the one whose hash is
/// `digest`, or with none named, the last one it sent. Its replay capsule
/// first, then a durable step's row. A capsule whose copy reads as none is
/// read again before a step's row stands in for it, so an erase meanwhile
/// reads as erased (FIX 6251).
fn attempt_request(
    vault: &Vault,
    attempt: EntityId,
    digest: Option<[u8; 32]>,
) -> Result<ExactReplay> {
    let capsule = step_replay_capsules(vault, attempt)?
        .into_iter()
        .rev()
        .find(|capsule| digest.is_none_or(|digest| capsule.request_hash == digest));
    // The selected capsule, once it read as live but its copy as none.
    let mut held = None;
    if let Some(capsule) = capsule {
        // An erased capsule's request went with its actor (FIX 6144): no
        // other copy stands in for it.
        if capsule.content.actor().is_none() {
            return Ok(ExactReplay::Erased);
        }
        // The copy kept is the request as sent unless the wall masked a
        // secret in it: its sent identity and its stored hash then differ.
        let as_sent = capsule.as_sent();
        if let Some(request) = capsule_request(vault, &capsule)? {
            return Ok(ExactReplay::of(Some(ExactReplayRequest {
                request,
                rung: capsule.binding,
                as_sent,
            })));
        }
        held = Some(capsule);
    }
    let steps = {
        let txn = vault.store.env.read_txn()?;
        step_sources_in(vault, &txn, AttemptId::from_bytes(attempt.as_bytes())?)?
    };
    let copy = steps
        .into_iter()
        .rev()
        .find(|(key, _)| digest.is_none_or(|digest| key.step == digest))
        .and_then(|(key, source)| {
            as_kept(
                source.request.request,
                None,
                key.step,
                source.request.stored,
            )
        });
    let Some(capsule) = held else {
        return Ok(ExactReplay::of(copy));
    };
    // Read again after the step's row, before its copy stands in: an erase
    // since the first read takes the call, and no copy replays it.
    let erased = step_replay_capsules(vault, attempt)?
        .iter()
        .find(|again| {
            again.lease_generation == capsule.lease_generation && again.step == capsule.step
        })
        .is_some_and(|again| again.content.actor().is_none());
    if erased {
        return Ok(ExactReplay::Erased);
    }
    Ok(match capsule.request {
        CapsuleRequest::Withheld { reasons } => ExactReplay::Withheld {
            reasons,
            fallback: copy.map(Box::new),
        },
        CapsuleRequest::Kept { .. } => ExactReplay::of(copy),
    })
}
