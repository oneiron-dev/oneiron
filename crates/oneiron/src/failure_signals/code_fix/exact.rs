//! The request a code fix replays exactly (FIX 1662): the one the failing
//! call sent, as the vault kept it before the call, rather than one rebuilt
//! from the failure's instructions, briefing and task. A failure-ladder case
//! reads its failing attempt's last kept call: its replay capsule (an
//! executor or workflow step's), else a durable step's row. A blocked report
//! reads the request its row keeps, or the call of its run that the row
//! names by its hash. A request that no longer reads as the copy kept, or
//! that was never kept, leaves the replay to rebuild the call, and the
//! replay says so.

use serde::{Deserialize, Serialize};

use super::{CodeFixSource, failed_case_in};
use crate::attempt_queue::AttemptId;
use crate::code_run::{CapsuleRungBinding, capsule_request, step_replay_capsules};
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

/// The request the failure `source` names was sent as, when the vault kept
/// it; `None` leaves the replay to rebuild the call.
pub(crate) fn exact_replay_request(
    vault: &Vault,
    source: &CodeFixSource,
) -> Result<Option<ExactReplayRequest>> {
    let txn = vault.store.env.read_txn()?;
    // The attempt whose kept calls hold it, and the hash of the one a report
    // names, when it names one.
    let (attempt, digest) = match source {
        CodeFixSource::Case { case_ref } => match failed_case_in(vault, &txn, case_ref)? {
            Some((case, _)) => (
                EntityId::from_bytes(*case.failing_attempt_id.as_bytes())?,
                None,
            ),
            None => return Ok(None),
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
                ) => return Ok(as_kept(kept.request, None, digest, kept.stored)),
                (sent, Some(run)) => (*run, sent.map(|sent| sent.digest)),
                (_, None) => return Ok(None),
            }
        }
    };
    drop(txn);
    attempt_request(vault, attempt, digest)
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
/// first, then a durable step's row.
fn attempt_request(
    vault: &Vault,
    attempt: EntityId,
    digest: Option<[u8; 32]>,
) -> Result<Option<ExactReplayRequest>> {
    let capsule = step_replay_capsules(vault, attempt)?
        .into_iter()
        .rev()
        .find(|capsule| digest.is_none_or(|digest| capsule.request_hash == digest));
    if let Some(capsule) = capsule
        && let Some(request) = capsule_request(vault, &capsule)?
    {
        return Ok(Some(ExactReplayRequest {
            request,
            rung: capsule.binding,
            as_sent: true,
        }));
    }
    let steps = {
        let txn = vault.store.env.read_txn()?;
        step_sources_in(vault, &txn, AttemptId::from_bytes(attempt.as_bytes())?)?
    };
    Ok(steps
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
        }))
}
